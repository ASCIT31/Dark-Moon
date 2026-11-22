"""`darkmoon --log <session_id>` (darkmoon-cli = src.mcp_monitoring) must show the live output of THAT session.

A user report: the console printed « streaming MCP output... » and nothing else. The MCP server broadcasts the
output of a command run with the session id of darkmoon_get_session to /tmp/darkmoon_mcp_stream_<sid>.sock, while the
console ignored its argument and listened only on /tmp/darkmoon_mcp_stream.sock. The image wrapper did not even pass
the argument along. These tests drive the real console process and the real broadcaster of DarkmoonDockerClient.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

import src.docker_client as dc

MCP_DIR = Path(__file__).resolve().parents[1]
REPO = MCP_DIR.parent


@pytest.fixture
def base():
    # AF_UNIX paths are limited to ~108 bytes: keep the directory short.
    d = tempfile.mkdtemp(prefix="dmlog", dir="/tmp")
    yield os.path.join(d, "stream")
    shutil.rmtree(d, ignore_errors=True)


def _console(base, *args, idle="20.0"):
    code = (
        "import sys, src.mcp_monitoring as m\n"
        f"m.STREAM_BASE = {base!r}; m.STREAM_SOCK = m.STREAM_BASE + '.sock'; m.IDLE_HINT_AFTER_S = {float(idle)}\n"
        "sys.exit(m.main(sys.argv[1:]))\n"
    )
    p = subprocess.Popen([sys.executable, "-c", code, *args], cwd=MCP_DIR,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.time() + 10
    want = [base + ".sock"] + ([f"{base}_{args[0]}.sock"] if args else [])
    while time.time() < deadline and not all(os.path.exists(w) for w in want):
        if p.poll() is not None:
            break
        time.sleep(0.05)
    return p


def _stop(p):
    p.terminate()
    return p.communicate(timeout=10)[0].decode(errors="replace")


def _broadcaster(monkeypatch, base):
    monkeypatch.setattr(dc, "STREAM_BASE", base)
    c = dc.DarkmoonDockerClient.__new__(dc.DarkmoonDockerClient)
    c._stream_enabled = True
    return c


def test_session_output_reaches_the_console_of_that_session(monkeypatch, base):
    p = _console(base, "ee11e1dd")
    b = _broadcaster(monkeypatch, base)
    b._broadcast(b"nmap output of session ee11e1dd\n", "ee11e1dd")   # execute_command(session_id=...)
    b._broadcast(b"output without a session id\n", None)            # still shown, as before
    time.sleep(0.5)
    out = _stop(p)
    assert "streaming MCP output for session ee11e1dd" in out
    assert "nmap output of session ee11e1dd" in out
    assert "output without a session id" in out
    assert not os.path.exists(f"{base}_ee11e1dd.sock") and not os.path.exists(base + ".sock")  # cleaned up


def test_other_session_output_is_not_shown(monkeypatch, base):
    p = _console(base, "ee11e1dd")
    _broadcaster(monkeypatch, base)._broadcast(b"output of another campaign\n", "aaaa0000")
    time.sleep(0.5)
    assert "output of another campaign" not in _stop(p)


def test_sockets_are_never_world_accessible(base):
    p = _console(base, "ee11e1dd")
    try:
        for path in (base + ".sock", f"{base}_ee11e1dd.sock"):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            assert mode & 0o007 == 0 and mode & 0o660 == 0o660, oct(mode)
    finally:
        _stop(p)


def test_invalid_session_id_is_refused(base):
    p = subprocess.run([sys.executable, "-c",
                        "import sys, src.mcp_monitoring as m\n"
                        f"m.STREAM_BASE = {base!r}; m.STREAM_SOCK = m.STREAM_BASE + '.sock'\n"
                        "sys.exit(m.main(sys.argv[1:]))\n", "../../etc/x"],
                       cwd=MCP_DIR, capture_output=True, text=True, timeout=20)
    assert p.returncode == 2 and "invalid session id" in p.stderr
    assert not os.listdir(os.path.dirname(base))  # no socket created anywhere


def test_silent_session_gets_an_explanation_instead_of_nothing(base):
    """A session whose agent ended (or never ran a command, e.g. the model declined) used to show nothing at all."""
    p = _console(base, "ee11e1dd", idle="0.3")
    time.sleep(1.2)
    out = _stop(p)
    assert "no command output yet" in out and "web dashboard" in out


def test_image_wrapper_passes_the_session_id():
    df = (REPO / "Dockerfile.opencode").read_text()
    i = df.index("> /usr/local/bin/darkmoon-cli")
    wrapper = df[df.rindex("RUN printf", 0, i):i]
    assert "exec python -m src.mcp_monitoring \"$@\"" in wrapper


def test_a_second_console_keeps_its_socket_when_the_first_one_exits(monkeypatch, base):
    """Two `darkmoon --log` at once: the first one to exit must not delete the shared socket the other one bound."""
    a = _console(base, "aaaa0000")
    b = _console(base, "bbbb1111")          # rebinds the shared socket
    _stop(a)
    assert os.path.exists(base + ".sock")
    _broadcaster(monkeypatch, base)._broadcast(b"still streaming to B\n", None)
    time.sleep(0.5)
    assert "still streaming to B" in _stop(b)


def test_a_dangling_link_planted_in_tmp_does_not_stop_the_console(base):
    os.symlink(os.path.dirname(base) + "/nowhere", f"{base}_ee11e1dd.sock")
    p = _console(base, "ee11e1dd")
    try:
        assert p.poll() is None and stat.S_ISSOCK(os.lstat(f"{base}_ee11e1dd.sock").st_mode)
    finally:
        _stop(p)
