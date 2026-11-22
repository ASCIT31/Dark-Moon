"""An install seeded before the Darkmoon agent registry is refreshed once at start (conf/entrypoint-opencode.sh).

The agents directory (./darkmoon-settings/agents) is seeded from the image only when it is empty, so an existing install
keeps its old agent files across image updates. The old orchestrator looks for the agent files in opencode.json, which
no longer lists them (darkmoon-agents.json does), and the old front matter carries an « id: » key that opencode sends
to the model provider. The entrypoint block refreshes such a set from the image once, keeping a backup of every file.
These tests run the real block of the entrypoint with its paths redirected to a temporary directory.
"""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "conf" / "entrypoint-opencode.sh"
OLD_PENTEST = 'Read the\n"prompt_file" value of the sub-agent\'s entry in opencode.json and read THAT\n'


def _block():
    m = re.search(r"^# >>> agents-registry-upgrade.*?^# <<< agents-registry-upgrade$", ENTRYPOINT.read_text(), re.S | re.M)
    assert m, "agents-registry-upgrade block not found in the entrypoint"
    return m.group(0)


def _run(tmp_path):
    script = "\n".join([
        "set -u",
        "log() { printf '%s\\n' \"$*\"; }",
        f'AGENTS_DIR="{tmp_path}/agents"',
        f'DEFAULT_AGENTS="{tmp_path}/default-agents"',
        f'OPENCODE_CONFIG_FILE="{tmp_path}/cfg/opencode.json"',
        _block(),
    ])
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       env={"PATH": os.environ["PATH"]})
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout


def _setup(tmp_path, pentest_text):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "default-agents").mkdir()
    (tmp_path / "agents").mkdir()
    (tmp_path / "default-agents" / "pentest.md").write_text((ROOT / "conf" / "agents" / "pentest.md").read_text())
    (tmp_path / "default-agents" / "php.md").write_text("---\nname: php\n---\nnew\n")
    (tmp_path / "agents" / "pentest.md").write_text(pentest_text)
    (tmp_path / "agents" / "php.md").write_text("---\nid: php\nname: php\n---\nold\n")
    (tmp_path / "agents" / "my-agent.md").write_text("---\nname: my-agent\n---\nmine\n")


def test_shipped_orchestrator_is_not_detected_as_old():
    assert "entry in opencode.json" not in (ROOT / "conf" / "agents" / "pentest.md").read_text()


def test_pre_registry_set_is_refreshed_with_a_backup(tmp_path):
    _setup(tmp_path, "---\nid: pentest\nname: pentest\n---\n" + OLD_PENTEST)
    out = _run(tmp_path)
    assert "refreshed from the image" in out
    assert "darkmoon-agents.json" in (tmp_path / "agents" / "pentest.md").read_text()
    assert (tmp_path / "agents" / "php.md").read_text().endswith("new\n")
    assert (tmp_path / "agents" / "my-agent.md").exists()                 # a file of the user is never removed
    backups = list((tmp_path / "cfg").glob("agents-backup-*"))
    assert len(backups) == 1
    assert (backups[0] / "php.md").read_text().endswith("old\n")
    assert OLD_PENTEST in (backups[0] / "pentest.md").read_text()
    # second start: nothing left to migrate
    assert "refreshed" not in _run(tmp_path)
    assert len(list((tmp_path / "cfg").glob("agents-backup-*"))) == 1


def test_current_set_is_left_alone(tmp_path):
    _setup(tmp_path, (ROOT / "conf" / "agents" / "pentest.md").read_text())
    assert "refreshed" not in _run(tmp_path)
    assert (tmp_path / "agents" / "php.md").read_text().endswith("old\n")
    assert not list((tmp_path / "cfg").glob("agents-backup-*"))
