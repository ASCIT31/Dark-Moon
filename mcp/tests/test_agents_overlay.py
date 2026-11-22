"""Agents = image + user overlay (conf/agents-overlay.py, run by the opencode entrypoint before apply-settings.sh).

Shipped agents always come from the image; darkmoon-settings/agents holds only the agents the user added or customised
(a file named like a shipped one replaces it). The runtime directory /root/.opencode/agents is rebuilt from both at every
start, never persisted. An install from before the overlay is migrated once: files byte-identical to a version we
shipped (conf/agents-shipped.sha256) leave the overlay, after a backup of the whole folder; customised ones stay and are
listed once. These tests run the real script, the real apply-settings.sh and read the real compose files.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "conf" / "agents-overlay.py"
SHIPPED = ROOT / "conf" / "agents-shipped.sha256"
AGENTS = ROOT / "conf" / "agents"
OLD_PENTEST = ("---\nid: pentest\nname: pentest\n---\nRead the\n\"prompt_file\" value of the sub-agent's entry in "
               "opencode.json and read THAT\n")


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def env(tmp_path):
    image = tmp_path / "image"
    settings = tmp_path / "darkmoon-settings"           # mounted on /root/.config/opencode
    overlay, runtime = settings / "agents", tmp_path / "home" / ".opencode" / "agents"
    image.mkdir()
    settings.mkdir()
    old = {"php.md": b"---\nid: php\nname: php\n---\nold php\n", "pentest.md": OLD_PENTEST.encode(),
           "aws.md": b"---\nid: aws\nname: aws\n---\nold aws\n"}
    new = {"php.md": b"---\nname: php\n---\nnew php\n", "pentest.md": AGENTS.joinpath("pentest.md").read_bytes(),
           "aws.md": b"---\nname: aws\n---\nnew aws\n", "golang.md": b"---\nname: golang\n---\nnew agent\n"}
    for name, data in new.items():
        (image / name).write_bytes(data)
    shipped = tmp_path / "shipped.sha256"
    shipped.write_text("# list\n" + "".join(f"{h(d)}  {n}\n" for n, d in list(old.items()) + list(new.items())))
    return dict(image=image, settings=settings, overlay=overlay, runtime=runtime, shipped=shipped, old=old, new=new)


def run(e, shipped=None, rc=0):
    p = subprocess.run([sys.executable, str(SCRIPT), str(e["image"]), str(e["overlay"]), str(e["runtime"]),
                        str(shipped or e["shipped"])], capture_output=True, text=True, timeout=30)
    assert p.returncode == rc, p.stdout + p.stderr
    return p.stdout


def seed_old_install(e, **custom):
    """darkmoon-settings/agents as the old entrypoint left it: every shipped agent of the old image, seeded once."""
    e["overlay"].mkdir()
    for name, data in e["old"].items():
        (e["overlay"] / name).write_bytes(custom.get(name, data))


def listing(d):
    return {p.name: p.read_bytes() for p in Path(d).iterdir() if p.is_file()}


def test_fresh_install_runs_the_image_agents_and_writes_nothing_shipped_to_settings(env):
    out = run(env)
    assert listing(env["runtime"]) == env["new"]
    assert listing(env["overlay"]) == {}                       # the overlay exists, empty: where custom agents go
    assert "NOTICE" not in out and "WARNING" not in out


def test_unmodified_old_files_leave_the_overlay_after_a_backup(env):
    seed_old_install(env)
    out = run(env)
    assert listing(env["overlay"]) == {}
    assert listing(env["runtime"]) == env["new"]               # the new shipped versions run
    backups = list(env["settings"].glob("agents-backup-*"))
    assert len(backups) == 1 and listing(backups[0]) == env["old"]   # nothing deleted without a backup
    assert "is now an overlay" in out and "NOTICE" not in out


def test_customised_file_stays_as_an_overlay_and_is_listed_once(env):
    mine = env["old"]["aws.md"] + b"my own extra check\n"
    seed_old_install(env, **{"aws.md": mine})
    out = run(env)
    assert listing(env["overlay"]) == {"aws.md": mine}
    assert (env["runtime"] / "aws.md").read_bytes() == mine    # the customisation replaces the shipped agent
    assert (env["runtime"] / "php.md").read_bytes() == env["new"]["php.md"]
    assert "NOTICE" in out and "  - aws.md" in out and "\"id:\" line" in out


def test_customised_pre_registry_orchestrator_is_explained(env):
    mine = (OLD_PENTEST + "my house rule\n").encode()
    seed_old_install(env, **{"pentest.md": mine})
    out = run(env)
    assert (env["runtime"] / "pentest.md").read_bytes() == mine
    assert "no agent registry" in out and "task tool's own list" in out and "compatibility mode" in out


def test_user_added_agent_is_never_touched_and_runs(env):
    seed_old_install(env)
    (env["overlay"] / "my-agent.md").write_text("---\nname: my-agent\n---\nmine\n")
    out = run(env)
    assert (env["overlay"] / "my-agent.md").read_text().endswith("mine\n")
    assert (env["runtime"] / "my-agent.md").read_text().endswith("mine\n")
    assert "user agents (darkmoon-settings/agents): my-agent.md" in out


def test_new_shipped_agent_runs_without_being_copied_to_settings(env):
    seed_old_install(env)
    run(env)
    assert (env["runtime"] / "golang.md").read_bytes() == env["new"]["golang.md"]
    assert not (env["overlay"] / "golang.md").exists()


def test_second_start_is_idempotent(env):
    seed_old_install(env, **{"aws.md": env["old"]["aws.md"] + b"mine\n"})
    run(env)
    overlay, runtime = listing(env["overlay"]), listing(env["runtime"])
    out = run(env)
    assert listing(env["overlay"]) == overlay and listing(env["runtime"]) == runtime
    assert len(list(env["settings"].glob("agents-backup-*"))) == 1
    assert "NOTICE" not in out and "is now an overlay" not in out
    assert "customised agents (darkmoon-settings/agents, replace the shipped ones): aws.md" in out


def test_after_migration_a_copy_of_a_shipped_file_is_a_deliberate_override(env):
    """The migration runs once: a file the user puts in the overlay later is theirs, even if equal to a shipped one."""
    run(env)
    (env["overlay"] / "php.md").write_bytes(env["old"]["php.md"])
    run(env)
    assert (env["overlay"] / "php.md").exists()
    assert (env["runtime"] / "php.md").read_bytes() == env["old"]["php.md"]


def test_runtime_is_rebuilt_so_no_stale_file_survives(env):
    run(env)
    (env["overlay"] / "tmp-agent.md").write_text("x\n")
    run(env)
    (env["overlay"] / "tmp-agent.md").unlink()
    (env["image"] / "golang.md").write_bytes(b"---\nname: golang\n---\nnewer\n")   # an image update
    run(env)
    assert not (env["runtime"] / "tmp-agent.md").exists()
    assert (env["runtime"] / "golang.md").read_bytes().endswith(b"newer\n")
    assert not [p for p in env["runtime"].parent.iterdir() if p.name != "agents"]  # no leftover tmp / old dirs


def test_unreadable_shipped_list_removes_nothing_and_retries(env, tmp_path):
    seed_old_install(env)
    out = run(env, shipped=tmp_path / "missing.sha256")
    assert listing(env["overlay"]) == env["old"] and "unreadable" in out
    assert not (env["settings"] / ".darkmoon-agents-overlay").exists()   # migration retried at the next start
    run(env)
    assert listing(env["overlay"]) == {}


def test_old_compose_mount_is_left_as_it_was_with_a_warning(env):
    """Old docker-compose.yml: the runtime directory IS darkmoon-settings/agents (bind mount). Nothing shipped may be
    written into it beyond the first seeding it always had, and nothing is removed."""
    seed_old_install(env)
    env["runtime"].parent.mkdir(parents=True)
    env["runtime"].symlink_to(env["overlay"], target_is_directory=True)   # same directory, as the bind mount
    out = run(env)
    assert listing(env["overlay"]) == env["old"]
    assert "still mounts darkmoon-settings/agents" in out
    assert not list(env["settings"].glob("agents-backup-*"))
    # install.sh deletes darkmoon-settings (customised agents included, no backup): the warning must not send a user
    # with customisations there
    assert "docker compose up -d" in out and "Do not use ./install.sh" in out


# --- the shipped list -------------------------------------------------------------------------------------------

def _shipped():
    out = {}
    for line in SHIPPED.read_text().splitlines():
        if line and not line.startswith("#"):
            digest, name = line.split()
            out.setdefault(name, set()).add(digest)
    return out


def test_shipped_list_has_the_version_this_image_ships():
    """The next update must recognise today's files: run tools/agent-build/shipped_hashes.py after an agent edit."""
    shipped = _shipped()
    for f in sorted(AGENTS.glob("*.md")):
        assert h(f.read_bytes()) in shipped.get(f.name, ()), \
            f"{f.name}: current version missing from conf/agents-shipped.sha256 (run tools/agent-build/shipped_hashes.py)"


def test_shipped_list_has_the_released_versions():
    p = subprocess.run(["git", "-C", str(ROOT), "show", "v1.7.0:conf/agents/pentest.md"], capture_output=True)
    if p.returncode != 0:
        pytest.skip("release tag v1.7.0 not in this checkout")
    assert h(p.stdout) in _shipped()["pentest.md"]


# --- wiring ---------------------------------------------------------------------------------------------------

def test_compose_files_no_longer_mount_the_settings_agents_on_the_runtime_dir():
    for name in ("docker-compose.yml", "docker-compose-dev.yml"):
        text = (ROOT / name).read_text()
        assert "./darkmoon-settings:/root/.config/opencode/" in text           # the overlay, seen by opencode too
        assert "/root/.opencode/agents" not in text, name


def test_image_and_entrypoint_wiring():
    df = (ROOT / "Dockerfile.opencode").read_text()
    assert "COPY conf/agents-shipped.sha256 /opt/darkmoon/agents-shipped.sha256" in df
    assert "COPY conf/agents-overlay.py /root/conf/agents-overlay.py" in df
    ep = (ROOT / "conf" / "entrypoint-opencode.sh").read_text()
    assert 'AGENTS_OVERLAY="/root/.config/opencode/agents"' in ep and 'AGENTS_DIR="/root/.opencode/agents"' in ep
    assert ep.index('python3 "$AGENTS_OVERLAY_SCRIPT"') < ep.index('if ! "$APPLY_SCRIPT"')


# --- compatibility mode for a customised pre-registry orchestrator --------------------------------------------

def _apply(tmp_path, pentest_text):
    agents = tmp_path / "agents"
    shutil.copytree(AGENTS, agents)                             # the runtime directory: shipped agents ...
    (agents / "pentest.md").write_text(pentest_text)            # ... with this orchestrator
    script = (ROOT / "conf" / "apply-settings.sh").read_text() \
        .replace('OPENCODE_CONFIG_DIR="/root/.config/opencode"', f'OPENCODE_CONFIG_DIR="{tmp_path}/cfg"') \
        .replace('OPENCODE_AUTH_DIR="/root/.local/share/opencode"', f'OPENCODE_AUTH_DIR="{tmp_path}/share"')
    s = tmp_path / "apply-settings.sh"
    s.write_text(script)
    p = subprocess.run(["bash", str(s)], capture_output=True, text=True, timeout=60,
                       env={"PATH": os.environ["PATH"], "HOME": str(tmp_path), "DARKMOON_MCP_TRANSPORT": "stdio",
                            "DARKMOON_AGENTS_DIR": str(agents)})
    assert p.returncode == 0, p.stdout + p.stderr
    return json.loads((tmp_path / "cfg" / "opencode.json").read_text()), p.stdout + p.stderr


def test_customised_pre_registry_orchestrator_still_finds_its_agents(tmp_path):
    cfg, out = _apply(tmp_path, OLD_PENTEST + "my house rule\n")
    agents = tmp_path / "agents"
    for name, block in cfg["agent"].items():
        assert set(block) == {"model", "mode", "prompt_file"}, name    # only the key the old orchestrator reads
        assert Path(block["prompt_file"]).is_file() and Path(block["prompt_file"]).parent == agents
    assert cfg["agent"]["active-directory"]["prompt_file"].endswith("/ad.md")
    assert cfg["agent"]["nodejs"]["prompt_file"].endswith("/nodejs-express-angular.md")
    assert cfg["agent"]["kubernetes"]["prompt_file"].endswith("/kubernetes.md")
    assert "compatibility mode" in out


def test_current_orchestrator_gets_native_keys_only(tmp_path):
    cfg, out = _apply(tmp_path, AGENTS.joinpath("pentest.md").read_text())
    assert all("prompt_file" not in b for b in cfg["agent"].values())
    assert "compatibility mode" not in out
