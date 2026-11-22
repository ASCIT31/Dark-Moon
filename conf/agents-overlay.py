#!/usr/bin/env python3
"""Compose the runtime agent directory: agents of the image + the user's overlay (darkmoon-settings/agents).

Layout (docker-compose.yml):
  image    /opt/darkmoon/default-agents   the shipped agents, always those of the running image
  overlay  /root/.config/opencode/agents  = darkmoon-settings/agents on the host: ONLY the agents the user added or
                                          customised. A file named like a shipped one replaces it; any other is added.
  runtime  /root/.opencode/agents         container filesystem, rebuilt at every start = image + overlay. opencode loads
                                          it after the overlay (~/.opencode comes after ~/.config/opencode), so a
                                          customised agent wins; the task tool lists every agent from it.
Shipped agents are never copied into darkmoon-settings, so an update can never leave a stale shipped file behind.

One-time migration of an install from before the overlay (the old docker-compose.yml mounted darkmoon-settings/agents
on the runtime directory and the entrypoint seeded every shipped agent into it): a file byte-identical to a version we
shipped (conf/agents-shipped.sha256) was never customised and is removed from the overlay; any other file stays as a
customisation and is listed once. The whole old folder is first copied to darkmoon-settings/agents-backup-<date>.

Still on the old docker-compose.yml (runtime directory = the overlay, a bind mount): nothing can be composed without
writing shipped files into darkmoon-settings, so the folder is left as it is (seeded when empty, as before) and a
warning says to update docker-compose.yml.

Usage: agents-overlay.py <image dir> <overlay dir> <runtime dir> <shipped sha256 list>
"""
import hashlib
import os
import shutil
import sys
import time

MARKER = ".darkmoon-agents-overlay"          # in the overlay's parent (darkmoon-settings): migration done
PRE_REGISTRY_MARK = b"entry in opencode.json"  # orchestrator from before the native dispatch (reads prompt_file)


def log(msg):
    print(f"[agents] {msg}", flush=True)


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def load_shipped(path):
    shipped = {}
    with open(path, encoding="ascii") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                digest, name = line.split(None, 1)
                shipped.setdefault(name.strip(), set()).add(digest)
    return shipped


def files(d):
    """Top-level regular files of a directory (symlinks and dot files are left alone)."""
    if not os.path.isdir(d):
        return []
    return sorted(n for n in os.listdir(d)
                  if not n.startswith(".") and os.path.isfile(os.path.join(d, n))
                  and not os.path.islink(os.path.join(d, n)))


def is_legacy_mount(overlay, runtime):
    """Old docker-compose.yml: darkmoon-settings/agents is bind-mounted on the runtime directory."""
    if not os.path.isdir(runtime):
        return False
    if os.path.ismount(runtime):
        return True
    try:
        return os.path.isdir(overlay) and os.path.samefile(overlay, runtime)
    except OSError:
        return False


def has_id_key(path):
    with open(path, "rb") as fh:
        head = fh.read(400).replace(b"\r\n", b"\n")
    if not head.startswith(b"---\n"):
        return False
    return any(line.startswith(b"id:") for line in head[4:].split(b"\n---", 1)[0].split(b"\n"))


def notes_for(overlay, names):
    lines = []
    for name in names:
        path = os.path.join(overlay, name)
        try:
            if name == "pentest.md" and PRE_REGISTRY_MARK in open(path, "rb").read():
                lines += [
                    "pentest.md: your orchestrator predates the native agent dispatch. There is no agent registry",
                    "any more: the shipped pentest.md takes its sub-agents from the task tool's own list (every",
                    "installed agent with its description) and never reads an agent file; yours still reads each",
                    "agent's \"prompt_file\" from opencode.json. Until you merge the shipped version, a",
                    "compatibility mode keeps \"prompt_file\" in opencode.json so your orchestrator still finds the",
                    "agents. Strict OpenAI-compatible endpoints (Azure AI Foundry, Azure OpenAI) reject that key",
                    "(\"Unrecognized request argument supplied: prompt_file\"): with them, merge before running."]
            if has_id_key(path):
                lines += [f"{name}: its front matter has an \"id:\" line. Delete it (\"name\" is the agent id): opencode "
                          "sends unknown front-matter keys to the model, and strict endpoints reject them."]
        except OSError:
            pass
    return lines


def migrate(image, overlay, shipped_list):
    """Once: drop never-customised shipped files from an old seeded folder, after a backup of the whole folder."""
    state = os.path.dirname(os.path.abspath(overlay))
    marker = os.path.join(state, MARKER)
    if os.path.exists(marker):
        return
    present = files(overlay)
    if present:
        try:
            shipped = load_shipped(shipped_list)
        except (OSError, ValueError) as e:              # nothing is removed; retried at the next start
            log(f"WARNING: shipped versions list unreadable ({e}): darkmoon-settings/agents left as it is")
            return
        stale = [n for n in present if sha256(os.path.join(overlay, n)) in shipped.get(n, ())]
        customised = [n for n in present if n not in stale and n in set(files(image))]
        if stale:
            backup = os.path.join(state, "agents-backup-" + time.strftime("%Y%m%d-%H%M%S"))
            shutil.copytree(overlay, backup, symlinks=True)
            for n in stale:
                os.unlink(os.path.join(overlay, n))
            log(f"darkmoon-settings/agents is now an overlay: {len(stale)} shipped agent file(s) never modified were "
                f"removed from it (they come from the image); the previous folder is kept in {backup}")
        if customised:
            bar = "=" * 78
            for line in [bar,
                         "NOTICE: these agents of darkmoon-settings/agents differ from every version Darkmoon shipped:",
                         "they are kept as YOUR customisations and replace the shipped agents of the same name.",
                         *[f"  - {n}" for n in customised],
                         "The shipped version of each is in the image, /opt/darkmoon/default-agents/<name>",
                         "(docker compose exec opencode cat /opt/darkmoon/default-agents/<name>). To take the shipped",
                         "version again, delete your file from darkmoon-settings/agents and restart.",
                         *notes_for(overlay, customised),
                         bar]:
                log(line)
    with open(marker, "w") as fh:
        fh.write("darkmoon-settings/agents holds only user-added or customised agents (conf/agents-overlay.py)\n")


def compose(image, overlay, runtime):
    """runtime = image + overlay, swapped in whole (no stale file from a previous start survives)."""
    parent = os.path.dirname(os.path.abspath(runtime))
    os.makedirs(parent, exist_ok=True)
    tmp = f"{runtime}.new-{os.getpid()}"
    shutil.copytree(image, tmp)
    if os.path.isdir(overlay):
        shutil.copytree(overlay, tmp, dirs_exist_ok=True, symlinks=False,
                        ignore=lambda d, names: [n for n in names if n.startswith(".")])
    if os.path.lexists(runtime):
        old = f"{runtime}.old-{os.getpid()}"
        os.rename(runtime, old)
        os.rename(tmp, runtime)
        shutil.rmtree(old)
    else:
        os.rename(tmp, runtime)
    shipped_names = set(files(image))
    mine = files(overlay)
    overrides = [n for n in mine if n in shipped_names]
    added = [n for n in mine if n not in shipped_names]
    if overrides:
        log(f"customised agents (darkmoon-settings/agents, replace the shipped ones): {', '.join(overrides)}")
    if added:
        log(f"user agents (darkmoon-settings/agents): {', '.join(added)}")


def run(image, overlay, runtime, shipped_list):
    if is_legacy_mount(overlay, runtime):
        if not files(runtime):
            shutil.copytree(image, runtime, dirs_exist_ok=True)
        log("WARNING: docker-compose.yml still mounts darkmoon-settings/agents on /root/.opencode/agents (layout from "
            "before the agent overlay): the shipped agents in that folder are NOT updated by this image. Update "
            "docker-compose.yml (git pull, then ./install.sh or docker compose up -d) to run the agents of the image "
            "with your own changes on top.")
        return
    os.makedirs(overlay, exist_ok=True)
    migrate(image, overlay, shipped_list)
    compose(image, overlay, runtime)


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        run(*argv)
    except Exception as e:                              # reported; the entrypoint stops if no orchestrator is in place
        log(f"WARNING: agent setup failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
