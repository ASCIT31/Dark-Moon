#!/usr/bin/env python3
"""Write conf/agents-shipped.sha256: the SHA-256 of every version of every agent file Darkmoon has shipped.

conf/agents-overlay.py (run by the opencode entrypoint) uses it once per install, when darkmoon-settings/agents becomes
a user overlay: a file byte-identical to a version we shipped was never customised and leaves the overlay (the image
provides it); any other file stays as the user's customisation.

Shipped versions = every blob of conf/agents/<name>.md in:
  - every commit of the default branch that touched conf/agents (the published image is rebuilt from every push to the
    default branch, so a user may have been seeded from any of them, not only from a release),
  - every release tag (a tag that is not on the default branch, e.g. v1.2.0, still shipped its files),
  - the working tree (the version this build ships; run this script again whenever an agent file changes,
    mcp/tests/test_agents_overlay.py fails otherwise).
Bytes are hashed as stored in git (the image copies the checkout, LF or CRLF as committed).

Usage: python3 tools/agent-build/shipped_hashes.py [--ref origin/master]
"""
import argparse
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
AGENTS = "conf/agents"
OUT = os.path.join(REPO, "conf", "agents-shipped.sha256")


def git(*args, binary=False):
    out = subprocess.run(["git", "-C", REPO, *args], capture_output=True, check=True).stdout
    return out if binary else out.decode()


def versions_at(rev):
    """{name: sha256} of the agent files at a revision."""
    found = {}
    for line in git("ls-tree", rev, f"{AGENTS}/").splitlines():
        meta, path = line.split("\t", 1)
        name = os.path.basename(path)
        if meta.split()[1] != "blob" or not name.endswith(".md"):
            continue
        found[name] = hashlib.sha256(git("cat-file", "blob", meta.split()[2], binary=True)).hexdigest()
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ref", default="origin/master", help="default branch whose history is shipped")
    args = ap.parse_args()
    revs = git("rev-list", args.ref, "--", AGENTS).split()
    revs += [t for t in git("tag", "--list").split()]
    pairs = set()
    for rev in revs:
        pairs.update((name, h) for name, h in versions_at(rev).items())
    for name in os.listdir(os.path.join(REPO, AGENTS)):
        if name.endswith(".md"):
            with open(os.path.join(REPO, AGENTS, name), "rb") as fh:
                pairs.add((name, hashlib.sha256(fh.read()).hexdigest()))
    with open(OUT, "w", encoding="ascii", newline="\n") as fh:
        fh.write("# SHA-256 of every shipped version of each conf/agents file (tools/agent-build/shipped_hashes.py).\n")
        fh.write("# Generated: do not edit by hand.\n")
        for name, h in sorted(pairs):
            fh.write(f"{h}  {name}\n")
    print(f"{len(pairs)} versions of {len({n for n, _ in pairs})} agent files from {len(set(revs))} revisions -> "
          f"{os.path.relpath(OUT, REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
