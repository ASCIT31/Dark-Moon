#!/usr/bin/env python3
"""
Conformance validator for Darkmoon sub-agent .md files.

Enforces the mandatory rules from docs/hldd/writing-agents.md so a new agent can
never silently drift from the fleet. Runs on generated agents (tools/agent-build/out)
by default, or on any list of files passed as arguments. Exit non-zero on any failure.

This doubles as the pre-commit / anti-regression gate for agent authoring.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CANON = os.path.join(REPO, "conf", "agents", "graphql.md")


def read(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def canonical_banner():
    text = read(CANON)
    lines = text.split("\n")
    fences = [i for i, l in enumerate(lines) if l.startswith("=" * 40)]
    open_i = fences[0]
    close_i = next(i for i in fences if i > open_i and "confidence" in lines[i - 1])
    return "\n".join(lines[open_i:close_i + 1])


# Blocks that belong ONLY to the orchestrator (pentest.md). A secondary that
# carries them would try to dispatch its own siblings.
ORCH_ONLY = [
    "SIGNAL DETECTION MATRIX",
    "CASCADE DEPTH LIMIT",
    "REACTIVE MULTI-DISPATCH",
    "SUBAGENT SPAWN PROTOCOL",
    "PHASE 2 — SIGNAL DETECTION",
]


def validate(path, banner):
    errs = []
    text = read(path)
    name = os.path.basename(path)

    if "\r" in text:
        errs.append("contains CR (must be LF-only)")

    m_id = re.search(r"^id:\s*(\S+)\s*$", text, re.M)
    m_name = re.search(r"^name:\s*(\S+)\s*$", text, re.M)
    m_desc = re.search(r"^description:\s*(\S.+)$", text, re.M)
    if not m_id:
        errs.append("missing front-matter id")
    if not m_name:
        errs.append("missing front-matter name")
    if m_id and m_name and m_id.group(1) != m_name.group(1):
        errs.append(f"id ({m_id.group(1)}) != name ({m_name.group(1)})")
    if not m_desc:
        errs.append("missing front-matter description")

    if banner not in text:
        errs.append("STATUS QUALIFICATION banner not byte-identical to graphql.md")

    if "SUB-AGENT REPORTING RULE — DO NOT FINALIZE THE CAMPAIGN" not in text:
        errs.append("missing SUB-AGENT REPORTING RULE (do-not-finalize) block")
    if "YOU MUST NOT call dashboard_finalize_campaign()" not in text:
        errs.append("missing 'MUST NOT call dashboard_finalize_campaign()'")

    if "DASHBOARD REAL-TIME PUSH (MANDATORY)" not in text:
        errs.append("missing DASHBOARD REAL-TIME PUSH block")

    if "{{TARGET}}" not in text:
        errs.append("missing {{TARGET}} placeholder")

    if "END OF PROMPT" not in text and "END OF INSTRUCTIONS" not in text:
        errs.append("missing END marker")

    for bad in ORCH_ONLY:
        if bad in text:
            errs.append(f"orchestrator-only block leaked in: '{bad}'")

    return errs


def main():
    banner = canonical_banner()
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        out = os.path.join(HERE, "out")
        files = [os.path.join(out, f) for f in sorted(os.listdir(out))] if os.path.isdir(out) else []
    if not files:
        print("no files to validate")
        return 0
    failed = 0
    for f in files:
        if not f.endswith(".md"):
            continue
        errs = validate(f, banner)
        if errs:
            failed += 1
            print(f"[FAIL] {os.path.basename(f)}")
            for e in errs:
                print(f"        - {e}")
        else:
            print(f"[OK]   {os.path.basename(f)}")
    print(f"\n{'PASS' if not failed else 'FAIL'}: {failed} file(s) with problems")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
