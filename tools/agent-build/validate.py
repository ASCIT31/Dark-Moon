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


# opencode's agent config keys (packages/core/src/v1/config/agent.ts, KNOWN_KEYS, at the fork ref pinned in
# Dockerfile.opencode). Any other key of an agent block or agent front matter is sent to the model as a call option.
# mcp/tests/test_agent_native_keys.py checks this list against the opencode source when it is available.
OPENCODE_AGENT_KEYS = ("name", "model", "variant", "prompt", "description", "temperature", "top_p", "mode", "hidden",
                       "color", "steps", "maxSteps", "options", "permission", "disable", "tools")


def frontmatter(text):
    """The front matter as opencode reads it (gray-matter 4): the file opens with exactly « --- » (a longer dash line is
    no front matter) and the block ends at the first line that starts with « --- » (ad.md closes on a dash rule)."""
    text = text.replace("\r\n", "\n")  # a CRLF agent file must not slip past the checks
    if not text.startswith("---") or text[3:4] == "-":
        return ""
    body = text[3:]
    end = body.find("\n---")
    return (body if end < 0 else body[:end]).lstrip("\n")


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

    fm = frontmatter(text)
    m_name = re.search(r"^name:\s*(\S+)\s*$", fm, re.M)
    m_desc = re.search(r"^description:\s*(\S.+)$", fm, re.M)
    # opencode's own agent keys only: an unknown front-matter key (the old « id: ») becomes a model call option, and
    # strict OpenAI-compatible endpoints reject it (« Unrecognized request argument supplied: id »). The agent id is
    # its « name » (its key in the "agent" map of conf/apply-settings.sh, and its subagent_type).
    for key in re.findall(r"^([A-Za-z_][\w-]*)\s*:", fm, re.M):
        if key not in OPENCODE_AGENT_KEYS:
            errs.append(f"front-matter key '{key}' is not an opencode agent key")
    if not m_name:
        errs.append("missing front-matter name")
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
