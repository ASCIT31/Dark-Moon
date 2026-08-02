#!/usr/bin/env python3
"""
Darkmoon agent generator.

Builds spine-compliant sub-agent .md files. The mandatory "spine" blocks
(STATUS QUALIFICATION banner, SUB-AGENT REPORTING RULE, ANTI-BRUTEFORCE,
SCANNER CONTROL, BLACKBOX/STATE, DASHBOARD REAL-TIME PUSH) are extracted
VERBATIM from the canonical source agent (graphql.md) so they stay
byte-identical across the whole fleet — never retyped. Only the variable
parts (front-matter, objective, strict-constraints, credential preflight,
offensive modules, priorities, stop note) come from a per-agent profile.

Usage:
    python3 generate.py                 # build every profile in profiles/
    python3 generate.py aws azure       # build a subset
    python3 generate.py --selfcheck     # verify spine round-trips golang.md

Output: one LF .md per profile in ./out/ , also mirrored into the three repos'
conf/agents/ by mirror.sh.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CANON = os.path.join(REPO, "conf", "agents", "graphql.md")
PROFILES_DIR = os.path.join(HERE, "profiles")
OUT_DIR = os.path.join(HERE, "out")


def read_lines(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def _slice(text, start_marker, end_marker, include_end=True):
    """Return the substring from the line containing start_marker up to and
    including the line containing end_marker (the first end_marker at/after start)."""
    lines = text.split("\n")
    si = ei = None
    for i, ln in enumerate(lines):
        if si is None and start_marker in ln:
            si = i
            continue
        if si is not None and end_marker in ln:
            ei = i
            break
    if si is None or ei is None:
        raise RuntimeError(f"marker not found: {start_marker!r} .. {end_marker!r}")
    end = ei + 1 if include_end else ei
    return "\n".join(lines[si:end])


def extract_spine(canon_text):
    """Pull the constant blocks out of graphql.md, verbatim."""
    lines = canon_text.split("\n")

    # STATUS QUALIFICATION banner: the whole banner between the first two
    # ==== fences (opening fence above the title, closing fence after "confidence").
    fences = [i for i, l in enumerate(lines) if l.startswith("=" * 40)]
    # fences[0] is the opening fence above the title; find the fence that closes the banner
    open_i = fences[0]
    close_i = next(i for i in fences if i > open_i and "confidence" in lines[i - 1])
    status_banner = "\n".join(lines[open_i:close_i + 1])

    sub_start = next(i for i, l in enumerate(lines) if "SUB-AGENT REPORTING RULE — DO NOT FINALIZE" in l)
    sub_end = next(i for i in range(sub_start, len(lines)) if "breaking the UI." in lines[i])
    # walk forward to the ==== fence that closes it
    sub_close = next(i for i in range(sub_end, len(lines)) if lines[i].startswith("=" * 40))
    subagent_rule = "\n".join(lines[sub_start - 1:sub_close + 1])

    antibrute = _slice(canon_text, "ANTI-BRUTEFORCE & FIREWALL PROTECTION RULES",
                       "Max total execute_command calls per single attack vector: 10.")
    # prepend the opening ==== fence
    ab_start = next(i for i, l in enumerate(lines) if "ANTI-BRUTEFORCE & FIREWALL PROTECTION RULES" in l)
    ab_open = ab_start - 1 if lines[ab_start - 1].startswith("=" * 40) else ab_start
    ab_end = next(i for i in range(ab_start, len(lines)) if "per single attack vector: 10." in lines[i])
    ab_close = next(i for i in range(ab_end, len(lines)) if lines[i].startswith("=" * 40))
    antibrute = "\n".join(lines[ab_open:ab_close + 1])

    scanner = _slice(canon_text, "SCANNER CONTROL BLOCK (NUCLEI / VULNX)",
                     "If error/empty twice → mark FAILED_WITH_PROOF and stop scanner")
    sc_start = next(i for i, l in enumerate(lines) if "SCANNER CONTROL BLOCK (NUCLEI / VULNX)" in l)
    sc_open = sc_start
    while sc_open > 0 and lines[sc_open - 1].startswith("-" * 10):
        sc_open -= 1
    sc_end = next(i for i in range(sc_start, len(lines)) if "FAILED_WITH_PROOF and stop scanner" in lines[i])
    scanner = "\n".join(lines[sc_open:sc_end + 1])

    blackbox = _slice(canon_text, "BLACKBOX MODE:", "Maximum one ffuf execution per target.")
    bb_start = next(i for i, l in enumerate(lines) if l.strip() == "BLACKBOX MODE:")
    bb_open = bb_start
    while bb_open > 0 and lines[bb_open - 1].startswith("-" * 10):
        bb_open -= 1
    bb_end = next(i for i in range(bb_start, len(lines)) if "Maximum one ffuf execution per target." in lines[i])
    blackbox = "\n".join(lines[bb_open:bb_end + 1])

    dashboard = _slice(canon_text, "DASHBOARD REAL-TIME PUSH (MANDATORY)",
                       "If no campaign_id is provided, skip dashboard pushes.")
    db_start = next(i for i, l in enumerate(lines) if "DASHBOARD REAL-TIME PUSH (MANDATORY)" in l)
    db_open = db_start
    while db_open > 0 and lines[db_open - 1].startswith("-" * 10):
        db_open -= 1
    db_end = next(i for i in range(db_start, len(lines)) if "If no campaign_id is provided, skip dashboard pushes." in lines[i])
    dashboard = "\n".join(lines[db_open:db_end + 1])

    return {
        "status_banner": status_banner,
        "subagent_rule": subagent_rule,
        "antibrute": antibrute,
        "scanner": scanner,
        "blackbox": blackbox,
        "dashboard": dashboard,
    }


SECTION_RULE = "-" * 66  # matches graphql.md separators

EXECUTION_SAFETY = """EXECUTION SAFETY — EVERY COMMAND MUST RETURN (NON-BLOCKING, MANDATORY)

A blocked command hangs the whole campaign: the toolbox process never returns, the
sub-agent stalls, and no finding is ever pushed. These rules are NON-NEGOTIABLE.

- PREFER THE DEDICATED CLIENT, ALWAYS. Use `redis-cli`, `psql`, `mysql`, `curl`,
  `aws`, `az`, `gcloud`, `kubectl` (all in the toolbox) — they connect, run one
  command, print the result, and EXIT.
- THESE CLIENTS ARE AVAILABLE — run them wrapped in `bash -c`:
  darkmoon_execute_command(command="bash -c 'redis-cli -h 127.0.0.1 -p 6379 INFO'").
  The allow-list validates only the OUTER `bash`, so the client inside runs fine.
  If `darkmoon_check_tool` or `darkmoon_list_allowed_tools` does NOT list
  redis-cli/psql/mysql/az/gcloud, IGNORE that — it is not authoritative for tools
  run inside `bash -c`. NEVER conclude a client is unavailable from that check, and
  NEVER fall back to raw `/dev/tcp` sockets because of it.
- NEVER read a live service socket with raw bash `/dev/tcp` + `cat`. Redis,
  RabbitMQ, Kafka, NATS, MQTT and most databases keep the connection OPEN and send
  no EOF, so `cat <&3` blocks FOREVER. This is the single most common way to hang a
  campaign. If you have no client, use `curl` for HTTP, or wrap the raw socket in a
  hard `timeout` AND close it explicitly — but the dedicated client is always better.
- WRAP EVERY POTENTIALLY-BLOCKING COMMAND IN `timeout`. Example:
  darkmoon_execute_command(command="bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 INFO'").
  Interactive tools MUST run non-interactively: `redis-cli <CMD>`, `psql -c '<SQL>'`,
  `mysql -e '<SQL>'`, `curl -s --max-time 15`. Never launch an interactive REPL.
- ARCHIVE TOOLS PROMPT FOR A PASSWORD ON STDIN AND HANG. `7z x` / `unzip` on an
  encrypted archive wait FOREVER for a password with no TTY. NEVER run `7z x` (or
  `unzip`) to "test" a protected archive — use `7z l` to inspect it, pass the
  password inline once cracked (`7z x -p<PW> -y ... `), and append `</dev/null` to
  EVERY archive command so an unexpected prompt gets EOF and fails fast.
- PAGERS BLOCK ON A KEYPRESS. `git` invokes a pager by default — `git show`/`git
  log`/`git diff`/`git branch` spawn `less` and wait for 'q', hanging the campaign
  for many minutes. ALWAYS disable it: run `git --no-pager <cmd>` or prefix the
  command with `GIT_PAGER=cat PAGER=cat`. Never pipe into `less`/`more`/`man`, and
  never launch a bare `git log`/`git show`/`git diff` without `--no-pager`.
- PASSWORD CRACKING IS GPU-GATED. Before any hashcat/john attack, check for a GPU:
  `hashcat -I 2>/dev/null | grep -iq "Type[. ]*: *GPU"`. WITH a GPU present, mask /
  `--increment` / large-wordlist (rockyou) attacks are fine. On CPU-ONLY (no GPU
  device — pocl/pthread only), run ONLY a fast TARGETED wordlist (IoT/Mirai defaults,
  default-creds, top-1k) against a hash — NEVER a mask, `--increment`, or full-rockyou
  brute of a SLOW hash ($1$ md5crypt, $5$/$6$ sha-crypt, bcrypt, 7-Zip/WinZip AES):
  on CPU it runs for hours and stalls the whole campaign. If the fast targeted wordlist
  misses, declare the hash UNCRACKED, record it as a finding, and move on — do not brute.
- If a command yields no output within its timeout, treat that vector as DONE and
  move on. NEVER re-run the same blocking command hoping it will return."""


def build_agent(profile, spine):
    p = profile
    parts = []
    # 1) front matter (LF, lowercase --- fence, canonical)
    parts.append("---")
    parts.append(f"id: {p['id']}")
    parts.append(f"name: {p['id']}")
    parts.append(f"description: {p['description']}")
    parts.append("---")
    # 2) STATUS QUALIFICATION banner (verbatim)
    parts.append(spine["status_banner"])
    parts.append("")
    parts.append("")
    # 3) OBJECTIVE
    parts.append(p["objective"].rstrip())
    parts.append("")
    # 4) STRICT CONSTRAINTS
    parts.append("STRICT CONSTRAINTS:")
    parts.append("")
    for c in p["strict_constraints"]:
        parts.append(f"- {c}")
    parts.append("")
    parts.append("")
    # 5) SUB-AGENT REPORTING RULE (verbatim)
    parts.append(spine["subagent_rule"])
    parts.append("")
    # 6) ANTI-BRUTEFORCE (verbatim)
    parts.append(spine["antibrute"])
    parts.append("")
    # 7) SCANNER CONTROL (verbatim)
    parts.append(spine["scanner"])
    parts.append("")
    # 8) BLACKBOX + STATE (verbatim)
    parts.append(spine["blackbox"])
    parts.append("")
    # 9) DASHBOARD REAL-TIME PUSH (verbatim)
    parts.append(spine["dashboard"])
    parts.append("")
    parts.append(SECTION_RULE)
    parts.append("")
    # 9b) EXECUTION SAFETY — non-blocking commands (all agents)
    parts.append(EXECUTION_SAFETY)
    parts.append("")
    parts.append(SECTION_RULE)
    parts.append("")
    # 10) CREDENTIAL PREFLIGHT (credential-gated dispatch — mirrors kubernetes.md)
    parts.append(p["preflight"].rstrip())
    parts.append("")
    parts.append(SECTION_RULE)
    parts.append("")
    # 11) OFFENSIVE MODULES (the expertise)
    parts.append(p["offensive"].rstrip())
    parts.append("")
    parts.append(SECTION_RULE)
    parts.append("")
    # 12) PRIORITIES + stop note + END marker
    parts.append(p["priorities"].rstrip())
    parts.append("")
    parts.append(p.get("stop_note", "").rstrip())
    parts.append("")
    parts.append("You must use the Darkmoon MCP toolbox exclusively; reference toolbox")
    parts.append("binaries by name and never install anything.")
    parts.append("")
    parts.append("================================================================================")
    parts.append("END OF PROMPT")
    parts.append("================================================================================")
    text = "\n".join(parts)
    text = re.sub(r"\n{4,}", "\n\n\n", text)  # cap blank runs at 2
    if not text.endswith("\n"):
        text += "\n"
    return text


def load_profiles(names=None):
    out = []
    for fn in sorted(os.listdir(PROFILES_DIR)):
        if not fn.endswith(".json"):
            continue
        aid = fn[:-5]
        if names and aid not in names:
            continue
        with open(os.path.join(PROFILES_DIR, fn), encoding="utf-8") as fh:
            prof = json.load(fh)
        prof.setdefault("id", aid)
        out.append(prof)
    return out


def selfcheck(spine):
    """Verify every extracted spine block round-trips against the canonical
    source (graphql.md) and against golang.md. golang.md is known to have
    hand-edited ONE line of the STATUS banner (line ~20), so the banner is
    validated against graphql.md only; all other blocks must match both."""
    canon = read_lines(CANON)
    gol = read_lines(os.path.join(REPO, "conf", "agents", "golang.md"))
    ok = True
    for key in ("status_banner", "subagent_rule", "antibrute", "scanner", "blackbox", "dashboard"):
        block = spine[key]
        in_canon = block in canon
        in_gol = block in gol
        if key == "status_banner":
            status = "OK" if in_canon else "FAIL"
            note = "(canonical; golang has a known 1-line hand-edit)"
        else:
            status = "OK" if (in_canon and in_gol) else "FAIL"
            note = ""
        if status == "FAIL":
            ok = False
        print(f"[{status:4}] spine '{key}' verbatim canon={in_canon} golang={in_gol} "
              f"({len(block)} bytes) {note}")
    return ok


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    canon = read_lines(CANON)
    spine = extract_spine(canon)
    if "--selfcheck" in flags:
        sys.exit(0 if selfcheck(spine) else 1)
    os.makedirs(OUT_DIR, exist_ok=True)
    profiles = load_profiles(args or None)
    if not profiles:
        print("no profiles found in", PROFILES_DIR)
        return
    for prof in profiles:
        text = build_agent(prof, spine)
        dest = os.path.join(OUT_DIR, f"{prof['id']}.md")
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        assert "\r" not in text, f"{prof['id']} has CR!"
        print(f"[built] {prof['id']}.md  ({text.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
