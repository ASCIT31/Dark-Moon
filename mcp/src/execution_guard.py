"""
Execution guard — keeps one command from freezing a whole campaign.

A campaign runs as a single sequential loop: the agent issues a command, waits
for its output, then reasons about it. A command that never returns therefore
does not just fail, it freezes everything downstream — no more findings, no
finalize, no report. That is how the 2026-08-03 IoTGoat campaign was lost: the
model escalated to `hydra -P rockyou.txt` (14M candidates) and the executor,
which accepted a `timeout` argument but never enforced it, waited forever.

Prompt rules alone do not prevent this. pentest.md already forbade hydra, capped
login attempts at 50 and restricted wordlists to a 200-line allowlist, and the
model still did it. So the rule is enforced here, where it cannot be argued with.

Two jobs:

1. PRE-FLIGHT (`classify`) — recognise a command that cannot finish before it is
   ever started, so we do not burn N minutes discovering it.
2. POST-MORTEM (`remediation`) — when something did time out, tell the agent WHY
   it blocked and HOW to reach the same goal without blocking. A bare "timeout"
   makes a model retry the same thing; a concrete alternative makes it progress.

Both return the same escalation ladder, which is the operating doctrine:
    bounded attempt -> different approach -> declare not-exploitable and move on.
Giving up is an allowed, explicit outcome. Hanging is not.
"""

import re
from typing import NamedTuple, Optional


class Verdict(NamedTuple):
    blocked: bool          # True: refuse to run it at all
    label: str             # short machine-readable reason
    why: str               # why this cannot finish
    instead: str           # what to do to reach the same goal without blocking


# Wordlists whose size makes any credential/fuzzing loop unbounded in practice.
_HUGE_LISTS = r"(rockyou|big\.txt|directory-list|raft-\w+|seclists/(?!.*tiny)|top-?1million|10-?million|names\.txt|passwords?/[^\s]*\.txt)"

_BOUNDED_HINT = (
    "Re-run bounded, and treat the bounded run as the experiment: if it yields "
    "nothing, that is a RESULT (not-exploitable), not a reason to widen the net."
)

_RULES = [
    (
        "credential-bruteforce-unbounded",
        re.compile(rf"\b(hydra|medusa|ncrack|patator|crackmapexec|netexec)\b.*{_HUGE_LISTS}", re.I),
        "A credential attack over a multi-million-entry list cannot complete in a "
        "campaign. It holds the executor open for hours and starves every other vector.",
        "The finding you are actually after is 'authentication accepts unlimited "
        "attempts', and that is proven with about 11 requests, not 14 million. "
        "Send a bounded burst (<= 11) and document that none were rejected. If you "
        "genuinely need candidates, build a SMALL targeted list (<= 200) from what "
        "this host already gave you: vendor defaults, usernames seen in /etc/passwd, "
        "strings pulled from the firmware or the config. " + _BOUNDED_HINT,
    ),
    (
        "socket-read-without-eof",
        re.compile(r"(cat|head|tail)\s+[^|;]*(<&\d|/dev/tcp/)|/dev/tcp/[^\s]+.*\b(cat|head)\b", re.I),
        "A live service socket never sends EOF, so the reader blocks forever. "
        "Redis, MySQL and most daemons keep the connection open after answering.",
        "Use the dedicated client instead of a raw socket: redis-cli, mysql, psql, "
        "mongosh, or `nc -w 5`. Always wrap it: `timeout 15 <client> ...`. The MCP "
        "allow-list only validates the outer `bash`, so the client IS available even "
        "if check_tool says otherwise.",
    ),
    (
        "portscan-full-range",
        re.compile(r"\b(naabu|nmap|masscan)\b[^|;]*(-p-|-p\s*1-65535|--top-ports\s*65535)", re.I),
        "A full 65535-port sweep against a host that silently drops packets stalls "
        "on per-port timeouts for many minutes and often returns nothing.",
        "Scan the ports that decide your next move first: "
        "`naabu -host <t> -p 22,80,443,3306,5432,6379,8080,8443 -timeout 1500 -retries 1`. "
        "Widen only if that surface is genuinely empty, and only in bounded slices.",
    ),
    (
        "fuzzing-huge-wordlist",
        re.compile(rf"\b(ffuf|dirb|gobuster|feroxbuster|wfuzz)\b.*{_HUGE_LISTS}", re.I),
        "Directory fuzzing with a giant list is rate-limited by the target and "
        "routinely outlives the campaign.",
        "Use the bounded list the rules allow: /opt/darkmoon/wordlists/tiny.txt "
        "(<= 200 entries), at <= 2 requests/second, one run per target. Prefer "
        "katana crawling first: real links beat guessed ones. " + _BOUNDED_HINT,
    ),
    (
        "follow-stream-never-returns",
        re.compile(r"(tail\s+-[fF]|journalctl\s+-f|docker\s+logs\s+-f|watch\s|while\s+true|for\s*\(\(\s*;\s*;\s*\)\))", re.I),
        "This command follows a stream or loops forever by construction. It has no "
        "natural end, so the executor never regains control.",
        "Take a bounded snapshot instead: `tail -n 200 <file>`, "
        "`journalctl -n 200`, or a single poll. If you need to observe a change, "
        "sample twice with a sleep between, then compare.",
    ),
    (
        "sqlmap-heavy",
        re.compile(r"\bsqlmap\b(?!.*--batch)|--level\s*[45]|--risk\s*[23]|--dump-all|--crawl", re.I),
        "sqlmap in interactive or deep mode waits on prompts or enumerates for hours.",
        "sqlmap is forbidden by default here. Validate SQL injection with 1 to 3 "
        "manual probes (a quote, a boolean pair, one timing payload) and stop at the "
        "first strong signal. No dumps.",
    ),
]

# Time budget for an offline cracking run. hashcat honours it natively via
# --runtime, so a heavy job returns what it found instead of running for hours.
CRACK_BUDGET_SECONDS = 300

# Any command with no explicit bound gets this ceiling, in seconds.
DEFAULT_HARD_TIMEOUT = 300
# Nothing may ask for more than this, whatever the caller passes.
MAX_HARD_TIMEOUT = 900


def gpu_state() -> dict:
    """Read what the toolbox entrypoint detected at container start.

    Written to /run/darkmoon-gpu.env because an `export` in the entrypoint does
    not reach the sibling processes the MCP starts through `docker exec`.
    """
    state = {"DM_GPU": "0", "DM_GPU_VENDOR": "unknown", "DM_HASHCAT_OPTS": ""}
    try:
        with open("/run/darkmoon-gpu.env") as fh:
            for line in fh:
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    state[k] = v
    except OSError:
        pass
    return state


def adapt_command(command: str, gpu: Optional[dict] = None) -> tuple[str, str]:
    """Make a heavy command fit the time budget instead of refusing it.

    The rule is not "block expensive work", it is "guarantee it finishes". Offline
    cracking is legitimate and valuable; it just has to run on the right component
    and carry a bound. hashcat has a native `--runtime`, so a full rockyou run is
    allowed on both CPU and GPU: on GPU it completes, on CPU it returns whatever it
    found within the budget instead of running for hours.

    Returns (possibly rewritten command, human-readable note or "").
    """
    if not command or "hashcat" not in command:
        return command, ""

    g = gpu if gpu is not None else gpu_state()
    on_gpu = str(g.get("DM_GPU", "0")) == "1"
    notes = []
    out = command

    # Pin hashcat to the GPU when one is usable. Left alone otherwise: forcing
    # -D 2 with no GPU makes hashcat exit with "No devices found/left".
    if on_gpu and "-D " not in out and "--opencl-device-types" not in out:
        out = out.replace("hashcat", f"hashcat {g.get('DM_HASHCAT_OPTS', '-D 2')}", 1)
        notes.append(f"pinned to GPU ({g.get('DM_GPU_VENDOR', 'gpu')})")

    # Always bound the run. Without this a slow hash on CPU threads holds the
    # campaign for hours, which is exactly how one was lost.
    if "--runtime" not in out:
        out = out.replace("hashcat", f"hashcat --runtime {CRACK_BUDGET_SECONDS}", 1)
        notes.append(f"capped at {CRACK_BUDGET_SECONDS}s")

    if not on_gpu:
        notes.append(
            "NO GPU: this host cracks about 200x slower. Expect partial coverage, "
            "and prefer a targeted candidate list over a full dictionary"
        )
    return out, "; ".join(notes)


def classify(command: str) -> Verdict:
    """Pre-flight: can this command finish? Cheap, pure, no side effects."""
    for label, rx, why, instead in _RULES:
        if rx.search(command or ""):
            return Verdict(True, label, why, instead)
    return Verdict(False, "", "", "")


def remediation(command: str, elapsed: float, timeout: int) -> str:
    """Post-mortem: an actionable message for a command that hit the deadline.

    Returned to the agent in place of output. It must answer three questions:
    why it blocked, what to do instead, and when to stop trying.
    """
    v = classify(command)
    if v.blocked:
        why, instead = v.why, v.instead
    else:
        why = (
            "The command produced no output and did not exit within the deadline. "
            "It is most likely waiting on a socket, a prompt, or a target that "
            "silently drops traffic."
        )
        instead = (
            "Re-run it with a hard bound and a narrower scope: add `timeout 30`, "
            "reduce the input set, target a single port or a single parameter, and "
            "prefer a tool that streams results as it finds them."
        )

    return (
        f"[EXECUTION TIMEOUT after {elapsed:.0f}s (limit {timeout}s)] "
        f"The process was killed so the campaign can continue.\n\n"
        f"WHY IT BLOCKED: {why}\n\n"
        f"DO THIS INSTEAD: {instead}\n\n"
        "HOW TO PROCEED (do not repeat the same command):\n"
        "  1. Retry ONCE with the bounded form above.\n"
        "  2. If that yields nothing, try a DIFFERENT angle on the same objective "
        "(another endpoint, another protocol, another credential source, or evidence "
        "you already collected).\n"
        "  3. If two bounded attempts fail, the vector is not exploitable with the "
        "access you have. Push what you DID prove as a finding at its real severity, "
        "note the attempted vector as not-exploitable, and move to the next vector. "
        "Abandoning a dead end is a correct outcome; blocking the campaign is not."
    )


def effective_timeout(requested: Optional[int]) -> int:
    """Clamp a caller-supplied timeout into something that cannot hang a campaign."""
    if not requested or requested <= 0:
        return DEFAULT_HARD_TIMEOUT
    return min(int(requested), MAX_HARD_TIMEOUT)
