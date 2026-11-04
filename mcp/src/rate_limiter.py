"""
Mechanical rate limiting for network tools — 2026-11-03, ALSCO campaign audit.

Why this exists: during the ALSCO / Secure Gateway campaign the engine launched
`naabu -p top-1000 -rate 500` against a programme whose policy caps automated
scanning at 5 req/s, and the Secure Gateway firewall banned the source IP for
~6 minutes, killing the run. The cap existed — in the prompt. The agent
overrode it when it picked tool flags, and prompt text cannot argue with a
model that has already decided to add `-rate 500`.

So the cap is enforced HERE, at the single choke point every command passes
through (`DarkmoonDockerClient.execute_command`), where it cannot be argued
with: if a network tool is invoked without its vendor rate flag, the flag is
injected with the default cap. If the agent passes its own (lower or equal)
rate flag, it is kept — the engine never RAISES a rate, it only floors it.

The caps are deliberately conservative (25 packets/s ceiling). They exist to
keep the campaign alive, not to optimise scan speed.
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union

from src.scope_policy import tool_cap as _scope_tool_cap

# Default per-tool rate flags. `flag` is the vendor's requests/packets-per-second
# knob; `cap` is the ceiling the engine enforces when the agent did not set
# one. Tools without a rate knob in their CLI are simply absent from the map.
NETWORK_RATE_TOOLS = {
    "naabu":       {"flag": "-rate",       "cap": 25},
    "masscan":     {"flag": "--max-rate",  "cap": 25},
    "nmap":        {"flag": "--max-rate",  "cap": 25},
    "ffuf":        {"flag": "-rate",       "cap": 25},
    "feroxbuster": {"flag": "--rate-limit", "cap": 25},
    "nuclei":      {"flag": "-rate-limit", "cap": 15},
    "katana":      {"flag": "-rate-limit", "cap": 10},
    "httpx":       {"flag": "-rate-limit", "cap": 15},
    "dirsearch":   {"flag": "--rate",      "cap": 25},
    "wpscan":      {"flag": "--throttle",  "cap": 5},
}

# Segment separators inside a composed shell script. Rate capping is applied
# PER SEGMENT so that `naabu … && cat out` only caps the naabu part — a flag
# belonging to one command must not leak into (or mask) another.
_SEPARATOR_RE = re.compile(r"(&&|\|\||;|\||\n)")

_BASH_C_RE = re.compile(r"(?<!\S)(-c)\s+(\S.*)$", re.S)


def _is_number(s: str) -> bool:
    try:
        int(s)
        return True
    except ValueError:
        return False


def _tokens(segment: str) -> List[str]:
    # Whitespace split is fine for capping purposes: we only ever insert
    # "<flag> <cap>" tokens next to a network tool name, we never rebuild
    # quoted strings that we did not touch.
    return segment.split()


def _cap_segment(
    seg_tokens: List[str], policy: Optional[Dict[str, Any]] = None
) -> Tuple[List[str], bool]:
    """Floor/inject the rate flag for the (single) command in one segment.

    The cap is the MINIMUM of the tool's conservative default and the scope's
    allowance (scope_policy.tool_cap) — the programme's own stated rate wins
    whenever it is tighter than the engine default.
    """
    out = list(seg_tokens)
    changed = False

    for i, tok in enumerate(out):
        cfg = NETWORK_RATE_TOOLS.get(tok)
        if not cfg:
            continue
        flag = cfg["flag"]
        cap = _scope_tool_cap(policy, cfg["cap"]) if policy else cfg["cap"]
        if flag in out:
            # Explicit rate: floor any value above the cap, never raise.
            j = 0
            while j < len(out) - 1:
                if out[j] == flag and _is_number(out[j + 1]) and int(out[j + 1]) > cap:
                    out[j + 1] = str(cap)
                    changed = True
                j += 1
        else:
            out[i + 1:i + 1] = [flag, str(cap)]
            changed = True
        break  # one command per segment: cap the first tool found

    return out, changed


def _enforce_string(
    script: str, policy: Optional[Dict[str, Any]] = None
) -> Tuple[str, bool]:
    """Apply rate caps inside a shell-script string, per segment."""
    parts = _SEPARATOR_RE.split(script)
    changed = False
    for idx in range(0, len(parts), 2):  # separators sit at odd indices
        seg = parts[idx]
        # Recurse into `bash -c <body>` wrappers.
        m = _BASH_C_RE.search(seg)
        if m:
            inner, inner_changed = _enforce_string(m.group(2))
            if inner_changed:
                parts[idx] = seg[: m.start(2)] + inner
                changed = True
            continue
        capped, seg_changed = _cap_segment(_tokens(seg), policy)
        if seg_changed:
            parts[idx] = " ".join(capped)
            changed = True
    return ("".join(parts), changed) if changed else (script, False)


def enforce_rate_limits(
    command: Union[str, List[str]],
    policy: Optional[Dict[str, Any]] = None,
) -> Union[str, List[str]]:
    """Inject the vendor rate flag into any network tool that lacks one.

    Applied mechanically at the docker_client choke point, so a workflow (or a
    free-form agent command) cannot launch an unbounded scanner even when the
    prompt's rate discipline is ignored. An explicit flag set by the caller is
    respected: the engine never *raises* a rate, it only *floors* it at the cap
    (a caller asking for less traffic keeps asking for less).

    The cap itself comes from the SCOPE (see src/scope_policy.py): a programme
    that states "5 requests per second" gets 5, one that forbids automated
    tools gets manual-mode trickle and its high-volume scanners refused
    upstream. The bare-function call keeps the engine default for callers that
    have no scope context yet.

    Returns the command unchanged (same type) when there is nothing to do.
    """
    if isinstance(command, (list, tuple)):
        tokens = [str(t) for t in command]
        # An argv list is ONE command: cap it as a single segment.
        capped, changed = _cap_segment(tokens, policy)
        # A list may still carry a script body in one token (`bash -c <script>`
        # with the script as a single argv element) — cap inside those too.
        # Only tokens that span multiple words can be script bodies; a bare
        # tool name was already capped by _cap_segment above.
        out = []
        for tok in capped:
            if " " in tok or "\n" in tok:
                t, ch = _enforce_string(tok, policy)
                out.append(t)
                changed = changed or ch
            else:
                out.append(tok)
        return out if changed else list(command)
    return _enforce_string(command, policy)[0]


def describe_rate_limits() -> dict:
    """Machine-readable copy of the caps, for list_allowed_tools()/diagnostics."""
    return {
        name: {"flag": cfg["flag"], "cap": cfg["cap"]}
        for name, cfg in NETWORK_RATE_TOOLS.items()
    }