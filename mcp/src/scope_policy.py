"""
Scope-driven rate policy — 2026-11-03, PornBox campaign directive.

Why this exists: the first version of the mechanical rate limiter (D1) used a
single global cap. That is wrong, and the PornBox programme proves it: ALSCO's
policy ALLOWS automated scanning within 5 req/s, while PornBox's policy
PROHIBITS automated tools and any tool "that generates a significant volume of
traffic" outright. A 25-pps floor is a compliance violation on one programme and
an over-permission on another.

The rate budget is therefore a property of the SCOPE, resolved from whatever the
programme states (its policy text, the AI scope generator's `rate_limit` field,
or an explicit operator override), and enforced mechanically at the same choke
point as before. Fallback order:

    session policy  >  scope JSON  >  operator override (env var)  >  default

Modes:
    "automated"  automated scanning allowed up to the programme's stated rate
                 (its own number when it states one, else the engine default)
    "limited"    automation allowed but tightly capped (rate far below default;
                 set when the programme mentions throttles or courtesy rates)
    "manual"     the programme prohibits automated tools / significant traffic:
                 high-volume scanners are REFUSED (execution-guard style) and
                 every remaining request is floored to a human-speed trickle
"""

import os
import re
from typing import Any, Dict, Optional


DEFAULT_POLICY: Dict[str, Any] = {
    "mode": "automated",
    "rps": 25,            # global requests-or-packets per second ceiling
    "concurrency": 5,
    "prohibit_automation": False,
    "required_headers": {},   # headers the programme demands on EVERY request
    "source": "engine default",
    "notes": "",
}

# Human-speed ceiling when the programme forbids automated tooling: slow enough
# that a session behaves like a person reading pages, not like a scanner.
MANUAL_MODE_RPS = 2
MANUAL_MODE_CONCURRENCY = 1

_RPS_PATTERNS = [
    (r"(\d+)\s*requests?\s*(?:per|/)\s*second", "second"),
    (r"(\d+)\s*requests?\s*(?:per|/)\s*sec\b", "second"),
    (r"(\d+)\s*reqs?\s*(?:per|/)\s*second", "second"),
    (r"(\d+)\s*req(?:uest)?s?/(?:s\b|sec\b)", "second"),
    (r"(\d+)\s*rps\b", "second"),
    (r"(\d+)\s*requests?\s*(?:per|/)\s*minute", "minute"),
    (r"(\d+)\s*requests?\s*(?:per|/)\s*min\b", "minute"),
]

_CONCURRENCY_PATTERNS = [
    r"(\d+)\s*concurrent",
    r"concurr(?:ency|ent)\s*(?:of|:)?\s*(\d+)",
]

# Phrases that forbid automation outright. When ANY matches, the policy flips
# to manual mode regardless of any rate number also present in the text.
_PROHIBITION_PATTERNS = [
    r"automated\s+tools?\s+(?:or\s+scripted\s+testing\s+)?(?:is|are)\s+not\s+allowed",
    r"use\s+of\s+automated\s+tools?\s+or\s+scripted\s+testing\s+is\s+not\s+allowed",
    r"automated\s+(?:tools?|scans?|scanning)[^.]{0,80}not\s+allowed",
    r"no\s+automated\s+(?:tools|scans?|scanning)",
    r"significant\s+volume\s+of\s+traffic",
    r"large\s+automated\s+exploitation",
    r"automated\s+tool[^.]{0,40}significant\s+volume",
]

# Courtesy-rate phrases ("keep scanning during regular business hours to a
# minimum", "minimise scanning") suggest limited mode even without numbers.
_LIMITED_HINTS = [
    r"keep\s+(?:the\s+)?(?:scanning|testing|load)[^.]{0,60}to\s+a\s+minimum",
    r"minimi[sz]e\s+(?:the\s+)?(?:scanning|testing|load)",
    r"throttl\w+",
    r"respect(?:ful)?\s+rate",
]


def _first_int(text: str, patterns) -> Optional[int]:
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return int(m.group(1))
    return None


def parse_rate_policy(text: str, source: str = "programme policy") -> Dict[str, Any]:
    """Derive a rate policy from programme text (policy page, scope brief)."""
    t = str(text or "")
    policy = dict(DEFAULT_POLICY)
    policy["source"] = source

    policy["required_headers"] = parse_required_headers(t)

    if any(re.search(p, t, re.I) for p in _PROHIBITION_PATTERNS):
        policy.update({
            "mode": "manual",
            "prohibit_automation": True,
            "rps": MANUAL_MODE_RPS,
            "concurrency": MANUAL_MODE_CONCURRENCY,
            "notes": "programme prohibits automated tools / significant traffic",
        })
        return policy

    per_sec = _first_int(t, [p for p, _unit in _RPS_PATTERNS])
    if per_sec is not None and per_sec > 0:
        policy["rps"] = per_sec
        policy["notes"] = f"programme states {per_sec} req/s"
    else:
        policy["notes"] = "no stated rate — engine default"

    conc = _first_int(t, _CONCURRENCY_PATTERNS)
    if conc is not None and conc > 0:
        policy["concurrency"] = conc

    if per_sec is None and any(re.search(p, t, re.I) for p in _LIMITED_HINTS):
        policy["mode"] = "limited"
        policy["rps"] = min(policy["rps"], 10)
        policy["notes"] = "programme asks to keep scanning to a minimum"

    return policy


def policy_from_scope_json(scope_json: Any, source: str = "AI scope generator") -> Dict[str, Any]:
    """Read the `rate_limit` field the AI scope generator already extracts.

    The scope JSON also carries the whole policy narrative is not stored, so the
    `rate_limit` string ("5 requests per second, 5 concurrent") is parsed with
    the same parser as full text. Programmes that forbid automation usually say
    so in prose that never reaches that field — operators can pass the raw
    policy text instead (see parse_rate_policy).
    """
    if isinstance(scope_json, dict):
        text = str(scope_json.get("rate_limit") or "")
        if not text:
            out = dict(DEFAULT_POLICY)
            out["source"] = source
            out["notes"] = "scope JSON carries no rate_limit field — engine default"
            return out
        policy = parse_rate_policy(text, source=source)
        policy.setdefault("notes", "")
        policy["notes"] = (policy["notes"] + f" (from scope JSON: {text[:80]})").strip()
        return policy
    if isinstance(scope_json, str):
        return parse_rate_policy(scope_json, source=source)
    out = dict(DEFAULT_POLICY)
    out["source"] = source
    return out


_HEADER_RE = re.compile(
    r"(?<![\w-])([Xx]-[A-Za-z0-9-]{2,40})\s*:\s*([^\n\r;,]{1,200}?)"
    r"(?=\s*(?:$|[\n\r;,]|\bAdd\b|\bwith\b))"
)


def parse_required_headers(text: str) -> Dict[str, str]:
    """Extract the headers a programme requires on EVERY request.

    Intigriti programmes state it as `X-Intigriti-Username: {your username}` or
    `Add request header X-Foo: bar` — the name can sit mid-sentence, so this
    scans the whole text rather than anchoring to a line.

    The VALUE is deliberately restricted to a single token (or a quoted
    string): a programme page puts the header sentence next to other prose, and
    a greedy capture would produce a header whose value is a whole paragraph
    ("X-Foo: abc. Do not use bulk scanners against ..."). A header with a
    polluted value is worse than no header at all.
    """
    headers: Dict[str, str] = {}
    for m in _HEADER_RE.finditer(str(text or "")):
        name = m.group(1).strip()
        value = m.group(2).strip().strip('"').strip("'")
        if not value:
            continue
        # Keep only a single token, unless the value was explicitly quoted.
        if " " in value and not (m.group(2).strip().startswith(('"', "'"))):
            value = value.split()[0]
        value = value.strip().strip('"').strip("'").rstrip(".,;:")
        if not value:
            continue
        headers[name] = value
    return headers


def inject_required_headers(
    command: str, headers: Dict[str, str], skip_clients: tuple = ()
) -> str:
    """Add the programme's mandatory headers to an HTTP client invocation.

    Some programmes require a header on EVERY request (Intigriti:
    `X-Intigriti-Username`). Relying on the agent to remember it is exactly
    how a request goes out unidentified and the report gets discarded, so the
    engine injects it mechanically into curl/wget calls that do not already
    carry it. A header the caller set explicitly is never overwritten.
    """
    if not headers:
        return command
    lowered = command.lower()
    is_curl = re.search(r"(?<![\w-])curl(?![\w-])", lowered) is not None
    is_wget = re.search(r"(?<![\w-])wget(?![\w-])", lowered) is not None
    # A client whose headers are already installed globally (curl via the
    # toolbox ~/.curlrc) must NOT get them again here: curl sends every
    # occurrence, so the request would carry the header twice.
    if is_curl and "curl" in skip_clients:
        is_curl = False
    if not (is_curl or is_wget):
        return command

    additions = []
    for name, value in headers.items():
        if re.search(rf"(?<![\w-]){re.escape(name)}\s*:", command, re.I):
            continue  # the caller already set it
        if is_curl:
            additions.append(f'-H "{name}: {value}"')
        else:
            additions.append(f'--header="{name}: {value}"')
    if not additions:
        return command

    # Insert right after the client name so the flags bind to that invocation.
    m = re.search(r"(?<![\w-])(curl|wget)(?![\w-])", command, re.I)
    if not m:
        return command
    end = m.end()
    return command[:end] + " " + " ".join(additions) + command[end:]


def resolve_policy(
    session_policy: Optional[Dict[str, Any]] = None,
    allow_file: bool = True,
) -> Dict[str, Any]:
    """Effective policy for a session.

    Fallback order (most specific wins):
        session policy (dashboard_init_campaign rate_policy)
      > campaign scope file (rate_policy.json written by the Web UI launch —
        the MCP container sees it through the darkmoon-settings bind mount)
      > DARKMOON_RATE_POLICY env override
      > engine default
    """
    if session_policy:
        return session_policy

    if allow_file:
        from pathlib import Path

        path = Path(os.getenv(
            "DARKMOON_RATE_POLICY_FILE",
            str(Path.home() / ".local" / "share" / "opencode" / "rate_policy.json"),
        ))
        try:
            import json as _json

            data = _json.loads(path.read_text(encoding="utf-8"))
            text = str(data.get("text") or "").strip()
            if text:
                policy = parse_rate_policy(text, source="campaign scope file")
                policy["notes"] = (policy.get("notes", "") +
                                   f" (programme: {str(data.get('program') or '?')[:60]})").strip()
                return policy
        except FileNotFoundError:
            pass
        except (ValueError, OSError):
            pass  # malformed file: fall through to the default

    env_override = os.getenv("DARKMOON_RATE_POLICY", "")
    if env_override:
        try:
            import json as _json
            parsed = _json.loads(env_override)
            if isinstance(parsed, dict):
                merged = dict(DEFAULT_POLICY)
                merged.update({k: v for k, v in parsed.items() if k in DEFAULT_POLICY})
                merged["source"] = "DARKMOON_RATE_POLICY env"
                return merged
        except (ValueError, TypeError):
            pass
        return parse_rate_policy(env_override, source="DARKMOON_RATE_POLICY env")
    return dict(DEFAULT_POLICY)


def effective_policy(rate_policy: Optional[str] = None) -> Dict[str, Any]:
    """The policy that will actually govern a campaign.

    The operator's own wording wins; otherwise the engagement's scope file (the
    Web UI writes it at launch) is used; otherwise the engine default.

    This is what the campaign record must carry. A campaign whose record says
    "engine default" while the scope said "5 req/s + a mandatory header"
    produces a report that misstates the compliance facts of the engagement.
    """
    if rate_policy:
        return parse_rate_policy(rate_policy, source="operator scope")
    resolved = resolve_policy(None)
    if resolved.get("source") != "engine default":
        return resolved
    return dict(DEFAULT_POLICY)


def tool_cap(policy: Dict[str, Any], tool_default_cap: Optional[int]) -> Optional[int]:
    """Effective cap for one tool under this policy.

    The engine never RAISES a rate: the effective cap is the MINIMUM of the
    tool's own conservative default and the scope's allowance. A "manual"
    programme (automation prohibited) floors everything to the trickle rate.
    """
    if policy.get("prohibit_automation") or policy.get("mode") == "manual":
        return MANUAL_MODE_RPS
    scope_rps = policy.get("rps")
    if not scope_rps:
        return tool_default_cap
    if tool_default_cap is None:
        return scope_rps
    return min(int(scope_rps), int(tool_default_cap))


# High-volume scanners that a "manual" programme forbids outright. Running one
# against such a target is a policy violation, not a tuning problem — refused
# pre-flight with the same escalation ladder as execution_guard.
HIGH_VOLUME_TOOLS = (
    "naabu", "masscan", "nmap", "ffuf", "feroxbuster", "nuclei",
    "katana", "dirsearch", "gobuster", "nikto", "arjun", "sqlmap",
    "wpscan", "subfinder", "amass", "gau", "waybackurls", "vulnx",
    "nuclei-fuzz", "ha!!!",
)


def is_prohibited_tool(command: str, policy: Dict[str, Any]) -> Optional[str]:
    """Return the tool name when a prohibited-automation programme forbids it."""
    if not policy.get("prohibit_automation") and policy.get("mode") != "manual":
        return None
    lowered = f" {command.lower()} "
    for tool in HIGH_VOLUME_TOOLS:
        if re.search(rf"(?<![\w.-]){re.escape(tool)}(?![\w-])", lowered):
            return tool
    return None