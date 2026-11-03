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