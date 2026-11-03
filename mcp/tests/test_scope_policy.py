"""
Scope-driven rate policy — 2026-11-03 PornBox directive tests.

The rate budget is a property of the TARGET PROGRAMME, not a global constant:

  ALSCO   — allows automated scanning, states "automated scanners must stay
            within 5 requests per second (300 requests per minute) per target
            host, with no more than 5 concurrent requests".
  PornBox — FORBIDS automation outright: "The use of automated tools or
            scripted testing is not allowed" and prohibits any "tool that
            generates a significant volume of traffic".

A fixed global cap (the first rate_limiter version) was wrong on both: it
over-permitted PornBox and ignored ALSCO's own stated number. The policy is now
parsed from the programme's own wording and enforced mechanically.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from src.rate_limiter import enforce_rate_limits  # noqa: E402
from src.scope_policy import (  # noqa: E402
    MANUAL_MODE_RPS,
    is_prohibited_tool,
    parse_rate_policy,
    policy_from_scope_json,
    tool_cap,
)

ALSCO_POLICY = (
    "When using automated scanners, testing must stay within 5 requests per second "
    "(300 requests per minute) per target host across all tools and threads combined, "
    "with no more than 5 concurrent requests at any moment."
)

PORBOX_POLICY = (
    "The use of automated tools or scripted testing is not allowed. Automated tools "
    "or scans, botnet, compromised site, end-clients or any other means of large "
    "automated exploitation or use of a tool that generates a significant volume of "
    "traffic are strictly prohibited."
)


# ── parsing ───────────────────────────────────────────────────────────────────

def test_alsco_policy_parses_stated_rate():
    p = parse_rate_policy(ALSCO_POLICY)
    assert p["mode"] == "automated"
    assert p["rps"] == 5, f"ALSCO states 5 req/s, parsed {p['rps']}"
    assert p["concurrency"] == 5
    assert not p["prohibit_automation"]


def test_pornbox_policy_flips_to_manual_mode():
    p = parse_rate_policy(PORBOX_POLICY)
    assert p["prohibit_automation"] is True
    assert p["mode"] == "manual"
    assert p["rps"] == MANUAL_MODE_RPS, "automation prohibited but no trickle rate set"


def test_policy_with_no_stated_rate_keeps_engine_default():
    p = parse_rate_policy("We appreciate responsible disclosure.")
    assert p["mode"] == "automated"
    assert p["rps"] > 0
    assert p["source"].startswith("programme")


def test_scope_json_rate_limit_field_is_used():
    """The AI scope generator already extracts a rate_limit field — the policy
    must consume it instead of requiring a second parse of the raw text."""
    p = policy_from_scope_json({"rate_limit": "5 requests per second, 5 concurrent"})
    assert p["rps"] == 5
    assert p["concurrency"] == 5


def test_scope_json_without_rate_field_falls_back():
    p = policy_from_scope_json({"in_scope": ["x.com"]})
    assert p["rps"] > 0


def test_limited_mode_on_courtesy_phrases():
    p = parse_rate_policy("Please keep scanning during regular business hours to a minimum.")
    assert p["mode"] == "limited"
    assert p["rps"] <= 10


# ── enforcement ───────────────────────────────────────────────────────────────

def test_tool_cap_is_min_of_default_and_scope():
    # ALSCO 5/s vs naabu default 25 → 5
    assert tool_cap({"rps": 5, "prohibit_automation": False}, 25) == 5
    # A scope more generous than the tool default must NOT raise the tool cap
    assert tool_cap({"rps": 100, "prohibit_automation": False}, 25) == 25
    # Manual programme floors everything
    assert tool_cap({"rps": 25, "prohibit_automation": True, "mode": "manual"}, 25) == MANUAL_MODE_RPS


def test_pornbox_policy_floors_rates_to_trickle():
    """Under PornBox's manual mode even naabu must be floored to the trickle
    rate, never the global 25."""
    p = parse_rate_policy(PORBOX_POLICY)
    out = enforce_rate_limits("naabu -top-ports 100", policy=p)
    assert f"-rate {MANUAL_MODE_RPS}" in out
    assert "-rate 25" not in out


def test_alsco_policy_caps_naabu_to_its_own_number():
    """ALSCO states 5 req/s — the engine must inject -rate 5, not the generic
    default 25."""
    p = parse_rate_policy(ALSCO_POLICY)
    out = enforce_rate_limits("naabu -top-ports 100", policy=p)
    assert "-rate 5" in out and "-rate 25" not in out


def test_pornbox_refuses_automated_scanners():
    """'The use of automated tools or scripted testing is not allowed' — the
    bulk scanners are refused pre-flight, not merely slowed."""
    p = parse_rate_policy(PORBOX_POLICY)
    for tool in ("nuclei", "ffuf", "katana", "sqlmap", "naabu", "nikto"):
        assert is_prohibited_tool(f"{tool} -u http://x", p) == tool, (
            f"{tool} must be refused under a no-automation policy"
        )


def test_pornbox_still_allows_manual_requests():
    """Manual mode must not refuse the tools a human-equivalent workflow needs:
    curl-based single requests, file reads, grep."""
    p = parse_rate_policy(PORBOX_POLICY)
    for cmd in ("curl -sk https://x/", "cat /tmp/notes.txt", "grep -i token resp.html"):
        assert is_prohibited_tool(cmd, p) is None, f"over-blocked: {cmd}"


def test_alsco_policy_does_not_refuse_scanners():
    p = parse_rate_policy(ALSCO_POLICY)
    assert is_prohibited_tool("nuclei -u http://x", p) is None


def test_nuclei_rate_capped_by_scope():
    p = parse_rate_policy(ALSCO_POLICY)
    out = enforce_rate_limits("nuclei -u http://x -t cves", policy=p)
    assert "-rate-limit 5" in out, f"ALSCO 5 req/s not applied to nuclei: {out}"
