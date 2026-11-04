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
    parse_required_headers,
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


# ── required headers (Intigriti X-Intigriti-Username) ───────────────────────

def test_required_header_is_parsed_from_programme_text():
    p = parse_rate_policy(
        "Automated tooling max. 5 requests/sec Request header "
        "Add request header X-Intigriti-Username: davidgonzalez"
    )
    assert p["required_headers"] == {"X-Intigriti-Username": "davidgonzalez"}
    assert p["rps"] == 5


def test_required_header_placeholder_is_parsed():
    h = parse_required_headers("Add request header X-Intigriti-Username: {Username}")
    assert h == {"X-Intigriti-Username": "{Username}"}


def test_required_header_is_injected_into_curl_and_wget():
    from src.scope_policy import inject_required_headers

    h = {"X-Intigriti-Username": "davidgonzalez"}
    out = inject_required_headers("curl -sk https://fucd.com/", h)
    assert '-H "X-Intigriti-Username: davidgonzalez"' in out
    out = inject_required_headers("wget -qO- https://x/", h)
    assert '--header="X-Intigriti-Username: davidgonzalez"' in out


def test_required_header_not_duplicated_when_already_present():
    from src.scope_policy import inject_required_headers

    h = {"X-Intigriti-Username": "davidgonzalez"}
    cmd = 'curl -sk -H "X-Intigriti-Username: other" https://x/'
    out = inject_required_headers(cmd, h)
    assert out.count("X-Intigriti-Username") == 1
    assert "other" in out, "an explicitly set header must never be overwritten"


def test_non_http_commands_are_untouched():
    from src.scope_policy import inject_required_headers

    h = {"X-Intigriti-Username": "davidgonzalez"}
    assert inject_required_headers("ls -la /tmp", h) == "ls -la /tmp"
    assert inject_required_headers("cat /etc/hosts", h) == "cat /etc/hosts"


def test_required_header_value_is_not_polluted_by_prose():
    """A programme page puts the header sentence next to other prose. A greedy
    capture would send 'X-Intigriti-Username: davidgonzalez. The engine injects
    it into every curl.' as the header value - worse than no header at all."""
    h = parse_required_headers(
        "Required header on every request: X-Intigriti-Username: davidgonzalez. "
        "The engine injects it into every curl call."
    )
    assert h == {"X-Intigriti-Username": "davidgonzalez"}


def test_curl_is_skipped_when_the_curlrc_already_carries_the_header():
    """curl sends EVERY occurrence of a header, so a request would carry it
    twice when both the ~/.curlrc and the command line add it."""
    from src.scope_policy import inject_required_headers

    h = {"X-Intigriti-Username": "davidgonzalez"}
    assert inject_required_headers("curl -sk https://x/", h, skip_clients=("curl",)) == "curl -sk https://x/"
    assert "--header=" in inject_required_headers("wget -qO- https://x/", h, skip_clients=("curl",))


def test_effective_policy_prefers_the_scope_file_over_the_default(monkeypatch, tmp_path):
    """The campaign record must state the rule that actually governed the run.

    An agent that does not pass rate_policy explicitly still runs under the
    engagement's scope file (written by the Web UI at launch). Recording
    "engine default" there would put a false compliance statement in the
    vendor-facing report.
    """
    import json
    import os

    from src import scope_policy

    store = tmp_path / "viewer-session.json"
    home = tmp_path / "home"
    (home / ".local" / "share" / "opencode").mkdir(parents=True)
    (home / ".local" / "share" / "opencode" / "rate_policy.json").write_text(
        json.dumps({
            "text": "Automated tooling: maximum 5 requests per second.\n"
                    "Required header on every request: X-Intigriti-Username: zerodayexploit@intigriti.me\n",
            "program": "PB Web Media bug bounty (Intigriti)",
        })
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("DARKMOON_RATE_POLICY", raising=False)
    monkeypatch.setattr(scope_policy, "_session_store_path", lambda: home / ".local" / "share" / "opencode" / "rate_policy.json", raising=False)

    # resolve_policy reads the file through _session_store_path only for the
    # viewer session; the rate policy file path is derived from HOME, so point
    # it there explicitly.
    monkeypatch.setenv("DARKMOON_RATE_POLICY_FILE", str(home / ".local" / "share" / "opencode" / "rate_policy.json"))

    pol = scope_policy.effective_policy(None)
    assert pol["rps"] == 5, f"scope rate not resolved: {pol}"
    assert pol["required_headers"] == {"X-Intigriti-Username": "zerodayexploit@intigriti.me"}
    assert pol["source"] != "engine default"


def test_mandatory_headers_survive_an_operator_policy_that_omits_them(monkeypatch, tmp_path):
    """A programme-mandated header must not be silently dropped.

    The agent passes its own rate_policy text to dashboard_init_campaign. If that
    text does not spell out the mandatory header, the session policy would
    carry no required_headers - and the engine rewrites the toolbox ~/.curlrc
    from that policy, so the header would stop being sent at all.
    """
    import json

    from src import scope_policy

    home = tmp_path / "home"
    (home / ".local" / "share" / "opencode").mkdir(parents=True)
    (home / ".local" / "share" / "opencode" / "rate_policy.json").write_text(json.dumps({
        "text": "Automated tooling: maximum 5 requests per second.\n"
                "Required header on every request: X-Intigriti-Username: zerodayexploit@intigriti.me\n",
        "program": "PB Web Media bug bounty (Intigriti)",
    }))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("DARKMOON_RATE_POLICY", raising=False)
    monkeypatch.setenv(
        "DARKMOON_RATE_POLICY_FILE",
        str(home / ".local" / "share" / "opencode" / "rate_policy.json"),
    )

    # The agent's own text states the rate but NOT the header.
    pol = scope_policy.effective_policy("automated scanning max 5 requests per second")
    assert pol["rps"] == 5
    assert pol["required_headers"] == {"X-Intigriti-Username": "zerodayexploit@intigriti.me"}, (
        "the programme's mandatory header was dropped: "
        f"{pol.get('required_headers')}"
    )
