"""exec_core.maintenance: golden fixtures, daylight-saving edges and bypass attempts (same file in both editions).

Regenerate the expected evaluations after a deliberate change: ``python3 tests/test_exec_core_maintenance.py``.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api.exec_core import maintenance as M  # noqa: E402

FIX = MCP / "tests" / "fixtures" / "exec_core" / "maintenance"


def _cases():
    return json.loads((FIX / "cases.json").read_text(encoding="utf-8"))


def _run_all():
    doc = _cases()
    out = {}
    for c in doc["cases"]:
        pol = doc["policies"][c["policy"]] if c["policy"] else None
        out[c["name"]] = M.evaluate(pol, c["at"], c["kind"], c.get("duration"))
    return out


def _by_name():
    return _run_all()


def _codes(ev):
    return [r["code"] for r in ev["reasons"]]


# ── golden ──

def test_golden_evaluations():
    want = json.loads((FIX / "expected.json").read_text(encoding="utf-8"))
    got = json.loads(json.dumps(_run_all(), sort_keys=True))
    assert set(got) == set(want)
    for k in want:
        assert got[k] == want[k], f"maintenance golden drift: {k}"


def test_golden_decisions_are_the_intended_ones():
    e = _by_name()
    dec = {k: v["decision"] for k, v in e.items()}
    assert dec["no_policy"] == "allowed"
    assert dec["weeknight_inside"] == "allowed"
    assert dec["weeknight_start_edge_inclusive"] == "allowed"            # 22:00 local, start inclusive
    assert dec["weeknight_end_edge_exclusive"] == "blocked"              # 06:00 local, end exclusive
    # one minute before the end: allowed to start; a 30-minute run goes on after the window (a warning, not a block)
    assert dec["weeknight_one_minute_before_end"] == "warn"
    assert _codes(e["weeknight_one_minute_before_end"]) == ["inside-window", "may-run-past-window"]
    assert e["weeknight_duration_over_maximum"]["next_window_start_utc"] is None   # no later start would fix it
    assert dec["weeknight_runs_past_window"] == "warn" and "may-run-past-window" in _codes(e["weeknight_runs_past_window"])
    assert dec["weeknight_duration_over_maximum"] == "blocked"
    assert dec["weeknight_duration_not_declared"] == "warn"
    assert dec["friday_night_into_saturday"] == "allowed"                # overnight window started on Friday
    assert dec["saturday_night_outside"] == "blocked"
    assert dec["business_hours_outside"] == "blocked"
    assert dec["blackout_inside_window"] == "blocked" and "blackout" in _codes(e["blackout_inside_window"])
    assert dec["run_enters_blackout"] == "blocked" and "run-enters-blackout" in _codes(e["run_enters_blackout"])
    assert dec["freeze_only_inside_blackout"] == "blocked" and dec["freeze_only_outside_blackout"] == "allowed"
    assert dec["intrusive_only_passive_outside"] == "allowed"
    assert dec["intrusive_only_full_outside"] == "blocked"
    assert dec["unknown_kind_counts_as_intrusive"] == "blocked"
    assert dec["disabled_policy"] == "allowed"
    assert dec["invalid_timezone_blocks"] == "blocked" and _codes(e["invalid_timezone_blocks"]) == ["timezone-unavailable"]
    assert dec["invalid_shape_blocks"] == "blocked" and _codes(e["invalid_shape_blocks"]) == ["policy-invalid"]
    assert dec["unreadable_instant_blocks"] == "blocked"


def test_next_window_skips_blackouts_and_resumes_after_midnight():
    e = _by_name()
    # blocked in the year-end freeze: the next weeknight window after 2027-01-02 is Monday 2027-01-04 22:00 Paris
    assert e["blackout_inside_window"]["next_window_start_utc"] == "2027-01-04T21:00:00Z"
    # Friday 2026-11-20 is a blackout date; the Friday-night window goes on into Saturday: allowed from 00:00 Paris
    assert e["blackout_friday_night_resumes_at_midnight"]["decision"] == "blocked"
    assert e["blackout_friday_night_resumes_at_midnight"]["next_window_start_utc"] == "2026-11-20T23:00:00Z"
    assert e["business_hours_outside"]["next_window_start_utc"] == "2026-11-20T21:00:00Z"


# ── daylight saving ──

def test_dst_spring_forward_gap():
    e = _by_name()
    # 02:00–04:00 Paris on 2026-03-29: 02:00–03:00 does not exist; the window opens at 03:00 CEST = 01:00 UTC
    assert e["dst_spring_gap_window_start"]["decision"] == "allowed"
    assert e["dst_spring_before_gap"]["decision"] == "blocked"
    assert e["dst_spring_before_gap"]["next_window_start_utc"] == "2026-03-29T01:00:00Z"
    # the window lasts one real hour that day (ends 04:00 CEST = 02:00 UTC): a 60-minute run from 01:30 UTC runs past it
    assert e["dst_spring_window_is_one_hour"]["window_ends_at_utc"] == "2026-03-29T02:00:00Z"
    assert "may-run-past-window" in _codes(e["dst_spring_window_is_one_hour"])


def test_dst_fall_back_repeated_hour():
    e = _by_name()
    # 02:30 Paris happens twice on 2026-10-25 (00:30 UTC and 01:30 UTC): both are inside the 02:00–04:00 window
    assert e["dst_fall_first_occurrence"]["decision"] == "allowed"
    assert e["dst_fall_second_occurrence"]["decision"] == "allowed"
    # the window lasts three real hours that day (00:00–03:00 UTC)
    assert e["dst_fall_window_is_three_hours"]["window_ends_at_utc"] == "2026-10-25T03:00:00Z"
    assert "may-run-past-window" not in _codes(e["dst_fall_window_is_three_hours"])
    assert e["dst_fall_after_window"]["decision"] == "blocked"


def test_dst_other_zones():
    e = _by_name()
    assert e["ny_spring_forward_sunday_night"]["decision"] == "allowed"        # Sun 01:59 EST, just before the gap
    assert e["ny_spring_forward_sunday_night"]["window_ends_at_utc"] == "2026-03-09T04:00:00Z"   # Mon 00:00 EDT
    assert e["ny_fall_back_sunday_end"]["decision"] in ("allowed", "warn")    # Sun 23:59 EST, inside
    assert e["ny_monday_outside"]["decision"] == "blocked"                    # Mon 00:00 EST
    # Lord Howe moves by 30 minutes: the 01:30–02:30 window is 1 h 30 on the day DST ends and 30 min when it starts
    assert e["lord_howe_half_hour_dst_end"]["decision"] in ("allowed", "warn")
    assert e["lord_howe_half_hour_dst_start"]["decision"] == "blocked"


def test_local_instant_gap_and_repeat():
    tz = M.zone("Europe/Paris")
    assert M.local_instant(datetime(2026, 3, 29).date(), 150, tz) == datetime(2026, 3, 29, 1, 0, tzinfo=timezone.utc)
    assert M.local_instant(datetime(2026, 10, 25).date(), 150, tz) == datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
    assert M.local_instant(datetime(2026, 11, 20).date(), 1440, tz) == datetime(2026, 11, 20, 23, 0, tzinfo=timezone.utc)


# ── bypass attempts ──

POL = _cases()["policies"]["paris_nights"]


def test_timezone_tricks_on_the_instant():
    # the same instant written with any offset, or naive (= UTC), gives the same decision
    base = M.evaluate(POL, "2026-11-20T10:00:00Z", "full", 60)
    for at in ("2026-11-20T11:00:00+01:00", "2026-11-20T00:00:00-10:00", "2026-11-21T00:00:00+14:00",
               "2026-11-20T10:00:00", datetime(2026, 11, 20, 10, 0), datetime(2026, 11, 20, 5, 0,
                                                                                tzinfo=timezone(timedelta(hours=-5)))):
        ev = M.evaluate(POL, at, "full", 60)
        assert (ev["decision"], ev["at_utc"]) == (base["decision"], base["at_utc"]) == ("blocked", "2026-11-20T10:00:00Z")


def test_timezone_names_that_must_be_refused():
    for tz in ("../../../../etc/passwd", "/etc/localtime", "Europe/../Paris", "UTC+02:00", "Europe/Paris\n",
               "Europe/Paris ", "", None, 1, "Etc/../../x", "Paris", "Europe//Paris", "Europe/Paris/../../x"):
        clean, issues = M.validate_policy({**POL, "timezone": tz})
        assert clean is None and any(i["field"] == "timezone" for i in issues), tz
        assert M.zone(tz) is None


def test_malformed_policies_are_refused_whole():
    bad = [
        {**POL, "windows": [{"days": ["mon"], "start": "22:00", "end": "22:00"}]},           # empty window
        {**POL, "windows": [{"days": [], "start": "22:00", "end": "06:00"}]},
        {**POL, "windows": [{"days": ["mon", "mon"], "start": "22:00", "end": "06:00"}]},
        {**POL, "windows": [{"days": ["mon"], "start": "24:00", "end": "06:00"}]},
        {**POL, "windows": [{"days": ["mon"], "start": "7:00", "end": "08:00"}]},
        {**POL, "windows": [{"days": ["mon"], "start": "07:00", "end": "08:00", "evil": 1}]},
        {**POL, "windows": "mon-fri"},
        {**POL, "windows": [{"days": ["mon"], "start": "07:00", "end": "08:00"}] * 29},
        {**POL, "blackouts": [{"start": "2026-12-31", "end": "2026-12-01"}]},
        {**POL, "blackouts": [{"start": "2026-02-30"}]},
        {**POL, "blackouts": [{"start": "2026-01-01", "end": "2028-01-01"}]},
        {**POL, "max_duration_minutes": 0}, {**POL, "max_duration_minutes": True}, {**POL, "max_duration_minutes": "60"},
        {**POL, "enabled": "false"}, {**POL, "intrusive_only": 1},
        {**POL, "windows": [{"days": ["mon"], "start": "07:00", "end": "08:00", "label": "a\nb"}]},
        {**POL, "note": "x‮y"}, {**POL, "extra": True}, {**POL, "schema_version": "other/9"},
        [], "policy", None,
    ]
    for b in bad:
        clean, issues = M.validate_policy(b)
        assert clean is None and issues, b
        if b is not None:
            assert M.evaluate(b, "2026-11-19T22:30:00Z", "full", 30)["decision"] == "blocked"


def test_project_id_must_match():
    assert M.validate_policy({**POL, "project_id": "proj_b"}, "proj_a")[0] is None
    assert M.validate_policy({**POL, "project_id": "proj_a"}, "proj_a")[0] is not None


def test_overlapping_windows_add_up_and_never_widen_beyond_their_union():
    e = _by_name()
    # 08:00–12:00 + 11:00–14:00 + 14:00–24:00 Saturday Paris = one span 08:00–24:00 (= 23:00 UTC)
    assert e["overlap_union_end"]["window_ends_at_utc"] == "2026-11-21T23:00:00Z"
    assert e["overlap_union_end"]["decision"] == "allowed"
    assert "may-run-past-window" in _codes(e["overlap_union_past_midnight"])
    # Sunday is not in the windows
    assert M.evaluate(_cases()["policies"]["paris_overlap"], "2026-11-21T23:00:00Z", "full", 10)["decision"] == "blocked"


def test_window_edges_minute_by_minute():
    # every minute around both edges: start inclusive, end exclusive, nothing in between leaks
    pol = {k: v for k, v in POL.items() if k != "max_duration_minutes"}
    start = datetime(2026, 11, 19, 20, 55, tzinfo=timezone.utc)     # Thu 21:55 Paris
    got = [M.evaluate(pol, start + timedelta(minutes=i), "full")["decision"] for i in range(11)]
    assert got == ["blocked"] * 5 + ["allowed"] * 6
    end = datetime(2026, 11, 20, 4, 55, tzinfo=timezone.utc)        # Fri 05:55 Paris
    got = [M.evaluate(pol, end + timedelta(minutes=i), "full")["decision"] for i in range(10)]
    assert got == ["allowed"] * 5 + ["blocked"] * 5
    # seconds: 05:59:59.999 Paris is still inside, 06:00:00 is not
    assert M.evaluate(pol, datetime(2026, 11, 20, 4, 59, 59, 999000, tzinfo=timezone.utc), "full")["decision"] == "allowed"
    assert M.evaluate(pol, datetime(2026, 11, 20, 5, 0, 0, tzinfo=timezone.utc), "full")["decision"] == "blocked"


def test_advisory_never_blocks_but_keeps_the_reasons():
    ev = M.evaluate(POL, "2026-11-20T10:00:00Z", "full", 60)
    adv = M.as_advisory(ev)
    assert adv["decision"] == "warn" and adv["advisory_of"] == "blocked" and adv["enforced"] is False
    assert adv["reasons"] == ev["reasons"]
    assert M.summary_line(adv).startswith("WARNING:")


def test_combine_takes_the_strictest():
    assert M.combine([]) == "allowed"
    assert M.combine([{"decision": "allowed"}, {"decision": "warn"}]) == "warn"
    assert M.combine([{"decision": "warn"}, {"decision": "blocked"}]) == "blocked"
    assert M.combine([{"decision": "weird"}]) == "blocked"


def test_describe_is_plain_words():
    clean, _ = M.validate_policy(POL)
    lines = M.describe(clean)
    assert lines[0].startswith("Every campaign may start only inside these windows (Europe/Paris time)")
    assert "Monday to Friday, 22:00–06:00 (next day) — Weeknights" in lines[1]
    assert M.describe(None) == ["No maintenance policy: launches are not restricted by time."]


def test_deterministic_and_pure():
    a = _run_all()
    b = _run_all()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_target_matching_forms():
    """R4 S1: IP forms, CIDR ranges, URL forms, subdomains and parent domains (both directions)."""
    m = M.target_matches
    assert m("https://APP.example.com.:443/x", "app.example.com", "")
    for form in ("10.0.0.5", "167772165", "0x0a000005", "10.0.0.05", "10.5", "http://[::ffff:10.0.0.5]/",
                 "10.0.0.0/24", "10.0.0.0/8", "http://u@10.0.0.5:8080/a"):
        assert m(form, "db.example.com", "10.0.0.5"), form
    assert m("example.com", "app.example.com", "") and m("x.app.example.com", "app.example.com", "")
    assert m("*.example.com", "app.example.com", "")
    for form in ("10.0.1.0/24", "10.0.0.6", "evil.com", "com", "ample.com", ""):
        assert not m(form, "app.example.com", "10.0.0.5"), form
    # dotless host names (container names, localhost, intranet short names) match too (pass B live finding)
    for form in ("dm-community-port-dvga", "http://DM-Community-Port-DVGA:8080/graphql", "x.dm-community-port-dvga"):
        assert m(form, "dm-community-port-dvga", ""), form
    assert m("localhost", "http://localhost:3000", "") and not m("other-host", "dm-community-port-dvga", "")
    assert not m("dvga", "app.dvga.example.com", "")   # a bare label never acts as a parent domain
    assert M.parse_ip("::ffff:192.0.2.1") == M.parse_ip("192.0.2.1")
    assert M.parse_ip("999.1.1.1") is None and M.parse_network("10.0.0.0/99") is None


# ── the decision recorded on a campaign, in words (owner decision 20/11: an override is visible) ──

_OVERRIDE = {"decision": "blocked", "at_utc": "2026-11-20T14:03:00Z", "kind": "full", "source": "launch",
             "enforced": True,
             "projects": [{"project_id": "p1", "decision": "blocked", "reasons": ["blackout", "outside-window"]}],
             "override": {"override": True, "by": "ada", "at": "2026-11-20T14:03:09Z",
                          "reason": "Emergency fix validation agreed with the owner"}}


def test_launch_view_every_case():
    v = M.launch_view
    assert v(None)["decision"] == v({})["decision"] == v("x")["decision"] == "not_recorded"
    assert v(None)["text"] == "Not recorded (the campaign predates the maintenance record)"
    assert v({"decision": "allowed", "projects": [], "source": "launch"})["text"] == "No maintenance policy applied"
    assert v({"decision": "allowed", "reasons": ["no-policy"], "enforced": False})["decision"] == "no_policy"
    inside = v({"decision": "allowed", "projects": [{"reasons": ["inside-window"]}], "source": "launch", "enforced": True})
    assert (inside["decision"], inside["text"], inside["overridden"]) == ("within", "Within the maintenance policy", False)
    warn = v({"decision": "warn", "projects": [{"reasons": ["inside-window", "duration-not-declared"]}]})
    assert warn["text"] == "Within the maintenance policy, with a warning (planned duration not declared)"
    o = v(_OVERRIDE)
    assert (o["decision"], o["overridden"], o["by"], o["at"]) == ("outside", True, "ada", "2026-11-20 14:03 UTC")
    assert o["text"] == ("Outside the maintenance policy (blackout date, outside every window) — launched by an "
                         "administrator override: ada, 2026-11-20 14:03 UTC, reason: « Emergency fix validation agreed "
                         "with the owner »")
    mcp = v({"decision": "blocked", "projects": [{"reasons": ["outside-window"]}], "source": "mcp_init", "enforced": False})
    assert mcp["text"] == ("Outside the maintenance policy (outside every window) — recorded, not enforced (campaign "
                           "started outside the dashboard)") and not mcp["overridden"]
    com = v({"decision": "warn", "advisory_of": "blocked", "reasons": ["outside-window"], "enforced": False})
    assert com["decision"] == "outside" and com["text"].endswith("recorded, not enforced (Community warns, it does not "
                                                                 "block a launch)")
    # an override record on a decision that was not outside the policy is not shown as an override
    assert not v({**_OVERRIDE, "decision": "allowed", "projects": [{"reasons": ["inside-window"]}]})["overridden"]


def test_launch_view_sanitises_the_override_reason():
    long = "x" * 900
    for reason, check in (
            ("line one\nline two\u202e", lambda r: "\n" not in r and "\u202e" not in r),
            ("token ghp_abcdefghijklmnopqrstuvwxyz0123 used", lambda r: "ghp_" not in r and "[redacted]" in r),
            ("Bearer abcdefghijklmnop1234", lambda r: "abcdefghijklmnop1234" not in r),
            (long, lambda r: len(r) == M.OVERRIDE_REASON_MAX and r.endswith("…")),
            ("", lambda r: r == "not recorded")):
        got = M.launch_view({**_OVERRIDE, "override": {**_OVERRIDE["override"], "reason": reason}})
        assert check(got["reason"]), (reason, got["reason"])
        assert got["reason"] in got["text"]
    odd = M.launch_view({**_OVERRIDE, "override": {"override": True, "by": "a\nb", "at": "not a date", "reason": "r"}})
    assert "\n" not in odd["by"] and odd["at"] == "not a date"
    assert M.launch_view({**_OVERRIDE, "override": {"override": True}})["by"] == "unknown account"


if __name__ == "__main__":
    (FIX / "expected.json").write_text(json.dumps(_run_all(), indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    print("maintenance expected.json written")
