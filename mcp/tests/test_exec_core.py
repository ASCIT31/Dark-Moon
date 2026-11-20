"""exec_core: finding identity, the one stats function, Cyber Score v1, project reference score, legend.

Unit tests + adversarial tests (gaming, low coverage, missing data). Same file in both editions."""
from __future__ import annotations

import copy

import pytest

from api.exec_core import identity, legend, project, score, stats

SIG = "darkmoon-coverage-signals/1"


def sig(kind="full", dur=3600, agents=("php", "headless-browser", "graphql"), assets=4, commands=120, workflows=0,
        source="default", agents_source="opencode_sessions"):
    return {"schema": SIG, "campaign_kind": kind, "campaign_kind_source": source,
            "started_at": "2026-11-20T09:00:00Z", "finalized_at": "2026-11-20T10:00:00Z",
            "measured_duration_seconds": dur, "agents_dispatched": [{"agent": a} for a in agents],
            "agents_source": agents_source, "assets_registered": assets, "commands_executed": commands,
            "workflows_executed": workflows}


def camp(status="completed", signals=None, cid="camp_t", tid="tgt_t", date="2026-11-20T09:00:00Z"):
    c = {"id": cid, "target_id": tid, "status": status, "date": date}
    if signals is not None:
        c["coverage_signals"] = signals
    return c


def fnd(i, sev="high", status="confirmed", cat="xss", ep="/app", agent="php", **kw):
    return {"id": f"v{i}", "target_id": "tgt_t", "title": f"t{i}", "severity": sev, "status": status,
            "category": cat, "endpoint": ep, "discovered_by_agent": agent, **kw}


def rated(findings, **kw):
    return score.cyber_score({"campaign": camp(signals=sig(**kw)), "findings": findings})


# ---------------------------------------------------------------- identity

def test_exclusions_and_open():
    assert identity.exclusion_reason(fnd(1, quarantined=True)) == "quarantined"
    assert identity.exclusion_reason(fnd(1, quarantined=True, quarantine_reviewed_by="op")) is None
    assert identity.exclusion_reason(fnd(1, status="quarantined")) is None, "only the server flag quarantines"
    for st in ("false_positive", "False Positive", "false-positive"):
        assert identity.exclusion_reason(fnd(1, status=st)) == "false_positive"
    assert identity.is_open(fnd(1)) and not identity.is_open(fnd(1, status="remediated"))
    assert not identity.is_open(fnd(1, quarantined=True))


def test_severity_aliases_and_unknown():
    assert identity.severity_of({"severity": " Crit "}) == "critical"
    assert identity.severity_of({"severity": "moderate"}) == "medium"
    assert identity.severity_of({"severity": "bogus"}) == "unknown"
    assert identity.severity_of({}) == "unknown"


def test_weakness_class_merges_agent_vocabulary():
    assert identity.weakness_class({"category": "xss_stored"}) == identity.weakness_class({"category": "XSS-DOM"})
    assert identity.weakness_class({"category": "rce"}) == identity.weakness_class({"category": "command_injection"})
    assert identity.weakness_class({"category": "brand_new_thing"}) == "brand_new_thing"
    assert identity.weakness_class({}) == "unclassified"


def test_fingerprint_is_stable_and_ignores_host_and_numeric_ids():
    a = identity.fingerprint({"target_id": "t", "category": "idor", "endpoint": "http://h1/users/12?x=1"})
    b = identity.fingerprint({"target_id": "t", "category": "idor", "endpoint": "h2:8080/users/7"})
    assert a == b and a.startswith("fp_")
    assert identity.fingerprint({"target_id": "t", "dedup_key": "k"}) != identity.fingerprint(
        {"target_id": "u", "dedup_key": "k"})


def test_fingerprint_never_raises_on_hostile_endpoints():
    for ep in ("http://[::1", "http://h:99999999/a", "\x00\x01", "[]]]", None, 12):
        identity.fingerprint({"target_id": "t", "category": "x", "endpoint": ep})


# ---------------------------------------------------------------- stats

def test_stats_exclude_quarantined_and_false_positive():
    vs = [fnd(1, "critical", "exploited"), fnd(2, "high", "false_positive"), fnd(3, "critical", "exploited",
          quarantined=True), fnd(4, "info", "confirmed"), fnd(5, "low", "remediated"), "garbage"]
    s = stats.compute_stats(vs)
    assert s["total_findings"] == 3
    assert (s["critical"], s["high"], s["low"], s["info"]) == (1, 0, 1, 1)
    assert s["exploited"] == 1 and s["exploited_by_severity"]["critical"] == 1
    assert s["excluded"] == {"quarantined": 1, "false_positive": 1}
    assert stats.overall_risk(s) == "critical"
    assert stats.overall_risk(stats.compute_stats([fnd(1, "info")])) == "none"


def test_open_fingerprints_distinct():
    vs = [fnd(1, ep="/a"), fnd(2, ep="/a", agent="other"), fnd(3, ep="/b"), fnd(4, status="fixed")]
    assert len(stats.open_fingerprints(vs)) == 2


# ---------------------------------------------------------------- score gate

def test_old_campaign_without_signals_is_not_rated_with_explicit_limitation():
    d = score.cyber_score({"campaign": camp(), "findings": [fnd(1)]})
    assert d["score_status"] == "not_rated" and d["score"] is None and d["grade"] is None
    assert [r["code"] for r in d["status_reasons"]] == ["no_coverage_signals"]
    assert any("before coverage signals existed" in x for x in d["limitations"])
    assert d["penalty_total"] is None
    assert all("penalty" not in u for c in d["components"] for u in c["units"]), "no hidden number when not rated"


@pytest.mark.parametrize("status", ["running", "aborted", "stopped", "error", ""])
def test_incomplete_campaigns_are_not_rated(status):
    d = score.cyber_score({"campaign": camp(status=status, signals=sig()), "findings": []})
    assert d["score_status"] == "not_rated" and d["score"] is None


def test_retest_is_not_rated():
    d = score.cyber_score({"campaign": camp(signals=sig(kind="retest")), "findings": []})
    assert d["score_status"] == "not_rated"


def test_no_measured_activity_is_not_rated():
    d = score.cyber_score({"campaign": camp(signals=sig(agents=(), commands=0)), "findings": []})
    assert "no_activity_observed" in [r["code"] for r in d["status_reasons"]]
    d = score.cyber_score({"campaign": camp(signals=sig(dur=None)), "findings": []})
    assert d["score_status"] == "not_rated"


@pytest.mark.parametrize("kw,code", [({"kind": "short"}, "short_campaign"), ({"dur": 600}, "short_duration"),
                                     ({"agents": ("php",)}, "few_agents"), ({"assets": 0}, "no_assets"),
                                     ({"commands": 3}, "few_commands")])
def test_low_coverage_is_never_reassuring(kw, code):
    d = rated([], **kw)
    assert d["score_status"] == "limited"
    assert d["score"] <= score.LIMITED_CAP and d["grade"] not in ("A", "B")
    assert code in [r["code"] for r in d["status_reasons"]]


def test_hundred_only_for_a_rated_full_campaign_and_says_so():
    d = rated([])
    assert d["score"] == 100 and d["grade"] == "A"
    assert any("not a proof" in x for x in d["limitations"])
    for kw in ({"kind": "short"}, {"dur": 60}):
        assert rated([], **kw)["score"] < 100


# ---------------------------------------------------------------- caps

@pytest.mark.parametrize("sev,st,cap", [("critical", "exploited", 39), ("critical", "confirmed", 49),
                                        ("high", "exploited", 59)])
def test_caps_by_worst_evidence(sev, st, cap):
    d = rated([fnd(1, sev, st, "csrf")])
    assert d["score"] <= cap
    assert any(c["finding_ids"] == ["v1"] for c in d["caps"])


def test_unconfirmed_never_sets_a_cap_and_is_listed_to_confirm():
    d = rated([fnd(1, "critical", "unconfirmed", "sql_injection")])
    assert d["caps"] == [] and d["evidence_summary"]["to_confirm"] == ["v1"]
    assert d["score"] > 49


def test_proof_order_exploited_below_confirmed_below_unconfirmed():
    s = [rated([fnd(1, "high", st, "csrf")])["score"] for st in ("exploited", "confirmed", "unconfirmed")]
    assert s[0] < s[1] < s[2]


# ---------------------------------------------------------------- adversarial: gaming

def test_exact_duplicates_from_more_agents_do_not_move_the_score():
    base = [fnd(1, "critical", "exploited", "sqli", "/s"), fnd(2, "high", "confirmed", "xss", "/x"),
            fnd(3, "medium", "confirmed", "csrf", "/c")]
    dup = base + [dict(v, id=v["id"] + "b", discovered_by_agent="other") for v in base]
    assert rated(base)["penalty_total"] == rated(dup)["penalty_total"]


def test_variant_duplicates_change_the_score_within_the_bound():
    base = [fnd(1, "high", "confirmed", "xss_stored", "/x"), fnd(2, "medium", "confirmed", "csrf", "/c")]
    b = rated(base)
    noisy = base + [dict(v, id=f"{v['id']}-{k}", endpoint=f"{v['endpoint']}/{k}", category=c,
                         discovered_by_agent=f"agent{k}")
                    for v, c in ((base[0], "xss_dom"), (base[1], "csrf")) for k in range(10)]
    n = rated(noisy)
    bound = score.UNIT_INCREMENT_CAP * sum(c["top_unit_penalty"] for c in b["components"])
    assert 0 <= n["penalty_total"] - b["penalty_total"] <= bound + 1e-9
    assert b["score"] - n["score"] <= bound + 1


def test_agent_count_is_a_gate_never_a_weight():
    vs = [fnd(1, "high", "confirmed", "csrf")]
    assert rated(vs, agents=("a", "b"))["score"] == rated(vs, agents=tuple("abcdefgh"))["score"]


def test_treatment_and_retest_fields_never_change_the_score():
    vs = [fnd(1, "high", "confirmed", "csrf")]
    tweaked = [dict(vs[0], treatment="applied", pull_requests=[{"state": "merged"}], retest_verdict="fixed")]
    assert rated(vs)["score"] == rated(tweaked)["score"]


def test_quarantine_and_false_positive_counted_nowhere():
    vs = [fnd(1, "low", "confirmed", "insecure_cookie")]
    extra = vs + [fnd(2, "critical", "exploited", "rce", quarantined=True), fnd(3, "critical", "false_positive")]
    a, b = rated(vs), rated(extra)
    assert a["score"] == b["score"]
    assert b["evidence_summary"]["excluded"]["quarantined"] == 1
    assert b["evidence_summary"]["excluded"]["false_positive"] == 1


def test_missing_coverage_is_not_rated_never_a_low_score():
    legacy = score.cyber_score({"campaign": camp(), "findings": [fnd(1, "critical", "exploited")]})
    assert legacy["score"] is None and legacy["score_status"] == "not_rated"
    empty_legacy = score.cyber_score({"campaign": camp(), "findings": []})
    assert empty_legacy["score"] is None, "no data is never a 100 either"


@pytest.mark.parametrize("label", ["very high", "P1", "9.8", "severe", None, ""])
def test_unrecognised_severity_is_never_reassuring(label):
    d = rated([fnd(1, label, "exploited", "rce")])
    assert d["evidence_summary"]["unknown_severity"] == ["v1"]
    assert d["score"] <= 59, "weighted as high (conservative) and capped like an exploited high"
    assert any("recognised severity" in x for x in d["limitations"])


def test_unrecognised_severity_takes_the_band_of_a_valid_vector():
    v = fnd(1, "P1", "exploited", "rce", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score.scored_severity(v) == "critical"
    assert rated([v])["score"] <= 39


def test_agent_declared_closure_does_not_change_the_score():
    """Treatment states never change the rating: a finding closed during the campaign is still scored."""
    base = rated([fnd(1, "critical", "exploited", "rce")])
    for st in ("remediated", "fixed", "closed", "resolved"):
        d = rated([fnd(1, "critical", st, "rce")])
        assert d["score"] <= 49 and d["evidence_summary"]["declared_closed"] == ["v1"]
        assert any("declared closed" in x for x in d["limitations"])
    assert base["score"] <= 39


def test_agent_status_quarantined_is_not_a_quarantine():
    d = rated([fnd(1, "critical", "quarantined", "rce")])
    assert d["evidence_summary"]["excluded"]["quarantined"] == 0 and d["score"] < 100


def test_false_positive_exclusion_is_disclosed():
    d = rated([fnd(1, "critical", "false_positive", "rce")])
    assert any("false positive" in x for x in d["limitations"])


def test_malformed_signals_are_ignored_not_trusted():
    bad = sig()
    bad["schema"] = "something-else"
    assert score.cyber_score({"campaign": camp(signals=bad), "findings": []})["score_status"] == "not_rated"
    weird = sig(kind="mega", dur="abc", commands="lots")
    d = score.cyber_score({"campaign": camp(signals=weird), "findings": []})
    assert d["assessment_coverage"]["campaign_kind"] == "unknown"
    assert d["score_status"] == "not_rated"
    for patch in ({"agents_dispatched": "xyz"}, {"agents_dispatched": [{"agent": None}, {"agent": 5}, None]},
                  {"measured_duration_seconds": float("inf")}, {"measured_duration_seconds": float("nan")},
                  {"assets_registered": -3}, {"commands_executed": [1, 2]}, {"agents_dispatched": 7}):
        s2 = dict(sig(), **patch)
        d = score.cyber_score({"campaign": camp(signals=s2), "findings": []})   # never raises
        assert d["score"] is None or d["score"] <= score.LIMITED_CAP, patch


def test_agent_floor_needs_agents_observed_in_the_session_log():
    d = rated([], agents_source="tool_calls_only")
    assert d["score_status"] == "limited" and "agents_not_observed" in [r["code"] for r in d["status_reasons"]]
    d = rated([], agents=("general", "build", "php"))
    assert d["score_status"] == "limited" and "few_agents" in [r["code"] for r in d["status_reasons"]]


def test_deterministic_and_input_order_independent():
    vs = [fnd(i, s, st, c, f"/{i}") for i, (s, st, c) in enumerate(
        [("critical", "confirmed", "sqli"), ("high", "exploited", "xss"), ("low", "unconfirmed", "csrf")])]
    a = rated(vs)
    b = rated(list(reversed(copy.deepcopy(vs))))
    assert a == b


def test_breakdown_explains_the_number():
    vs = [fnd(1, "medium", "confirmed", "csrf", "/a"), fnd(2, "high", "confirmed", "csrf", "/b"),
          fnd(3, "medium", "confirmed", "xss", "/x")]
    d = rated(vs)
    assert d["caps_applied"] == []
    total = sum(c["class_penalty"] for c in d["components"])
    assert abs(total - d["penalty_total"]) < 0.01
    assert d["score"] == max(0, min(100, int(100 - total + 0.5)))
    csrf = next(c for c in d["components"] if c["weakness_class"] == "csrf")
    assert csrf["units"][0]["head_finding_id"] == "v2" and csrf["units"][0]["distinct_weaknesses"] == 2


def test_output_fields():
    d = rated([])
    for k in ("score", "grade", "score_status", "methodology_version", "assessment_coverage", "assessed_at",
              "evidence_summary", "limitations", "trend", "source_campaign_ids", "components"):
        assert k in d
    assert d["assessed_at"] == "2026-11-20T10:00:00Z"
    assert "sentence" in d["assessment_coverage"]


# ---------------------------------------------------------------- project reference + trend

def _b(cid, date, signals, findings, tid="tgt_t"):
    return {"campaign": camp(cid=cid, date=date, signals=signals, tid=tid),
            "findings": [dict(f, target_id=tid) for f in findings]}


def test_project_reference_is_latest_rated_full_and_trend_only_between_them():
    bundles = [
        _b("c1", "2026-10-01", sig(), [fnd(1, "critical", "exploited")]),
        _b("c2", "2026-11-01", sig(), [fnd(2, "low", "confirmed")]),
        _b("c3", "2026-11-05", sig(kind="retest"), []),
        _b("c4", "2026-11-06", sig(kind="short"), []),
        _b("c5", "2026-11-07", None, []),
    ]
    p = project.reference_score(bundles)
    assert p["score_status"] == "rated" and p["reference"]["campaign_id"] == "c2"
    assert p["trend"]["available"] and p["trend"]["previous_campaign_id"] == "c1"
    assert p["trend"]["direction"] == "improved"
    assert [c["score_status"] for c in p["campaigns_considered"]] == [
        "rated", "rated", "not_rated", "limited", "not_rated"]


def test_project_without_rated_campaign():
    p = project.reference_score([_b("c1", "2026-10-01", None, [fnd(1)])])
    assert p["score_status"] == "not_rated" and p["score"] is None and p["reason"]


def test_trend_refused_between_limited_and_rated():
    a = rated([])
    b = score.cyber_score({"campaign": camp(cid="c0", signals=sig(kind="short")), "findings": []})
    t = score.trend_between(a, b)
    assert t["available"] is False


def test_reference_campaign_rule():
    cs = [{"id": "a", "date": "1", "status": "completed"}, {"id": "b", "date": "2", "status": "running"},
          {"id": "s", "date": "3", "status": "completed", "is_subagent": True}]
    assert project.reference_campaign(cs)["id"] == "a"
    assert project.reference_campaign([{"id": "b", "date": "2", "status": "running"}])["id"] == "b"
    assert project.reference_campaign([]) is None


def test_reference_campaign_is_never_a_retest_or_a_short_run_when_a_full_one_exists():
    cs = [{"id": "full", "date": "1", "status": "completed", "coverage_signals": sig()},
          {"id": "rt", "date": "2", "status": "completed", "coverage_signals": sig(kind="retest")},
          {"id": "sh", "date": "3", "status": "completed", "coverage_signals": sig(kind="short")}]
    assert project.reference_campaign(cs)["id"] == "full"
    assert project.reference_campaign(cs[1:])["id"] == "sh", "no full campaign: the last complete one"
    tie = [{"id": "b", "date": "1", "status": "completed"}, {"id": "a", "date": "1", "status": "completed"}]
    assert project.reference_campaign(tie)["id"] == project.reference_campaign(list(reversed(tie)))["id"] == "b"


# ---------------------------------------------------------------- legend

def test_legend_vocabulary_separates_evidence_from_severity():
    lg = legend.legend()
    assert set(lg["evidence_status"]).isdisjoint(set(lg["severity"]))
    assert lg["path_kind"]["possible"]["label"] == "Possible Attack Path"
    assert lg["path_kind"]["evidence_backed"]["label"] == "Evidence-Backed Attack Path"
    assert lg["treatment"]["in_progress"]["label"] == "Treatment in Progress"
    assert {"declared", "corroborated"} <= set(lg["declaration"])
    assert legend.path_kind("observed") == "evidence_backed"
    assert legend.path_kind("agent-declared") == legend.path_kind("whatever") == "possible"
    assert legend.evidence_label("bogus") == "To confirm"
    assert set(lg["grade"]) == {g for g, _ in score.GRADES}
