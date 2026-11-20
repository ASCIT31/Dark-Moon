"""Prioritized Treatment Plan (exec_core.actions + exec_core.retest), shared by Community and Pro (same file in both
editions, same fixture, same expected output).

Covers: one action per (asset, weakness class) = the score's penalty unit, many findings / one action, partial fix,
failed retest, interrupted retest, a retest without coverage (verifies nothing), deferred and back, applied !=
verified, risk acceptance (named owner, expiry <= 12 months, expired), append-only history with invalid entries
skipped, cyclic paths, old campaigns without a treatment file, migration of the per-fix-item ids of exec_core <= 1.4
(merged states keep the least advanced status), the plan never touching findings or the score, and the parity fixture
run through each edition's own attack-path engine.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api import attack_paths  # noqa: E402
from api.exec_core import actions as A  # noqa: E402
from api.exec_core import retest as R  # noqa: E402
from api.exec_core import score, stats  # noqa: E402

FIX = MCP / "tests" / "fixtures" / "exec_core" / "treatment"
CID = "camp_t"


def _v(i, cat="sql_injection", sev="high", st="confirmed", ep="http://h/a", **kw):
    return {"id": i, "title": kw.pop("title", f"t {i}"), "category": cat, "severity": sev, "status": st,
            "endpoint": ep, "target_id": "tg", **kw}


def _doc(groups, source="reported-severity-x-proof", paths=(), ranking=None, items=None):
    return {"fix_first": {"source": source, "items": items if items is not None else groups, "open_findings": 9,
                          "label": "x"},
            "triage": {"groups_all": groups, "items": groups[:20]}, "paths": list(paths),
            "ranking": ranking or {"fixes": []}}


def _g(fix_id, ids, rank=1, **kw):
    return {"fix_id": fix_id, "finding_ids": ids, "rank": rank, "head_finding_id": ids[0], "label": f"Fix {fix_id}",
            **kw}


COV = {"present": True, "campaign_kind": "retest", "measured_duration_seconds": 900, "agents_dispatched": ["web"],
       "specialised_agents": ["web"], "agents_source": "opencode_sessions", "assets_registered": 1,
       "commands_executed": 12, "workflows_executed": 0}


def _retest(verdicts, outcome="complete", at="2026-11-10T00:00:00Z", scope=None, coverage=COV):
    return {"retest_id": "rt1", "at": at, "outcome": outcome, "finding_ids": scope, "coverage": coverage,
            "verdicts": [{"finding_id": k, "verdict": v} for k, v in verdicts.items()]}


def _uid(cls="sql_injection", asset="tg"):
    return A.unit_action_id(CID, f"{asset}|{cls}")


def _state(aid, *entries, finding_ids=None):
    return {"actions": {aid: {"finding_ids": finding_ids or [], "history": list(entries)}}}


def _e(at, status=None, role="admin", **kw):
    e = {"at": at, "by_role": role, **kw}
    if status:
        e["status"] = status
    return e


# ── actions ──

def test_one_action_many_findings_and_stable_ids():
    vs = [_v("a"), _v("b"), _v("c", remediation="Use prepared statements.")]
    doc = _doc([_g("fx1", ["a", "b", "c"])])
    p1, p2 = A.build_plan(CID, doc, vs), A.build_plan(CID, copy.deepcopy(doc), vs)
    assert len(p1["actions"]) == 1
    a = p1["actions"][0]
    assert a["finding_ids"] == ["a", "b", "c"] and a["expected_impact"]["findings_covered"] == 3
    assert a["action_id"] == p2["actions"][0]["action_id"] == _uid()
    assert A.unit_action_id("other_campaign", "tg|sql_injection") != a["action_id"]
    assert a["unit"] == "tg|sql_injection" and a["weakness_class_label"] == "SQL injection"
    assert a["title"] == "SQL injection — t a (+2 related findings)"
    assert a["effort"]["band"] == "M" and "indicative" in a["effort"]["provenance"]
    assert [f["finding_id"] for f in a["findings"]] == ["a", "b", "c"] and a["fix_ids"] == ["fx1"]
    # the head has no text: the member's text is quoted as the agent's, never generated
    assert a["recommended_treatment"]["text"] == "Use prepared statements."
    assert a["recommended_treatment"]["source"] == "testing_agent"
    assert "quoted" in a["recommended_treatment"]["label"]
    assert a["status"] == "proposed" and a["owner"]["value"] == "unknown"
    assert a["approval_required"]["value"] == a["service_interruption_risk"]["value"] == "unknown"
    assert a["related_controls"] == ["gdpr:Art.32(1)(b)-ci", "iso27001:A.8.26", "iso27001:A.8.28",
                                     "nis2:Art.21(2)(e)"]
    assert a["dependencies"] == []
    assert "%" not in a["expected_impact"]["text"]


def test_no_remediation_text_is_said_not_invented():
    a = A.build_plan(CID, _doc([_g("fx", ["a"])]), [_v("a")])["actions"][0]
    assert a["recommended_treatment"]["text"] is None and "No remediation text" in a["recommended_treatment"]["label"]


def test_one_action_per_weakness_class_and_asset():
    """R1 H-3 / R3 D1: the same root cause on the same asset is one action whatever the fix items; another class or
    another asset is another action; the unit is the score's penalty unit."""
    vs = [_v("a", title="SQLi in search"), _v("b", title="SQLi in login", ep="http://h/b", sev="critical",
                                                st="exploited"),
          _v("c", cat="xss_stored", title="Stored XSS"), _v("d", title="SQLi on API", target_id="tg2")]
    plan = A.build_plan(CID, _doc([_g("f1", ["a"]), _g("f2", ["b"], rank=2), _g("f3", ["c"], rank=3),
                                   _g("f4", ["d"], rank=4)]), vs)
    got = [(x["unit"], x["finding_ids"]) for x in plan["actions"]]
    assert got == [("tg|sql_injection", ["a", "b"]), ("tg|xss", ["c"]), ("tg2|sql_injection", ["d"])]
    first = plan["actions"][0]
    assert first["head_finding_id"] == "b" and first["severity"] == "critical" and first["proof"] == "exploited"
    assert first["title"] == "SQL injection — SQLi in login (+1 related finding)"
    assert first["fix_ids"] == ["f1", "f2"]
    units = {u["unit"] for c in score.cyber_score({"campaign": {"id": CID, "status": "completed", "target_id": "tg"},
                                                   "findings": vs})["components"] for u in c["units"]}
    assert units == {x["unit"] for x in plan["actions"]}


def test_titles_keep_the_agent_casing():
    """R1 H-3 / R3 D9: no « Fix remote Code Execution… »: the class in words, then the agent's title as written."""
    vs = [_v("a", cat="rce", title="Remote Code Execution via systemDiagnostics"),
          _v("b", cat="jwt", title="graphQL Users Query exposes JWT")]
    plan = A.build_plan(CID, _doc([_g("f1", ["a"]), _g("f2", ["b"], rank=2)]), vs)
    assert [x["title"] for x in plan["actions"]] == ["Code execution — Remote Code Execution via systemDiagnostics",
                                                     "Authentication — graphQL Users Query exposes JWT"]


def test_ties_share_a_rank():
    vs = [_v("a", cat="xss"), _v("b", cat="csrf"), _v("c", cat="ssrf", sev="critical")]
    plan = A.build_plan(CID, _doc([_g("f1", ["a"]), _g("f2", ["b"], rank=2), _g("f3", ["c"], rank=3)]), vs)
    assert [(x["weakness_class"], x["priority"], x["rank"], x["tie_size"]) for x in plan["actions"]] == [
        ("ssrf", 1, 1, 1), ("xss", 2, 2, 2), ("csrf", 3, 2, 2)]


def test_attack_path_actions_and_verification_per_unit():
    vs = [_v("a"), _v("b", cat="xss"), _v("c", cat="csrf")]
    items = [{"fix_id": "g1", "finding_ids": ["a", "b"], "rank": 1, "of_total": 2, "breaks": 1},
             {"fix_id": "g2", "finding_ids": ["a", "c"], "rank": 2, "of_total": 2, "breaks": 1}]
    ranking = {"fixes": [{"fix_id": "g1", "interrupts": ["p1"]}, {"fix_id": "g2", "interrupts": ["p2"]}]}
    # p1 observed by the server (Evidence-Backed); p2 not a hypothesis, but nothing backs it: a Possible path
    paths = [{"id": "p1", "finding_ids": ["a", "b"], "hypothesis": False, "provenance": "observed"},
             {"id": "p2", "finding_ids": ["a", "c"], "hypothesis": False}]
    doc = _doc([], source="attack-paths", paths=paths, ranking=ranking, items=items)
    rt = [_retest({"a": "fixed", "b": "fixed", "c": "still_present"})]
    st = {"actions": {_uid(c): {"history": [_e("2026-11-02", "applied")]} for c in ("sql_injection", "xss", "csrf")}}
    plan = A.build_plan(CID, doc, vs, st, rt)
    by = {a["weakness_class"]: a for a in plan["actions"]}
    sq, xs, cs = by["sql_injection"], by["xss"], by["csrf"]
    # « a » sits on both fix items: its unit takes both simulations (2 paths), the other units one each
    assert sq["interrupts_attack_paths"] == ["p1", "p2"] and sq["priority"] == 1 and sq["fix_ids"] == ["g1", "g2"]
    assert xs["interrupts_attack_paths"] == ["p1"] and cs["interrupts_attack_paths"] == ["p2"]
    # the impact text counts Evidence-Backed Attack Paths only (legend vocabulary), the rest is said apart (L9)
    assert xs["expected_impact"]["text"] == "Findings covered: 1 · Evidence-Backed Attack Paths interrupted: 1 of 1"
    assert cs["expected_impact"]["text"] == ("Findings covered: 1 · Evidence-Backed Attack Paths interrupted: 0 of 1"
                                             " · other attack paths interrupted (not evidence-backed): 1")
    assert sq["expected_impact"]["evidence_backed_paths_interrupted"] == 1
    assert cs["proven_attack_paths"] == [] and xs["proven_attack_paths"] == ["p1"]
    assert all("Proven" not in a["expected_impact"]["text"] and "proven" not in a["explanation"]
               for a in plan["actions"])
    assert sq["status"] == xs["status"] == "verified_resolved"
    assert xs["status_text"] == "Not reproduced at retest (2026-11-10)"
    assert cs["status"] == "failed_verification"


def test_path_mode_then_open_findings_off_paths():
    vs = [_v("a"), _v("b"), _v("c", sev="low")]
    items = [{"fix_id": "g1", "finding_ids": ["a"], "rank": 1, "of_total": 1, "breaks": 1}]
    doc = _doc([_g("t1", ["a", "b"]), _g("t2", ["c"], rank=2)], source="attack-paths", items=items,
               ranking={"fixes": [{"fix_id": "g1", "interrupts": ["p1"]}]})
    plan = A.build_plan(CID, doc, vs)
    # « a » and « b » are one root cause (same class, same asset): one action, on a path; « c » follows
    vs[2]["category"] = "xss"
    plan = A.build_plan(CID, doc, vs)
    assert [(x["basis"], x["finding_ids"]) for x in plan["actions"]] == [
        ("attack-paths", ["a", "b"]), ("reported-severity-x-proof", ["c"])]


def test_cyclic_paths_are_listed_once():
    vs = [_v("a"), _v("b")]
    cyc = {"id": "pc", "finding_ids": ["a", "b", "a"], "node_ids": ["n1", "n2", "n1"], "hypothesis": True}
    plan = A.build_plan(CID, _doc([_g("f", ["a", "b"])], paths=[cyc, cyc]), vs)
    a = plan["actions"][0]
    assert a["related_attack_paths"] == ["pc"] and a["proven_attack_paths"] == []


def test_empty_plan_when_nothing_is_open():
    plan = A.build_plan(CID, {"fix_first": {"source": "none", "items": []}, "triage": {"groups_all": []}}, [])
    assert plan["actions"] == [] and plan["summary"]["actions"] == 0
    assert plan["label"] == "Prioritized Treatment Plan" and plan["definition"] == A.DEFINITION


# ── status machine and history ──

def _one(entries, retests=(), finding_ids=("a",), today=None):
    vs = [_v(i) for i in finding_ids]
    return A.build_plan(CID, _doc([_g("f", list(finding_ids))]), vs, _state(_uid(), *entries), list(retests),
                        today=today)


def test_applied_is_not_verified():
    p = _one([_e("2026-11-02", "applied", role="ops lead")])
    a = p["actions"][0]
    assert a["status"] == "applied" and a["status_verified"] is False
    assert a["status_text"] == "Declared applied by ops lead, 2026-11-02 — not verified"


def test_verified_only_from_a_completed_retest():
    entries = [_e("2026-11-02T00:00:00Z", "applied")]
    for outcome in ("incomplete", "running", "did_not_finish"):
        assert _one(entries, [_retest({"a": "fixed"}, outcome=outcome)])["actions"][0]["status"] == "applied"
    a = _one(entries, [_retest({"a": "fixed"})])["actions"][0]
    assert a["status"] == "verified_resolved" and a["status_verified"] is True
    assert a["status_label"] == "Not reproduced at retest"
    # a status string « verified_resolved » written by a person is refused and reported
    p = _one([_e("2026-11-02", "verified_resolved")])
    assert p["actions"][0]["status"] == "proposed" and p["issues"]


def test_partial_fix_and_failed_retest():
    ids = ("a", "b", "c")
    a = _one([_e("2026-11-02", "applied")], [_retest({"a": "fixed", "b": "fixed", "c": "still_present"})], ids)
    act = a["actions"][0]
    assert act["status"] == "partially_resolved"
    assert act["status_text"].endswith("2 of 3 findings not reproduced")
    f = _one([_e("2026-11-02", "applied")], [_retest({"a": "still_present", "b": "regressed", "c": "still_present"})], ids)
    assert f["actions"][0]["status"] == "failed_verification"
    # a focused retest that checked only part of the action is partial even if all it checked is not reproduced
    s = _one([_e("2026-11-02", "applied")], [_retest({"a": "fixed"}, scope=["a"])], ids)
    assert s["actions"][0]["status"] == "partially_resolved"
    # a retest whose scope holds none of the action's findings says nothing about it
    n = _one([_e("2026-11-02", "applied")], [_retest({"z": "fixed"}, scope=["z"])], ids)
    assert n["actions"][0]["status"] == "applied" and n["actions"][0]["last_retest"] is None


def test_retest_on_an_action_not_applied_is_an_observation():
    a = _one([], [_retest({"a": "fixed"})])["actions"][0]
    assert a["status"] == "proposed" and a["status_verified"] is False
    assert a["last_retest"]["result"] == "verified_resolved" and a["last_retest"]["label"] == "Not reproduced at retest"
    assert a["history"][0]["observation"] == "verified_resolved" and "to" not in a["history"][0]


def test_failed_verification_then_reapplied_then_verified():
    entries = [_e("2026-11-02T00:00:00Z", "applied"), _e("2026-11-06T00:00:00Z", "in_progress"),
               _e("2026-11-07T00:00:00Z", "applied")]
    rts = [_retest({"a": "still_present"}, at="2026-11-05T00:00:00Z"), _retest({"a": "fixed"}, at="2026-11-08T00:00:00Z")]
    a = _one(entries, rts)["actions"][0]
    assert [h["to"] for h in a["history"]] == ["applied", "failed_verification", "in_progress", "applied",
                                               "verified_resolved"]
    assert [h["source"] for h in a["history"]][1] == "retest"


def test_deferred_and_back_and_risk_accepted():
    a = _one([_e("2026-11-02", "deferred", note="next quarter"), _e("2026-11-03", "proposed")])["actions"][0]
    assert a["status"] == "proposed" and [h["to"] for h in a["history"]] == ["deferred", "proposed"]
    r = _one([_e("2026-11-02", "risk_accepted", by="alice",
                 declared={"risk_accepted_until": "2027-01-31", "risk_owner": "Head of Payments"})])["actions"][0]
    assert r["status_text"] == ("Risk accepted by Head of Payments, recorded by alice on 2026-11-02, "
                                "until 2027-01-31")
    assert r["risk_accepted_until"]["value"] == "2027-01-31" and r["risk_accepted_until"]["provenance"] == "declared"
    assert r["risk_acceptance"] == {"risk_owner": "Head of Payments", "until": "2027-01-31", "recorded_by": "alice",
                                    "recorded_at": "2026-11-02", "expired": False, "complete": True}


def test_history_is_append_only_and_invalid_entries_are_skipped():
    entries = [_e("2026-11-02", "applied"), _e("2026-11-03", "approved"), _e("bad", "approved"),
               _e("2026-11-04", status=None, declared={"owner": "infra", "service_interruption_risk": "low"}),
               _e("2026-11-05", status=None, declared={"owner": None}), {"at": "2026-11-06"}]
    p = _one(entries)
    a = p["actions"][0]
    assert a["status"] == "applied"                       # applied -> approved is not a transition
    assert len(a["history"]) == 3 and len(p["issues"]) == 3
    assert a["owner"]["value"] == "unknown" and a["service_interruption_risk"]["value"] == "low"
    assert all(set(h) >= {"at", "by_role", "source"} for h in a["history"])


def test_declared_fields_are_validated():
    assert A.validate_declared({"owner": "x" * 65})[1]
    assert A.validate_declared({"approval_required": "yes"})[1]
    assert A.validate_declared({"service_interruption_risk": "maybe"})[1]
    assert A.validate_declared({"due_date": "2026-02-30"})[1]
    assert A.validate_declared({"cost": 3})[1]
    assert A.validate_declared({"owner": "web team", "approval_required": False})[1] == []


def test_every_manual_transition_target_is_a_status_and_never_retest_only():
    for k, targets in A.TRANSITIONS.items():
        assert k in A.STATUSES and targets <= set(A.STATUSES) and not (targets & A.RETEST_ONLY)
    assert set(A.TRANSITIONS) == set(A.STATUSES)


# ── retest coverage gate (R1 H-4, R4 S2) ──

def test_hollow_retest_verifies_nothing():
    """R4 probe p2: a retest that pushed nothing and recorded no coverage is « complete » but verifies nothing: the
    action stays « Applied — not verified » and the retest is an observation « Retest without coverage »."""
    base = [{"id": "v1", "title": "SQL injection in login", "severity": "critical", "status": "exploited",
             "category": "sqli", "endpoint": "/login", "target_id": "tg"},
            {"id": "v2", "title": "Stored XSS", "severity": "high", "status": "confirmed", "category": "xss",
             "endpoint": "/comment", "target_id": "tg"}]
    hollow = {"retest_id": "rt1", "retest_campaign_id": "c2", "at": "2026-11-19T12:00:00Z", "outcome": "complete",
              "finding_ids": None, "verdicts": R.compute_verdicts(base, [])}
    v = A.verification(["v1", "v2"], hollow)
    assert v["status"] == "inconclusive" and v["coverage_ok"] is False and "coverage not recorded" in v["coverage_missing"]
    empty_cov = dict(hollow, coverage={**COV, "assets_registered": 0, "commands_executed": 0, "workflows_executed": 0,
                                       "agents_dispatched": [], "specialised_agents": []})
    v = A.verification(["v1", "v2"], empty_cov)
    assert v["status"] == "inconclusive"
    assert set(v["coverage_missing"]) == {"no asset registered", "no toolbox command executed",
                                          "no specialised agent dispatched"}
    doc = _doc([_g("f1", ["v1"]), _g("f2", ["v2"], rank=2)])
    st = {"actions": {_uid("sql_injection"): {"history": [_e("2026-11-02", "applied")]}}}
    plan = A.build_plan(CID, doc, base, st, [empty_cov])
    a = plan["actions"][0]
    assert a["status"] == "applied" and a["status_label"] == "Applied — not verified" and a["status_verified"] is False
    assert a["last_retest"]["result"] == "inconclusive"
    assert a["last_retest"]["label"] == "Retest without coverage — not verified"
    assert a["last_retest"]["coverage_ok"] is False
    assert a["history"][-1]["observation"] == "inconclusive"


def test_retest_must_dispatch_an_agent_of_the_findings():
    vs = [_v("a", discovered_by_agent="sqli-agent")]
    other = {**COV, "agents_dispatched": ["xss-agent"], "specialised_agents": ["xss-agent"]}
    a = A.build_plan(CID, _doc([_g("f", ["a"])]), vs, _state(_uid(), _e("2026-11-02", "applied")),
                     [_retest({"a": "fixed"}, coverage=other)])["actions"][0]
    assert a["status"] == "applied" and "no agent of these findings dispatched (sqli-agent)" in a["last_retest"]["text"]
    same = {**COV, "agents_dispatched": ["sqli-agent"], "specialised_agents": ["sqli-agent"]}
    a = A.build_plan(CID, _doc([_g("f", ["a"])]), vs, _state(_uid(), _e("2026-11-02", "applied")),
                     [_retest({"a": "fixed"}, coverage=same)])["actions"][0]
    assert a["status"] == "verified_resolved"


# ── risk acceptance (R2 H-4) ──

def test_risk_acceptance_needs_a_named_owner_and_an_expiry_within_12_months():
    ok = {"at": "2026-11-20T10:00:00Z", "by_role": "admin", "status": "risk_accepted",
          "declared": {"risk_owner": "Head of Payments", "risk_accepted_until": "2027-05-31"}}
    assert A.validate_new_entry(ok, "2026-11-20")[1] == []
    no_owner = {**ok, "declared": {"risk_accepted_until": "2027-05-31"}}
    assert any("risk_owner" in p for p in A.validate_new_entry(no_owner, "2026-11-20")[1])
    no_until = {**ok, "declared": {"risk_owner": "CISO"}}
    assert any("risk_accepted_until" in p for p in A.validate_new_entry(no_until, "2026-11-20")[1])
    too_far = {**ok, "declared": {"risk_owner": "CISO", "risk_accepted_until": "2027-12-01"}}
    assert any("12 months" in p for p in A.validate_new_entry(too_far, "2026-11-20")[1])
    past = {**ok, "declared": {"risk_owner": "CISO", "risk_accepted_until": "2026-11-01"}}
    assert A.validate_new_entry(past, "2026-11-20")[1]
    # a stored legacy acceptance without owner/expiry is replayed (never dropped) and said incomplete
    p = _one([_e("2026-11-02", "risk_accepted")])
    a = p["actions"][0]
    assert a["status"] == "risk_accepted" and "incomplete" in a["status_text"]
    assert any(i.get("kind") == "risk-acceptance-incomplete" for i in p["issues"])


def test_expired_risk_acceptance():
    entries = [_e("2026-01-02", "risk_accepted", declared={"risk_owner": "CISO", "risk_accepted_until": "2026-06-30"})]
    a = _one(entries, today="2026-11-20")["actions"][0]
    assert a["status"] == "risk_accepted" and a["status_label"] == "Risk acceptance expired"
    assert a["status_text"].startswith("Risk acceptance expired on 2026-06-30")
    assert a["risk_acceptance"]["expired"] is True
    assert _one(entries, today="2026-03-01")["actions"][0]["status_label"] == "Risk accepted"


# ── migration of the exec_core <= 1.4 ids (one action per fix item) ──

def test_legacy_ids_follow_their_findings_and_merge_to_the_least_advanced_status():
    vs = [_v("a"), _v("b", ep="http://h/b"), _v("c", cat="xss")]
    doc = _doc([_g("f1", ["a"]), _g("f2", ["b"], rank=2), _g("f3", ["c"], rank=3)])
    legacy = A.legacy_action_ids(CID, doc)
    assert legacy == {A.action_id(CID, "f1"): ["a"], A.action_id(CID, "f2"): ["b"], A.action_id(CID, "f3"): ["c"]}
    st = {"actions": {
        A.action_id(CID, "f1"): {"finding_ids": ["a"], "history": [_e("2026-11-02T00:00:00Z", "applied")]},
        A.action_id(CID, "f2"): {"finding_ids": ["b"], "history": [_e("2026-11-03T00:00:00Z", "approved")]},
        A.action_id(CID, "f3"): {"finding_ids": ["c"], "history": [_e("2026-11-04T00:00:00Z", "in_progress")]},
        _uid(): {"finding_ids": ["a", "b"], "history": [_e("2026-11-05T00:00:00Z", "scheduled")]},
    }}
    plan = A.build_plan(CID, doc, vs, st)
    sq = next(a for a in plan["actions"] if a["weakness_class"] == "sql_injection")
    xs = next(a for a in plan["actions"] if a["weakness_class"] == "xss")
    # applied + approved -> least advanced « approved », then the action's own entry (approved -> scheduled)
    assert sq["status"] == "scheduled"
    merged = [h for h in sq["history"] if h.get("merged")]
    assert len(merged) == 1 and merged[0]["to"] == "approved"
    assert {m["status"] for m in merged[0]["merged_from"]} == {"applied", "approved"}
    assert sum(1 for h in sq["history"] if h.get("carried_from")) == 2      # no former entry dropped
    assert sq["state_carried_from"] == sorted([A.action_id(CID, "f1"), A.action_id(CID, "f2")])
    assert xs["status"] == "in_progress" and xs["state_carried_from"] == [A.action_id(CID, "f3")]
    assert plan["orphaned_states"] == []


def test_same_status_former_states_are_replayed_together():
    vs = [_v("a"), _v("b", ep="http://h/b")]
    doc = _doc([_g("f1", ["a"]), _g("f2", ["b"], rank=2)])
    st = {"actions": {A.action_id(CID, "f1"): {"finding_ids": ["a"], "history": [_e("2026-11-02", "approved")]},
                      A.action_id(CID, "f2"): {"finding_ids": ["b"], "history": [_e("2026-11-03", "approved")]}}}
    a = A.build_plan(CID, doc, vs, st)["actions"][0]
    assert a["status"] == "approved" and not any(h.get("merged") for h in a["history"])


# ── old campaigns, reattachment, historical truth ──

def test_old_campaign_without_treatment_file():
    p = A.build_plan(CID, _doc([_g("f", ["a"])]), [_v("a")], None, None)
    assert p["actions"][0]["status"] == "proposed" and p["actions"][0]["history"] == [] and p["issues"] == []
    assert p["schema_version"] == "darkmoon-treatment-plan/2"


def test_state_follows_its_findings_when_the_fix_list_changes():
    old_id = A.action_id(CID, "old_fix")
    st = _state(old_id, _e("2026-11-02", "approved"), finding_ids=["a", "b"])
    p = A.build_plan(CID, _doc([_g("new_fix", ["a", "b"]), _g("other", ["c"], rank=2)]), [_v(x) for x in "abc"], st)
    assert p["actions"][0]["status"] == "approved" and p["actions"][0]["state_carried_from"] == [old_id]
    lost = A.build_plan(CID, _doc([_g("other", ["c"])]), [_v("c")], st)
    assert lost["orphaned_states"] == [old_id]


def test_plan_never_touches_findings_stats_or_score():
    vs = [_v("a", sev="critical", st="exploited", evidence={"request": "r"}), _v("b", sev="low")]
    before = copy.deepcopy(vs)
    inp = {"campaign": {"id": CID, "status": "completed"}, "findings": vs}
    s0 = score.cyber_score(copy.deepcopy(inp))
    A.build_plan(CID, _doc([_g("f", ["a", "b"])]), vs, _state(_uid(), _e("2026-11-02", "applied")),
                 [_retest({"a": "fixed", "b": "fixed"})])
    assert vs == before and stats.compute_stats(vs) == stats.compute_stats(before)
    assert score.cyber_score(copy.deepcopy(inp)) == s0


# ── retest identity ──

def test_retest_matching_with_the_exec_core_identity():
    base = [_v("b1", cat="sql_injection", ep="http://h/search?q=1", title="SQLi in search"),
            _v("b2", cat="xss_stored", ep="http://h/c", title="Stored XSS"),
            _v("b3", cat="csrf", ep="http://h/pw", title="CSRF on password", status="remediated"),
            _v("b4", cat="ssrf", ep="http://h/fetch", title="SSRF")]
    new = [_v("n1", cat="blind_sql_injection", ep="http://other/search?q=9", title="Time-based SQLi"),  # class+path
           _v("n2", cat="xss_stored", ep="http://h/c", title="Persistent XSS"),                    # fingerprint
           _v("n3", cat="csrf", ep="http://h/pw", title="CSRF on password"),
           _v("n4", cat="ssrf", ep="http://h/fetch", st="false_positive"),                         # FP reproduces nothing
           _v("n5", cat="idor", ep="http://h/u/1", title="IDOR")]
    out = {(r["finding_id"], r["new_finding_id"]): r for r in R.compute_verdicts(base, new)}
    assert out[("b1", "n1")]["verdict"] == "still_present" and out[("b1", "n1")]["match_basis"] == "class_endpoint"
    assert out[("b2", "n2")]["match_basis"] == "fingerprint"
    assert out[("b3", "n3")]["verdict"] == "regressed"
    assert out[("b4", None)]["verdict"] == "fixed" and out[("b4", None)]["label"] == "Not reproduced at retest"
    assert out[(None, "n5")]["verdict"] == "new"
    assert len(out) == 5
    only = R.compute_verdicts(base, new, ["b4"])
    assert [r["finding_id"] for r in only if r["finding_id"]] == ["b4"]


def test_retest_legacy_key_still_matches():
    b = [{"id": "x", "title": "Weird", "endpoint": "", "category": ""}]
    n = [{"id": "y", "title": "weird ", "endpoint": "", "category": ""}]
    assert R.compute_verdicts(b, n)[0]["verdict"] == "still_present"


# ── parity fixture (same expected output in Community and Pro) ──

def _parity_plan():
    fx = json.loads((FIX / "plan_parity.json").read_text(encoding="utf-8"))
    c, vs = fx["campaign"], fx["findings"]
    doc = attack_paths.build_paths(c, [], [], copy.deepcopy(vs), include_steps=False, retest_verdicts=None,
                                   now="2026-11-01T00:00:00Z")
    bare = A.build_plan(c["id"], doc, vs)
    by_head = {a["head_finding_id"]: a for a in bare["actions"]}
    state = {"actions": {}}
    for e in fx["state_entries"]:
        a = by_head[e["select"]["head_finding_id"]]
        rec = state["actions"].setdefault(a["action_id"], {"finding_ids": a["finding_ids"], "history": []})
        rec["history"].append({k: v for k, v in e.items() if k != "select"})
    rt = dict(fx["retest"], verdicts=R.compute_verdicts(vs, fx["retest_findings"], fx["retest"]["finding_ids"]))
    return A.build_plan(c["id"], doc, vs, state, [rt])


def test_parity_fixture_gives_the_expected_plan():
    got = json.loads(json.dumps(_parity_plan(), sort_keys=True))
    want = json.loads((FIX / "expected_plan.json").read_text(encoding="utf-8"))
    assert got == want


def test_parity_fixture_decisions():
    p = _parity_plan()
    st = {a["head_finding_id"]: a["status"] for a in p["actions"]}
    assert st["vuln_xs1"] == "verified_resolved"          # applied, then not reproduced by a completed retest
    assert st["vuln_sq1"] == "failed_verification"        # applied, but the retest reproduced the SQL injection
    assert st["vuln_hdr"] == "risk_accepted"              # a person cannot write verified_resolved
    hdr = next(a for a in p["actions"] if a["head_finding_id"] == "vuln_hdr")
    assert hdr["last_retest"]["result"] == "verified_resolved"   # observed, not a verification of a declared fix
    cmp_ = next(a for a in p["actions"] if a["head_finding_id"] == "vuln_cmp")
    assert cmp_["status"] == "proposed" and cmp_["last_retest"]["result"] == "failed_verification"
    assert "vuln_fp" not in {i for a in p["actions"] for i in a["finding_ids"]}
    assert "vuln_inf" not in {i for a in p["actions"] for i in a["finding_ids"]}
    assert len(p["issues"]) == 1


if __name__ == "__main__":   # regenerate the expected plan after a deliberate change
    (FIX / "expected_plan.json").write_text(json.dumps(_parity_plan(), indent=1, sort_keys=True, ensure_ascii=False)
                                            + "\n", encoding="utf-8")
    print("expected_plan.json written")
