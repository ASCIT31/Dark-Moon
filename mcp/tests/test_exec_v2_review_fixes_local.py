"""Regression tests of the cross-review fixes (executive V2, pass A), Community side.

R4 probe p1 (re-finalize flips an aborted campaign to completed), the status whitelist, the digest of the coverage
signals taken at finalisation (Community: the local agent has shell access, the digest detects naive edits only), the
Community limitations of the report, the legacy action ids of a local declarations file (migration), and the
methodology label of the legacy report header.
"""
import json

import pytest

from api import coverage_signals as cs
from api import json_storage as js
from api import live_push as lp
from api.exec_core import report_model as RM
from api.exec_core import score
from tests.exec_store import isolate

FRAG = "bbbbbbbb"


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.delenv(cs.KIND_ENV, raising=False)
    isolate(monkeypatch, tmp_path)
    return tmp_path


def _init():
    return lp.init_live_campaign(FRAG, "victim.example", "10.0.0.5", project_name="P")["campaign_id"]


def test_probe_p1_refinalize_cannot_flip_an_aborted_campaign(store):
    cid = _init()
    lp.abort_campaign(cid)
    c = js.load_campaign(cid)
    measured = c["coverage_signals"]["measured_duration_seconds"]
    c["coverage_signals"]["started_at"] = "2026-11-19T23:00:00Z"
    js.save_campaign(c)
    res = lp.finalize_campaign(campaign_id=cid, final_status="completed")
    c = js.load_campaign(cid)
    assert res["status"] == c["status"] == "aborted"
    assert c["coverage_signals"]["measured_duration_seconds"] == measured


def test_arbitrary_final_status_is_refused(store):
    cid = _init()
    assert "error" in lp.finalize_campaign(campaign_id=cid, final_status="whatever-i-want")
    assert js.load_campaign(cid)["status"] == "running"


def test_signals_edited_after_finalize_are_flagged(store):
    cid = _init()
    lp.finalize_campaign(campaign_id=cid)
    c = js.load_campaign(cid)
    assert score.coverage_of(c)["signals_intact"] is True
    c["coverage_signals"]["agents_source"] = "opencode_sessions"
    c["coverage_signals"]["commands_executed"] = 999
    js.save_campaign(c)
    gate = score.gate(js.load_campaign(cid))
    assert gate["score_status"] == "not_rated"
    assert any(r["code"] == "signals_modified" for r in gate["not_rated_reasons"])


def test_community_report_states_that_local_files_are_not_tamper_evident():
    m = RM.build({"edition": "community", "campaign": {"id": "c", "status": "completed"}, "findings": []})
    lim = next(s for s in m["sections"] if s["id"] == "limitations")["blocks"][0]["items"]
    assert RM.COMMUNITY_LIMITS[0] in lim
    pro = RM.build({"edition": "pro", "campaign": {"id": "c", "status": "completed"}, "findings": []})
    assert RM.COMMUNITY_LIMITS[0] not in next(s for s in pro["sections"] if s["id"] == "limitations")["blocks"][0]["items"]


def test_legacy_report_header_never_names_iso_27001(store):
    cid = _init()
    md = lp._generate_report_from_db(cid, lp.load_campaign(cid))
    head = md.split("## MANAGEMENT SUMMARY")[0]
    assert "ISO 27001" not in head and "Test references: NIST SP 800-115" in head


def test_legacy_action_ids_in_the_declarations_file_still_apply(store, monkeypatch):
    from api import treatment_local as TL
    from api.exec_core import actions as A
    cid = _init()
    lp.push_finding(cid, {"title": "SQLi search", "severity": "high", "status": "confirmed",
                          "category": "sql_injection", "endpoint": "http://victim.example/s"})
    lp.push_finding(cid, {"title": "SQLi login", "severity": "high", "status": "confirmed",
                          "category": "sql_injection", "endpoint": "http://victim.example/l"})
    lp.finalize_campaign(campaign_id=cid)
    from api.attack_paths_local import attack_paths_doc
    doc = attack_paths_doc(cid, "all", False)
    legacy = A.legacy_action_ids(cid, doc)
    old = sorted(legacy)[0]
    p = TL.declarations_path(cid)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"schema_version": TL.DECLARATIONS_VERSION, "campaign_id": cid, "declarations": [
        {"action_id": old, "at": "2026-11-20", "by_role": "web lead", "status": "approved"}]}))
    plan = TL.plan_doc(cid)
    assert len(plan["actions"]) == 1                                    # one SQL injection root cause
    a = plan["actions"][0]
    assert a["status"] == "approved" and a["state_carried_from"] == [old]
    assert not [i for i in plan["issues"] if i.get("kind") == "declaration-invalid"]
