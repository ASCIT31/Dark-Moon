"""Framework assessment and application profile read from the local store (Community).

The assessment is exactly exec_core's on the stored campaign (same function, same inputs as Pro's route); the
profile comes only from the owner's file ``profiles/<project_id>.json`` validated on read; no MCP tool writes it;
the detected stack is shown as detected; old projects without a file read « unknown ».
"""
import json

from api import framework_local as FL
from api import profile_local as PL
from api.exec_core import actions as A
from api.exec_core import frameworks_assess as FA
from api.exec_core import profile as P
from tests.exec_store import isolate

SIG = {"schema": "darkmoon-coverage-signals/1", "campaign_kind": "full", "started_at": "2026-11-01T09:00:00Z",
       "finalized_at": "2026-11-01T10:00:00Z", "measured_duration_seconds": 3600,
       "agents_dispatched": [{"agent": "php"}, {"agent": "headless-browser"}], "agents_source": "opencode_sessions",
       "assets_registered": 2, "commands_executed": 40, "workflows_executed": 0}


def _store(data):
    (data / "projects.json").write_text(json.dumps([{"id": "p1", "name": "Lab", "target_id": "t1"}]))
    (data / "targets.json").write_text(json.dumps([{"id": "t1", "project_id": "p1", "host": "10.0.0.5",
                                                     "technologies": [{"name": "PHP", "version": "8.2",
                                                                       "category": "language"}]}]))
    camp = {"id": "c1", "project_id": "p1", "target_id": "t1", "status": "completed", "date": "2026-11-01T09:00:00Z",
            "coverage_signals": SIG}
    (data / "campaigns" / "c1.json").write_text(json.dumps(camp))
    vulns = [{"id": "v1", "campaign_id": "c1", "target_id": "t1", "title": "SQLi", "category": "sql_injection",
              "severity": "critical", "status": "exploited", "endpoint": "/a"},
             {"id": "v2", "campaign_id": "c1", "target_id": "t1", "title": "TLS", "category": "weak_tls",
              "severity": "medium", "status": "confirmed", "endpoint": "/"}]
    (data / "vulnerabilities" / "c1.json").write_text(json.dumps(vulns))
    (data / "infrastructure" / "c1.json").write_text(json.dumps([{"id": "n1", "type": "app", "label": "app",
                                                                  "technology": "nginx", "version": "1.25"}]))
    return camp, vulns


def test_old_project_without_profile_file(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    _store(data)
    doc = PL.profile_doc("p1")
    assert doc["declarations"]["status"] == "absent" and doc["can_edit"] is False
    f = doc["profile"]["fields"]
    assert f["business_purpose"]["provenance"] == "unknown" and f["personal_data"]["value"] is None
    assert f["languages"] == {**f["languages"], "value": ["PHP 8.2"], "provenance": "detected"}
    assert doc["profile"]["detected"]["confirmed"] is False
    assert PL.profile_doc("nope") is None and PL.profile_doc("../x") is None
    assert not (data / "profiles").exists()


def test_profile_file_is_validated_on_read(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    _store(data)
    (data / "profiles").mkdir()
    (data / "profiles" / "p1.json").write_text(json.dumps({
        "schema_version": P.FILE_VERSION, "project_id": "p1",
        "fields": {"personal_data": {"value": "yes", "at": "2026-11-20", "by_role": "DPO"},
                   "nis2_entity_type": {"value": "essential", "provenance": "inferred"},
                   "languages": ["PHP", "JavaScript"], "rto": "eventually"}}))
    doc = PL.profile_doc("p1")
    f = doc["profile"]["fields"]
    assert f["personal_data"]["provenance"] == "declared_by_customer" and f["personal_data"]["by_role"] == "DPO"
    assert f["nis2_entity_type"]["provenance"] == "unknown"
    assert f["languages"]["value"] == ["PHP", "JavaScript"] and f["languages"]["provenance"] == "declared_by_customer"
    assert sorted(i["field"] for i in doc["issues"]) == ["nis2_entity_type", "rto"]
    (data / "profiles" / "p1.json").write_text("x" * (PL.MAX_FILE + 1))
    assert PL.profile_doc("p1")["declarations"]["status"] == "unreadable"


def test_assessment_is_exec_core_on_the_stored_campaign(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    camp, vulns = _store(data)
    (data / "profiles").mkdir()
    (data / "profiles" / "p1.json").write_text(json.dumps({"project_id": "p1", "fields": {"personal_data": "yes"}}))
    doc = FL.assessment_doc("c1")
    assert doc["schema_version"] == FA.ASSESSMENT_VERSION
    st = {f["framework"]: f["applicability"]["status"] for f in doc["frameworks"]}
    assert st == {"iso27001": "to_confirm", "gdpr": "declared_by_customer", "nis2": "to_confirm",
                  "ai_act": "to_confirm"}
    gdpr = {c["control_id"]: c["state"] for c in next(f for f in doc["frameworks"] if f["framework"] == "gdpr")["controls"]}
    assert gdpr["Art.32(1)(a)"] == "weakness_observed" and gdpr["Art.32(1)(b)-ci"] == "weakness_observed"
    # same function, same inputs: equal to a direct exec_core call
    from api.attack_paths_local import attack_paths_doc
    from api.infrastructure_graph import build_infrastructure
    infra = build_infrastructure("c1", camp)
    acts = A.build_actions("c1", attack_paths_doc("c1", "all", False), infra["vulnerabilities"])
    direct = FA.assess({"campaign": camp, "findings": infra["vulnerabilities"], "nodes": infra["nodes"],
                        "profile": PL.profile_view("p1")[0],
                        "actions": [{"action_id": a["action_id"], "finding_ids": a["finding_ids"],
                                     "related_attack_paths": a["related_attack_paths"]} for a in acts]})
    got = {k: v for k, v in doc.items() if k not in ("summary_line", "profile_file")}
    assert got == direct
    assert set(doc["navigation"]["actions"]) == {a["action_id"] for a in acts}
    assert FL.assessment_doc("nope") is None and FL.assessment_doc("../c1") is None


def test_no_mcp_tool_writes_a_profile():
    """H5: declarations come from the owner's file only; nothing the model can call writes it."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src" / "server.py").read_text(encoding="utf-8")
    assert "profile_local" not in src and "profiles/" not in src
    assert "framework_local" not in src
