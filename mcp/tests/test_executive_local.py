"""Executive block read from the local store (Community): the same exec_core block as Pro's /executive routes, built
from the local plan, assessment, attack paths and Cyber Score; nothing written; unknown ids give None."""
import json

from api import exec_score
from api import executive_local as XL
from api.exec_core import executive as X
from api.exec_core import legend as L
from tests.exec_store import isolate
from tests.test_framework_profile_local import _store


def test_campaign_block_from_the_local_documents(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    _store(data)
    doc = XL.campaign_doc("c1")
    assert doc["schema_version"] == X.EXECUTIVE_VERSION and doc["campaign_id"] == "c1"
    sc = exec_score.campaign_score("c1")
    assert (doc["score"]["score"], doc["score"]["grade"], doc["score"]["score_status"]) == (sc["score"], sc["grade"], sc["score_status"])
    assert doc["treatment_plan"]["actions_total"] == 2
    assert [a["priority"] for a in doc["treatment_plan"]["top_actions"]] == [1, 2]
    assert doc["frameworks"]["summary_line"].startswith("Technical findings relevant to")
    assert doc["attack_paths"]["evidence_backed"] == 0
    assert doc["legend"] == L.legend()
    assert doc["links"]["treatment_plan"] == "plan c1"
    assert "compliant" not in json.dumps(doc).lower()
    assert not (data / "treatments").exists() and not (data / "profiles").exists()


def test_running_campaign_has_no_analysis_and_unknown_ids(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    camp, _ = _store(data)
    (data / "campaigns" / "c1.json").write_text(json.dumps({**camp, "status": "running"}))
    doc = XL.campaign_doc("c1")
    assert doc["treatment_plan"] is doc["frameworks"] is doc["attack_paths"] is None
    assert doc["score"]["score"] is None and doc["score"]["status_label"] == "Not rated"
    assert XL.campaign_doc("nope") is None and XL.campaign_doc("../x") is None
    assert XL.project_doc("nope") is None and XL.project_doc("../x") is None


def test_project_block_uses_the_reference_campaign(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    _store(data)
    doc = XL.project_doc("p1")
    ref = exec_score.project_score("p1")
    assert doc["schema_version"] == X.PROJECT_EXECUTIVE_VERSION
    assert doc["score"]["score_status"] == ref["score_status"]
    assert doc["reference_campaign_id"] == (ref.get("reference") or {}).get("campaign_id")
    assert doc["latest_campaign"]["campaign_id"] == "c1"
    assert doc["plan_campaign_id"] == "c1" and doc["treatment_plan"]["actions_total"] == 2
