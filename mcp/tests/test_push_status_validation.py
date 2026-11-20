"""dashboard_push_finding (live_push.push_finding): an agent pushes only exploited / confirmed / unconfirmed.

False positive, quarantine and closure are operator decisions: any other status pushed by an agent is stored as
``unconfirmed`` (the finding stays visible and counted), the agent's word is kept in ``status_reported`` and the reply
carries a ``status_warning``. Same file in Community and Pro."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from api import json_storage, live_push  # noqa: E402
from api.exec_core import identity, stats  # noqa: E402

CID = "camp_test_push_status"


@pytest.fixture
def store(tmp_path, monkeypatch):
    data = tmp_path / "data"
    dirs = {"DATA_DIR": data, "CAMPAIGNS_DIR": data / "campaigns", "INFRASTRUCTURE_DIR": data / "infrastructure",
            "VULNERABILITIES_DIR": data / "vulnerabilities", "REPORTS_DIR": data / "reports"}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    for name, d in dirs.items():
        for mod in (json_storage, live_push):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, d, raising=False)
    monkeypatch.setattr(json_storage, "PROJECTS_FILE", data / "projects.json", raising=False)
    monkeypatch.setattr(json_storage, "TARGETS_FILE", data / "targets.json", raising=False)
    json_storage.save_target({"id": "tgt_1", "host": "app.example.test"})
    json_storage.save_campaign({"id": CID, "project_id": "p", "target_id": "tgt_1", "status": "running", "stats": {}})
    return CID


def _push(status, title="Weakness"):
    return live_push.push_finding(CID, {"title": title, "severity": "critical", "status": status,
                                        "category": "sql_injection", "endpoint": f"/{title.lower()}"})


@pytest.mark.parametrize("status,stored", [("exploited", "exploited"), ("Confirmed", "confirmed"),
                                           (" unconfirmed ", "unconfirmed"), ("", "unconfirmed")])
def test_agent_statuses_are_kept(store, status, stored):
    r = _push(status)
    assert "status_warning" not in r
    v = json_storage.load_vulnerabilities(CID)[-1]
    assert v["status"] == stored and "status_reported" not in v


@pytest.mark.parametrize("status", ["false_positive", "False Positive", "false-positive", "quarantined", "remediated",
                                    "fixed", "closed", "resolved", "verified_resolved", "risk_accepted", "P1"])
def test_operator_statuses_are_refused_and_the_finding_stays_counted(store, status):
    r = _push(status)
    assert r["status"] == "finding_pushed" and "operator decisions" in r["status_warning"]
    v = json_storage.load_vulnerabilities(CID)[-1]
    assert v["status"] == "unconfirmed" and v["status_reported"] == status.strip()
    assert identity.exclusion_reason(v) is None and identity.is_open(v)
    s = stats.compute_stats(json_storage.load_vulnerabilities(CID))
    assert s["total_findings"] == 1 and s["excluded"] == {"quarantined": 0, "false_positive": 0}
    assert json_storage.load_campaign(CID)["stats"]["total_findings"] == 1


def test_agent_push_status_function():
    assert identity.agent_push_status("EXPLOITED") == ("exploited", None)
    st, w = identity.agent_push_status("x" * 200)
    assert st == "unconfirmed" and len(w) < 300
