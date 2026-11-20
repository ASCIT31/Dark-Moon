"""exec_score: the storage adapter of exec_core (Community: isolated temporary store)."""
import pytest

from api import exec_score
from api import json_storage as js

SIG = {"schema": "darkmoon-coverage-signals/1", "campaign_kind": "full", "campaign_kind_source": "default",
       "started_at": "x", "finalized_at": "y", "measured_duration_seconds": 3600,
       "agents_dispatched": [{"agent": "a"}, {"agent": "b"}], "agents_source": "opencode_sessions",
       "assets_registered": 3, "commands_executed": 50, "workflows_executed": 0}


@pytest.fixture
def store(monkeypatch, tmp_path):
    from tests.exec_store import isolate
    isolate(monkeypatch, tmp_path)   # never the user's real ~/.local/share/opencode
    js.save_project({"id": "proj_a", "name": "A", "target_id": "tgt_a"})


def _camp(cid, date, status="completed", sig=SIG, findings=()):
    c = {"id": cid, "project_id": "proj_a", "target_id": "tgt_a", "date": date, "status": status,
         "is_subagent": False}
    if sig is not None:
        c["coverage_signals"] = dict(sig)
    js.save_campaign(c)
    js.save_vulnerabilities(cid, [dict(f, campaign_id=cid, target_id="tgt_a") for f in findings])


def test_campaign_score_with_trend_against_previous_rated_full(store):
    _camp("camp_1", "2026-10-01T00:00:00Z", findings=[{"id": "v1", "severity": "critical", "status": "exploited",
                                                       "category": "rce"}])
    _camp("camp_2", "2026-10-15T00:00:00Z", sig=None)          # legacy: never the trend baseline
    _camp("camp_3", "2026-11-01T00:00:00Z", findings=[{"id": "v2", "severity": "low", "status": "confirmed",
                                                       "category": "insecure_cookie"}])
    d = exec_score.campaign_score("camp_3")
    assert d["score_status"] == "rated" and d["trend"]["previous_campaign_id"] == "camp_1"
    assert d["trend"]["direction"] == "improved"
    assert exec_score.campaign_score("camp_2")["score_status"] == "not_rated"
    assert exec_score.campaign_score("camp_missing") is None


def test_project_score_is_the_reference_campaign(store):
    _camp("camp_1", "2026-10-01T00:00:00Z")
    _camp("camp_2", "2026-11-01T00:00:00Z", status="aborted")
    p = exec_score.project_score("proj_a")
    assert p["project_id"] == "proj_a" and p["reference"]["campaign_id"] == "camp_1" and p["score"] == 100
    assert exec_score.project_score("proj_none") is None
    assert exec_score.legend()["version"].startswith("darkmoon-legend/")
