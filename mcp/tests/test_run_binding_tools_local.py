"""R4 S3 (Community): the dashboard_* write tools go through the same run binding as Pro (api/run_binding.py).

Community hands no run key today (one local operator; the TUI runs several sessions in one opencode process, so a
per-process key would merge them into one campaign): campaigns are unbound and the TUI flow is unchanged. When a key
is present (X-Darkmoon-Campaign-Frag header or DARKMOON_CAMPAIGN_FRAG env), the rule is the Pro one: it names the
campaign, binds it, and another key / no key cannot write into it.
"""
from unittest import mock

import pytest

from api import coverage_signals as cs
from api import json_storage as js
from api import live_push as lp
from api import run_binding as RB
from tests.exec_store import isolate

A, B = "aaaa1111", "bbbb2222"
REPORT = "# Report\n\n" + "Finding details. " * 200  # a full report: the tool does not look for one on disk


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.delenv(cs.KIND_ENV, raising=False)
    monkeypatch.delenv(RB.RUN_KEY_ENV, raising=False)
    isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(lp, "_today_compact", lambda: "20261120")
    return tmp_path


@pytest.fixture
def srv(monkeypatch):
    pytest.importorskip("fastmcp")
    import docker
    monkeypatch.setattr(docker, "from_env", lambda *a, **k: mock.MagicMock())
    from src import server
    return server


@pytest.fixture
def as_run(monkeypatch):
    import fastmcp.server.dependencies as deps

    def _set(key):
        headers = {RB.RUN_KEY_HEADER: key} if key else {}
        monkeypatch.setattr(deps, "get_http_headers", lambda include_all=False: dict(headers))
    return _set


def _init(srv, session="mcpsess1"):
    return srv.dashboard_init_campaign(session_id=session, target_host="victim.example", target_ip="10.0.0.5")


def _finding(srv, cid, title="SQLi"):
    return srv.dashboard_push_finding(campaign_id=cid, title=title, severity="high", cvss_score=8.0,
                                      category="sql_injection", status="confirmed", description="d",
                                      endpoint="/login", discovered_by_agent="php")


def _node(srv, cid, label="api"):
    return srv.dashboard_push_infra_node(campaign_id=cid, node_type="service", label=label, host="victim.example",
                                         technology="nginx", port=443)


def _refused(res):
    return isinstance(res, dict) and res.get("error") == RB.REFUSAL


def test_tui_flow_without_a_run_key_is_unchanged(store, srv, as_run):
    as_run(None)
    cid = _init(srv)["campaign_id"]
    assert RB.BOUND_FIELD not in js.load_campaign(cid)
    assert not _refused(_finding(srv, cid)) and len(js.load_vulnerabilities(cid)) == 1
    assert not _refused(_node(srv, cid))
    _init(srv)  # a sub-agent's (or a retried) init in the same TUI session
    assert not _refused(_finding(srv, cid, "from a sub-agent")) and len(js.load_vulnerabilities(cid)) == 2
    res = srv.dashboard_finalize_campaign(campaign_id=cid, duration_seconds=60, executive_summary="done",
                                          report_markdown=REPORT)
    assert not _refused(res) and js.load_campaign(cid)["status"] == "completed"


def test_with_a_run_key_same_run_and_sub_agents_write(store, srv, as_run):
    as_run(A)
    cid = _init(srv)["campaign_id"]
    assert cid == f"camp_20261120_{A}" and js.load_campaign(cid)[RB.BOUND_FIELD] is True
    assert not _refused(_finding(srv, cid))
    assert _init(srv, session="childses")["campaign_id"] == cid
    assert not _refused(_finding(srv, cid, "sub-agent")) and len(js.load_vulnerabilities(cid)) == 2


def test_with_a_run_key_another_run_is_refused(store, srv, as_run):
    as_run(A)
    cid_a = _init(srv)["campaign_id"]
    _finding(srv, cid_a)
    before = (js.load_vulnerabilities(cid_a), js.load_infrastructure(cid_a), js.load_campaign(cid_a))
    as_run(B)
    assert _refused(_finding(srv, cid_a, "injected"))
    assert _refused(_node(srv, cid_a, "injected"))
    assert _refused(srv.dashboard_finalize_campaign(campaign_id=cid_a, executive_summary="forged"))
    assert _refused(_finding(srv, "camp_20261120_cccc3333"))  # unknown: same answer
    assert (js.load_vulnerabilities(cid_a), js.load_infrastructure(cid_a), js.load_campaign(cid_a)) == before


def test_keyless_caller_cannot_touch_a_bound_campaign(store, srv, as_run, monkeypatch):
    monkeypatch.setenv(RB.RUN_KEY_ENV, A)
    as_run(None)
    cid_a = _init(srv)["campaign_id"]
    monkeypatch.delenv(RB.RUN_KEY_ENV)
    assert _refused(_finding(srv, cid_a))
    assert _refused(srv.dashboard_finalize_campaign(campaign_id=cid_a, executive_summary="x"))
    projects = js.load_projects()
    assert _refused(_init(srv, session=A))  # keyless re-init colliding with the bound key: nothing written
    assert js.load_projects() == projects and js.load_campaign(cid_a)["status"] == "running"


def test_the_opencode_db_guess_never_merges_into_a_bound_campaign(store, srv, as_run, monkeypatch):
    as_run(B)
    cid_b = _init(srv)["campaign_id"]
    nodes_b = len(js.load_infrastructure(cid_b))
    monkeypatch.setattr(lp, "_is_subagent_session", lambda sid: True)
    monkeypatch.setattr(lp, "_find_parent_campaign_id", lambda sid: cid_b)
    as_run(A)
    res = _init(srv, session="childses")
    assert res["campaign_id"] == f"camp_20261120_{A}" and len(js.load_infrastructure(cid_b)) == nodes_b
