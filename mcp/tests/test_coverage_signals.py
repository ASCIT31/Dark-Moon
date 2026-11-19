"""Coverage signals recorded server-side for every campaign (executive V2, L1): kind, measured duration, dispatched
agents, registered assets, toolbox command count. Read by exec_core.score's status gate. Isolated store."""
import sqlite3
import time

import pytest

from api import coverage_signals as cs
from api import json_storage as js
from api import live_push as lp
from api.exec_core import score
from tests.exec_store import isolate

FRAG = "aaaaaaaa"


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.delenv(cs.KIND_ENV, raising=False)
    isolate(monkeypatch, tmp_path)
    return tmp_path


def _init(**kw):
    return lp.init_live_campaign(FRAG, "dvga.example.test", "192.0.2.10", project_name="P", **kw)


def _sig(cid):
    return js.load_campaign(cid)["coverage_signals"]


def _db(tmp_path, root_id="ses_" + FRAG + "rootXYZ", children=(("graphql", ""), ("python-flask", ""),
                                                                 ("", "Web pentest (@php subagent)"))):
    p = tmp_path / "opencode-dev.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE session (id TEXT, parent_id TEXT, title TEXT, agent TEXT, time_created INT, "
              "time_updated INT)")
    now = int(time.time() * 1000)
    c.execute("INSERT INTO session VALUES (?,?,?,?,?,?)", (root_id, None, "root", "pentest", now, now))
    for i, (agent, title) in enumerate(children):
        c.execute("INSERT INTO session VALUES (?,?,?,?,?,?)",
                  (f"ses_child{i}", root_id, title or f"{agent} work", agent or None, now, now + 60_000))
    c.commit()
    c.close()
    return p


def test_init_records_a_server_signal_block(store):
    r = _init()
    s = _sig(r["campaign_id"])
    assert s["schema"] == cs.SCHEMA
    assert (s["campaign_kind"], s["campaign_kind_source"]) == ("full", "default")
    assert s["started_at"] == js.load_campaign(r["campaign_id"])["date"]


def test_declared_kind_and_a_repeated_init_keeps_the_start(store):
    r = _init(campaign_kind="short")
    c = js.load_campaign(r["campaign_id"])
    c["coverage_signals"]["started_at"] = c["date"] = "2026-01-01T00:00:00Z"
    js.save_campaign(c)
    _init()
    s = _sig(r["campaign_id"])
    assert (s["campaign_kind"], s["campaign_kind_source"]) == ("short", "declared_at_init")
    assert s["started_at"] == "2026-01-01T00:00:00Z"


def test_launcher_env_beats_the_agent_declaration(store, monkeypatch):
    monkeypatch.setenv(cs.KIND_ENV, "retest")
    r = _init(campaign_kind="full")
    assert _sig(r["campaign_id"])["campaign_kind_source"] == "launcher"


def test_commands_counted_and_merged_at_finalize_with_measured_duration(store):
    cs.count_call(FRAG, "command")
    r = _init()
    c = js.load_campaign(r["campaign_id"])
    c["coverage_signals"]["started_at"] = c["date"] = "2020-01-01T00:00:00Z"
    js.save_campaign(c)
    cs.count_call(FRAG, "command")
    cs.count_call(FRAG, "workflow")
    cs.count_call("../x", "command")
    lp.push_finding(r["campaign_id"], {"title": "x", "severity": "high", "status": "confirmed", "category": "xss",
                                       "endpoint": "/a", "discovered_by_agent": "php"})
    lp.finalize_campaign(campaign_id=r["campaign_id"], duration_seconds=900)
    camp = js.load_campaign(r["campaign_id"])
    s = camp["coverage_signals"]
    assert (s["commands_executed"], s["workflows_executed"]) == (2, 1)
    assert s["measured_duration_seconds"] > 3600
    assert camp["duration_seconds"] > 3600, "the server clock, not the agent's declared 900 s"
    assert s["assets_registered"] == len(js.load_infrastructure(r["campaign_id"])) > 0
    assert s["agents_source"] == "tool_calls_only" and [a["agent"] for a in s["agents_dispatched"]] == ["php"]


def test_dispatched_agents_come_from_the_session_store(store, monkeypatch, tmp_path):
    monkeypatch.setattr(lp, "_OPENCODE_DB", _db(tmp_path))
    r = _init()
    assert r["campaign_id"].endswith(FRAG)
    lp.finalize_campaign(campaign_id=r["campaign_id"])
    s = _sig(r["campaign_id"])
    assert s["agents_source"] == "opencode_sessions"
    assert [a["agent"] for a in s["agents_dispatched"]] == ["graphql", "php", "python-flask"]


def test_legacy_campaign_never_gets_invented_signals(store):
    r = _init()
    c = js.load_campaign(r["campaign_id"])
    c.pop("coverage_signals")
    js.save_campaign(c)
    lp.finalize_campaign(campaign_id=r["campaign_id"])
    assert "coverage_signals" not in js.load_campaign(r["campaign_id"])


def test_aborted_campaign_is_not_rated(store):
    r = _init()
    lp.abort_campaign(r["campaign_id"])
    camp = js.load_campaign(r["campaign_id"])
    assert camp["coverage_signals"]["finalized_at"]
    assert score.cyber_score({"campaign": camp, "findings": []})["score_status"] == "not_rated"


def test_mcp_toolbox_calls_are_counted_for_the_calling_run(store, monkeypatch):
    pytest.importorskip("fastmcp")
    import sys
    from unittest import mock
    docker = pytest.importorskip("docker")
    monkeypatch.setattr(docker, "from_env", lambda *a, **k: mock.MagicMock())
    sys.modules.pop("src.server", None)
    try:
        import importlib
        srv = importlib.import_module("src.server")
        monkeypatch.setattr(srv, "SESSION_ID", FRAG)
        srv._count_toolbox_call("command")
        srv._count_toolbox_call("workflow")
        assert cs.read_counters(FRAG) == {"commands_executed": 1, "workflows_executed": 1}
    finally:
        sys.modules.pop("src.server", None)


def test_released_db_name_and_latest_root_fallback(store, monkeypatch, tmp_path):
    """The released OpenCode writes opencode.db (not opencode-dev.db): the recorder finds it next to the configured
    file, and in the single-user TUI the run's root is the latest root session when the key is not its prefix."""
    real = _db(tmp_path, root_id="ses_zzzzzzzzrootXYZ")
    real.rename(tmp_path / "opencode.db")
    monkeypatch.setattr(lp, "_OPENCODE_DB", tmp_path / "opencode-dev.db")   # absent, as in the release
    monkeypatch.setattr(lp, "_run_campaign_frag", lambda fallback: fallback)
    r = _init()
    lp.finalize_campaign(campaign_id=r["campaign_id"])
    s = _sig(r["campaign_id"])
    assert s["root_session_id"] == "ses_zzzzzzzzrootXYZ"
    assert s["agents_source"] == "opencode_sessions"
    assert [a["agent"] for a in s["agents_dispatched"]] == ["graphql", "php", "python-flask"]


def test_a_new_campaign_of_the_same_tui_session_inherits_nothing(store, monkeypatch, tmp_path):
    db = _db(tmp_path)
    monkeypatch.setattr(lp, "_OPENCODE_DB", db)
    earlier = {"id": "camp_20261101_" + FRAG, "session_id": FRAG, "target_id": "t", "status": "completed",
               "date": "2026-11-01T00:00:00Z", "is_subagent": False,
               "coverage_signals": dict(cs.blank({"date": "2026-11-01T00:00:00Z"}),
                                        counter_totals={"commands_executed": 40, "workflows_executed": 2})}
    js.save_campaign(earlier)
    c = sqlite3.connect(str(db))
    old = int(time.time() * 1000) - 6 * 3600 * 1000
    c.execute("INSERT INTO session VALUES (?,?,?,?,?,?)",
              ("ses_old", "ses_" + FRAG + "rootXYZ", "yesterday", "wordpress", old, old + 1000))
    c.commit()
    c.close()
    for _ in range(43):
        cs.count_call(FRAG, "command")
    r = _init()
    assert r["campaign_id"] != earlier["id"]
    lp.finalize_campaign(campaign_id=r["campaign_id"])
    s = _sig(r["campaign_id"])
    assert (s["commands_executed"], s["workflows_executed"]) == (3, 0)
    assert "wordpress" not in [a["agent"] for a in s["agents_dispatched"]]


def test_legacy_campaign_reinitialised_gets_no_signals(store):
    r = _init()
    c = js.load_campaign(r["campaign_id"])
    c.pop("coverage_signals")
    js.save_campaign(c)
    _init()
    assert "coverage_signals" not in js.load_campaign(r["campaign_id"])
