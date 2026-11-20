"""Maintenance windows in Community (L9): the owner's file, a WARNING at campaign start (never a block, nothing said
to the model), the record on the campaign, the check command, and no write path a model could call."""
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest

from api import json_storage as js
from api import live_push as lp
from api import maintenance_local as ML
from api import security_log as SL
from tests.exec_store import isolate

FRAG = "bbbbbbbb"
# a window that is never open on 2026-11-20 at 10:00 UTC (a Friday), and a blackout on that day
CLOSED = {"schema_version": "darkmoon-maintenance-policy/1", "timezone": "Europe/Paris",
          "windows": [{"days": ["sat"], "start": "09:00", "end": "17:00"}]}


@pytest.fixture
def store(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    return data


@pytest.fixture
def audit():
    lg = logging.getLogger(SL.AUDIT_LOGGER)
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(SL.JsonFormatter())
    lg.addHandler(h)
    old = lg.level
    lg.setLevel(logging.INFO)
    yield lambda: [json.loads(x) for x in buf.getvalue().splitlines() if x.strip()]
    lg.removeHandler(h)
    lg.setLevel(old)


def _policy(data: Path, pid: str, doc):
    d = data / "policies"
    d.mkdir(exist_ok=True)
    (d / f"{pid}.json").write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")


def _freeze(monkeypatch, at):
    class _DT(datetime):
        @classmethod
        def now(cls, tz=None):
            return at if tz else at.replace(tzinfo=None)
    monkeypatch.setattr(ML, "datetime", _DT)


def _init():
    return lp.init_live_campaign(FRAG, "shop.example.test", "192.0.2.20", project_name="Shop")


def test_no_policy_nothing_recorded(store, audit):
    r = _init()
    assert r["status"] == "campaign_initialized"
    assert "maintenance_check" not in js.load_campaign(r["campaign_id"])
    assert [e for e in audit() if e["event"] == "campaign.launch"] == []


def test_outside_the_policy_warns_and_records_but_never_blocks(store, audit, monkeypatch, caplog):
    first = _init()                                   # creates the project; the policy is written for it
    pid = first["project_id"]
    _policy(store, pid, CLOSED)
    (store / "campaigns" / f"{first['campaign_id']}.json").unlink()   # a new campaign of the same project
    _freeze(monkeypatch, datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc))
    with caplog.at_level(logging.WARNING, logger="darkmoon.maintenance"):
        r = _init()
    assert r["status"] == "campaign_initialized"                     # not blocked
    assert set(r) == {"project_id", "target_id", "campaign_id", "status"}   # the model is told nothing new
    mc = js.load_campaign(r["campaign_id"])["maintenance_check"]
    assert mc["decision"] == "warn" and mc["advisory_of"] == "blocked" and mc["enforced"] is False
    assert "outside-window" in mc["reasons"] and mc["next_window_start_utc"] == "2026-11-21T08:00:00Z"
    assert any("Maintenance policy" in rec.getMessage() and "WARNING" in rec.getMessage() for rec in caplog.records)
    ev = [e for e in audit() if e["event"] == "campaign.launch"]
    assert ev[-1]["outcome"] == "warning" and ev[-1]["via"] == "mcp" and ev[-1]["target"]["project_id"] == pid


def test_repeated_init_keeps_the_first_record(store, monkeypatch):
    first = _init()
    _policy(store, first["project_id"], CLOSED)
    (store / "campaigns" / f"{first['campaign_id']}.json").unlink()
    _freeze(monkeypatch, datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc))
    r = _init()
    before = js.load_campaign(r["campaign_id"])["maintenance_check"]
    _freeze(monkeypatch, datetime(2026, 11, 21, 10, 0, tzinfo=timezone.utc))   # inside the window now
    _init()
    assert js.load_campaign(r["campaign_id"])["maintenance_check"] == before


def test_broken_file_warns(store, monkeypatch):
    first = _init()
    _policy(store, first["project_id"], "{nope")
    (store / "campaigns" / f"{first['campaign_id']}.json").unlink()
    r = _init()
    mc = js.load_campaign(r["campaign_id"])["maintenance_check"]
    assert mc["decision"] == "warn" and mc["file_status"] == "unreadable"


def test_file_outside_the_store_or_foreign_is_refused(store, tmp_path):
    js.save_project({"id": "p1", "name": "Lab"})
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({**CLOSED, "windows": []}))
    (store / "policies").mkdir(exist_ok=True)
    (store / "policies" / "p1.json").symlink_to(outside)
    assert ML.load_policy("p1")[1] == "unreadable"
    (store / "policies" / "p1.json").unlink()
    _policy(store, "p1", {**CLOSED, "project_id": "p2"})
    assert ML.load_policy("p1")[1] == "unreadable"
    assert ML.evaluate("p1")["decision"] == "warn"
    assert ML.load_policy("../p1") == (None, "absent", [])


def test_check_command_exit_codes(store, capsys):
    js.save_project({"id": "p1", "name": "Lab"})
    assert ML.main(["check", "p1"]) == 0
    capsys.readouterr()
    _policy(store, "p1", CLOSED)
    assert ML.main(["check", "p1", "--at", "2026-11-20T10:00:00Z"]) == 3
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "warn" and out["advisory_of"] == "blocked"
    assert ML.main(["check", "p1", "--at", "2026-11-21T10:00:00Z"]) == 0
    assert ML.main(["check", "p1", "--at", "bad"]) == 2


def test_no_mcp_tool_writes_a_policy():
    """Declarations come from the owner's file only; nothing the model can call writes or reads it."""
    src = (Path(__file__).resolve().parents[1] / "src" / "server.py").read_text(encoding="utf-8")
    assert "maintenance_local" not in src and "policies/" not in src
