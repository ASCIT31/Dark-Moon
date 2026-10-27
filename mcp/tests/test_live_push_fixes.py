"""
Regression tests for two run-robustness bugs found on 2026-10-27 during a real
IoTGoat campaign. These MUST stay green on every push so the bugs cannot come back.

Bug B  — campaign_id collision. campaign_id was ``camp_<day>_<session_id>`` where
         session_id is the MCP SESSION_ID generated ONCE per long-lived MCP
         server process, so a SECOND campaign on the same server/day merged into
         the first (empty new project, findings in the wrong campaign). Fix: key
         the campaign on the current run's ROOT opencode session.

Bug A2 — headless-browser OOM. The Playwright launch args must carry the
         memory/process flags, or Chromium exhausts /dev/shm and the PID limit
         and OOM-kills the whole run.

(The dashboard "report-on-crash" and "auto-refresh" fixes are Pro-only — the
open-source edition is CLI, with no web dashboard / run API — so they are not
tested here.)
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from api import json_storage, live_push  # noqa: E402


@pytest.fixture
def lp(tmp_path, monkeypatch):
    """live_push wired to temp data dirs + a controllable fake opencode DB."""
    data = tmp_path / "data"
    dirs = {
        "DATA_DIR": data,
        "CAMPAIGNS_DIR": data / "campaigns",
        "INFRASTRUCTURE_DIR": data / "infrastructure",
        "VULNERABILITIES_DIR": data / "vulnerabilities",
        "REPORTS_DIR": data / "reports",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    for name, d in dirs.items():
        monkeypatch.setattr(json_storage, name, d, raising=False)
        if hasattr(live_push, name):
            monkeypatch.setattr(live_push, name, d, raising=False)
    monkeypatch.setattr(json_storage, "PROJECTS_FILE", data / "projects.json", raising=False)
    monkeypatch.setattr(json_storage, "TARGETS_FILE", data / "targets.json", raising=False)

    # OSS resolves the opencode DB via the _OPENCODE_DB constant (a Path).
    dbpath = tmp_path / "opencode-dev.db"
    monkeypatch.setattr(live_push, "_OPENCODE_DB", dbpath, raising=False)
    conn = sqlite3.connect(dbpath)
    conn.execute("CREATE TABLE session(id TEXT, parent_id TEXT, time_created INTEGER)")
    conn.commit()
    conn.close()
    live_push._TEST_DB = dbpath  # type: ignore[attr-defined]
    return live_push


def _root(lp, sid, t):
    c = sqlite3.connect(lp._TEST_DB)
    c.execute("INSERT INTO session VALUES (?,?,?)", (sid, None, t))
    c.commit()
    c.close()


def _child(lp, sid, parent, t):
    c = sqlite3.connect(lp._TEST_DB)
    c.execute("INSERT INTO session VALUES (?,?,?)", (sid, parent, t))
    c.commit()
    c.close()


def _init(lp, host="172.17.0.2", ip="172.17.0.2", name="IoTGoat"):
    return lp.init_live_campaign(
        session_id="MCPCONST", target_host=host, target_ip=ip, project_name=name
    )["campaign_id"]


# ── Bug B ────────────────────────────────────────────────────────────────────

def test_two_runs_get_distinct_campaigns(lp):
    """Two runs (two ROOT opencode sessions) on the same server/day must NOT
    collide onto one campaign_id."""
    _root(lp, "ses_RUN1aaaa1111", 1000)
    c1 = _init(lp)
    _root(lp, "ses_RUN2bbbb2222", 2000)
    c2 = _init(lp)
    assert c1 != c2, f"Bug B regression: campaigns collided ({c1} == {c2})"


def test_subagent_merges_into_parent_run(lp):
    """A sub-agent (CHILD session) must resolve to the SAME campaign as its
    orchestrator, so its findings land in the right campaign."""
    _root(lp, "ses_RUN2bbbb2222", 2000)
    parent = _init(lp)
    _child(lp, "ses_SUBAGENTx", "ses_RUN2bbbb2222", 2100)
    child = _init(lp)
    assert child == parent, "sub-agent merge broke — findings would split off"


def test_fallback_when_db_missing(lp, monkeypatch):
    """If the opencode DB is unavailable, init must still work (degrade to the
    passed session_id) rather than crash."""
    monkeypatch.setattr(lp, "_OPENCODE_DB", Path("/nonexistent-xyz/opencode-dev.db"), raising=False)
    cid = _init(lp)
    assert cid.startswith("camp_")


# ── Bug A2 ───────────────────────────────────────────────────────────────────

def test_headless_browser_has_memory_flags():
    """The headless-browser agent prompt must mandate the Chromium memory/process
    flags, or the headless phase OOM-kills the run."""
    agent = (
        Path(__file__).resolve().parents[2] / "conf" / "agents" / "headless-browser.md"
    )
    text = agent.read_text(encoding="utf-8")
    for flag in ("--disable-dev-shm-usage", "--single-process", "--no-zygote"):
        assert flag in text, f"Bug A2 regression: headless-browser missing {flag}"
