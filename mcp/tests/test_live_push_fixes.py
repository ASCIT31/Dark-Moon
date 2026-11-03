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


# ── 2026-11-03 ALSCO campaign audit ──────────────────────────────────────────
# Two more live-run defects, found during the ALSCO / Secure Gateway campaign
# (2026-11-02/03) and fixed the same day. These tests keep them fixed.

# Dedup bug — push_finding() appended blindly, so the campaign ended with 39
# records for 38 distinct titles (several near-duplicates with different
# wording), and an agent that wanted to withdraw a finding had to push a new
# "WITHDRAWN / FALSE POSITIVE - ..." record next to the original.
#
# Stale-summary bug — the report's management summary counted withdrawn
# records as live, so a report regenerated AFTER the agent refuted its own
# CRITICAL and both HIGH findings still shipped "N high severity
# vulnerabilities requiring urgent attention".


def _push(lp, campaign_id, title, severity="high", status="confirmed", agent="php"):
    return lp.push_finding(
        campaign_id=campaign_id,
        finding={
            "title": title,
            "severity": severity,
            "cvss_score": 7.5,
            "category": "sql_injection",
            "status": status,
            "description": "desc",
            "endpoint": "/x",
            "discovered_by_agent": agent,
            "evidence": {"commands": ["curl a"], "logs": [], "explanation": ""},
            "remediation": "fix",
        },
    )


def test_push_finding_upserts_by_title(lp):
    """Re-pushing the same title must UPDATE the record, not append a
    duplicate: same vuln_id, one record on disk, revision incremented and
    earlier evidence preserved."""
    _root(lp, "ses_UPSERTaaaa1", 1000)
    cid = _init(lp)

    r1 = _push(lp, cid, "SQL Injection in Royal CMS article parameter")
    r2 = _push(lp, cid, "SQL injection in royal-cms article   parameter!!")

    assert r1["updated"] is False
    assert r2["updated"] is True, "Bug: re-push appended a duplicate record"
    assert r1["vuln_id"] == r2["vuln_id"], "Bug: re-push minted a new vuln_id"
    assert r2["revision"] == 2

    from api.json_storage import VULNERABILITIES_DIR
    stored = lp._read_json(VULNERABILITIES_DIR / f"{cid}.json") if hasattr(lp, "_read_json") else None
    if stored is None:
        from api import json_storage
        import json as _json
        stored = _json.loads((json_storage.VULNERABILITIES_DIR / f"{cid}.json").read_text())
    assert isinstance(stored, list) and len(stored) == 1, (
        f"Bug: expected 1 record after a re-push, found {len(stored)}"
    )


def test_withdrawn_findings_do_not_inflate_counts(lp):
    """A record the agent withdrew (title carries a withdrawal marker) must be
    excluded from severity/status/risk counts while remaining on disk."""
    _root(lp, "ses_WITDRaaaa1", 1000)
    cid = _init(lp)

    _push(lp, cid, "SQL Injection in complaint insert", severity="high", status="confirmed")
    r2 = _push(
        lp, cid,
        "WITHDRAWN / FALSE POSITIVE - SQL Injection in complaint insert",
        severity="high", status="confirmed",
    )
    _push(lp, cid, "Cleartext session cookie on 307 hop", severity="low", status="confirmed")

    camp = lp.load_campaign(cid)
    stats = camp["stats"]
    assert stats["high"] == 0, "Bug: a withdrawn HIGH still counts as high"
    assert stats["critical"] == 0
    assert stats["low"] == 1
    assert stats["withdrawn"] == 1
    assert stats["total_findings"] == 1
    # The withdrawal record UPDATES the original in place (marker-insensitive
    # title key), so the store holds 2 records, not 3.
    assert stats["total_records"] == 2
    assert camp["overall_risk"] == "low", (
        f"Bug: overall risk {camp['overall_risk']} driven by a withdrawn record"
    )
    assert r2["withdrawn_records"] == 1


def test_report_summary_ignores_withdrawn(lp):
    """The vendor-facing management summary must be computed from validated
    records only: with every CRITICAL/HIGH withdrawn, the report may not
    claim an urgent-remediation posture."""
    _root(lp, "ses_REPOaaaaa1", 1000)
    cid = _init(lp)

    _push(lp, cid, "SQL Injection in homeLang", severity="critical", status="confirmed")
    _push(
        lp, cid,
        "FALSE POSITIVE (not a vulnerability) - SQL Injection in homeLang",
        severity="critical", status="confirmed",
    )
    _push(
        lp, cid,
        "REFUTED - claimed WAF bypass",
        severity="high", status="confirmed",
    )

    camp = lp.load_campaign(cid)
    md = lp._generate_report_from_db(cid, camp)

    assert "Urgent Remediation Required" not in md, (
        "Bug: report claims urgent remediation from a withdrawn HIGH"
    )
    assert "Immediate Action Required" not in md, (
        "Bug: report claims immediate action from a withdrawn CRITICAL"
    )
    assert "withdrawn / false-positive record" in md or "withdrawn" in md.lower()
    # The withdrawn record must still be visible in the table as the audit trail.
    assert "WITHDRAWN / FALSE POSITIVE" in md or "REFUTED" in md or "withdrawn / false positive" in md.lower()
