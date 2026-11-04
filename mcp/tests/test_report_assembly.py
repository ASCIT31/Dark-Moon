"""
Report-assembly regressions — 2026-11-03 PornBox follow-up audit.

Two defects surfaced when reviewing the PornBox round-2 deliverable:

R1 — the agent's own report body was DISCARDED. finalize_campaign() always
     regenerated the body from the findings store ("deterministic reports") and
     dropped the agent's markdown entirely, so the agent's reasoning, its
     explicit list of untested vectors and its remediation advice never reached
     the file — while the agent's executive_summary still referenced them. The
     report contradicted itself. The narrative is now kept as an appendix.

R2 — an all-informational campaign produced an EMPTY remediation roadmap:
     every band (P0..P3) is filtered by severity, and a campaign whose only
     findings are proven negatives/hardening notes hit none of them. P4
     (informational) now exists, with the finding's own remediation text.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from api import json_storage, live_push  # noqa: E402


@pytest.fixture
def lp(tmp_path, monkeypatch):
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
    return live_push


def _finding(lp, cid, title, severity="info", remediation=""):
    lp.push_finding(campaign_id=cid, finding={
        "title": title,
        "severity": severity,
        "cvss_score": 0.0,
        "category": "negative_result",
        "status": "confirmed",
        "description": "d",
        "endpoint": "https://x/",
        "discovered_by_agent": "pentest-orchestrator",
        "remediation": remediation,
        "evidence": {"commands": [], "logs": []},
    })


def test_agent_narrative_is_kept_as_appendix(lp):
    """R1: the agent's report body must survive into the written report."""
    cid = "camp_test_r1"
    lp.save_campaign({
        "id": cid, "project_id": "p", "target_id": "t", "status": "running",
        "stats": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                  "exploited": 0, "confirmed": 0, "unconfirmed": 0},
        "agents_dispatched": [], "report_path": "", "executive_summary": "",
    })
    _finding(lp, cid, "NEGATIVE RESULT: reset token is single-use")

    narrative = (
        "# Agent narrative\n\n"
        "## Vectors NOT TESTED\n\n"
        "1. SSRF via the url= parameter - needs one manual request.\n"
        "2. Portal API IDOR - needs a second account.\n"
    )
    out = lp.finalize_campaign(
        campaign_id=cid,
        executive_summary="Three negatives, five untested vectors filed.",
        report_markdown=narrative,
    )
    path = lp.REPORTS_DIR / os.path.basename(out["report_path"])
    body = path.read_text(encoding="utf-8")

    assert "Vectors NOT TESTED" in body, (
        "R1 regression: the agent's narrative was dropped from the report"
    )
    assert "AGENT ANALYSIS" in body
    # the deterministic body must still be there
    assert "FINDINGS TABLE" in body
    assert "NEGATIVE RESULT: reset token is single-use" in body


def test_informational_only_campaign_has_a_non_empty_roadmap(lp):
    """R2: an all-informational campaign must still carry its remediation."""
    cid = "camp_test_r2"
    lp.save_campaign({
        "id": cid, "project_id": "p", "target_id": "t", "status": "running",
        "stats": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                  "exploited": 0, "confirmed": 0, "unconfirmed": 0},
        "agents_dispatched": [], "report_path": "", "executive_summary": "",
    })
    _finding(lp, cid, "BACKEND INTERFACE TAKEOVER via IDOR - NOT EXPLOITABLE", remediation="Ignore the id parameter")
    out = lp.finalize_campaign(campaign_id=cid, executive_summary="No qualifying vulnerability.")
    body = (lp.REPORTS_DIR / os.path.basename(out["report_path"])).read_text(encoding="utf-8")

    roadmap = body.split("REMEDIATION ROADMAP")[-1]
    assert "P4" in roadmap, "R2 regression: empty remediation roadmap for an informational-only campaign"
    assert "Ignore the id parameter" in roadmap, (
        "R2 regression: the finding's own remediation text was dropped"
    )
