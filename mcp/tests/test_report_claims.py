"""The generated report carries no hard-coded unproven claim (executive V2, L1); CVSS recomputed from the vector,
the agent's value shown as « reported » when it differs. Isolated store."""
import re

import pytest

from api import json_storage as js
from api import live_push as lp
from tests.exec_store import isolate


@pytest.fixture
def store(monkeypatch, tmp_path):
    isolate(monkeypatch, tmp_path)


def _report(findings):
    r = lp.init_live_campaign("bbbbbbbb", "app.example.test", "192.0.2.10", project_name="P")
    operator_fp = []
    for f in findings:
        out = lp.push_finding(r["campaign_id"], dict(f))
        if f.get("status") == "false_positive":   # an operator decision: an agent cannot push it (stored unconfirmed)
            operator_fp.append(out["vuln_id"])
    if operator_fp:
        vs = js.load_vulnerabilities(r["campaign_id"])
        for v in vs:
            if v["id"] in operator_fp:
                v["status"] = "false_positive"
        js.save_vulnerabilities(r["campaign_id"], vs)
    camp = js.load_campaign(r["campaign_id"])
    return lp._generate_report_from_db(r["campaign_id"], camp, "")


AV = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8


def F(i, sev, st, **kw):
    return {"title": f"Finding {i}", "severity": sev, "status": st, "category": "sql_injection",
            "endpoint": f"/e{i}", "discovered_by_agent": "php", "description": "d", **kw}


def test_no_hard_coded_claims(store):
    md = _report([F(1, "critical", "exploited", cvss_score=9.8, cvss_vector=AV), F(2, "high", "confirmed"),
                  F(3, "medium", "confirmed"), F(4, "low", "unconfirmed")])
    for claim in ("Our team", "multiple independent attack paths", "**Today**", "**This week**", "**2 weeks**",
                  "**1 month**", "| Timeframe |", "Immediate (< 24h)", "(< 1 week)", "| Effort |"):
        assert claim not in md, claim
    assert "1 critical and 1 high severity findings; 1 of them were exploited" in md
    assert re.search(r"\| \*\*1\*\* \| Treat the 1 critical severity finding\(s\) \(1 exploited", md)
    assert "| Finding | Proof |" in md


def test_empty_campaign_does_not_claim_moderate_issues(store):
    md = _report([F(1, "info", "confirmed")])
    assert "moderate security issues" not in md and "not a proof that none exists" in md


def test_cvss_recomputed_from_the_vector_and_reported_value_marked(store):
    md = _report([F(1, "critical", "exploited", cvss_score=9.1, cvss_vector=AV),
                  F(2, "high", "confirmed", cvss_score=7.5, cvss_vector="garbage")])
    assert "| 9.8 (reported 9.1) |" in md
    assert "9.8 (computed from the vector; reported by the agent: 9.1)" in md
    assert "7.5 (reported by the agent; no valid vector)" in md


def test_report_counts_match_the_one_stats_function(store):
    md = _report([F(1, "critical", "exploited"), F(2, "high", "false_positive")])
    assert "| **TOTAL** | **1** | **1** | **0** |" in md


def test_false_positives_are_neither_listed_nor_counted(store):
    md = _report([F(1, "high", "confirmed"), dict(F(2, "critical", "false_positive"), title="Retracted finding")])
    assert "Retracted finding" not in md
    assert "**Not listed:** 1 finding(s) marked false positive" in md
    assert "| **TOTAL** | **1** |" in md


def test_unrecognised_severities_never_read_as_no_significant_finding(store):
    md = _report([F(1, "very high", "exploited"), F(2, "P1", "confirmed")])
    assert "NO SIGNIFICANT FINDING" not in md and "not a proof that none exists" not in md
    assert "SEVERITY NOT RECOGNISED" in md and "2 finding(s)" in md
