"""Community report = the report Darkmoon Pro writes at finalisation + the report annex Pro shows next to it
(remediation priorities, attack paths, infrastructure map, fix first, framework mapping), in one Markdown file.

Community never observes a link between findings: every attack path is a hypothesis (declared by an agent or inferred
from the topology), and nothing in the report may present one as proven. Nothing about automated remediation pull
requests appears in the Community report."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from api import json_storage, live_push  # noqa: E402

CID = "camp_20261119_parity01"
PRO_HEADINGS = ["MANAGEMENT SUMMARY", "1. EXECUTIVE SUMMARY", "2. FINDINGS TABLE", "3. VULNERABILITY DETAILS",
                "4. REMEDIATION ROADMAP"]
ANNEX_HEADINGS = ["REMEDIATION PRIORITIES & ATTACK PATHS", "ATTACK PATHS", "INFRASTRUCTURE MAP", "FIX FIRST",
                  "FRAMEWORK MAPPING"]


@pytest.fixture
def store(tmp_path, monkeypatch):
    data = tmp_path / "data"
    dirs = {"DATA_DIR": data, "CAMPAIGNS_DIR": data / "campaigns", "INFRASTRUCTURE_DIR": data / "infrastructure",
            "VULNERABILITIES_DIR": data / "vulnerabilities", "REPORTS_DIR": data / "reports"}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    for name, d in dirs.items():
        for mod in (json_storage, live_push):
            monkeypatch.setattr(mod, name, d, raising=False)
    monkeypatch.setattr(json_storage, "PROJECTS_FILE", data / "projects.json")
    monkeypatch.setattr(json_storage, "TARGETS_FILE", data / "targets.json")
    json_storage.save_target({"id": "tgt_1", "host": "app.example.test"})
    json_storage.save_campaign({"id": CID, "project_id": "p", "target_id": "tgt_1", "target": "app.example.test",
                                "status": "running", "stats": {}})
    json_storage.save_infrastructure(CID, [
        {"id": "host_app", "node_type": "host", "label": "app.example.test"},
        {"id": "svc_http", "node_type": "service", "label": "HTTP", "port": 443, "protocol": "tcp",
         "parent_node_id": "host_app"},
        {"id": "app_web", "node_type": "application", "label": "Shop", "parent_node_id": "svc_http"},
        {"id": "db_main", "node_type": "database", "label": "Customer database", "parent_node_id": "app_web"},
    ])
    return dirs


def _push(title, severity="high", status="exploited", enabled_by=None, **kw):
    f = {"title": title, "severity": severity, "status": status, "category": re.sub(r"\W", "_", title.lower()),
         "endpoint": "https://app.example.test/" + re.sub(r"[^a-z]", "", title.lower()), "node_id": "app_web",
         "discovered_by_agent": "web", "cvss_score": 8.1, "remediation": "Validate the input server-side.",
         "mitre_attack_id": "T1190", "iso27001_control": "A.8.28", **kw}
    if enabled_by is not None:
        f["enabled_by"] = enabled_by
    return live_push.push_finding(CID, f)


def _declared_campaign():
    a = _push("Default credentials on admin login", severity="critical", category="weak_credentials")
    b = _push("Authenticated file upload leads to RCE", severity="critical", category="rce",
              enabled_by=[a["vuln_id"]])
    _push("Customer table dumped through SQL injection", severity="critical", category="sql_injection",
          enabled_by=[b["vuln_id"], "vuln_unknown"])
    _push("Missing security headers", severity="low", status="confirmed", category="misconfiguration")


def _report() -> str:
    return live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "Summary of the run.")


def _section(md: str, title: str) -> str:
    m = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^<!-- dm-section|^## |^---\n\n\*Report auto-generated|\Z)", md, re.S | re.M)
    assert m, f"section {title} missing"
    return m.group(1)


def test_report_has_the_pro_sections_then_the_annex_then_the_footer(store):
    _declared_campaign()
    md = _report()
    heads = [h[3:] for h in md.splitlines() if h.startswith("## ")]
    assert heads == PRO_HEADINGS + ANNEX_HEADINGS
    assert md.rstrip().endswith(f"*Campaign: {CID} | Target: app.example.test*")
    assert md.index("## 4. REMEDIATION ROADMAP") < md.index("## REMEDIATION PRIORITIES & ATTACK PATHS")


def test_declared_only_campaign_is_never_worded_as_proven(store):
    _declared_campaign()
    md = _report()
    lead = _section(md, "REMEDIATION PRIORITIES & ATTACK PATHS")
    assert "0 observed attack paths" in lead and "Path-based prioritisation unavailable" in lead
    paths = _section(md, "ATTACK PATHS")
    assert paths.startswith("\n0 observed attack paths")
    ranked = re.search(r"### Attack paths \(ranked: observed and declared\)\n\n(.*?)\n\n", paths, re.S).group(1)
    assert ranked == "None."
    assert "### Paths declared by the agent (not verified by the server)" in paths
    for line in paths.splitlines():
        if line.startswith("Status: **"):
            assert re.match(r"Status: \*\*(declared by the agent · not verified by the server|possible · not proven "
                            r"\(hypothesis\))\*\*", line), line
    # the diagram never draws a thick (observed / declared-ranked) arrow
    fence = paths.split("```mermaid", 1)[1].split("```", 1)[0]
    assert "==>" not in fence
    fix = _section(md, "FIX FIRST")
    assert "No attack-path ranking for this campaign" in fix and "Paths interrupted" not in fix
    # EBIOS sequences: each status is the honest per-path word, never « observed » nor a bare « proven »
    fw = _section(md, "FRAMEWORK MAPPING")
    m = re.search(r"\| Sequence \| Status \| Steps \|\n\|[-| ]+\|\n((?:\|.*\n?)+)", fw)
    assert m, "EBIOS sequence table missing"
    statuses = {r.split("|")[2].strip() for r in m.group(1).splitlines() if r.startswith("|")}
    assert statuses and statuses <= {"declared by the agent · not verified by the server",
                                     "possible · not proven (hypothesis)"}


def test_declared_links_list_keeps_rejected_declarations(store):
    _declared_campaign()
    md = _report()
    links = md[md.index("### Links declared by the agents"):md.index("## INFRASTRUCTURE MAP")]
    assert "`vuln_unknown`" in links and "Rejected declaration" in links
    assert "no path is counted as proven" in links


def test_no_automated_remediation_content(store):
    _declared_campaign()
    md = _report()
    assert not re.search(r"pull request|remediation agent|\bPRs?\b|merge request", md, re.I)
    # per-finding remediation advice written by the agent stays (Pro writes it too)
    assert "#### Remediation\n\nValidate the input server-side." in md


def test_infrastructure_section_has_zones_and_hypotheses_never_raise_risk(store):
    from api.attack_paths_local import attack_paths_doc
    from api.report_annex_local import infrastructure_doc
    _declared_campaign()
    camp = json_storage.load_campaign(CID)
    infra = infrastructure_doc(CID, camp, attack_paths_doc(CID))
    zones = {n["id"]: n["zone"] for n in infra["nodes"]}
    assert zones["db_main"] == "data" and zones["svc_http"] == "edge" and zones["app_web"] == "app"
    for n in infra["nodes"]:
        assert n["reached_by"] is None and n["effective_risk"] == (n.get("risk_level") or "none")
    md = _report()
    infra_md = _section(md, "INFRASTRUCTURE MAP")
    assert "%% figure: infrastructure" in infra_md and "| Data |" in infra_md and "443/tcp" in infra_md


def test_frameworks_doc_contract(store):
    from api.report_annex_local import frameworks_doc
    _declared_campaign()
    d = frameworks_doc(CID, json_storage.load_campaign(CID))
    assert d["schema_version"] == "darkmoon-frameworks/v1" and d["campaign_id"] == CID
    assert {"attack", "iso", "iec62443", "atlas", "ebios", "findings", "licences"} <= set(d)
    assert d["attack"]["version"] == "20.0"
    eb = d["ebios"]
    assert set(eb["feasibility_distribution"]) == {"F4", "F3", "F2", "F1", "not_rated"}
    for c in eb["candidate_paths"]:
        assert c["hypothesis"] is True and c["gravity"]["state"] == "to_assess" and c["risk"] is None
        assert c["difficulty_proposed"]["state"] == "not_proposed"


def test_framework_failure_leaves_only_that_section_out(store, monkeypatch):
    import api.report_annex_local as RL
    _declared_campaign()
    monkeypatch.setattr(RL, "frameworks_doc", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bad table")))
    heads = [h[3:] for h in _report().splitlines() if h.startswith("## ")]
    assert heads == PRO_HEADINGS + ANNEX_HEADINGS[:-1]


def test_framework_licences_and_notices_are_shipped(store):
    from api import frameworks as F
    _declared_campaign()
    fw = _section(_report(), "FRAMEWORK MAPPING")
    assert "Reproduced and distributed with the permission of The MITRE Corporation" in fw
    assert "MITRE ATLAS™ 2026.10 — Apache-2.0" in fw
    base = Path(F.__file__).parent
    for rel in ("vendor/mitre_attack/LICENSE.txt", "vendor/mitre_attack/NOTICE", "frameworks_data/LICENSE-ATLAS.txt",
                "frameworks_data/NOTICE", "frameworks_data/README-PROVENANCE.md"):
        assert (base / rel).is_file(), rel


def test_quarantined_findings_are_held_out_of_the_report(store):
    _push("Visible finding")
    _push("Held finding", severity="critical")
    vulns = json_storage.load_vulnerabilities(CID)
    for v in vulns:
        if v["title"] == "Held finding":
            v["quarantined"] = True
    json_storage.save_vulnerabilities(CID, vulns)
    md = _report()
    body = md[:md.index("## REMEDIATION PRIORITIES & ATTACK PATHS")]
    assert "Visible finding" in body and "Held finding" not in body
    assert "**Held for review:** 1 finding(s)" in body and "| **TOTAL** | **1** |" in body
    for v in vulns:
        v["quarantine_reviewed_by"] = "operator"
    json_storage.save_vulnerabilities(CID, vulns)
    assert "Held finding" in _report()


def test_finalize_writes_the_annex_into_the_report_file(store):
    _declared_campaign()
    res = live_push.finalize_campaign(CID, executive_summary="Done.")
    assert "error" not in res, res
    body = (store["REPORTS_DIR"] / Path(json_storage.load_campaign(CID)["report_path"]).name).read_text(encoding="utf-8")
    assert "## FRAMEWORK MAPPING" in body and "### Links declared by the agents" in body
    assert "## 1. EXECUTIVE SUMMARY\n\n> Done." in body
