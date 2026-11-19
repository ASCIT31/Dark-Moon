"""Community attack paths: agent-declared links (enabled_by) pushed through the MCP tool, stored in the JSON store,
turned into an attack-path document without a web server, and printed in the report as declarations only."""
from __future__ import annotations

import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from api import json_storage, live_push  # noqa: E402

CID = "camp_20261119_cport001"


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
    return data


def _push(title, enabled_by=None, status="exploited", cid=CID):
    f = {"title": title, "severity": "high", "status": status, "category": re.sub(r"\W", "_", title.lower()),
         "endpoint": "/" + re.sub(r"[^a-z]", "", title.lower()), "discovered_by_agent": "graphql"}
    if enabled_by is not None:
        f["enabled_by"] = enabled_by
    return live_push.push_finding(cid, f)


def test_enabled_by_is_stored_and_unknown_refs_are_reported(store):
    a = _push("Introspection leaks admin token")
    b = _push("Admin mutation with leaked token", enabled_by=[a["vuln_id"], "vuln_nope"])
    stored = {v["id"]: v for v in json_storage.load_vulnerabilities(CID)}
    assert stored[b["vuln_id"]]["enabled_by"] == [a["vuln_id"], "vuln_nope"]
    assert set(stored[b["vuln_id"]]["enabled_by_at"]) == {a["vuln_id"], "vuln_nope"}
    assert any("vuln_nope" in w for w in b.get("enabled_by_warnings") or [])
    assert "enabled_by" not in stored[a["vuln_id"]]


def test_repush_adds_references_without_a_duplicate(store):
    a = _push("Default credentials")
    c = _push("SQL injection in search")
    b = _push("Authenticated RCE", enabled_by=[a["vuln_id"]])
    again = _push("Authenticated RCE", enabled_by=[c["vuln_id"]])
    assert again["status"] == "finding_updated" and again["vuln_id"] == b["vuln_id"]
    assert again["enabled_by_added"] == [c["vuln_id"]]
    vulns = json_storage.load_vulnerabilities(CID)
    assert len(vulns) == 3
    assert next(v for v in vulns if v["id"] == b["vuln_id"])["enabled_by"] == [a["vuln_id"], c["vuln_id"]]


def test_push_reply_suggests_recent_exploited_findings(store):
    a = _push("Default credentials")
    b = _push("Weak session cookie")
    c = _push("Directory listing", status="confirmed")
    d = _push("Admin upload")
    hint = d.get("recent_exploited", "")
    # same item count as without the new finding; the finding just pushed comes first; never a non-exploited one
    assert hint.index(d["vuln_id"]) < hint.index(b["vuln_id"]) and hint.count("vuln_") == 2 and a["vuln_id"] not in hint
    assert c["vuln_id"] not in hint and c["vuln_id"] not in b.get("recent_exploited", "")


@pytest.mark.parametrize("bad", ["../../etc/passwd", "..", "camp/../x", "/abs", "a b", "camp\x00x", ""])
def test_crafted_campaign_ids_never_touch_the_filesystem(store, bad):
    before = sorted(p.relative_to(store) for p in store.rglob("*"))
    assert "error" in live_push.push_finding(bad, {"title": "x"})
    assert "error" in live_push.push_infra_node(bad, {"node_type": "host", "label": "x"})
    assert sorted(p.relative_to(store) for p in store.rglob("*") if ".locks" not in p.parts) == \
        [p for p in before if ".locks" not in p.parts]


def test_declared_paths_are_hypotheses_never_proofs(store):
    from api.attack_paths_local import attack_paths_doc
    a = _push("Default credentials")
    _push("Authenticated RCE", enabled_by=[a["vuln_id"]])
    doc = attack_paths_doc(CID)
    assert doc["schema_version"] and doc["summary"]["proven_paths"] == 0
    declared = [p for p in doc["paths"] if p["provenance"] == "agent-declared"]
    assert declared, doc["paths"]
    for p in declared:
        assert p["hypothesis"] is True and p["level"] == "declared_by_agent"
        assert "not verified" in p["level_label"]


def test_unknown_or_malformed_campaign_gives_no_document(store):
    from api.attack_paths_local import attack_paths_doc
    assert attack_paths_doc("camp_unknown") is None
    assert attack_paths_doc("../etc") is None


def test_report_lists_declared_links_without_calling_them_proven(store):
    a = _push("Default credentials")
    _push("Authenticated RCE", enabled_by=[a["vuln_id"], "vuln_nope"])
    report = live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "summary")
    section = report[report.index("## 5. ATTACK PATHS AND DECLARED LINKS"):]
    assert "declared by the testing agents" in section and "not a proof" in section
    assert "Declared by the agent · not verified by the server" in section
    assert "Rejected declaration" in section and "`vuln_nope`" in section
    rows = [line for line in section.splitlines() if line.startswith("| ") and "`" in line]
    assert len(rows) == 2
    for row in rows:
        assert not re.search(r"\b(proven|observed|demonstrated)\b", row, re.I), row


def test_campaign_without_declared_links_keeps_the_old_report(store):
    _push("Default credentials")
    report = live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "summary")
    assert "## 5. ATTACK PATHS" not in report and "## 4. REMEDIATION ROADMAP" in report


def test_mcp_tool_exposes_enabled_by_and_stores_it(store, monkeypatch):
    pytest.importorskip("fastmcp")
    from unittest import mock
    import docker
    monkeypatch.setattr(docker, "from_env", lambda *a, **k: mock.MagicMock())
    from src import server as srv

    async def run():
        tools = {t.name: t for t in await srv.mcp._list_tools()}
        schema = tools["dashboard_push_finding"].parameters
        assert "enabled_by" in schema["properties"] and "enabled_by" not in schema.get("required", [])
        base = dict(campaign_id=CID, severity="high", cvss_score=8.0, category="auth", status="exploited",
                    description="d", endpoint="/login", discovered_by_agent="t")
        a = await srv.mcp.call_tool("dashboard_push_finding", dict(base, title="Default credentials"))
        vid = a.structured_content["result"]["vuln_id"] if "result" in a.structured_content else a.structured_content["vuln_id"]
        await srv.mcp.call_tool("dashboard_push_finding",
                                dict(base, title="Admin upload", endpoint="/admin", enabled_by=[vid, "  ", "x" * 300]))
        return vid

    vid = asyncio.run(run())
    stored = {v["title"]: v for v in json_storage.load_vulnerabilities(CID)}
    assert stored["Admin upload"]["enabled_by"] == [vid, "x" * 120]
    assert "enabled_by" not in stored["Default credentials"]


def test_report_checks_links_in_push_order_not_severity_order(store):
    # the report lists findings by severity; a low finding pushed FIRST enabling a critical one is still valid
    a = live_push.push_finding(CID, {"title": "Open registration", "severity": "low", "status": "exploited",
                                     "category": "auth", "endpoint": "/register"})
    live_push.push_finding(CID, {"title": "Admin file read", "severity": "critical", "status": "exploited",
                                 "category": "lfi", "endpoint": "/admin/export", "enabled_by": [a["vuln_id"]]})
    report = live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "summary")
    section = report[report.index("## 5. ATTACK PATHS AND DECLARED LINKS"):]
    assert "forward" not in section and "Declared by the agent · not verified by the server" in section
