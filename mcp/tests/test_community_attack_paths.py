"""Community attack paths: agent-declared links (enabled_by) pushed through the MCP tool, stored in the JSON store,
turned into an attack-path document without a web server, and printed in the report annex as declarations and
hypotheses only."""
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
    section = report[report.index("### Links declared by the agents"):report.index("## INFRASTRUCTURE MAP")]
    assert "declared by the testing agents" in section and "not a proof" in section
    assert "Declared by the agent · not verified by the server" in section
    assert "Rejected declaration" in section and "`vuln_nope`" in section
    rows = [line for line in section.splitlines() if line.startswith("| ") and "`" in line]
    assert len(rows) == 2
    for row in rows:
        assert not re.search(r"\b(proven|observed|demonstrated)\b", row, re.I), row
    paths = report[report.index("## ATTACK PATHS"):report.index("### Links declared by the agents")]
    assert "0 observed attack paths" in paths and "declared by the agent (not verified by the server)" in paths
    assert "### Paths declared by the agent (not verified by the server)" in paths


def test_campaign_without_declared_links_still_gets_a_valid_report(store):
    # an older campaign (no enabled_by anywhere): the report and its annex are built, without the declared-link list
    _push("Default credentials")
    report = live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "summary")
    assert "## 4. REMEDIATION ROADMAP" in report and "## ATTACK PATHS" in report and "## FIX FIRST" in report
    assert "### Links declared by the agents" not in report
    assert report.rstrip().endswith(f"*Campaign: {CID} | Target: app.example.test*")


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
    section = report[report.index("### Links declared by the agents"):report.index("## INFRASTRUCTURE MAP")]
    assert "forward" not in section and "Declared by the agent · not verified by the server" in section


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.Qm9ndXNTaWduYXR1cmVYWFhYWFhYWFg"


def _push_ev(title, cat, ep, req, resp, enabled_by=None):
    f = {"title": title, "severity": "critical", "status": "exploited", "category": cat, "endpoint": ep,
         "evidence": {"commands": [f"curl -H 'Authorization: Bearer {JWT}' {ep}"], "raw_request": req,
                      "raw_response": resp, "logs": [], "extracted_data": None}}
    if enabled_by:
        f["enabled_by"] = enabled_by
    return live_push.push_finding(CID, f)


@pytest.mark.parametrize("declare", [False, True])
def test_a_value_shared_by_two_agent_written_evidences_is_never_a_proof(store, declare):
    # the same token in the response of one finding and the request of another: written by the agent, not observed
    from api.attack_paths_local import attack_paths_doc
    a = _push_ev("SQL injection in login", "sql_injection", "/api/login", "user=' OR 1=1--", '{"token":"%s"}' % JWT)
    _push_ev("Admin panel access", "broken_access_control", "/admin/users",
             f"GET /admin/users\nAuthorization: Bearer {JWT}", "[{\"user\":\"root\"}]",
             enabled_by=[a["vuln_id"]] if declare else None)
    doc = attack_paths_doc(CID)
    assert doc["summary"]["proven_paths"] == 0
    assert all(p["hypothesis"] is True for p in doc["paths"])
    assert not [l for l in doc.get("observed_links") or [] if l.get("kind") in ("R1", "R2", "R3")]
    assert JWT not in __import__("json").dumps(doc)  # evidence text never reaches the path document
    report = live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "s")
    annex = report[report.index("## REMEDIATION PRIORITIES & ATTACK PATHS"):]
    assert JWT not in annex  # the annex is built from the path document, never from the evidence text
    assert "0 observed attack paths" in annex
    assert not re.search(r"proven by the server", annex, re.I)


def test_evidence_counts_survive_without_the_text(store):
    from api.attack_paths_local import attack_paths_doc
    a = _push("Default credentials")
    _push("Authenticated RCE", enabled_by=[a["vuln_id"]])
    vulns = json_storage.load_vulnerabilities(CID)
    vulns[0]["evidence"] = {"commands": ["c1", "c2"], "raw_request": "GET /", "extracted_data": "x"}
    json_storage.save_vulnerabilities(CID, vulns)
    doc = attack_paths_doc(CID)
    metas = [f["evidence_meta"] for p in doc["paths"] for s in p.get("steps") or [] for f in s.get("findings") or []
             if f.get("id") == a["vuln_id"]]
    assert metas and metas[0] == {"commands": 2, "requests": 1, "has_extracted_data": True}


def test_a_repush_that_changes_the_finding_keeps_both_versions(store):
    a = _push("Default credentials")
    first = _push("Admin upload", status="confirmed")
    again = live_push.push_finding(CID, {"title": "Admin upload", "severity": "critical", "status": "exploited",
                                         "category": "admin_upload", "endpoint": "/adminupload",
                                         "evidence": {"commands": ["new proof"]}, "enabled_by": [a["vuln_id"]]})
    assert again["status"] == "finding_pushed" and again["vuln_id"] != first["vuln_id"]
    stored = {v["id"]: v for v in json_storage.load_vulnerabilities(CID)}
    assert stored[again["vuln_id"]]["status"] == "exploited" and stored[again["vuln_id"]]["severity"] == "critical"
    assert stored[first["vuln_id"]]["status"] == "confirmed"


def test_declared_links_are_listed_even_if_the_path_engine_fails(store, monkeypatch):
    import api.attack_paths_local as apl
    a = _push("Default credentials")
    _push("Authenticated RCE", enabled_by=[a["vuln_id"]])
    monkeypatch.setattr(apl, "attack_paths_doc", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("engine bug")))
    report = live_push._generate_report_from_db(CID, json_storage.load_campaign(CID), "s")
    assert "Declared by the agent · not verified by the server" in report[report.index("### Links declared by the agents"):]
    assert "could not be computed" in report and "## 4. REMEDIATION ROADMAP" in report


def test_init_with_a_crafted_session_id_writes_nothing(store):
    def files():
        return sorted(p.name for p in store.rglob("*") if ".locks" not in p.parts)
    before = files()
    r = live_push.init_live_campaign(session_id="../../x", target_host="h.test", target_ip="10.0.0.9")
    assert "error" in r and files() == before


def test_store_files_follow_the_umask(store):
    import os
    old = os.umask(0o022)
    try:
        monkey = json_storage._UMASK
        json_storage._UMASK = 0o022
        json_storage._write_json(store / "probe.json", {})
        assert (store / "probe.json").stat().st_mode & 0o777 == 0o644
    finally:
        json_storage._UMASK = monkey
        os.umask(old)


@pytest.mark.parametrize("value,expected", [
    ("vuln_a", ["vuln_a"]), ([1, 2], ["1", "2"]), ([["vuln_a"], None, "", "  "], ["vuln_a"]),
    ([None], []), ("", []), ({"id": "x"}, []), (["x" * 300], ["x" * 120]), ([f"v{i}" for i in range(40)], [f"v{i}" for i in range(16)]),
])
def test_enabled_by_of_any_shape_never_loses_the_finding(value, expected):
    pytest.importorskip("fastmcp")
    from unittest import mock
    import docker
    with mock.patch.object(docker, "from_env", lambda *a, **k: mock.MagicMock()):
        from src import server as srv
    assert srv._enabled_by_refs(value) == expected


@pytest.mark.parametrize("flag", ["DM_LEGACY_DERIVED_PROOF", "DM_FINALIZE_CHAINS_AS_PATHS", "DM_TOOL_PROVENANCE"])
def test_proof_rollback_flags_cannot_be_enabled(monkeypatch, flag):
    from api import feature_flags
    monkeypatch.setenv(flag, "1")
    assert feature_flags.enabled(flag) is False
