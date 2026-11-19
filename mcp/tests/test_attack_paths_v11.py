"""darkmoon-attack-paths/v1 revision 1.1 (ATTACK-PATH-BENCHMARK.md): additive insights, all derived from campaign data."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from api.attack_paths import SCHEMA_REVISION, SCHEMA_VERSION, build_paths, path_detail, simulate  # noqa: E402
from api.attack_paths_schema import DETAIL_SCHEMA, LIST_SCHEMA, SIMULATION_SCHEMA, validate  # noqa: E402
from test_attack_paths import DEMO_ID, FIXTURE, NOW, _assert_no_secret, _load  # noqa: E402


def _doc(monkeypatch, **kw):
    camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
    return (camp, nodes, edges, vulns), build_paths(camp, nodes, edges, vulns, now=NOW, **kw)


def test_revision_is_additive(monkeypatch):
    _, doc = _doc(monkeypatch)
    assert doc["schema_version"] == SCHEMA_VERSION == "darkmoon-attack-paths/v1"
    assert doc["schema_revision"] == SCHEMA_REVISION == "1.3"
    assert validate(doc, LIST_SCHEMA) == []
    _assert_no_secret(doc)


def test_choke_points_match_the_ranking_and_the_simulation(monkeypatch):
    inp, doc = _doc(monkeypatch)
    ins = doc["insights"]
    top = ins["choke_points"][0]
    assert (top["kind"], top["fix_id"], top["paths_eliminated"], top["of_total"]) == ("group", doc["ranking"]["fixes"][0]["fix_id"], 3, 5)
    sim = simulate(*inp, [top["fix_id"]])
    assert sorted(sim["interrupted"]) == top["path_ids"]
    assert sim["simulation"] is True and sim["paths_before"] == 5 and sim["paths_after"] == 2
    assert validate(sim, SIMULATION_SCHEMA) == []
    counts = [c["paths_eliminated"] for c in ins["choke_points"]]
    assert counts == sorted(counts, reverse=True)


def test_choke_points_never_present_a_consequence_as_a_fix(monkeypatch):
    """Reviewer calcul F2: the engine's non-admissible findings (a terminal consequence / indeterminate lead) must be
    excluded from the choke-point FIX surface, so a realised data breach is never shown as « Fix … »."""
    from api.attack_paths import _insights

    def rec(rid, obj, crit, steps, fids):
        return {"id": rid, "entry_node_id": "n_entry", "objective_node_id": obj, "criticality": crit,
                "provenance": "observed", "status": "open", "hypothesis": False, "steps": steps, "finding_ids": fids}
    records = [
        rec("P_sqli", "n_obj", "high", [{"node_id": "n_obj", "satisfied_by": [["sqli"]]}], ["sqli"]),
        # P_breach is interruptible ONLY by the terminal consequence (ghost prerequisite ≠ finding)
        rec("P_breach", "n_crm", "critical",
            [{"node_id": "n_pre", "satisfied_by": [["ghost"]]}, {"node_id": "n_crm", "satisfied_by": [["breach"]]}],
            ["breach"]),
    ]
    a = {"vmap": {"sqli": {"title": "SQL injection", "severity": "high", "status": "confirmed"},
                  "breach": {"title": "CRM customer data breach", "severity": "critical", "status": "confirmed"}},
         "labels": {}, "node_map": {}, "groups": [], "attached": {"sqli": "n_obj", "breach": "n_crm"}}
    ins_unfiltered = _insights(a, records)
    assert any(c["finding_id"] == "breach" for c in ins_unfiltered["choke_points"])  # without the filter it leaks
    ins = _insights(a, records, non_admissible={"breach"})
    choke_fids = {c["finding_id"] for c in ins["choke_points"]} | {f for c in ins["choke_points"] for f in c["finding_ids"]}
    assert "breach" not in choke_fids                                   # the consequence is never a « fix »
    assert "sqli" in choke_fids                                        # the real weakness still surfaces


def test_critical_assets_blast_radius_and_asset_chokes(monkeypatch):
    _, doc = _doc(monkeypatch)
    ins = doc["insights"]
    objectives = {p["objective"]["node_id"] for p in doc["paths"] if not p["hypothesis"]}
    assert {a["node_id"] for a in ins["critical_assets"]} <= objectives
    assert all(a["critical_asset"] == (a["criticality"] in ("critical", "high")) for a in ins["critical_assets"])
    assert sum(a["paths"] for a in ins["critical_assets"]) == ins["paths_considered"]
    assert ins["blast_radius"] and all(b["assets_reached"] >= len(b["objectives"]) for b in ins["blast_radius"])
    assert all(c["paths_through"] >= 2 for c in ins["asset_choke_points"])


def test_toxic_combinations_are_real_sets_of_findings(monkeypatch):
    _, doc = _doc(monkeypatch)
    vids = {f for p in doc["paths"] for f in p["finding_ids"]}
    for t in doc["insights"]["toxic_combinations"]:
        assert len(t["finding_ids"]) >= 2 and set(t["finding_ids"]) <= vids and t["kind"] in ("together", "chain")
        assert set(t["path_ids"]) <= {p["id"] for p in doc["paths"]}


def test_edges_carry_technique_proof_and_evidence(monkeypatch):
    inp, doc = _doc(monkeypatch)
    for p in doc["paths"]:
        det = path_detail(*inp, p["id"])
        assert validate(det, DETAIL_SCHEMA) == [] and det["schema_revision"] == "1.3"
        assert det["path"]["node_ids"][0] == p["entry"]["node_id"]
        for e in det["path"]["edges"]:
            assert e["proof"] in ("exploited", "confirmed", "hypothesis", "none")
            if e["technique"]:
                assert e["technique"]["id"].startswith("T")
            if e["evidence"]:
                assert e["evidence"]["finding_id"] in p["finding_ids"]
        for s in det["path"]["steps"]:
            assert "proof" in s and "technique" in s


def test_no_path_no_insight(monkeypatch):
    camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
    doc = build_paths(camp, nodes, edges, [], now=NOW)
    ins = doc["insights"]
    assert ins["paths_considered"] == 0 and ins["choke_points"] == [] and ins["critical_assets"] == []
