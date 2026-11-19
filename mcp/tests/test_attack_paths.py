"""
Attack paths (darkmoon-attack-paths/v1): engine, gate, groups, observed derivation, documents.

The "equivalence" classes translate the frontend specs of branch fe/base-secu-attackpaths
(attack-path.engine.spec.ts, observed/ranking-gate.spec.ts, observed/remediation-groups.spec.ts,
observed/observed-paths.spec.ts, observed/adversarial-regression.spec.ts) with the same inputs and
the same expected outputs. All values are synthetic (generated from seeds).
"""

from __future__ import annotations

import base64
import copy
import json
import math
import re
import shutil
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import attack_paths_engine as engine_mod  # noqa: E402
from api.attack_chains import RAW_SECRET_KEYS  # noqa: E402
from api.attack_paths import SCHEMA_VERSION, build_paths, fix_label, path_detail, simulate  # noqa: E402
from api.attack_paths_engine import is_scenario_interrupted, prioritize_corrections, ranking_gate  # noqa: E402
from api.attack_paths_observed import (  # noqa: E402
    derive_observed_input,
    executable_lines,
    extract_artefacts,
    group_duplicate_findings,
    in_credential_context,
    is_placeholder,
    mask_line,
    mask_secret,
    normalise_cve,
    normalise_endpoint,
    normalise_title,
)
from api.attack_paths_schema import DETAIL_SCHEMA, LIST_SCHEMA, SIMULATION_SCHEMA, validate  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "chaindemo"
REAL_DATA = Path("/tmp/claude-1000/-home-mehdi/37134759-a62f-4fd5-bbd9-2f74fc4f0e15/scratchpad/focusapi/mcp/data")
NOW = "2026-11-01T00:00:00Z"


# ---------------------------------------------------------------------------
# synthetic fixtures (observed-test-fixtures.ts)
# ---------------------------------------------------------------------------

CAMPAIGN = "camp_synthetic"
HOST = "app.example.test"
BASE = f"http://{HOST}:3000"


def synth_hex(seed: int, length: int) -> str:
    x = (seed & 0xFFFFFFFF) or 1
    out = ""
    while len(out) < length:
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
        out += format(x >> 8, "06x")
    return out[:length]


def synth_b64(seed: int, length: int) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    h = synth_hex(seed, length * 2)
    return "".join(alphabet[int(h[i:i + 2], 16) % 64] for i in range(0, len(h), 2))[:length]


def vuln(vid: str, **o) -> dict:
    evidence = o.pop("evidence", {})
    v = {
        "id": vid, "project_id": "proj", "target_id": "tgt", "campaign_id": CAMPAIGN, "node_id": "",
        "title": f"Synthetic finding {vid}", "severity": "high", "cvss_score": 7, "cvss_vector": "", "cve": None,
        "category": "information_disclosure", "status": "confirmed", "description": "", "remediation": "",
        "endpoint": f"{BASE}/{vid}", "discovered_by_agent": "agent", "discovered_at": "2026-01-01T00:00:00Z",
    }
    v.update(o)
    v["evidence"] = {"commands": [], "payloads": [], "raw_request": "", "raw_response": "", "extracted_data": None,
                     "screenshots": [], "logs": [], "explanation": "", **evidence}
    return v


def node(nid: str, node_type: str, parent, vids=None, **extra) -> dict:
    n = {"id": nid, "campaign_id": CAMPAIGN, "node_type": node_type, "label": nid, "host": HOST, "port": 3000,
         "technology": "", "version": "", "risk_level": "none", "parent_node_id": parent, "vulnerability_ids": vids or []}
    n.update(extra)
    return n


def infra(attach=None, extra_nodes=None) -> list:
    a = attach or {}
    return [
        node("host-1", "host", None, a.get("host-1")),
        node("app", "application", "host-1", a.get("app")),
        node("api", "endpoint", "app", a.get("api")),
        node("db", "service_internal", "host-1", a.get("db"), technology="SQLite 3"),
        *(extra_nodes or []),
    ]


def derive(nodes, vulns):
    return derive_observed_input(nodes, vulns, CAMPAIGN)


def run(d):
    i = d["input"]
    return prioritize_corrections(i["scenarios"], i["findings"], i["groups"])


def links_of(d, *keys):
    return [[l[k] for k in keys] for l in d["links"]]


# engine helpers (attack-path.engine.spec.ts)
def finding(fid, severity="high", cvss=7, node_id=None):
    return {"id": fid, "title": fid, "severity": severity, "cvss_score": cvss, "node_id": node_id}


def scenario(sid, steps, objective=None, criticality="high", provenance="observed"):
    return {"id": sid, "entry_node_id": "entry", "objective_node_id": objective or f"obj-{sid}", "criticality": criticality,
            "provenance": provenance, "steps": [{"node_id": f"{sid}-n{i}", "satisfied_by": s} for i, s in enumerate(steps)]}


def prio(scenarios, findings, groups=None):
    return prioritize_corrections(scenarios, findings, groups)


# ===========================================================================
# 1. Engine (attack-path.engine.spec.ts)
# ===========================================================================

class TestEngineEquivalence:
    def test_interrupts_only_when_every_alternative_of_one_step_is_broken(self):
        s = scenario("s", [[["a"], ["b"]], [["c", "d"]]])
        assert is_scenario_interrupted(s, {"a"}) is False
        assert is_scenario_interrupted(s, {"a", "b"}) is True
        assert is_scenario_interrupted(s, {"d"}) is True
        assert is_scenario_interrupted(scenario("u", [[[]]]), {"x"}) is False

    def test_case_a_shared_fix_interrupts_exactly_eight(self):
        scs = [scenario(f"s{i}", [[["common"]], [[f"own{i}"]]]) for i in range(8)] + [scenario(f"t{i}", [[[f"other{i}"]]]) for i in range(4)]
        fs = [finding("common")] + [finding(f"own{i}") for i in range(8)] + [finding(f"other{i}") for i in range(4)]
        r = prio(scs, fs)
        assert r["status"] == "ok"
        assert r["ranking"][0]["finding_id"] == "common"
        assert r["ranking"][0]["marginal_interrupted"] == [f"s{i}" for i in range(8)]
        assert r["ranking"][0]["remaining_open"] == ["t0", "t1", "t2", "t3"]
        assert "8 of 12" in r["ranking"][0]["explanation"]

    def test_case_b_asset_reachable_another_way_is_never_protected(self):
        r = prio([scenario("via-a", [[["a"]]], "db"), scenario("via-b", [[["b"]]], "db")], [finding("a", "critical", 9.8), finding("b")])
        assert r["ranking"][0]["finding_id"] == "a"
        assert r["ranking"][0]["objectives_closed"] == []
        assert r["ranking"][0]["objectives_still_reachable"] == ["db"]
        assert r["ranking"][1]["objectives_closed"] == ["db"]

    def test_case_c_overlapping_fixes_not_counted_twice(self):
        scs = []
        for i in range(12):
            alts = []
            if i < 8:
                alts.append(["A"])
            if 5 <= i < 10:
                alts.append(["B"])
            if not alts:
                alts.append([f"x{i}"])
            scs.append(scenario(f"s{i}", [*[[a] for a in alts], [[f"ctx{i}"], []]]))
        fs = [finding(x, "low" if x.startswith("ctx") else "high") for x in ["A", "B", "x10", "x11", *[f"ctx{i}" for i in range(12)]]]
        r = prio(scs, fs)
        assert [[c["finding_id"], len(c["standalone_interrupted"]), len(c["marginal_interrupted"])] for c in r["ranking"]] == [
            ["A", 8, 8], ["B", 5, 2], ["x10", 1, 1], ["x11", 1, 1]]
        assert sum(len(c["marginal_interrupted"]) for c in r["ranking"]) == 12

    def test_case_d_unknown_dependencies_excluded(self):
        r = prio([scenario("known", [[]]), scenario("k2", [[], [["a"]]])], [finding("a")])
        assert r["status"] == "insufficient"
        assert r["ranking"] == []
        assert r["incomplete_scenario_ids"] == ["known", "k2"]
        assert "cannot be demonstrated" in r["reason"]

    def test_case_d_bis_objective_with_incomplete_scenario_never_closed(self):
        r = prio([scenario("ok", [[["a"]]], "db"), scenario("unk", [[]], "db")], [finding("a")])
        assert r["ranking"][0]["finding_id"] == "a"
        assert r["ranking"][0]["objectives_closed"] == []
        assert r["ranking"][0]["objectives_still_reachable"] == ["db"]

    def test_case_e_isolated_critical_stays_visible(self):
        r = prio([scenario("s", [[["a"]]])], [finding("a", "medium", 5), finding("iso", "critical", 10)])
        assert [c["finding_id"] for c in r["ranking"]] == ["a"]
        assert r["off_path_findings"] == ["iso"]

    def test_case_f_large_inputs_fast_and_deterministic(self):
        fs = [finding(f"f{i}", "high", (i % 100) / 10) for i in range(800)]
        scs = [scenario(f"s{i}", [[[f"f{i % 800}"], [f"f{(i * 7) % 800}"]], [[f"f{(i * 13) % 800}", f"f{(i * 31) % 800}"]]], f"o{i % 50}") for i in range(3000)]
        t0 = time.perf_counter()
        a = prio(scs, fs)
        elapsed = time.perf_counter() - t0
        b = prio(list(scs), list(fs))
        assert [c["finding_id"] for c in a["ranking"]] == [c["finding_id"] for c in b["ranking"]]
        assert elapsed < 10

    def test_case_g_never_mutates_input(self):
        scs = [scenario("s", [[["a"], ["b"]]])]
        fs = [finding("a"), finding("b")]
        snap = json.dumps({"s": scs, "f": fs})
        prio(scs, fs)
        assert json.dumps({"s": scs, "f": fs}) == snap

    def test_case_c_bis_needs_two_fixes(self):
        r = prio([scenario("s", [[["a"], ["b"]]])], [finding("a"), finding("b")])
        assert r["ranking"] == []
        assert r["multi_fix_scenario_ids"] == ["s"]

    def test_case_j_adversarial_data(self):
        weird = "f-<script>\"'‮"
        cyclic = {**scenario("cyc", [[["a"]], [["b"]], [["a"]]]), "entry_node_id": "n1", "objective_node_id": "n1"}
        r = prio([scenario("dup", [[["a"]]]), scenario("dup", [[["b"]]]), {**scenario("empty", []), "steps": []},
                  scenario("ghost", [[["missing"]]]), scenario("w", [[[weird]]]), cyclic, None],
                 [finding("a"), finding("a", "low"), finding("b"), finding(weird), {**finding("nan"), "cvss_score": float("nan")}])
        assert r["status"] == "ok"
        assert sorted(i["kind"] for i in r["issues"]) == ["duplicate-scenario", "empty-scenario", "unknown-finding"]
        assert [c["finding_id"] for c in r["ranking"]] == ["a", weird]
        assert r["multi_fix_scenario_ids"] == ["ghost"]

    def test_group_ranked_as_one_correction(self):
        scs = [scenario("rce", [[["reg1"], ["reg2"], ["reg3"]], [["rce"]]], "host", "critical")]
        fs = [finding(x) for x in ("reg1", "reg2", "reg3")] + [finding("rce", "critical", 9.8)]
        ungrouped = prio(scs, fs)
        assert [c["finding_id"] for c in ungrouped["ranking"]] == ["rce"]
        assert ungrouped["ranking"][0]["equivalent_alternatives"] == []
        grouped = prio(scs, fs, [{"id": "open-registration", "finding_ids": ["reg1", "reg2", "reg3"], "reason": "x"}])
        assert grouped["ranking"][0]["finding_id"] == "rce"
        assert grouped["ranking"][0]["equivalent_alternatives"] == ["open-registration"]
        assert "reg1" not in [f for c in grouped["ranking"] for f in c["finding_ids"]]

    def test_invalid_groups_rejected_without_dropping_findings(self):
        r = prio([scenario("s", [[["a"]]])], [finding("a"), finding("b")], [{"id": "g", "finding_ids": ["a", "ghost"], "reason": "x"}])
        assert "invalid-group" in [i["kind"] for i in r["issues"]]
        assert [c["finding_ids"] for c in r["ranking"]] == [["a"]]

    def test_refuses_demo_mixed_with_real(self):
        r = prio([scenario("real", [[["a"]]]), scenario("demo", [[["a"]]], provenance="demo")], [finding("a")])
        assert (r["status"], r["provenance"], r["ranking"]) == ("insufficient", "mixed", [])

    def test_documents_tie_break(self):
        r = prio([scenario("s1", [[["a"]]], "o1", "critical"), scenario("s2", [[["b"]]], "o2", "medium")], [finding("a"), finding("b")])
        assert r["ranking"][0]["finding_id"] == "a"
        assert r["ranking"][0]["tie_break"] == "criticality weight of newly interrupted scenarios"

    def test_empty(self):
        r = prio([], [finding("x", "critical")])
        assert r["status"] == "empty"
        assert r["off_path_findings"] == ["x"]


class TestEngineAdversarial:
    def test_defect_01_objective_not_closed_with_active_critical_on_it(self):
        r = prio([scenario("s1", [[["a"]]], "db"), scenario("s2", [[["b"]]], "web")],
                 [finding("a"), finding("b"), finding("db-direct", "critical", 9.8, "db")])
        assert r["off_path_findings"] == ["db-direct"]
        assert "db" not in r["ranking"][0]["objectives_closed"]

    def test_defect_02_never_decisive_critical_stays_listed(self):
        r = prio([scenario("s1", [[["a"]], [["crit"], []]]), scenario("s2", [[["b"]]])], [finding("a"), finding("b"), finding("crit", "critical", 10)])
        shown = set(r["off_path_findings"]) | {f for c in r["ranking"] for f in c["finding_ids"]}
        assert "crit" in shown

    def test_defect_03_equivalent_never_lists_ranked_fix(self):
        r = prio([scenario("s1", [[["a"]], [["b"]]]), scenario("s2", [[["a"], ["b"]]])], [finding("a", "high", 9), finding("b", "high", 1)])
        assert [c["finding_id"] for c in r["ranking"]] == ["a", "b"]
        assert "a" not in r["ranking"][1]["equivalent_alternatives"]

    def test_defect_04_malformed_steps_do_not_crash(self):
        bad = [{**scenario("s1", []), "steps": [{"node_id": "n", "satisfied_by": ["a"]}]},
               {**scenario("s2", []), "steps": [{"node_id": "n", "satisfied_by": [None]}]},
               {**scenario("s3", []), "steps": [None]}]
        for s in bad:
            prio([s, scenario("ok", [[["a"]]])], [finding("a")])

    def test_defect_05_unknown_criticality(self):
        r = prio([scenario("s1", [[["z"]]], "o", "constructor"), scenario("s2", [[["a"]]], "o", "critical")], [finding("a", "high", 1), finding("z", "high", 1)])
        assert r["ranking"][0]["finding_id"] == "a"
        assert r["ranking"][0]["tie_break"] == "criticality weight of newly interrupted scenarios"

    def test_held_j_prototype_unicode_huge_nan(self):
        ids = ["__proto__", "constructor", "toString", "‮evil‬", "x" * 100000]
        r = prio([*[scenario(f"s{i}", [[[x]]]) for i, x in enumerate(ids)], scenario("s0", [[["dup"]]]),
                  scenario("cyc", [[["__proto__"]], [["constructor"]], [["__proto__"]]])],
                 [*[finding(x, "critical", float("nan") if i == 0 else -5) for i, x in enumerate(ids)], finding("__proto__", "high", 99)])
        assert r["status"] == "ok"
        assert r["ranking"][0]["finding_id"] == "__proto__"
        assert any(i["kind"] == "duplicate-scenario" for i in r["issues"])

    def test_malformed_scenarios_reported(self):
        r = prio([{**scenario("s1", []), "steps": "x"}, {**scenario("s2", []), "steps": [{"node_id": "n", "satisfied_by": [["a", 3]]}]},
                  {**scenario("s3", []), "steps": [{"node_id": "n", "satisfied_by": None}]}, scenario("ok", [[["a"]]])], [finding("a"), None])
        assert r["eligible_scenario_ids"] == ["ok"]
        assert [i["scenario_id"] for i in r["issues"] if i["kind"] == "invalid-scenario"] == ["s1", "s2", "s3"]

    def test_non_finite_cvss_and_criticality(self):
        r = prio([scenario("s1", [[["a"]]], "o", float("nan")), scenario("s2", [[["b"]]], "o", "high")],
                 [finding("a", "high", float("nan")), finding("b", "high", float("inf"))])
        assert [c["finding_id"] for c in r["ranking"]] == ["b", "a"]

    def test_volume_cap(self, monkeypatch):
        monkeypatch.setitem(engine_mod.ENGINE_LIMITS, "max_scenarios", 2)
        r = prio([scenario("s1", [[["a"]]]), scenario("s2", [[["a"]], [["b"]]]), scenario("s3", [[["b"]]])], [finding("a"), finding("b")])
        assert (r["status"], len(r["ranking"])) == ("too-large", 0)
        assert "exceed" in r["reason"]
        assert ranking_gate(r)["reason"] == "too-large"
        monkeypatch.setitem(engine_mod.ENGINE_LIMITS, "max_scenarios", 10000)
        monkeypatch.setitem(engine_mod.ENGINE_LIMITS, "max_occurrences", 1)
        assert prio([scenario("s1", [[["a", "b"]]])], [finding("a"), finding("b")])["status"] == "too-large"

    def test_f1_every_high_critical_listed_random(self):
        x = 7

        def rnd():
            nonlocal x
            x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
            return x / 2 ** 32

        for _ in range(300):
            ids = [f"f{i}" for i in range(2 + math.floor(rnd() * 8))]
            pick = lambda: ids[math.floor(rnd() * len(ids))]  # noqa: E731
            fs = [finding(i, "critical" if rnd() < 0.6 else "medium", math.floor(rnd() * 10)) for i in ids]
            scs = [scenario(f"s{i}", [[[] if rnd() < 0.15 else [pick()] for _ in range(math.floor(rnd() * 3))] for _ in range(1 + math.floor(rnd() * 3))])
                   for i in range(1 + math.floor(rnd() * 6))]
            r = prio(scs, fs)
            shown = {f for c in r["ranking"] for f in c["finding_ids"]} | set(r["off_path_findings"])
            for f in fs:
                if f["severity"] == "critical":
                    assert f["id"] in shown

    def test_four_reasons(self):
        r = prio([scenario("s1", [[["a"]], [["alt"], ["a2"]]]), scenario("s2", [[["b"], ["c"]]]), scenario("s3", [[["a"]]]), scenario("s4", [[["d"]], [["a"]]])],
                 [finding("a", "high", 1), finding("alt", "critical"), finding("a2", "low"), finding("b", "critical"), finding("c", "critical"),
                  finding("d", "critical"), finding("iso", "critical")])
        assert [c["finding_id"] for c in r["ranking"]] == ["a"]
        assert {o["id"]: o["reason"] for o in r["off_path"]} == {
            "alt": "never-decisive", "b": "needs-combined-fixes", "c": "needs-combined-fixes", "d": "covered-by-higher-rank", "iso": "outside-chain"}

    def test_f8_active_descendant_keeps_objective_open(self):
        def inp(child_cvss):
            return ([scenario("s1", [[["a"]]], "db"), scenario("s2", [[["p"]], [["child"]]], "x")],
                    [finding("a", "critical", 9), finding("p", "high", 5), {**finding("child", "low", child_cvss, "db-table"), "node_ancestors": ["db", "host"]}])
        r = prio(*inp(1))
        assert [c["finding_id"] for c in r["ranking"]] == ["a", "p"]
        assert r["ranking"][0]["objectives_closed"] == []
        assert r["ranking"][0]["objectives_still_reachable"] == ["db"]
        assert r["ranking"][1]["objectives_closed"] == ["x"]
        later = prio(*inp(9.9))
        assert [c["finding_id"] for c in later["ranking"]] == ["child", "a"]
        assert later["ranking"][0]["objectives_closed"] == ["x"]
        assert later["ranking"][1]["objectives_closed"] == ["db", "x"]

    def test_pseudo_node_never_an_asset(self):
        r = prio([scenario("s1", [[["a"]]], "unresolved:a"), scenario("s2", [[["b"]]], "web")], [finding("a"), finding("b")])
        assert [o for c in r["ranking"] for o in c["objectives_closed"] + c["objectives_still_reachable"]] == ["web"]

    def test_f13_equivalent_compares_marginal_sets(self):
        r = prio([scenario("s1", [[["a"]]]), scenario("s2", [[["a"], ["b"]], [["b"], ["c"], ["d"]]]), scenario("s3", [[["d"]], [["e"]]])],
                 [finding("a", "high", 9), finding("b"), finding("c"), finding("d"), finding("e")])
        for c in r["ranking"]:
            before = {x["finding_id"] for x in r["ranking"] if x["rank"] <= c["rank"]}
            assert not any(i in before for i in c["equivalent_alternatives"])

    def test_perf_2000_findings_8000_scenarios(self):
        nf, ns = 2000, 8000
        fs = [finding(f"f{i}", "high", (i % 100) / 10) for i in range(nf)]
        scs = [scenario(f"s{i}", [[[f"f{i % nf}"], [f"f{(i * 7) % nf}"]], [[f"f{(i * 13) % nf}", f"f{(i * 31) % nf}", f"f{(i * 17) % nf}"]]], f"o{i % 200}")
               for i in range(ns)]
        t0 = time.perf_counter()
        r = prio(scs, fs)
        assert r["status"] == "ok"
        assert time.perf_counter() - t0 < 20


# ===========================================================================
# 2. Gate (ranking-gate.spec.ts)
# ===========================================================================

class TestGateEquivalence:
    def test_tautology_refused(self):
        r = prio([scenario("s1", [[["a"]]]), scenario("s2", [[["b"]]])], [finding("a"), finding("b")])
        assert ranking_gate(r) == {"meaningful": False, "reason": "no-choke-point", "scenario_count": 2, "top_interrupts": 1, "non_trivial_choke_point": False}

    def test_upstream_pivot_allowed(self):
        fs = [{**finding(i), "cvss_score": 9 if i == "p" else 1} for i in ("p", "c", "q", "b")]
        up = prio([scenario("s1", [[["p"]], [["c"]]]), scenario("s2", [[["q"]], [["b"]]])], fs)
        assert up["ranking"][0]["finding_id"] == "p" and up["ranking"][0]["pivot_interrupted"] == ["s1"]
        assert ranking_gate(up) == {"meaningful": True, "reason": "ok", "scenario_count": 2, "top_interrupts": 1, "non_trivial_choke_point": True}

    def test_identical_dependencies_merged(self):
        r = prio([scenario("s1", [[["a"]], [["a"]]]), scenario("s2", [[["a"]], [["a"]]])], [finding("a")])
        assert r["merged_scenarios"] == [{"id": "s2", "into": "s1"}]
        g = ranking_gate(r)
        assert (g["meaningful"], g["reason"], g["scenario_count"]) == (False, "too-few-scenarios", 1)

    def test_real_choke_point(self):
        r = prio([scenario("s1", [[["a"]], [["x"]]]), scenario("s2", [[["a"]], [["y"]]])], [finding("a"), finding("x"), finding("y")])
        g = ranking_gate(r)
        assert (g["meaningful"], g["top_interrupts"], g["non_trivial_choke_point"]) == (True, 2, True)

    def test_server_provenance_accepted(self):
        r = prio([scenario("s1", [[["a"]], [["x"]]], provenance="server"), scenario("s2", [[["a"]], [["y"]]], provenance="server")],
                 [finding("a"), finding("x"), finding("y")])
        assert ranking_gate(r)["meaningful"] is True

    def test_single_scenario_refused(self):
        r = prio([scenario("s1", [[["a"]]])], [finding("a")])
        assert r["status"] == "ok" and ranking_gate(r)["reason"] == "too-few-scenarios"

    def test_demo_and_mixed_refused(self):
        demo = prio([scenario("s1", [[["a"]], [["x"]]], provenance="demo"), scenario("s2", [[["a"]], [["y"]]], provenance="demo")],
                    [finding("a"), finding("x"), finding("y")])
        assert ranking_gate(demo)["reason"] == "provenance-not-real"
        mixed = prio([scenario("s1", [[["a"]]]), scenario("s2", [[["a"]]], provenance="demo")], [finding("a")])
        assert ranking_gate(mixed)["meaningful"] is False
        assert ranking_gate(prio([scenario("s1", [[]]), scenario("s2", [[]])], [finding("a")]))["reason"] == "status-not-ok"
        assert ranking_gate(prio([], []))["reason"] == "status-not-ok"
        mixed_real = prio([scenario("s1", [[["a"]]], provenance="server"), scenario("s2", [[["a"]]])], [finding("a")])
        assert ranking_gate(mixed_real)["meaningful"] is False

    def test_only_combined_fixes(self):
        r = prio([scenario("s1", [[["a"], ["b"]]]), scenario("s2", [[["a"], ["c"]]])], [finding("a"), finding("b"), finding("c")])
        assert r["ranking"] == []
        g = ranking_gate(r)
        assert (g["meaningful"], g["reason"], g["top_interrupts"]) == (False, "top-fix-interrupts-nothing", 0)

    def test_safe_on_missing(self):
        assert ranking_gate(None)["meaningful"] is False
        assert ranking_gate({"status": "ok", "provenance": "observed"})["meaningful"] is False


# ===========================================================================
# 3. Remediation groups (remediation-groups.spec.ts)
# ===========================================================================

def gf(fid, **o):
    f = {"id": fid, "campaign_id": "camp_synthetic", "category": "security_misconfiguration",
         "endpoint": "http://app.example.test:3000/user/sign_up", "cve": None, "title": "Open User Registration"}
    f.update(o)
    return f


def gids(groups):
    return [g["finding_ids"] for g in groups]


class TestGroupsEquivalence:
    def test_exact_duplicates(self):
        groups = group_duplicate_findings([gf("a"), gf("b", title="open user registration.", endpoint="http://APP.example.test:3000/user/sign_up/?next=/"),
                                           gf("c", title="Open  User-Registration")])
        assert gids(groups) == [["a", "b", "c"]]
        assert groups[0]["id"] == "group:a"
        assert "app.example.test:3000/user/sign_up" in groups[0]["reason"]
        assert "one fix removes them all" in groups[0]["reason"]

    def test_same_cve(self):
        groups = group_duplicate_findings([gf("a", cve="CVE-2024-0001", title="Pre-auth RCE"), gf("b", cve="cve-2024-0001", title="Git hook injection")])
        assert gids(groups) == [["a", "b"]]
        assert "CVE-2024-0001" in groups[0]["reason"]

    def test_cve_list(self):
        assert normalise_cve("CVE-2024-0002, CVE-2024-0001") == "CVE-2024-0001,CVE-2024-0002"
        assert gids(group_duplicate_findings([gf("a", cve="CVE-2024-0002, CVE-2024-0001"), gf("b", cve="CVE-2024-0001 CVE-2024-0002")])) == [["a", "b"]]

    @pytest.mark.parametrize("label,other", [
        ("different wording (no CVE)", gf("b", title="Open User Registration Without CAPTCHA")),
        ("different category", gf("b", category="authentication_bypass")),
        ("different path on the same host", gf("b", endpoint="http://app.example.test:3000/user/sign_in")),
        ("same path on another host", gf("b", endpoint="http://other.example.test:3000/user/sign_up")),
        ("same path on another port", gf("b", endpoint="http://app.example.test:8080/user/sign_up")),
        ("another campaign", gf("b", campaign_id="camp_other")),
        ("different CVE with the same title", gf("b", cve="CVE-2024-0009")),
        ("bare path without host", gf("b", endpoint="/user/sign_up")),
        ("different HTTP method", gf("b", endpoint="GET http://app.example.test:3000/user/sign_up")),
    ])
    def test_near_duplicates_never_grouped(self, label, other):
        base = gf("a", cve="CVE-2024-0001") if label == "different CVE with the same title" else gf("a")
        assert group_duplicate_findings([base, other]) == []

    def test_cwe_is_a_class(self):
        assert normalise_cve("CWE-89") is None
        assert group_duplicate_findings([
            gf("a", cve="CWE-89", category="sql_injection", endpoint="GET /rest/products/search?q=", title="UNION-based SQL injection"),
            gf("b", cve="CWE-89", category="sql_injection", endpoint="GET /rest/products/search?q=", title="Soft-deleted products via SQL injection"),
        ]) == []
        assert normalise_cve("CVE-2021-0001 (class); null if not tracked") is None

    def test_spa_hash_routes(self):
        assert normalise_endpoint("http://app.example.test/#/search?q=1") == "app.example.test/#/search"
        assert group_duplicate_findings([gf("a", category="xss_dom", title="DOM XSS", endpoint="http://app.example.test/#/search?q=x"),
                                         gf("b", category="xss_dom", title="DOM XSS", endpoint="http://app.example.test/#/track-result?id=x")]) == []

    def test_free_text_and_missing_fields(self):
        assert normalise_endpoint("Multiple endpoints (see description)") is None
        assert group_duplicate_findings([gf("a", endpoint="Any endpoint"), gf("b", endpoint="Any endpoint")]) == []
        assert group_duplicate_findings([gf("a", category=""), gf("b", category="")]) == []
        assert group_duplicate_findings([gf("a", title=""), gf("b", title="")]) == []

    def test_endpoint_parsing(self):
        assert normalise_endpoint("POST http://h.example.test:3000/rest/user/login") == "POST h.example.test:3000/rest/user/login"
        assert normalise_endpoint("GET /api/Users/") == "GET /api/Users"
        assert normalise_endpoint("127.0.0.1:3000/ftp/") == "127.0.0.1:3000/ftp"
        assert normalise_title("Été — Open, User!") == "ete open user"

    def test_deterministic_and_engine_accepts(self):
        inp = [gf("c"), gf("a"), gf("b"), gf("a"), gf("x", title="Other")]
        groups = group_duplicate_findings(inp)
        assert groups == group_duplicate_findings(list(reversed(inp)))
        assert gids(groups) == [["a", "b", "c"]]
        r = prio([{"id": "s", "entry_node_id": "e", "objective_node_id": "o", "criticality": "high", "provenance": "observed",
                   "steps": [{"node_id": "n", "satisfied_by": [["a"], ["b"], ["c"]]}]}],
                 [{"id": i, "title": i, "severity": "high", "cvss_score": 5, "node_id": None} for i in ("a", "b", "c", "x")], groups)
        assert [i for i in r["issues"] if i["kind"] == "invalid-group"] == []
        assert [c["finding_ids"] for c in r["ranking"]] == [["a", "b", "c"]]

    def test_f10_parameters_and_targets(self):
        assert group_duplicate_findings([{"id": "a", "campaign_id": "c", "category": "sql_injection", "endpoint": "http://h/search?q=1", "title": "SQL Injection"},
                                         {"id": "b", "campaign_id": "c", "category": "sql_injection", "endpoint": "http://h/search?sort=1", "title": "SQL Injection"}]) == []
        assert group_duplicate_findings([{"id": "a", "campaign_id": "c", "category": "xss", "endpoint": "/login", "title": "Reflected XSS", "target_id": "t1"},
                                         {"id": "b", "campaign_id": "c", "category": "xss", "endpoint": "/login", "title": "Reflected XSS", "target_id": "t2"}]) == []
        assert gids(group_duplicate_findings([{"id": "a", "campaign_id": "c", "category": "sql_injection", "endpoint": "http://h/search?q=1", "title": "SQL Injection", "target_id": "t1"},
                                              {"id": "b", "campaign_id": "c", "category": "sql_injection", "endpoint": "http://h/search?q=2", "title": "SQL Injection", "target_id": "t1"}])) == [["a", "b"]]
        assert group_duplicate_findings([{"id": "a", "campaign_id": "c", "category": "sql_injection", "endpoint": "http://h/search", "title": "SQL Injection"},
                                         {"id": "b", "campaign_id": "c", "category": "sql_injection", "endpoint": "http://h/search", "title": "SQL Injection"}]) == []
        assert gids(group_duplicate_findings([
            {"id": "a", "campaign_id": "c", "category": "xss", "endpoint": "/login?u=1", "title": "XSS", "evidence": {"raw_request": "GET /login?u=1 HTTP/1.1\nHost: h1"}},
            {"id": "b", "campaign_id": "c", "category": "xss", "endpoint": "/login?u=1", "title": "XSS", "evidence": {"raw_request": "GET /login?u=2 HTTP/1.1\nHost: h1"}},
        ])) == [["a", "b"]]

    def test_held_never_merged(self):
        assert group_duplicate_findings([
            {"id": "a", "campaign_id": "c", "category": "xss", "endpoint": "http://h1/x", "title": "T"},
            {"id": "b", "campaign_id": "c", "category": "xss", "endpoint": "http://h2/x", "title": "T"},
            {"id": "c", "campaign_id": "c", "category": "sqli", "endpoint": "http://h1/x", "title": "T"},
            {"id": "d", "campaign_id": "c", "category": "xss", "endpoint": "http://h1/x", "title": "T", "cve": "CVE-2024-0001"},
            {"id": "e", "campaign_id": "c", "category": "xss", "endpoint": "http://h1/x", "title": "T", "cve": "CVE-2024-0002"},
            {"id": "f", "campaign_id": "c", "category": "xss", "endpoint": "Multiple endpoints", "title": "T"},
            {"id": "g", "campaign_id": "c", "category": "xss", "endpoint": "Multiple endpoints", "title": "T"},
        ]) == []


# ===========================================================================
# 4. Observed derivation (observed-paths.spec.ts + adversarial-regression.spec.ts)
# ===========================================================================

TOKEN = synth_hex(1, 40)
HASH = synth_hex(2, 32)
SESSION = synth_hex(3, 32)
JWT = f"eyJ{synth_b64(4, 30)}.eyJ{synth_b64(5, 40)}.{synth_b64(6, 43)}"


def producer(pid="reg", **o):
    base = dict(title="Open User Registration Allows Unauthenticated Account Creation", category="security_misconfiguration",
                status="exploited", endpoint=f"{BASE}/user/sign_up",
                evidence={"commands": [f"curl -s -X POST {BASE}/user/sign_up -d 'user_name=tester'"],
                          "raw_request": f"POST /user/sign_up HTTP/1.1\nHost: {HOST}:3000",
                          "raw_response": f'HTTP/1.1 201 Created\n{{"name": "poc", "sha1": "{TOKEN}", "scopes": ["all"]}}'})
    base.update(o)
    return vuln(pid, **base)


def webhook(wid="hook", token=TOKEN, **extra):
    base = dict(title="SSRF via webhook configuration", category="ssrf", endpoint=f"{BASE}/api/v1/repos/tester/fork/hooks",
                evidence={"commands": [f"curl -s -X POST {BASE}/api/v1/repos/tester/fork/hooks -H \"Authorization: token {token}\" -d '{{\"type\":\"gitea\"}}'"],
                          "raw_request": f"POST /api/v1/repos/tester/fork/hooks HTTP/1.1\nHost: {HOST}:3000\nAuthorization: token {token}",
                          "raw_response": "HTTP/1.1 201 Created"})
    base.update(extra)
    return vuln(wid, **base)


class TestObservedR1:
    def test_strict_dependency(self):
        d = derive(infra({"app": ["reg"], "api": ["hook"]}), [producer(), webhook()])
        assert len(d["links"]) == 1
        l = d["links"][0]
        assert [l["kind"], l["producers"], l["consumer"], l["necessary"], l["auxiliary"]] == ["R1", ["reg"], "hook", True, False]
        assert mask_secret(TOKEN, "hex-secret") in l["proof"]
        assert re.match(r"^\[masked hex-secret #[0-9a-f]{4} ~40\]$", mask_secret(TOKEN, "hex-secret"))
        assert TOKEN[:4] not in mask_secret(TOKEN)
        assert [[s["id"], s["provenance"], [t["satisfied_by"] for t in s["steps"]]] for s in d["input"]["scenarios"]] == [
            ["obs-hook", "observed", [[["reg"]], [["hook"]]]]]
        assert d["input"]["scenarios"][0]["objective_node_id"] == "api"

    def test_no_clear_secret(self):
        assert TOKEN not in json.dumps(derive(infra(), [producer(), webhook()]))

    def test_unauthenticated_twin(self):
        reader = vuln("api-read", title="Credentials in .env read through the API", status="exploited", evidence={
            "commands": [f'curl -s -H "Authorization: token {TOKEN}" {BASE}/api/v1/repos/acme/infra-repo/contents/.env'],
            "raw_request": f"GET /api/v1/repos/acme/infra-repo/contents/.env HTTP/1.1\nHost: {HOST}:3000\nAuthorization: token {TOKEN}"})
        twin = vuln("raw-read", title="Public repository exposes .env", evidence={"commands": [f"curl -s {BASE}/acme/infra-repo/raw/branch/main/.env"]})
        d = derive(infra(), [producer(), reader, twin])
        l = next(x for x in d["links"] if x["consumer"] == "api-read")
        assert l["necessary"] is False and l["alternatives"] == ["raw-read"]
        assert d["input"]["scenarios"][0]["steps"][0]["satisfied_by"] == [["raw-read"], ["reg"]]
        assert [c["finding_id"] for c in run(d)["ranking"]] == ["api-read"]

    def test_read_twin_not_alternative_for_write(self):
        twin = vuln("list-hooks", evidence={"commands": [f"curl -s {BASE}/api/v1/repos/tester/fork/hooks"]})
        d = derive(infra(), [producer(), webhook(), twin])
        assert d["links"][0]["alternatives"] == [] and d["links"][0]["necessary"] is True

    def test_auxiliary(self):
        leak = vuln("leak", evidence={"commands": [f"curl -s {BASE}/", f'curl -s -H "Authorization: token {TOKEN}" {BASE}/api/v1/users/admin'],
                                      "raw_request": f"GET / HTTP/1.1\nHost: {HOST}:3000"})
        d = derive(infra(), [producer(), leak])
        assert d["links"][0]["auxiliary"] is True and d["links"][0]["necessary"] is False
        assert d["input"]["scenarios"] == []

    def test_truncated_jwt(self):
        header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
        a = producer("jwt-src", category="authentication_bypass", evidence={"raw_response": f'{{"token":"{header}...","note":"{header}"}}'})
        b = vuln("jwt-use", evidence={"commands": [f'curl -H "Authorization: Bearer {header}..." {BASE}/rest/basket/1', f'curl -H "Authorization: Bearer {header}" {BASE}/rest/basket/2'],
                                      "raw_request": f"GET /rest/basket/1 HTTP/1.1\nHost: {HOST}\nAuthorization: Bearer {header}..."})
        assert extract_artefacts(f"{header}...") == []
        assert derive(infra(), [a, b])["links"] == []

    def test_complete_jwt_links(self):
        a = producer("jwt-src", category="authentication_bypass", evidence={"raw_response": f'{{"authentication":{{"token":"{JWT}"}}}}'})
        b = vuln("jwt-use", evidence={"raw_request": f"GET /rest/basket/1 HTTP/1.1\nHost: {HOST}\nAuthorization: Bearer {JWT}"})
        d = derive(infra(), [a, b])
        assert [[l["kind"], l["producers"][0], l["consumer"]] for l in d["links"]] == [["R1", "jwt-src", "jwt-use"]]
        assert JWT not in json.dumps(d)

    def test_set_cookie_not_artefact(self):
        a = producer("cookie-src", category="sql_injection", evidence={"raw_response": f"HTTP/1.1 200 OK\nSet-Cookie: PHPSESSID={SESSION}; path=/"})
        b = vuln("upload", evidence={"commands": [f'curl -b "PHPSESSID={SESSION}" -F file=@shell.php {BASE}/upload.php'],
                                     "raw_request": f"POST /upload.php HTTP/1.1\nHost: {HOST}\nCookie: PHPSESSID={SESSION}"})
        assert derive(infra(), [a, b])["links"] == []

    def test_not_exploited_or_not_granting(self):
        body = f'{{"session_token": "{SESSION}x"}}'
        b = vuln("use", evidence={"raw_request": f"GET /admin HTTP/1.1\nHost: {HOST}\nCookie: session={SESSION}x"})
        ne = derive(infra(), [producer("c1", status="confirmed", evidence={"raw_response": body}), b])
        assert ne["links"] == [] and ne["rejected"] == [{"producer": "c1", "consumer": "use", "rule": "producer-not-exploited"}]
        ng = derive(infra(), [producer("c2", category="insecure_cookie", evidence={"raw_response": body}), b])
        assert ng["links"] == [] and ng["rejected"][0]["rule"] == "producer-not-granting"

    def test_consumer_obtained_it(self):
        a = producer("sqli", category="sql_injection", evidence={"raw_response": f'[{{"email":"admin@example.test","password":"{HASH}"}}]'})
        b = vuln("crack", status="exploited", evidence={"commands": [f"curl -s \"{BASE}/rest/products/search?q=x\" -H 'Authorization: Bearer {HASH}'"],
                                                        "raw_response": f"password={HASH}"})
        d = derive(infra(), [a, b])
        assert d["links"] == [] and [r["rule"] for r in d["rejected"]] == ["consumer-obtained-it"]

    def test_comments_and_prose(self):
        b = vuln("prose", evidence={"commands": [f'# curl -H "Authorization: token {TOKEN}" {BASE}/api/v1/admin', f"// Result: token={TOKEN}",
                                                 f"JWT token decode revealing token={TOKEN}", f"curl -s {BASE}/ // token={TOKEN} reused"]})
        assert executable_lines(b["evidence"]["commands"]) == [f"curl -s {BASE}/"]
        assert derive(infra(), [producer(), b])["links"] == []

    def test_anonymisation_tokens(self):
        a = producer("anon", evidence={"raw_response": "password: IP_PRIVATE_002\napi_key=EMAIL_USER_001 http://IP_PRIVATE_002:8080"})
        b = vuln("anon-use", evidence={"commands": [f'curl -u admin:IP_PRIVATE_002 -H "X-Api-Key: EMAIL_USER_001" {BASE}/admin']})
        assert extract_artefacts("password: IP_PRIVATE_002\napi_key=EMAIL_USER_001") == []
        assert derive(infra(), [a, b])["links"] == []

    def test_placeholders_reported_masked(self):
        a = producer("ph", evidence={"raw_response": "token: <admin_token>\naccess_token=$TOKEN"})
        b = vuln("ph-use", evidence={"commands": [f'curl -H "Authorization: Bearer <admin_token>" {BASE}/api/x', f'curl -H "Authorization: Bearer $TOKEN" {BASE}/api/y']})
        d = derive(infra(), [a, b])
        assert d["links"] == []
        assert next(i for i in d["issues"] if i["kind"] == "masked-credentials")["finding_ids"] == ["ph-use"]

    def test_self_minted(self):
        b = vuln("self", evidence={"commands": [f"T=$(curl -s -X POST {BASE}/login)  {TOKEN}", f'curl -H "Authorization: token {TOKEN}" {BASE}/api/v1/admin']})
        d = derive(infra(), [producer(), b])
        assert d["links"] == [] and [r["rule"] for r in d["rejected"]] == ["consumer-minted-it"]

    def test_target_host_not_internal_discovery(self):
        a = producer("rce", category="remote_code_execution", evidence={"raw_response": "inet 10.20.0.5/24 and 172.18.0.9"})
        b = vuln("scan", endpoint="http://10.20.0.5:8080/", evidence={"commands": ["curl -s http://10.20.0.5:8080/", "curl -s http://172.18.0.9:6379/"]})
        d = derive(infra(), [a, b])
        assert [l["capability"] for l in d["links"]] == ["reused internal-endpoint"]
        assert "172." in d["links"][0]["proof"] and "10.20.0.5" not in d["links"][0]["proof"]


REGS = [vuln(rid, title=t, category=c, status="exploited" if i == 0 else "confirmed", endpoint=f"{BASE}/user/sign_up")
        for i, (rid, t, c) in enumerate([
            ("reg-a", "Open User Registration Allows Unauthenticated Account Creation", "security_misconfiguration"),
            ("reg-b", "Open User Registration Without Restrictions", "security_misconfiguration"),
            ("reg-c", "Open User Registration Without CAPTCHA", "authentication_bypass")])]
RCE = vuln("rce", title="Remote code execution via git hook injection", category="remote_code_execution", status="exploited", severity="critical",
           endpoint=f"{BASE}/api/v1/repos/{{owner}}/{{repo}}/diffpatch", evidence={
               "raw_request": f"POST /api/v1/repos/tester/poc/diffpatch HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Basic {synth_b64(9, 20)}=",
               "payloads": ["cat /etc/passwd"], "raw_response": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1",
               "logs": ["1. POST /user/sign_up -> 303 (Account created successfully as tester)", "3. POST diffpatch with cat /etc/passwd payload -> 201"]})


class TestObservedR2:
    def test_successful_registration_call(self):
        d = derive(infra({"app": ["reg-a", "reg-b", "reg-c"], "api": ["rce"]}), [*REGS, RCE])
        r2 = next(l for l in d["links"] if l["kind"] == "R2")
        assert [r2["producers"], r2["consumer"], r2["necessary"]] == [["reg-a", "reg-b", "reg-c"], "rce", True]
        assert "/user/sign_up -> 303" in r2["proof"]
        r3 = next(l for l in d["links"] if l["kind"] == "R3")
        assert [r3["consumer"], r3["from_node_id"], r3["to_node_id"]] == ["rce", "api", "host-1"]
        # R2 isolation (52-arch-d-final-review): the R2 link is a historical INFERENCE (endpoint match). The chain through
        # it is kept (its step says « inferred »); the R3 reach, the server's own observation, is a path of its own
        assert [r2["level"], r2["provenance"]] == ["inferred", "inferred"] and "never a proof" in r2["inference_note"]
        assert {s["id"]: [t["satisfied_by"] for t in s["steps"]] for s in d["input"]["scenarios"]} == {
            "obs-rce-reach-host-1": [[["reg-a"], ["reg-b"], ["reg-c"]], [["rce"]], [["rce"]]],
            "obs-rce-reach-host-1-observed": [[["rce"]], [["rce"]]]}
        assert d["input"]["scenarios"][0]["steps"][0]["impact"]["level"] == "inferred"
        assert all(s["objective_node_id"] == "host-1" for s in d["input"]["scenarios"])

    def test_mass_assignment_not_open_registration(self):
        mass = vuln("mass", title="Mass Assignment - Self-Registration Grants Arbitrary Role (admin)", category="mass_assignment", status="exploited", endpoint="POST /api/Users")
        idor = vuln("idor", status="exploited", endpoint="GET /api/Users/", evidence={
            "raw_request": f"GET /api/Users/ HTTP/1.1\nHost: {HOST}\nAuthorization: Bearer $LOW_TOKEN",
            "logs": ["POST /api/Users (register lowpriv@example.test) -> 200, role=customer"]})
        assert derive(infra(), [mass, idor])["links"] == []

    def test_auxiliary_when_unauthenticated(self):
        anon = vuln("anon", evidence={"raw_request": f"GET /explore/users HTTP/1.1\nHost: {HOST}", "logs": ["POST /user/sign_up -> 303 created"]})
        d = derive(infra(), [REGS[0], anon])
        assert d["links"][0]["auxiliary"] is True and d["input"]["scenarios"] == []

    def test_failed_registration_ignored(self):
        failed = vuln("failed", evidence={"raw_request": "GET /x HTTP/1.1\nAuthorization: Basic abc", "logs": ["POST /user/sign_up -> 403 Forbidden"]})
        assert derive(infra(), [REGS[0], failed])["links"] == []

    def _reg(self):
        return vuln("reg", title="Open user registration", category="security_misconfiguration", status="exploited", endpoint=f"POST {BASE}/api/Users")

    def _consumer(self, logs, raw=f"GET /rest/basket/7 HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Bearer x\nX-User: mallory01"):
        return vuln("q", category="idor", status="exploited", evidence={"raw_request": raw, "logs": logs})

    def test_f5_needs_post_exact_path_status_identity(self):
        reg = self._reg()
        ok = derive(infra(), [reg, self._consumer(['POST /api/Users {"email":"mallory01"} -> 201'])])["links"]
        assert [[l["kind"], l["necessary"], l["auxiliary"]] for l in ok] == [["R2", True, False]]
        assert derive(infra(), [reg, self._consumer(['GET /api/Users {"email":"mallory01"} -> 201'])])["links"] == []
        assert derive(infra(), [reg, self._consumer(['POST /api/Users/7 {"email":"mallory01"} -> 201'])])["links"] == []
        assert derive(infra(), [reg, self._consumer(['POST /api/Users {"email":"mallory01","age":201} failed'])])["links"] == []
        other = derive(infra(), [reg, self._consumer(['POST /api/Users {"email":"eve0001"} -> 201'])])
        assert [[l["auxiliary"], l["necessary"]] for l in other["links"]] == [[True, False]]
        assert "not shown in an authenticated request" in other["links"][0]["necessity_note"]
        assert other["input"]["scenarios"] == []

    def test_identity_in_basic_credential(self):
        basic = base64.b64encode(b"mallory01:Zq9!pass").decode()
        d = derive(infra(), [self._reg(), self._consumer(["POST /api/Users user=mallory01 -> 201"], f"GET /x HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Basic {basic}")])
        assert [l["auxiliary"] for l in d["links"]] == [False]
        assert basic not in json.dumps(d)

    def test_defect_11_substring_path_and_any_200(self):
        reg = vuln("reg", title="Open user registration", category="security_misconfiguration", status="exploited", endpoint=f"POST {BASE}/api/Users")
        idor = vuln("idor", category="idor", status="exploited", endpoint=f"{BASE}/api/Users/5", evidence={
            "commands": [f'curl -s {BASE}/api/Users/5 -H "Authorization: Bearer $ADMIN_JWT"'],
            "raw_request": f"GET /api/Users/5 HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Bearer x", "logs": ["GET /api/Users/5 -> 200 (email of user 5 returned)"]})
        assert [l for l in derive(infra(), [reg, idor])["links"] if l["kind"] == "R2"] == []

    def test_defect_17b_r2_proof_masks_cookie(self):
        cookie = synth_b64(32, 26)
        reg = vuln("reg", title="Open user registration", category="security_misconfiguration", status="exploited", endpoint=f"{BASE}/user/sign_up")
        q = vuln("q", category="remote_code_execution", status="exploited", evidence={
            "commands": [f'curl -s -X POST {BASE}/user/sign_up -H "Cookie: gitea_session={cookie}" -d u=t # -> 303'],
            "logs": [f'POST /user/sign_up -H "Cookie: gitea_session={cookie}" -> 303'],
            "raw_request": f"POST /repo/hook HTTP/1.1\nHost: {HOST}:3000\nCookie: gitea_session={cookie}"})
        d = derive(infra(), [reg, q])
        assert len(d["links"]) > 0 and cookie not in json.dumps(d["links"])


class TestObservedR3:
    @staticmethod
    def lfi(status, request=f"GET /download?file=../../../../etc/passwd HTTP/1.1\nHost: {HOST}"):
        return vuln("lfi", category="path_traversal", status=status, evidence={"raw_request": request, "raw_response": "root:x:0:0:root:/root:/bin/bash"})

    def test_reaches_host(self):
        d = derive(infra({"api": ["lfi"]}), [self.lfi("exploited")])
        assert [[l["kind"], l["from_node_id"], l["to_node_id"], l["capability"]] for l in d["links"]] == [["R3", "api", "host-1", "system account file read on the host"]]
        assert d["input"]["scenarios"][0]["id"] == "obs-lfi-reach-host-1"

    def test_requires_exploited_and_file_request(self):
        assert derive(infra({"api": ["lfi"]}), [self.lfi("confirmed")])["links"] == []
        assert derive(infra({"api": ["lfi"]}), [self.lfi("exploited", "GET /about HTTP/1.1")])["links"] == []

    def test_no_reach_to_own_node(self):
        assert derive(infra({"host-1": ["lfi"]}), [self.lfi("exploited")])["links"] == []

    SQLI = vuln("sqli", category="sql_injection", status="exploited", description="UNION injection on the SQLite backend",
                evidence={"raw_response": f'HTTP/1.1 200 OK\n[{{"id":1,"email":"a@example.test","password":"{HASH}"}}] -- SQLITE_ERROR near UNION'})

    def test_unique_database(self):
        d = derive(infra({"app": ["sqli"]}), [self.SQLI])
        assert [[l["kind"], l["to_node_id"], l["capability"]] for l in d["links"]] == [["R3", "db", "sqlite database read"]]
        assert HASH not in json.dumps(d)

    def test_ambiguous_database(self):
        second = node("db-2", "service_internal", "host-1", [], technology="sqlite")
        assert derive(infra({"app": ["sqli"]}, [second]), [self.SQLI])["links"] == []

    def test_f9_response_not_logs(self):
        def lfi(resp, logs=()):
            return vuln("lfi", category="path_traversal", status="exploited", evidence={"commands": [f'curl -s "{BASE}/dl?f=../../etc/passwd"'], "raw_response": resp, "logs": list(logs)})
        assert len(derive(infra({"api": ["lfi"]}), [lfi("HTTP/1.1 200 OK\n\nroot:x:0:0:root:/root:/bin/bash")])["links"]) == 1
        assert derive(infra({"api": ["lfi"]}), [lfi("HTTP/1.1 403 Forbidden\n\nroot:x:0:0:root:/root:/bin/bash")])["links"] == []
        assert derive(infra({"api": ["lfi"]}), [lfi("HTTP/1.1 200 OK", ["root:x:0:0:root:/root:/bin/bash"])])["links"] == []
        page = "HTTP/1.1 410 Gone\n<pre>root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>"
        assert [l["capability"] for l in derive(infra({"api": ["lfi"]}), [lfi(page)])["links"]] == ["system account file read on the host"]

    def test_engine_never_from_description(self):
        s = vuln("s", category="sql_injection", status="exploited", description="SQLite backend", evidence={"raw_response": f'HTTP/1.1 200 OK\n[{{"h":"{synth_hex(44, 32)}"}}]'})
        assert derive(infra({"api": ["s"]}), [s])["links"] == []


class TestObservedScenariosAndGate:
    @staticmethod
    def build(same):
        regs = [producer(rid, title="Open User Registration" if same else t, category="security_misconfiguration" if same else c,
                         status="exploited" if i == 0 else "confirmed")
                for i, (rid, t, c) in enumerate([("reg-a", "Open User Registration Allows Account Creation", "security_misconfiguration"),
                                                  ("reg-b", "Open User Registration Without Restrictions", "security_misconfiguration"),
                                                  ("reg-c", "Open User Registration Without CAPTCHA", "authentication_bypass")])]
        rce = vuln("rce", category="remote_code_execution", status="exploited", evidence={
            "raw_request": f"POST /api/v1/repos/tester/poc/diffpatch HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Basic {synth_b64(9, 20)}=",
            "payloads": ["cat /etc/passwd"], "raw_response": "root:x:0:0:root:/root:/bin/sh",
            "logs": ["POST /user/sign_up -> 303 (Account created as tester)", "payload: cat /etc/passwd"]})
        return derive(infra({"app": ["reg-a", "reg-b", "reg-c"], "api": ["rce", "hook"]}), [*regs, rce, webhook()])

    @staticmethod
    def observed(d):
        """What the pipeline ranks: scenarios resting on the R2 inference are hypotheses (R2-ISOLATION.md)."""
        i = d["input"]
        return prioritize_corrections([s for s in i["scenarios"] if s["provenance"] == "observed"], i["findings"], i["groups"])

    def test_strict_grouping_no_choke_point(self):
        d = self.build(False)
        assert d["input"]["groups"] == []
        # the R2-inferred chain is « inferred »: mixed with real scenarios the engine's gate refuses to rank
        assert ranking_gate(run(d))["reason"] == "provenance-not-real"
        r = self.observed(d)
        assert r["eligible_scenario_ids"] == ["obs-hook", "obs-rce-reach-host-1-observed"]
        g = ranking_gate(r)
        assert [g["meaningful"], g["reason"], g["top_interrupts"], g["non_trivial_choke_point"]] == [False, "no-choke-point", 1, False]

    def test_exact_duplicates_choke_point(self):
        d = self.build(True)
        assert [g["finding_ids"] for g in d["input"]["groups"]] == [["reg-a", "reg-b", "reg-c"]]
        r = self.observed(d)
        assert r["ranking"][0]["finding_ids"] == ["reg-a", "reg-b", "reg-c"]
        # R2 isolation: the registration group no longer « interrupts » the RCE reach through the R2 inference
        assert r["ranking"][0]["standalone_interrupted"] == ["obs-hook"]
        g = ranking_gate(r)
        assert (g["meaningful"], g["non_trivial_choke_point"], g["top_interrupts"]) == (True, True, 1)

    def test_defect_06_one_finding_two_reaches(self):
        sqli = vuln("sqli", title="SQL injection with file read", category="sql_injection", status="exploited", severity="critical", evidence={
            "commands": [f"curl \"{BASE}/search?q=x' UNION SELECT load_file('/etc/passwd')--\""],
            "raw_response": f"root:x:0:0:root:/root:/bin/bash\n{synth_hex(9, 32)} sqlite_master"})
        d = derive(infra({"api": ["sqli"]}), [sqli])
        g = ranking_gate(run(d))
        assert len(d["input"]["scenarios"]) == 2
        assert not (g["meaningful"] and g["non_trivial_choke_point"])

    def test_robustness_excluded(self):
        d = derive(infra(), [producer(), webhook("hook", TOKEN, status="false_positive"), vuln("fixed", status="remediated")])
        assert d["links"] == []
        assert [f["id"] for f in d["input"]["findings"]] == ["reg"]
        assert next(i for i in d["issues"] if i["kind"] == "excluded-findings")["finding_ids"] == ["fixed", "hook"]

    def test_unresolved_nodes(self):
        d = derive(infra(), [producer(), webhook()])
        assert [s["node_id"] for s in d["input"]["scenarios"][0]["steps"]] == ["unresolved:reg", "unresolved:hook"]
        assert next(i for i in d["issues"] if i["kind"] == "unresolved-node")["finding_ids"] == ["hook", "reg"]

    def test_pure_deterministic_tolerant(self):
        vulns = [producer(), webhook()]
        graph = infra({"app": ["reg"]})
        snap = json.dumps({"v": vulns, "g": graph})
        a = derive(graph, vulns)
        b = derive(graph, list(reversed(vulns)))
        assert json.dumps({"v": vulns, "g": graph}) == snap
        assert b["input"]["scenarios"] == a["input"]["scenarios"]
        assert derive_observed_input(None, None)["input"] == {"scenarios": [], "findings": [], "groups": []}
        odd = vuln("odd", evidence={"commands": "not-a-list", "logs": [{"nested": True}], "raw_request": None})
        derive(graph, [odd])

    def test_ancestors_passed_to_engine(self):
        d = derive(infra({"api": ["p"]}), [vuln("p")])
        f = d["input"]["findings"][0]
        assert (f["node_id"], f["node_ancestors"]) == ("api", ["app", "host-1"])


class TestObservedAdversarial:
    TOK = synth_hex(11, 40)

    def test_defect_08_value_after_non_credential_header(self):
        sha = synth_hex(12, 40)
        a = vuln("a", category="information_disclosure", status="exploited", evidence={"raw_response": f'[{{"sha":"{sha}","message":"init"}}]'})
        b = vuln("b", category="idor", endpoint=f"{BASE}/api/v1/repos/o/r/git/commits/{sha}", evidence={
            "commands": [f'curl -s -H "Accept: application/json" {BASE}/api/v1/repos/o/r/git/commits/{sha}'],
            "raw_request": f"GET /api/v1/repos/o/r/git/commits/{sha} HTTP/1.1\nHost: {HOST}:3000", "raw_response": "HTTP/1.1 200 OK"})
        assert [l for l in derive(infra(), [a, b])["links"] if l["kind"] == "R1"] == []

    def test_defect_09_tester_chosen_password(self):
        pw = f"Tq{synth_b64(13, 10)}9#"
        reg = vuln("reg", title="Account registration", category="information_disclosure", status="confirmed", evidence={
            "commands": [f"curl -s -X POST {BASE}/register -d '{{\"email\":\"t@x.test\",\"password\":\"{pw}\"}}'"], "raw_response": "HTTP/1.1 201 Created"})
        dump = vuln("dump", category="sql_injection", status="exploited", evidence={"raw_response": f'[{{"email":"t@x.test","password":"{pw}"}}]'})
        use = vuln("use", category="idor", evidence={"commands": [f"curl -s -X POST {BASE}/api/orders -u t@x.test:{pw}"],
                                                     "raw_request": f"POST /api/orders HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Basic x\npassword={pw}"})
        d = derive(infra(), [reg, dump, use])
        assert not any("dump" in l["producers"] and l["consumer"] == "use" for l in d["links"])

    def test_defect_10_narrative_not_output(self):
        a = vuln("a", category="information_disclosure", status="exploited", evidence={"logs": [f"Step 3: authenticated with token={self.TOK} (ours) to confirm the leak"], "raw_response": "HTTP/1.1 200 OK"})
        b = vuln("b", category="ssrf", evidence={"commands": [f'curl -s -X POST {BASE}/api/hooks -H "Authorization: token {self.TOK}"'],
                                                 "raw_request": f"POST /api/hooks HTTP/1.1\nHost: {HOST}:3000\nAuthorization: token {self.TOK}"})
        assert derive(infra(), [a, b])["links"] == []

    def test_defect_12_13_r3_from_logs(self):
        x = vuln("x", category="path_traversal", status="exploited", evidence={"commands": [f'curl -s "{BASE}/download?f=../../etc/passwd"'], "raw_response": "HTTP/1.1 403 Forbidden",
                                                                               "logs": ["looked for root:x:0:0: in /etc/passwd output: blocked by WAF"]})
        assert [l for l in derive(infra({"api": ["x"]}), [x])["links"] if l["kind"] == "R3"] == []
        s = vuln("s", category="sql_injection", status="exploited", description="Error-based injection on a MySQL-like backend? sqlite suspected",
                 evidence={"logs": ["payload: ' UNION SELECT name FROM sqlite_master--"], "raw_response": "HTTP/1.1 500 Internal Server Error"})
        assert [l for l in derive(infra({"api": ["s"]}), [s])["links"] if l["kind"] == "R3"] == []

    def test_defect_14_unconfirmed_consumer(self):
        p = vuln("p", category="sql_injection", status="exploited", evidence={"raw_response": f'{{"token":"{self.TOK}"}}'})
        q = vuln("q", category="ssrf", status="unconfirmed", evidence={"commands": [f'curl -s -X POST {BASE}/api/hooks -H "Authorization: token {self.TOK}"'],
                                                                       "raw_request": f"POST /api/hooks HTTP/1.1\nHost: {HOST}:3000\nAuthorization: token {self.TOK}"})
        assert derive(infra(), [p, q])["input"]["scenarios"] == []

    def test_held_never_link_values(self):
        outs = ["IP_PRIVATE_002", "EMAIL_USER_001", "eyJhbGciOiJIUzI1NiJ9…", "d41d8cd98f00b204e9800998ecf8427e", f"set-cookie: sid={synth_hex(20, 32)}"]
        a = vuln("a", category="information_disclosure", status="exploited", evidence={"raw_response": "\n".join(outs)})
        b = vuln("b", category="ssrf", evidence={"commands": [*[f'curl -s -X POST {BASE}/h -H "Authorization: token {o}"' for o in outs],
                                                              f'# curl -X POST {BASE}/h -H "Cookie: sid={synth_hex(20, 32)}"',
                                                              f'curl -X POST {BASE}/h -H "Cookie: sid={synth_hex(20, 32)}"']})
        assert derive(infra(), [a, b])["links"] == []

    def test_defect_20_placeholder_variants(self):
        a = vuln("a", category="information_disclosure", status="exploited", evidence={"raw_response": "example config: token=changeme123"})
        b = vuln("b", category="ssrf", evidence={"commands": [f'curl -s -X POST {BASE}/h -H "Authorization: token changeme123"']})
        assert derive(infra(), [a, b])["links"] == []
        for v in ["changeme123", "password!", "admin2024#", "secret_01", "Passw0rd"]:
            assert is_placeholder(v) is True
        for v in ["Tq8#kLm2xV", "hunter2-is-not-a-default"]:
            assert is_placeholder(v) is False

    def test_held_self_link_rejected(self):
        a = vuln("a", category="sql_injection", status="exploited", evidence={"raw_response": f'{{"token":"{self.TOK}"}}', "commands": [f'curl -H "Authorization: token {self.TOK}" {BASE}/x']})
        b = vuln("b", category="ssrf", evidence={"commands": [f"T=$(curl -s {BASE}/t); echo {self.TOK}", f'curl -X POST {BASE}/h -H "Authorization: token {self.TOK}"']})
        assert derive(infra(), [a, b])["links"] == []

    def test_f3_credential_slots(self):
        v = synth_hex(40, 40)
        assert in_credential_context(f'curl -H "Authorization: token {v}" {BASE}/x', v, "hex-secret") is True
        assert in_credential_context(f"GET /x HTTP/1.1\nCookie: sid={v}\nAccept: */*", v, "hex-secret") is True
        assert in_credential_context(f'curl -H "X-Gitea-Token: {v}" {BASE}/x', v, "hex-secret") is True
        assert in_credential_context(f"curl -u admin:{v} {BASE}/x", f"admin:{v}", "basic-auth") is True
        assert in_credential_context(f'curl -b "sid={v}" {BASE}/x', v, "hex-secret") is True
        assert in_credential_context(f'curl -H "Accept: json" {BASE}/commits/{v}', v, "hex-secret") is False
        assert in_credential_context(f"curl -H \"Authorization: token x\" -d '{{\"sha\":\"{v}\"}}' {BASE}/x", v, "hex-secret") is False
        assert in_credential_context(f"curl -u admin:pw {BASE}/x?ref={v}", v, "hex-secret") is False
        assert in_credential_context(f"curl {BASE}/x?token={v}", v, "hex-secret") is False

    def test_f4_producer_output(self):
        tok = synth_hex(41, 40)
        use = vuln("use", category="ssrf", evidence={"raw_request": f"POST /api/hooks HTTP/1.1\nHost: {HOST}:3000\nAuthorization: token {tok}"})
        in_logs = vuln("p", category="information_disclosure", status="exploited", evidence={"logs": [f'leaked {{"sha1":"{tok}"}}']})
        assert derive(infra(), [in_logs, use])["links"] == []
        in_resp = vuln("p", category="information_disclosure", status="exploited", evidence={"raw_response": f'{{"sha1":"{tok}"}}'})
        assert [[l["kind"], l["producers"], l["consumer"]] for l in derive(infra(), [in_resp, use])["links"]] == [["R1", ["p"], "use"]]
        tok2 = synth_hex(42, 40)
        p = vuln("p", category="sql_injection", status="exploited", evidence={"raw_response": f'{{"api_key":"{tok2}"}}'})
        setter = vuln("setter", evidence={"commands": [f"curl -s -X POST {BASE}/keys -d '{{\"key\":\"{tok2}\"}}'"]})
        use2 = vuln("use", category="ssrf", evidence={"raw_request": f"GET /admin HTTP/1.1\nHost: {HOST}:3000\nX-Api-Key: {tok2}"})
        d = derive(infra(), [p, setter, use2])
        assert d["links"] == [] and d["rejected"] == [{"producer": "p", "consumer": "use", "rule": "tester-supplied"}]

    def test_f14_human_chosen_secret_uniqueness(self):
        pw = f"Tq{synth_b64(45, 10)}9#"
        tok = synth_hex(46, 40)

        def leak(lid):
            return vuln(lid, category="information_disclosure", status="exploited", evidence={"raw_response": f"db_password={pw}\napi_token={tok}"})
        use = vuln("use", category="ssrf", evidence={"commands": [f"curl -s -u svc:{pw} {BASE}/a", f'curl -s -X POST {BASE}/b -H "Authorization: token {tok}"']})
        d = derive(infra(), [leak("l1"), leak("l2"), use])
        assert [[l["producers"], l["capability"]] for l in d["links"]] == [[["l1", "l2"], "reused hex-secret"]]
        assert [r["producer"] for r in d["rejected"] if r["rule"] == "value-not-unique"] == ["l1", "l2"]


class TestMasking:
    def test_mask_line_no_double_masking(self):
        masked = mask_line(f"POST /login token={TOKEN} Authorization: Bearer {JWT} password=Hunter2!x")
        assert TOKEN not in masked and JWT not in masked and "Hunter2!x" not in masked
        assert mask_secret(TOKEN, "hex-secret") in masked
        assert len(re.findall(r"\[masked ", masked)) == 3

    def test_defect_15_16_17(self):
        assert "Qw9#" not in mask_secret("Qw9#Lk2!")
        v = next(a for a in extract_artefacts(f"curl -u ab:Zx9#Lm2!Qp {BASE}/x") if a["kind"] == "basic-auth")["value"]
        assert "ab:Z" not in mask_secret(v)
        bearer, cookie = synth_b64(30, 28), synth_b64(31, 26)
        out = [mask_line(l) for l in [f'curl -s -X POST {BASE}/user/sign_up -H "Authorization: Bearer {bearer}" -> 201',
                                      f'curl -s -X POST {BASE}/user/sign_up -H "Cookie: gitea_session={cookie}" -> 303',
                                      f"curl -s -u admin:changeme {BASE}/user/sign_up -> 200"]]
        assert bearer not in out[0] and cookie not in out[1] and "admin:changeme" not in out[2]
        jwt = f"eyJ{synth_b64(1, 20)}.eyJ{synth_b64(2, 30)}.{synth_b64(3, 43)}"
        assert jwt not in mask_line(f"Authorization: Bearer {jwt}")
        json.dumps(mask_secret("ab\U0001F511cdefgh"))

    def test_f6_every_credential_slot(self):
        out = mask_line('curl -u bob:pw1 -b "sid=aaaa" -H "Authorization: Basic Ym9iOnB3MQ==" -H "X-Api-Key: k" https://bob:pw2@h/x\nSet-Cookie: s=zz; path=/')
        for secret in ["bob:pw1", "aaaa", "Ym9iOnB3MQ==", "bob:pw2", "zz"]:
            assert secret not in out
        assert "Authorization: Basic [masked basic-auth" in out
        assert '-b "[masked credential' in out
        assert "s=[masked cookie" in out
        assert "X-Api-Key: [masked credential" in out

    def test_f6_proofs_and_rationales(self):
        tok = synth_hex(43, 40)
        p = vuln("p", category="sql_injection", status="exploited", evidence={"raw_response": f'{{"token":"{tok}"}}'})
        q = vuln("q", category="ssrf", status="exploited", evidence={"raw_request": f"POST /h HTTP/1.1\nHost: {HOST}:3000\nAuthorization: token {tok}"})
        d = derive(infra(), [p, q])
        assert len(d["links"]) == 1
        shown = json.dumps({"links": d["links"], "steps": [st["rationale"] for s in d["input"]["scenarios"] for st in s["steps"]]})
        assert tok not in shown and tok[:4] not in shown


# ===========================================================================
# 5. Documents (build_paths / path_detail / simulate) — ATTACK-PATHS-BACKEND §6
# ===========================================================================

def _patch_storage(monkeypatch, data_dir: Path):
    from api import json_storage as js
    for name, sub in (("DATA_DIR", ""), ("PROJECTS_FILE", "projects.json"), ("TARGETS_FILE", "targets.json"),
                      ("CAMPAIGNS_DIR", "campaigns"), ("INFRASTRUCTURE_DIR", "infrastructure"),
                      ("VULNERABILITIES_DIR", "vulnerabilities"), ("REPORTS_DIR", "reports")):
        monkeypatch.setattr(js, name, data_dir / sub if sub else data_dir)
    return js


def _load(monkeypatch, data_dir: Path, cid: str):
    """Campaign, enriched nodes, edges, vulns exactly as GET /campaigns/{id}/infrastructure builds them."""
    js = _patch_storage(monkeypatch, data_dir)
    from api.infrastructure_graph import build_infrastructure
    infra_doc = build_infrastructure(cid, js.load_campaign(cid))
    return js.load_campaign(cid), infra_doc["nodes"], infra_doc["edges"], js.load_vulnerabilities(cid)


DEMO_ID = "camp_demo_chaindemo"
_SECRET_PATTERNS = [
    re.compile(r"eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]{6,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"synthetic-demo-token"),
]


def _assert_no_secret(doc):
    text = json.dumps(doc, ensure_ascii=False)
    for rx in _SECRET_PATTERNS:
        assert not rx.search(text), rx.pattern

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                assert k.lower() not in RAW_SECRET_KEYS, f"raw secret key {k}"
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc)


class TestDemoDocuments:
    def test_demo_five_paths_rank_one_three_of_five(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        doc = build_paths(camp, nodes, edges, vulns, now=NOW)
        assert doc["schema_version"] == SCHEMA_VERSION and doc["demo"] is True
        assert doc["summary"]["paths_total"] == 5
        assert doc["summary"]["provenances"] == ["declared", "derived"]
        r = doc["ranking"]
        assert r["allowed"] is True and r["provenance"] == "declared+derived"
        top = r["fixes"][0]
        assert (top["rank"], top["label"], top["interrupts_count"], top["of_total"]) == (1, "Close open user registration", 3, 5)
        assert top["finding_ids"] == ["vuln_reg01", "vuln_reg02"] and top["kind"] == "group"
        assert [f["fix_id"] for f in r["fixes"][1:3]] == ["vuln_sqli01", "vuln_pkg01"]
        assert any(i["kind"] == "chain-rejected" and i.get("chain_id") == "chain-guess" for i in doc["issues"])
        assert validate(doc, LIST_SCHEMA) == []
        _assert_no_secret(doc)

    def test_negative_control_is_an_alternative(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        doc = build_paths(camp, nodes, edges, vulns, include_steps=True, now=NOW)
        pkg = next(p for p in doc["paths"] if "vuln_pkg01" in p["finding_ids"])
        assert pkg["steps"][0]["satisfied_by"] == [["vuln_reg01"], ["vuln_pkg01"]]
        assert pkg["id"] not in doc["ranking"]["fixes"][0]["interrupts"]

    def test_detail_and_simulation(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        doc = build_paths(camp, nodes, edges, vulns, now=NOW)
        pid = doc["paths"][0]["id"]
        det = path_detail(camp, nodes, edges, vulns, pid)
        assert validate(det, DETAIL_SCHEMA) == []
        assert det["path"]["steps"][0]["n"] == 1 and det["path"]["steps"][0]["node_label"]
        assert all(not re.search(r"\bvuln_\w+", s["plain"] + s["why"] + s["node_label"]) for s in det["path"]["steps"])
        _assert_no_secret(det)
        assert path_detail(camp, nodes, edges, vulns, "ap_000000000000") is None

        snap = copy.deepcopy((camp, nodes, edges, vulns))
        sim = simulate(camp, nodes, edges, vulns, [doc["ranking"]["fixes"][0]["fix_id"]])
        assert (camp, nodes, edges, vulns) == snap
        assert validate(sim, SIMULATION_SCHEMA) == []
        assert sim["simulation"] is True and sim["label"] == "SIMULATION · not applied"
        assert sorted(sim["interrupted"]) == sorted(doc["ranking"]["fixes"][0]["interrupts"])
        assert len(sim["still_open"]) == 2 and sim["removed"] == ["vuln_reg01", "vuln_reg02"]
        assert all(isinstance(v, int) and v >= 1 for v in sim["cut_at"].values())
        assert "forge-db" in sim["objectives_reachable"]  # the anonymous SQLi still reaches the database
        assert not re.search(r"(?i)\b(fixed|resolved|secure)\b", json.dumps(sim))
        assert simulate(camp, nodes, edges, vulns, ["nope"])["unknown"] == ["nope"]

    def test_simulation_writes_nothing(self, monkeypatch, tmp_path):
        data = tmp_path / "data"
        shutil.copytree(FIXTURE, data)
        before = {p: p.stat().st_mtime_ns for p in data.rglob("*") if p.is_file()}
        camp, nodes, edges, vulns = _load(monkeypatch, data, DEMO_ID)
        build_paths(camp, nodes, edges, vulns, include_steps=True)
        simulate(camp, nodes, edges, vulns, ["vuln_sqli01"])
        assert {p: p.stat().st_mtime_ns for p in data.rglob("*") if p.is_file()} == before

    def test_ids_stable_and_provenance_filter(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        a = build_paths(camp, nodes, edges, vulns, now=NOW)
        b = build_paths(copy.deepcopy(camp), copy.deepcopy(nodes), edges, list(reversed(vulns)), now=NOW)
        assert a == b
        assert all(re.match(r"^ap_[0-9a-f]{12}$", p["id"]) for p in a["paths"])
        assert len({p["id"] for p in a["paths"]}) == 5
        decl = build_paths(camp, nodes, edges, vulns, provenance="declared", now=NOW)
        assert [p["provenance"] for p in decl["paths"]] == ["declared"]
        with pytest.raises(ValueError):
            build_paths(camp, nodes, edges, vulns, provenance="bogus")

    def test_retest_status_only_from_real_verdict(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        doc = build_paths(camp, nodes, edges, vulns, retest_verdicts={"vuln_sqli01": "fixed"}, now=NOW)
        sqli = next(p for p in doc["paths"] if p["finding_ids"] == ["vuln_sqli01"])
        assert sqli["status"] == "interrupted_by_retest"
        assert all(p["status"] == "open" for p in build_paths(camp, nodes, edges, vulns, now=NOW)["paths"])

    def test_remediated_finding_excluded(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        vulns = [{**v, "status": "remediated"} if v["id"] == "vuln_sqli01" else v for v in vulns]
        doc = build_paths(camp, nodes, edges, vulns, now=NOW)
        assert doc["summary"]["paths_total"] == 4
        assert all("vuln_sqli01" not in p["finding_ids"] for p in doc["paths"])

    def test_declared_chain_revalidated(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        nodes = [n for n in nodes if n["id"] != "forge-db"]
        doc = build_paths(camp, nodes, edges, vulns, now=NOW)
        assert "declared" not in doc["summary"]["provenances"]
        assert any(i["kind"] == "chain-node-missing" for i in doc["issues"])

    def test_hypothesis_never_ranked(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        vulns = [{**v, "status": "unconfirmed"} if v["id"] in ("vuln_reg01", "vuln_reg02") else v for v in vulns]
        camp = copy.deepcopy(camp)
        doc = build_paths(camp, nodes, edges, vulns, now=NOW)
        declared = [p for p in doc["paths"] if p["provenance"] == "declared"]
        assert declared and declared[0]["hypothesis"] is True
        ranked = {pid for f in doc["ranking"]["fixes"] + doc["ranking"].get("pivots", []) for pid in f["interrupts"]}
        assert declared[0]["id"] not in ranked


def _join_campaign(chain_len=2, cycle=False):
    """Pure derived-path campaign built on synthetic finding fields."""
    ref = lambda i: format(i, "016x")  # noqa: E731
    vulns, nodes = [], [{"id": "web", "node_type": "application", "label": "Web", "vulnerability_ids": []}]
    for i in range(chain_len):
        v = {"id": f"v{i}", "title": f"Step {i}", "severity": "high", "status": "exploited", "category": "idor",
             "produced_artifacts": [{"ref": ref(i), "type": "token"}]}
        if i > 0:
            v["prerequisites"] = [{"artifact_ref": ref(i - 1)}]
        vulns.append(v)
        nodes[0]["vulnerability_ids"].append(v["id"])
    if cycle:
        vulns[0]["prerequisites"] = [{"artifact_ref": ref(chain_len - 1)}]
    return {"id": "camp_join"}, nodes, [], vulns


class TestDerivedDocuments:
    def test_join_a_to_b(self, monkeypatch):
        # RT-04 (P8): this test exercises the mechanics on a derived path built from DECLARED fields only; such a path is
        # a hypothesis by default now. The rollback flag restores the former proof rule for this mechanics test only.
        monkeypatch.setenv("DM_LEGACY_DERIVED_PROOF", "1")
        camp, nodes, edges, vulns = _join_campaign(2)
        doc = build_paths(camp, nodes, edges, vulns, include_steps=True, now=NOW)
        assert [p["provenance"] for p in doc["paths"]] == ["derived"]
        assert [s["satisfied_by"] for s in doc["paths"][0]["steps"]] == [[["v0"]], [["v1"]]]
        assert doc["ranking"]["allowed"] is False and doc["ranking"]["note"].startswith("Proven pivots")
        assert validate(doc, LIST_SCHEMA) == []

    def test_cycle_guard(self):
        camp, nodes, edges, vulns = _join_campaign(3, cycle=True)
        doc = build_paths(camp, nodes, edges, vulns, now=NOW)
        assert validate(doc, LIST_SCHEMA) == []
        assert all(p["steps_count"] <= 8 for p in doc["paths"])

    def test_too_large_gate(self, monkeypatch):
        from api import attack_paths as ap
        monkeypatch.setattr(ap, "MAX_RANKED_PATHS", 1)
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        r = build_paths(camp, nodes, edges, vulns, now=NOW)["ranking"]
        assert (r["allowed"], r["note"], r["fixes"]) == (False, "too-large", [])

    def test_observed_not_mixed_with_server(self, monkeypatch):
        camp, nodes, edges, vulns = _load(monkeypatch, FIXTURE, DEMO_ID)
        lfi = {"id": "vuln_lfi01", "title": "Path traversal", "severity": "high", "status": "exploited", "category": "path_traversal",
               "endpoint": "https://forge.demo.test/dl", "evidence": {"raw_request": "GET /dl?f=../../etc/passwd HTTP/1.1\nHost: forge.demo.test",
                                                                       "raw_response": "root:x:0:0:root:/root:/bin/bash"}}
        nodes = copy.deepcopy(nodes)
        next(n for n in nodes if n["id"] == "forge-api")["vulnerability_ids"].append("vuln_lfi01")
        doc = build_paths(camp, nodes, edges, vulns + [lfi], now=NOW)
        obs = [p for p in doc["paths"] if p["provenance"] == "observed"]
        assert len(obs) == 1
        assert doc["ranking"]["provenance"] == "declared+derived"
        assert all(obs[0]["id"] not in f["interrupts"] for f in doc["ranking"]["fixes"])

    def test_empty_campaign_honest_note(self):
        doc = build_paths({"id": "camp_empty"}, [], [], [vuln("x")], now=NOW)
        assert doc["paths"] == [] and doc["summary"]["paths_total"] == 0
        assert "does not mean that no path exists" in doc["note"]
        assert doc["summary"]["coverage"] == {"findings_total": 1, "findings_on_paths": 0, "findings_without_node": 1}
        assert validate(doc, LIST_SCHEMA) == []

    def test_fix_labels(self):
        assert fix_label("Open user registration") == "Close open user registration"
        assert fix_label("SQL injection in search") == "Fix SQL injection in search"
        assert fix_label("Missing Content-Security-Policy") == "Add the Content-Security-Policy"


@pytest.mark.skipif(not (REAL_DATA / "campaigns").is_dir(), reason="local copy of real campaigns not present")
def test_schema_and_no_secret_on_real_campaigns(monkeypatch):
    ids = sorted(p.stem for p in (REAL_DATA / "campaigns").glob("*.json"))
    assert ids
    for cid in ids:
        camp, nodes, edges, vulns = _load(monkeypatch, REAL_DATA, cid)
        doc = build_paths(camp, nodes, edges, vulns, include_steps=True, now=NOW)
        assert validate(doc, LIST_SCHEMA) == [], cid
        _assert_no_secret(doc)
        for p in doc["paths"]:
            assert validate(path_detail(camp, nodes, edges, vulns, p["id"]), DETAIL_SCHEMA) == []
        if doc["paths"]:
            sim = simulate(camp, nodes, edges, vulns, doc["paths"][0]["finding_ids"][:1])
            assert validate(sim, SIMULATION_SCHEMA) == []


