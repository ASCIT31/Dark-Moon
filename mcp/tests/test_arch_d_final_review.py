"""Architecture D final review (reports/52-arch-d-final-review): R2 isolation and S70 (cycles).

R2 — the historical server rule « open registration matched by ENDPOINT » is an inference: its links stay visible with
their fields (kind R2, producers, consumer, proof…) but carry ``level`` / ``provenance`` « inferred »; a path resting on
one is provenance « inferred », a hypothesis: never in summary.proven_paths, ranking, Fix first, simulation proven_* or
the report's observed paths; it never corroborates a derived claim and never promotes a declared (D) link.

S70 — CONTRACT-D final-review clarification: an edge is qualified on its own evidence (a declared cycle never demotes it);
path assembly walks SIMPLE paths only and reports the cycle (« cycle » warning on the links, « declared-cycle » issue).
"""
from __future__ import annotations

from api import attack_paths, edge_verifier as ev
from api.attack_paths_observed import derive_observed_input
from api.attack_paths_schema import DETAIL_SCHEMA, LIST_SCHEMA, SIMULATION_SCHEMA, validate

from test_attack_paths import BASE, CAMPAIGN, HOST, REGS, RCE, infra, vuln

NODES = infra({"app": ["reg-a", "reg-b", "reg-c"], "api": ["rce"]})


def _doc(vulns, nodes=NODES):
    return attack_paths.build_paths({"id": CAMPAIGN}, nodes, [], vulns, include_steps=True, now="2026-11-17T00:00:00Z")


# ------------------------------------------------------------------------------------------------------------- R2
def test_an_r2_path_is_an_inferred_hypothesis_and_the_bare_reach_stays_proven():
    doc = _doc([*REGS, RCE])
    assert validate(doc, LIST_SCHEMA) == []
    by_prov = {}
    for p in doc["paths"]:   # « inferred » also holds the topology hypotheses (attack_paths_inferred: an inference block)
        by_prov.setdefault("r2" if p["provenance"] == "inferred" and "inference" not in p else p["provenance"], []).append(p)
    (inf,) = by_prov["r2"]
    assert (inf["hypothesis"], inf["level"]) == (True, "inferred")
    assert "historical server rule R2" in inf["note"] and "not proven" in inf["level_label"]
    assert {"reg-a", "reg-b", "reg-c", "rce"} <= set(inf["finding_ids"])
    r2_step = next(s for s in inf["steps"] if (s.get("impact") or {}).get("rule") == "R2")
    assert r2_step["impact"]["source"] == "inferred-rule" and r2_step["impact"]["level"] == "inferred"
    assert "inferred, not proven" in r2_step["impact"]["label"]
    assert all(e["observed"] is False and e.get("inferred") is True for e in inf["edges"])
    # the R3 reach is the server's own observation: proven on its own, without the registration findings
    (obs,) = by_prov["observed"]
    assert obs["hypothesis"] is False and obs["finding_ids"] == ["rce"]
    assert doc["summary"]["proven_paths"] == 1 and doc["summary"]["inferred_paths"] == len(by_prov["r2"] + by_prov.get("inferred", []))
    # ranking / Fix first never rest on the inference
    ranked = {x for f in doc["ranking"]["fixes"] + doc["ranking"]["pivots"] for x in f["finding_ids"]}
    assert not ranked & {"reg-a", "reg-b", "reg-c"}
    assert all(inf["id"] not in f.get("interrupts", []) for f in doc["ranking"]["fixes"] + doc["ranking"]["pivots"])


def test_the_r2_link_keeps_its_api_fields_with_an_explicit_inferred_label():
    doc = _doc([*REGS, RCE])
    (l,) = [l for l in doc["observed_links"] if l["kind"] == "R2"]
    assert (l["producers"], l["consumer"], l["auxiliary"], l["ranked"]) == (["reg-a", "reg-b", "reg-c"], "rce", False, True)
    assert (l["level"], l["provenance"], l["usage"], l["necessity"]) == ("inferred", "inferred", "evidence", "not_assessed")
    assert "never a proof" in l["inference_note"] and "not proven" in l["usage_label"]
    assert "sign_up" in l["proof"]


def test_simulation_never_counts_an_r2_path_as_proven():
    sim = attack_paths.simulate({"id": CAMPAIGN}, NODES, [], [*REGS, RCE], ["reg-a", "reg-b", "reg-c"])
    assert validate(sim, SIMULATION_SCHEMA) == []
    assert sim["proven_paths_before"] == 1 and sim["proven_interrupted"] == []
    (r2_path,) = [p["id"] for p in _doc([*REGS, RCE])["paths"] if p["provenance"] == "inferred" and "inference" not in p]
    assert r2_path in sim["hypothesis_path_ids"] and r2_path in sim["interrupted"]


def _reg_and_consumer(enabled_by=None):
    reg = vuln("reg", title="Open user registration", category="security_misconfiguration", status="exploited",
               endpoint=f"POST {BASE}/api/Users", node_id="app")
    q = vuln("q", category="idor", status="exploited", node_id="api", evidence={
        "raw_request": f"GET /rest/basket/7 HTTP/1.1\nHost: {HOST}:3000\nAuthorization: Bearer x\nX-User: mallory01",
        "logs": ['POST /api/Users {"email":"mallory01"} -> 201']})
    if enabled_by:
        q["enabled_by"] = enabled_by
    return reg, q


def test_an_r2_link_never_promotes_a_declared_link_on_the_same_pair():
    reg, q = _reg_and_consumer(["reg"])
    nodes = infra({"app": ["reg"], "api": ["q"]})
    d = derive_observed_input(nodes, [reg, q], CAMPAIGN)
    kinds = {l["kind"]: l for l in d["links"] if l["consumer"] == "q"}
    assert set(kinds) == {"R2", "D"} and kinds["R2"]["level"] == "inferred"
    assert kinds["D"]["level"] == "declared_by_agent" and kinds["D"]["verification"]["state"] == "declared_by_agent"
    # no scenario rests on the pair at an observed level
    assert all(s["provenance"] == "inferred" or not any(
        (st.get("impact") or {}).get("rule") in ("R2", "D") for st in s["steps"]) for s in d["input"]["scenarios"])
    doc = _doc([reg, q], nodes)
    assert doc["summary"]["proven_paths"] == 0
    assert all(p["hypothesis"] for p in doc["paths"] if {"reg", "q"} <= set(p["finding_ids"]))


def test_an_r2_link_never_corroborates_a_derived_reuse_claim():
    links = [{"kind": "R2", "producers": ["reg"], "consumer": "q"}]
    claim = [{"kind": "reuse", "producers": ["reg"], "consumer": "q"}]
    vmap = {"reg": {"id": "reg", "campaign_id": "c"}, "q": {"id": "q", "campaign_id": "c"}}
    assert attack_paths._uncorroborated(claim, vmap, links) == ["reuse reg -> q is declared only"]
    assert attack_paths._uncorroborated(claim, vmap, [dict(links[0], kind="R1")]) == []


def test_path_level_puts_the_r2_inference_below_every_server_level():
    lv = lambda *xs: attack_paths.path_level([{"impact": {"level": x}} for x in xs])  # noqa: E731
    assert lv("observed", "inferred") == "inferred"
    assert lv("declared_by_agent", "inferred", "causal_necessity_demonstrated") == "inferred"
    assert lv("observed", "declared_by_agent") == "declared_by_agent" and lv("observed") == "observed"


# ------------------------------------------------------------------------------------------------------------- S70
def _cycle_vulns():
    """A(←C, late re-push), B(←A), C(←B), D(←C): a declared 3-cycle with an exit."""
    def f(fid, eb=None, at=None):
        v = vuln(fid, status="exploited", node_id={"A": "app", "B": "api", "C": "db", "D": "host-1"}[fid],
                 title=f"Weakness {fid}", category="x", endpoint=f"{BASE}/{fid.lower()}")
        if eb:
            v["enabled_by"] = eb
        if at:
            v["enabled_by_at"] = at
        return v
    return [f("A", ["C"], {"C": 3}), f("B", ["A"]), f("C", ["B"]), f("D", ["C"])]


def _nodes():
    return infra({"app": ["A"], "api": ["B"], "db": ["C"], "host-1": ["D"]})


def test_a_declared_cycle_is_reported_never_walked_and_never_blocks_its_links():
    d = derive_observed_input(_nodes(), _cycle_vulns(), CAMPAIGN)
    dl = {(l["producers"][0], l["consumer"]): l for l in d["links"] if l["kind"] == "D"}
    assert set(dl) == {("C", "A"), ("A", "B"), ("B", "C"), ("C", "D")}
    assert all(l["ranked"] for l in dl.values())
    assert {k for k, l in dl.items() if "cycle" in l["warnings"]} == {("C", "A"), ("A", "B"), ("B", "C")}
    (issue,) = [i for i in d["issues"] if i["kind"] == "declared-cycle"]
    assert issue["finding_ids"] == ["A", "B", "C"]
    # simple paths only: no finding repeated on any assembled scenario
    for s in d["input"]["scenarios"]:
        lead = [st["satisfied_by"][0][0] for st in s["steps"] if st["satisfied_by"] and st["satisfied_by"][0]]
        assert len(lead) == len(set(lead)), s["id"]
    assert any(s["consumer"] == "D" for s in d["input"]["scenarios"])


def test_s70_observed_edges_inside_a_cycle_give_a_proven_simple_path(monkeypatch):
    """The server established A→B, B→C and C→D on their own evidence (stubbed qualification); the back-edge C→A is
    only declared. The simple path A→B→C→D is proven at observed_flow; the cycle is never walked."""
    real = ev.qualify_edge
    observed = {("A", "B"), ("B", "C"), ("C", "D")}

    def stub(a, b, *args, **kw):
        if (str(a.get("id")), str(b.get("id"))) in observed:
            return ev.OBSERVED_FLOW, None, {"executions": ["ex_1", "ex_2"], "attribution": "exact_value"}
        return real(a, b, *args, **kw)
    monkeypatch.setattr(ev, "qualify_edge", stub)
    doc = _doc(_cycle_vulns(), _nodes())
    assert validate(doc, LIST_SCHEMA) == []
    proven = [p for p in doc["paths"] if not p["hypothesis"]]
    assert proven and all(p["level"] == "observed_flow" for p in proven)
    assert any(set(p["finding_ids"]) == {"A", "B", "C", "D"} for p in proven)
    for p in doc["paths"]:
        assert p["steps_count"] == len(p["steps"]) and len({s["node_id"] for s in p["steps"]}) == len(p["steps"]), p["id"]
    detail = attack_paths.path_detail({"id": CAMPAIGN}, _nodes(), [], _cycle_vulns(), proven[0]["id"])
    assert validate(detail, DETAIL_SCHEMA) == []
