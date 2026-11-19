"""Architecture D — engine tests written from the mutation-testing report (reports/51-architecture-d-implementation/
MUTATION-D.md, first run): each test pins one rule of CONTRACT-D (incl. its « Clarifications » section) that no test or
sealed scenario exercised, so that a weakened guard is detected. Pure calls to ``edge_verifier.qualify_edge`` (WITHOUT the
``declared_links.validate`` gate that masks most of these layers in the pipeline) and to ``declared_links.validate``.

Mutants each test is meant to kill are named in its docstring.
"""
from __future__ import annotations

import pytest

from api import declared_links as dl, edge_verifier as ev

R = "run-d0d0d0d0"
DECL = "declared_by_agent"


def X(eid, seq, produced=(), consumed=(), presented=(), outcome="success", run=R, keys=("op:b",), basis="http_2xx",
      session=None):
    return {"execution_id": eid, "run_id": run, "seq": seq, "session": session,
            "produced": [{"fp": f, "kind": "token"} for f in produced],
            "consumed": [{"fp": f, "producer_execution_id": p} for f, p in consumed],
            "presented": list(presented), "outcome": outcome, "outcome_basis": basis, "operation_keys": list(keys)}


def FD(fid, push_seq, fps=("v1",), enabled_by=(), run=R, **kw):
    return {"id": fid, "run_id": run, "push_seq": push_seq, "value_fps": list(fps), "enabled_by": list(enabled_by),
            "status": "exploited", **kw}


# e_a (seq 1) produces v1; A pushed at 2; e_b (seq 3) consumes v1 from e_a, 2xx; B pushed at 4 -> observed_flow
A = FD("A", 2)
B = FD("B", 4, enabled_by=["A"])
FLOW = [X("ex_a", 1, produced=["v1"], keys=("op:a",)), X("ex_b", 3, consumed=[("v1", "ex_a")], presented=["v1"])]


def q(a=A, b=B, ledger=FLOW, findings=None, sessions=1):
    return ev.qualify_edge(a, b, ledger, findings if findings is not None else [a, b], sessions=sessions)[:2]


def test_baseline_flow_is_observed():
    assert q() == ("observed_flow", None)


# --------------------------------------------------------------------------- CONTRACT-D cond. 1 at the API level
@pytest.mark.parametrize("status", ["withdrawn", "remediated", "false_positive", " Withdrawn "])
@pytest.mark.parametrize("side", ["a", "b"])
def test_a_finding_that_is_not_live_is_never_promoted(status, side):
    """« both live »: qualify_edge itself abstains (constant mutants C01–C03 on NOT_LIVE)."""
    a, b = (dict(A, status=status), B) if side == "a" else (A, dict(B, status=status))
    assert q(a, b) == (DECL, "finding_not_live")


@pytest.mark.parametrize("side", ["a", "b"])
def test_a_merged_away_finding_is_never_promoted(side):
    """« not merged-away »: duplicate_of on EITHER end (qualify_edge#37, #39–#41)."""
    a, b = (dict(A, duplicate_of="Z"), B) if side == "a" else (A, dict(B, duplicate_of="Z"))
    assert q(a, b) == (DECL, "duplicate_finding")


def test_two_findings_sharing_a_dedup_key_are_one_weakness_never_promoted():
    """« not duplicates of each other » (qualify_edge#46–#55)."""
    assert q(dict(A, dedup_key="k1"), dict(B, dedup_key="k1")) == (DECL, "duplicate_finding")
    # a key on one side only, or two different keys: not duplicates, the flow decides (stricter #49–#52)
    assert q(dict(A, dedup_key="k1"), B) == ("observed_flow", None)
    assert q(A, dict(B, dedup_key="k1")) == ("observed_flow", None)
    assert q(dict(A, dedup_key="k1"), dict(B, dedup_key="k2")) == ("observed_flow", None)


def test_a_direct_two_cycle_does_not_demote_an_established_edge():
    """CONTRACT-D final-review clarification (K4 withdrawn): A ⇄ B — the edge A → B is judged on ITS OWN evidence,
    with or without the campaign findings; the closing back-edge B → A is judged like any edge (here: forward, B's
    value never produced before A's push, so it stays declared)."""
    a = dict(A, enabled_by=["B"])
    assert ev.qualify_edge(a, B, FLOW, [], sessions=1)[:2] == ("observed_flow", None)
    assert ev.qualify_edge(a, B, FLOW, [a, B], sessions=1)[:2] == ("observed_flow", None)
    assert ev.qualify_edge(B, a, FLOW, [a, B], sessions=1)[0] == DECL
    assert "cycle" not in ev.D_REASONS


def test_s70_an_edge_inside_a_declared_cycle_keeps_the_state_of_its_own_evidence():
    """Sealed S70 shape: A(←C, late re-push), B(←A), C(←B); e_a → e_b carries v1 for A → B and e_b → e_c carries v2
    for B → C. Both are observed_flow, exactly as without the closing declaration; C → A (no shared value) stays
    declared (no_shared_value)."""
    flow = FLOW + [X("ex_c", 5, consumed=[("v2", "ex_b")], presented=["v2"], keys=("op:c",))]
    flow[1] = dict(flow[1], produced=[{"fp": "v2", "kind": "token"}])
    a, b, c = dict(A, enabled_by=["C"]), FD("B", 4, fps=("v1", "v2"), enabled_by=["A"]), FD("C", 6, fps=("v2",), enabled_by=["B"])
    for fs in ([a, b, c], [A, b, c]):
        assert ev.qualify_edge(fs[0], b, flow, fs, sessions=1)[:2] == ("observed_flow", None)
        assert ev.qualify_edge(b, c, flow, fs, sessions=1)[:2] == ("observed_flow", None)
    assert ev.qualify_edge(c, a, flow, [a, b, c], sessions=1)[:2] == (DECL, "no_shared_value")


def test_the_campaign_findings_carried_by_the_ledger_are_used_when_none_are_passed():
    """« several possible findings for one execution » with ``{"executions", "findings"}`` and no ``findings``
    argument (qualify_edge#6)."""
    c = FD("C", 7)                              # live, presents v1, pushed after e_a
    ledger = {"executions": FLOW, "findings": [A, B, c]}
    assert ev.qualify_edge(A, B, ledger, sessions=1)[:2] == (DECL, "several_findings")
    assert ev.qualify_edge(A, B, {"executions": FLOW, "findings": [A, B]}, sessions=1)[:2] == ("observed_flow", None)


# --------------------------------------------------------------------------- K1: ambiguous origin abstains
def test_k1_an_earlier_consumption_naming_another_producer_abstains():
    """K1: e2 (seq 3) consumed v1 naming ANOTHER producer (e9, unrecorded) before e_b → e_a is not shown to be the only
    origin → ``ambiguous_origin`` (_link_issue#24, #34)."""
    ledger = [X("ex_a", 1, produced=["v1"], keys=("op:a",)),
              X("ex_2", 3, consumed=[("v1", "ex_9")], keys=("op:x",)),
              X("ex_b", 4, consumed=[("v1", "ex_a")])]
    assert q(dict(A, push_seq=2), dict(B, push_seq=5), ledger) == (DECL, "ambiguous_origin")
    # the same earlier consumption naming e_a itself is no ambiguity
    ledger[1] = X("ex_2", 3, consumed=[("v1", "ex_a")], keys=("op:x",))
    assert q(dict(A, push_seq=2), dict(B, push_seq=5), ledger)[0] == "observed_flow"
    # an earlier consumption of ANOTHER value naming another producer is no ambiguity either
    ledger[1] = X("ex_2", 3, consumed=[("v7", "ex_9")], keys=("op:x",))
    assert q(dict(A, push_seq=2), dict(B, push_seq=5), ledger)[0] == "observed_flow"


# --------------------------------------------------------------------------- K2: id-less records are never link ends
@pytest.mark.parametrize("bad_id", ["", None, "   "])
def test_k2_an_execution_without_an_id_is_never_a_link_end(bad_id):
    """K2: e_a recorded WITHOUT an execution id produces v1; e_b consumes v1 naming no producer → no attribution
    (qualify_edge#118)."""
    ea = dict(X("ex_a", 1, produced=["v1"], keys=("op:a",)), execution_id=bad_id)
    eb = dict(X("ex_b", 3, presented=["v1"]), consumed=[{"fp": "v1", "producer_execution_id": bad_id}])
    assert q(ledger=[ea, eb])[0] == DECL
    ea.pop("execution_id")
    eb["consumed"][0].pop("producer_execution_id")
    assert q(ledger=[ea, eb])[0] == DECL


def test_k2_a_consumption_naming_no_producer_is_unattributed():
    eb = dict(X("ex_b", 3, presented=["v1"]), consumed=[{"fp": "v1"}])
    assert q(ledger=[FLOW[0], eb]) == (DECL, "value_not_consumed")


def test_unreadable_ledger_records_never_raise():
    """« never raises on bad input » (qualify_edge#118 also crashes on a non-dict record)."""
    assert q(ledger=["junk", 7, None, ["ex_a"]] + FLOW) == ("observed_flow", None)


# --------------------------------------------------------------------------- K3: blank fingerprints / value_fps shape
@pytest.mark.parametrize("blank", [" ", "", "\t\n"])
def test_k3_a_blank_fingerprint_is_never_a_value(blank):
    """K3 (_fps#8)."""
    a, b = dict(A, value_fps=[blank]), dict(B, value_fps=[blank])
    ledger = [X("ex_a", 1, produced=[blank], keys=("op:a",)), X("ex_b", 3, consumed=[(blank, "ex_a")], presented=[blank])]
    assert q(a, b, ledger) == (DECL, "no_shared_value")


def test_value_fps_must_be_a_list():
    """The server computes a LIST of full-value fingerprints; any other shape is no evidence (_fps#2)."""
    assert q(dict(A, value_fps=("v1",)), dict(B, value_fps=("v1",))) == (DECL, "no_shared_value")
    assert q(dict(A, value_fps="v1"), dict(B, value_fps="v1")) == (DECL, "no_shared_value")


# --------------------------------------------------------------------------- validate(): declarations
def V(fid, enabled_by=None, **kw):
    v = {"id": fid, "title": fid, "status": "exploited", "category": "x"}
    if enabled_by is not None:
        v["enabled_by"] = enabled_by
    v.update(kw)
    return v


def links(vulns):
    return {(l["producer"], l["consumer"]): l for l in dl.validate(vulns, b={"tactics": {}})}


def test_a_non_list_enabled_by_declares_nothing():
    """CONTRACT-D agent surface: enabled_by = [finding ids]; a string from an edited store is not iterated
    (validate#38)."""
    assert links([V("A"), V("D", enabled_by="A")]) == {}
    assert links([V("A"), V("D", enabled_by={"A": 1})]) == {}


def test_an_ambiguous_label_reference_is_a_rejected_declaration():
    """CONTRACT-D clarification: two findings share the short title « login » → rejected (ambiguous), never guessed
    (validate#89, #90, #98, #99, #111, #112 and the reason mutants of that branch)."""
    vulns = [V("A", short_title="login"), V("C", short_title="login"), V("B", enabled_by=["login"])]
    (l,) = dl.validate(vulns, b={"tactics": {}})
    assert (l["producer"], l["consumer"]) == ("login", "B")
    assert l["state"] == "rejected_declaration" and l["reason"] == "ambiguous_reference"
    assert l["valid"] is False and l["flags"] == ["ambiguous-reference"]
    # a unique label resolves to its finding
    (l,) = dl.validate([V("A", short_title="login"), V("B", enabled_by=["login"])], b={"tactics": {}})
    assert (l["producer"], l["state"], l["valid"]) == ("A", "declared_by_agent", True)


def test_unknown_and_self_references_are_rejected_with_their_own_reason():
    ls = links([V("A", enabled_by=["A", "nope"])])
    assert (ls[("A", "A")]["reason"], ls[("A", "A")]["flags"]) == ("self_reference", ["self-reference"])
    assert (ls[("nope", "A")]["reason"], ls[("nope", "A")]["flags"]) == ("unknown_finding", ["unknown-finding"])


def test_a_finding_without_an_id_never_declares_and_never_raises():
    """An id-less finding cannot be a link end (CONTRACT-D clarification): its references are skipped, fail-closed."""
    vulns = [V("A"), {"title": "orphan", "status": "exploited", "enabled_by": ["A"]}, V("B", enabled_by=["A"])]
    ls = dl.validate(vulns, b={"tactics": {}})
    assert [(l["producer"], l["consumer"], l["valid"]) for l in ls] == [("A", "B", True)]


def test_at_most_sixteen_references_per_finding():
    """MAX_REFS = 16 (constant mutants C14, C15): the 17th reference is dropped, the 16th kept."""
    prods = [V(f"P{i:02d}") for i in range(17)]
    ls = dl.validate(prods + [V("B", enabled_by=[p["id"] for p in prods])], b={"tactics": {}})
    assert [l["producer"] for l in ls] == [f"P{i:02d}" for i in range(16)]
    assert all(l["valid"] and l["state"] == "declared_by_agent" for l in ls)


def test_a_confirmed_producer_is_live():
    """LIVE = exploited | confirmed (constant mutant C16)."""
    (l,) = dl.validate([V("A", status="confirmed"), V("B", enabled_by=["A"])], b={"tactics": {}})
    assert l["valid"] is True and l["flags"] == []


# ------------------------------------------------- validate(): a cycle is a non-blocking, non-promoting WARNING
def test_a_cycle_reached_after_an_already_visited_root_is_flagged():
    """A, B(←A), C(←B), D(←E, late re-push), E(←D): D ⇄ E is a cycle → both links carry the ``cycle`` warning and
    stay usable (path assembly walks simple paths only); the acyclic links carry no warning (_cycle_nodes#5,
    validate#263). The state is never raised by the warning."""
    vulns = [V("A"), V("B", enabled_by=["A"]), V("C", enabled_by=["B"]),
             V("D", enabled_by=["E"], enabled_by_at={"E": 5}), V("E", enabled_by=["D"])]
    ls = links(vulns)
    assert {k: (l["valid"], "cycle" in l["warnings"], "cycle" in l["flags"]) for k, l in ls.items()} == {
        ("A", "B"): (True, False, False), ("B", "C"): (True, False, False),
        ("E", "D"): (True, True, False), ("D", "E"): (True, True, False)}
    assert all(l["state"] == "declared_by_agent" for l in ls.values())


def test_every_out_edge_is_walked_when_looking_for_cycles():
    """A(←C, late re-push), B(←A), C(←A): A ⇄ C is a cycle found through A's SECOND out-edge (_cycle_nodes#23); A → B
    has one end off the cycle and gets no warning."""
    vulns = [V("A", enabled_by=["C"], enabled_by_at={"C": 3}), V("B", enabled_by=["A"]), V("C", enabled_by=["A"])]
    ls = links(vulns)
    assert {k: ("cycle" in l["warnings"]) for k, l in ls.items()} == {("C", "A"): True, ("A", "B"): False, ("A", "C"): True}
    assert all(l["valid"] is True for l in ls.values())


def test_cycle_nodes_finds_every_cycle_of_the_graph():
    assert dl._cycle_nodes({"A": ["B"], "B": ["C"], "E": ["D"], "D": ["E"]}) == {"D", "E"}
    assert dl._cycle_nodes({"C": ["A"], "A": ["B", "C"]}) == {"A", "C"}
    assert dl._cycle_nodes({"A": ["B"], "B": []}) == set()
