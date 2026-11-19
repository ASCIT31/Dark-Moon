"""Report annex: the campaign's own data as report sections, appended to the Community report at finalisation.

Proven and possible (inferred) paths never mix; fix-first comes from the server's ranking or fix_first list; the
framework section only reads the framework views + the catalogue; Mermaid labels cannot carry syntax; raw HTML from a
finding never becomes live markup."""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import re

import pytest

from api import json_storage as js
from api import report_annex as RA

def _section(md: str, title: str) -> str:
    m = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", md, re.S | re.M)
    assert m, f"section {title} missing"
    return m.group(1)


def _sub(md: str, title: str) -> str:
    m = re.search(rf"^### {re.escape(title)}\n(.*?)(?=^### |^## |\Z)", md, re.S | re.M)
    assert m, f"sub-section {title} missing"
    return m.group(1)


def _proven_from_attack_paths_header(md: str) -> int:
    """The canonical proven-path count the exported report states: the header of « ## ATTACK PATHS »."""
    sec = _section(md, "ATTACK PATHS")
    m = re.search(r"(\d+)\s+observed attack paths?\b", sec)
    assert m, "ATTACK PATHS header states no proven-path count"
    return int(m.group(1))


def test_non_demo_campaign_has_no_demonstration_marker():
    """The marker is strictly gated on the campaign's `demo` flag: a real campaign never carries it."""
    ap = {"paths": [], "ranking": {"allowed": False, "note": "n/a"}, "fix_first": {}, "summary": {}}
    real = RA.remediation_priorities_section(ap, {}, {"demo": False, "stats": {}}, [], {})
    assert "Demonstration data" not in real


def _inferred_doc():
    return {
        "paths": [
            {"id": "ap_p", "title": "Proven RCE", "hypothesis": False, "status": "open", "provenance": "observed", "criticality": "critical",
             "certainty": "exploited", "entry": {"node_id": "a", "label": "Web"}, "objective": {"node_id": "b", "label": "Host"},
             "finding_ids": ["v1"], "steps": [], "edges": [{"from": "a", "to": "b", "technique": {"id": "T1190"}, "proof": "exploited"}]},
            {"id": "ap_h", "title": 'Guess "]; click a call x() %%{init}%%', "hypothesis": True, "status": "open", "provenance": "inferred",
             "criticality": "high", "certainty": "unconfirmed", "entry": {"node_id": "a", "label": "Web"},
             "objective": {"node_id": "c", "label": 'DB"]\nclick c href "javascript:alert(1)"'}, "finding_ids": ["v2"], "steps": [],
             "edges": [{"from": "a", "to": "c", "inferred": True}], "inference": {"rule": "I-DATA", "rule_label": "Data access"}},
        ],
        "ranking": {"allowed": False, "note": "No proven attack path: nothing to rank.", "fixes": [], "pivots": []},
        "fix_first": {"label": "By reported severity × proof", "items": [
            {"rank": 1, "label": "Fix v2", "finding_ids": ["v2"], "severity": "high", "proof": "confirmed", "breaks_paths": [], "reasons": ["high"]},
            {"rank": 2, "label": "Fix v1", "finding_ids": ["v1"], "severity": "critical", "proof": "exploited", "breaks_paths": ["ap_p"], "reasons": []}]},
    }


def test_unit_proven_vs_possible_and_mermaid_safety():
    md = RA.attack_paths_section(_inferred_doc(), {})
    assert "1 observed attack path · 1 possible path" in md
    proven = _sub(md, "Attack paths (ranked: observed and declared)")
    possible = _sub(md, "Possible paths (hypotheses, not proven)")
    assert "Proven RCE" in proven and "Guess" not in proven
    assert "possible · not proven (hypothesis)" in possible
    fence = md.split("```mermaid", 1)[1].split("```", 1)[0]
    body = fence.split("\n", 3)[3]  # after « %% figure » and « flowchart LR »
    # no data can open a directive, a click, a new statement or a second quoted string
    assert "%%" not in body and "click" not in body.replace('"', "") .split("[")[0]
    for line in body.strip().splitlines():
        assert line.count('"') in (0, 2), line
        assert "\n" not in line and ";" not in line and "]" not in line.split('"')[1 if '"' in line else 0]
    assert 'n0 ==>|"T1190 · exploited"| n1' in fence
    assert '-.->|"hypothesis"|' in fence


def test_unit_fix_first_labels_each_path():
    md = RA.fix_first_section(_inferred_doc(), {})
    assert "No attack-path ranking for this campaign" in md
    r1 = next(line for line in md.splitlines() if line.startswith("| 1 |"))
    r2 = next(line for line in md.splitlines() if line.startswith("| 2 |"))
    # v2 interrupts nothing proven; it only sits on the possible path, labelled as such
    assert r1.split(" | ")[5] == "—" and "possible · not proven" in r1
    assert "Proven RCE — observed" in r2


def test_mm_label_and_md_cell():
    assert RA.mm_label('a"b]c|d<e>f%%g\nh;i{j}`k#l') == "a b c d e f g h i j k l"
    assert len(RA.mm_label("x" * 200)) == 46
    assert RA.md_cell("a|b`c\nd") == "a\\|b'c d"


def _set_campaign(campaign_id, **fields):
    c = js.load_campaign(campaign_id)
    c.update(fields)
    js.save_campaign(c)


def test_f2_objectives_reachable_after_is_path_based():
    """Audit F2: after a fix, an objective can stay reachable by ANOTHER proven path. objectives_reachable_after must be
    PATH-based (objectives of the paths left open), not the engine's node-finding-closure. Two proven paths to obj A
    (p1,p3) and one to obj B (p2); fixing the finding that breaks p1+p2 leaves A reachable via p3."""
    paths = [
        {"id": "p1", "hypothesis": False, "objective": {"node_id": "A", "label": "CRM"}},
        {"id": "p2", "hypothesis": False, "objective": {"node_id": "B", "label": "Ops"}},
        {"id": "p3", "hypothesis": False, "objective": {"node_id": "A", "label": "CRM"}},
    ]
    # fix#1 (the shared RCE) breaks p1 (A) and p2 (B); A still reachable by p3, B is not
    f1 = {"rank": 1, "marginal_interrupts": ["p1", "p2"]}
    assert RA.objectives_reachable_after([f1], paths) == ["A"]            # node_id; A survives (p3), B closed
    assert RA.objective_names(["A"], paths) == ["CRM"]                   # label resolved only for display
    # fix#2 breaks p3 too -> nothing left
    f2 = {"rank": 2, "marginal_interrupts": ["p3"]}
    assert RA.objectives_reachable_after([f1, f2], paths) == []


def test_p2_objective_without_node_id_is_counted_not_dropped():
    """Regression guard: a proven objective WITHOUT a node_id must still be counted (never silently
    dropped), and two distinct labels stay distinct. Direction of safety: a still-reachable objective is never
    under-reported into a false « no path reaches it »."""
    paths = [
        {"id": "p1", "hypothesis": False, "objective": {"label": "Database"}},            # no node_id, has label
        {"id": "p2", "hypothesis": False, "objective": {"node_id": "db2", "label": "Ops"}},
    ]
    allobj = RA._all_proven_objectives(paths)
    assert len(allobj) == 2                                   # neither objective dropped
    reach = RA.objectives_reachable_after([], paths)
    assert len(reach) == 2                                    # both still reachable, none lost
    # a labelless objective is still counted (keyed on its path), never dropped
    nameless = [{"id": "p9", "hypothesis": False, "objective": {}}]
    assert len(RA._all_proven_objectives(nameless)) == 1
    assert RA.objective_names(RA._all_proven_objectives(nameless), nameless) == ["the objective"]


def test_p2_disambiguation_ignores_hypothesis_paths():
    """A proven objective whose label is unique AMONG PROVEN objectives is shown as the clean label, even
    if a hypothesis path happens to share that label — no spurious « (node_id) » suffix."""
    paths = [
        {"id": "p1", "hypothesis": False, "objective": {"node_id": "db1", "label": "Database"}},
        {"id": "p2", "hypothesis": True, "objective": {"node_id": "db2", "label": "Database"}},  # hypothesis, same label
    ]
    assert RA.objective_names(["db1"], paths) == ["Database"]           # clean, not « Database (db1) »
    # but two PROVEN objectives sharing a label ARE disambiguated
    both = [
        {"id": "p1", "hypothesis": False, "objective": {"node_id": "db1", "label": "Database"}},
        {"id": "p3", "hypothesis": False, "objective": {"node_id": "db2", "label": "Database"}},
    ]
    assert RA.objective_names(["db1", "db2"], both) == ["Database · db1", "Database · db2"]
    # collision-free — two node_ids whose short forms collide fall back to full ids, still distinct
    coll = [
        {"id": "p1", "hypothesis": False, "objective": {"node_id": "n_crm_172.31.20.12_postgres", "label": "DB"}},
        {"id": "p2", "hypothesis": False, "objective": {"node_id": "n_crm_172.31.20.99_postgres", "label": "DB"}},
    ]
    names = RA.objective_names(["n_crm_172.31.20.12_postgres", "n_crm_172.31.20.99_postgres"], coll)
    assert names[0] != names[1] and names[0] == "DB · n_crm_172.31.20.12_postgres"


def test_f3_lab_banner_and_no_regulatory_claim_only_when_lab():
    ap = {"paths": [], "ranking": {"allowed": False, "note": "n/a"}, "fix_first": {}, "summary": {}}
    lab = RA.remediation_priorities_section(ap, {}, {"target_environment": "lab", "stats": {}}, [], {})
    assert "ISOLATED TEST LAB with SYNTHETIC data" in lab and "no regulatory notification obligation" in lab
    real = RA.remediation_priorities_section(ap, {}, {"target_environment": "production", "stats": {}}, [], {})
    assert "ISOLATED TEST LAB" not in real


def test_f4_certified_severity_from_server_counts():
    """Audit F4: the severity figure is the server counter, stated canonically, so an agent's free-prose count never
    stands as the authority."""
    ap = {"paths": [], "ranking": {"allowed": False, "note": "n/a"}, "fix_first": {}, "summary": {}}
    stats = {"total_findings": 33, "critical": 15, "high": 7, "medium": 4, "low": 5, "info": 2, "exploited": 18}
    out = RA.remediation_priorities_section(ap, {}, {"stats": stats}, None, {})
    assert "Certified severity (server counts):** 33 findings — 15 critical, 7 high, 4 medium, 5 low, 2 info; 18 exploited" in out
    assert "authoritative counts" in out


def test_f1_proven_means_observed_not_strict_necessity():
    md = RA.attack_paths_section({"paths": [{"id": "x", "hypothesis": False, "title": "T", "steps": [],
        "entry": {"node_id": "a", "label": "A"}, "objective": {"node_id": "b", "label": "B"}, "edges": []}]}, {})
    assert "observed exploitation chain" in md and "not" in md.lower() and "necessity" in md.lower()


def test_f2_closed_and_reachable_columns_are_consistent_path_based():
    """The FIX FIRST « objectives closed » and « still reachable » columns must use the SAME path
    universe and partition the objectives, so an objective whose only path was cut is shown as closed (not lost between
    a node-based « closed » and a path-based « reachable »)."""
    paths = [
        {"id": "p1", "hypothesis": False, "objective": {"node_id": "A", "label": "CRM"}},
        {"id": "p2", "hypothesis": False, "objective": {"node_id": "B", "label": "Ops"}},
        {"id": "p3", "hypothesis": False, "objective": {"node_id": "A", "label": "CRM"}},
    ]
    f1 = {"rank": 1, "marginal_interrupts": ["p1", "p2"]}
    assert RA.objectives_closed_after([f1], paths) == ["B"]               # node_id; B closed (p2 cut)
    assert RA.objectives_reachable_after([f1], paths) == ["A"]            # A still reachable (p3)
    # the two partition the proven objectives
    assert set(RA.objectives_closed_after([f1], paths)) | set(RA.objectives_reachable_after([f1], paths)) == {"A", "B"}
    assert not (set(RA.objectives_closed_after([f1], paths)) & set(RA.objectives_reachable_after([f1], paths)))


def test_p2_objectives_keyed_by_node_id_not_label():
    """Audit P2: two DIFFERENT assets sharing a label must stay distinct (count 2, not merged), and one objective
    reached by several paths counts once. Identity = node_id; the label is only for display (disambiguated on clash)."""
    paths = [
        {"id": "p1", "hypothesis": False, "objective": {"node_id": "db1", "label": "Database"}},
        {"id": "p2", "hypothesis": False, "objective": {"node_id": "db2", "label": "Database"}},   # homonym, distinct asset
        {"id": "p3", "hypothesis": False, "objective": {"node_id": "db1", "label": "Database"}},   # same objective, 2nd path
    ]
    # all three proven objectives dedup to TWO distinct node_ids
    assert set(RA._all_proven_objectives(paths)) == {"db1", "db2"}
    # display disambiguates the shared label
    names = RA.objective_names(["db1", "db2"], paths)
    assert names == ["Database · db1", "Database · db2"]
    # fixing the finding that cuts p1+p3 (both db1) closes db1 only; db2 stays reachable (p2)
    f = {"rank": 1, "marginal_interrupts": ["p1", "p3"]}
    assert RA.objectives_reachable_after([f], paths) == ["db2"]
    assert RA.objectives_closed_after([f], paths) == ["db1"]


# ── RC final certification (semantic): report wording matches the true proof universe, declared is never « observed »/« proven » ──
def _mk_path(pid, prov, hypothesis, n_from, l_from, n_to, l_to, status="open", proof=None):
    e = {"from": n_from, "to": n_to}
    if proof:
        e["proof"] = proof
    return {
        "id": pid, "provenance": prov, "hypothesis": hypothesis, "status": status,
        "title": f"path {pid}", "certainty": "exploited",
        "entry": {"node_id": n_from, "label": l_from}, "objective": {"node_id": n_to, "label": l_to},
        "node_ids": [n_from, n_to],
        "steps": [{"node_id": n_from, "node_label": l_from}, {"node_id": n_to, "node_label": l_to}],
        "edges": [e],
        "finding_ids": [f"v_{pid}"],
    }


OBS = _mk_path("obs1", "derived", False, "web", "Web", "db", "Database", proof="exploited")
DECL = _mk_path("dec1", "declared", False, "edge", "Edge", "adm", "Admin console")  # no proof → fallback must be « declared », not « proven »
POSS = _mk_path("pos1", "inferred", True, "net", "Net", "crm", "CRM")


def test_rc_diagram_legend_distinguishes_and_never_says_proven_hops():
    md = RA.attack_paths_section({"paths": [OBS, DECL, POSS]}, {})
    assert "proven hops" not in md                                        # old legend gone
    assert "steps of an observed or declared attack path" in md          # new, honest legend
    assert "causal-necessity proof" in md and "not a strict" in md       # no implied strict causality


def test_rc_declared_hop_is_labelled_declared_not_proven():
    md = RA.attack_paths_section({"paths": [DECL]}, {})
    thick = [ln for ln in md.splitlines() if "==>" in ln]
    assert thick, "a declared (eligible) path must draw a thick hop"
    for ln in thick:
        label = ln.split("|")[1].lower() if "|" in ln else ln.lower()
        assert "declared" in label, ln
        assert "proven" not in label, ln                                 # would FAIL on the old « or 'proven' » fallback


def test_rc_observed_hop_keeps_its_proof_never_declared():
    md = RA.attack_paths_section({"paths": [OBS]}, {})
    thick = [ln for ln in md.splitlines() if "==>" in ln]
    assert thick
    for ln in thick:
        label = ln.split("|")[1].lower() if "|" in ln else ln.lower()
        assert "exploited" in label                                      # the real recorded proof is kept
        assert "declared" not in label                                   # a genuinely observed hop is never « declared »


def test_rc_fix_first_objective_columns_name_the_ranked_universe():
    ap = {"paths": [OBS, DECL],
          "ranking": {"allowed": True, "provenance": "declared+derived",
                      "fixes": [{"rank": 1, "label": "Close X", "finding_ids": ["v_obs1"],
                                 "interrupts": ["obs1"], "marginal_interrupts": ["obs1"],
                                 "interrupts_count": 1, "of_total": 2}]}}
    md = RA.fix_first_section(ap, {})
    assert "Objectives with no open ranked attack path" in md            # Defect 1 fixed
    assert "Objectives still reachable via another ranked attack path" in md
    assert "no open observed path" not in md                             # old wording gone (would FAIL before)
    assert "by another observed path" not in md


