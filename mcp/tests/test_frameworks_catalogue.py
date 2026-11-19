"""The static grids of the framework mapping: everything comes from the vendored MITRE catalogues and the Annex A
numbering the ISO parser already uses."""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from api import frameworks as F  # noqa: E402


def test_catalogue_contract():
    doc = F.framework_catalogue()
    assert doc["schema_version"] == F.CATALOGUE_SCHEMA
    assert set(doc) == {"schema_version", "attack", "atlas", "iso", "iec62443"}


def test_attack_grid_follows_the_vendored_catalogue():
    cat, a = F.attack_catalog(), F.framework_catalogue()["attack"]
    assert a["version"] == cat["version"]
    assert [t["id"] for t in a["tactics"]] == [t["id"] for t in cat["tactics_in_matrix_order"]]
    live = {k: v for k, v in cat["techniques"].items() if not v["revoked"] and not v["deprecated"]}
    seen_parents, seen_subs = set(), set()
    for tac in a["tactics"]:
        names = [t["name"].lower() for t in tac["techniques"]]
        assert names == sorted(names)                      # MITRE matrix: alphabetical inside a tactic
        for t in tac["techniques"]:
            src = live[t["id"]]
            assert not src["is_subtechnique"] and tac["shortname"] in src["tactics"]
            assert t["name"] == src["display_name"]
            seen_parents.add(t["id"])
            for s in t["subs"]:
                assert s["id"].split(".")[0] == t["id"] and tac["shortname"] in live[s["id"]]["tactics"]
                assert s["name"] == live[s["id"]]["name"]      # short name under its parent
                seen_subs.add(s["id"])
    assert seen_parents == {k for k, v in live.items() if not v["is_subtechnique"]}
    assert seen_subs == {k for k, v in live.items() if v["is_subtechnique"]}


def test_atlas_grid_in_matrix_order_and_complete():
    cat, t = F.atlas_catalog(), F.framework_catalogue()["atlas"]
    ids = [x["id"] for x in t["tactics"]]
    assert sorted(ids) == sorted(cat["tactics"])           # nothing dropped, nothing added
    assert ids[:4] == ["AML.TA0002", "AML.TA0003", "AML.TA0004", "AML.TA0000"] and ids[-1] == "AML.TA0011"
    assert all(x["name"] == cat["tactics"][x["id"]] for x in t["tactics"])
    placed = {s["id"] for tac in t["tactics"] for p in tac["techniques"] for s in [p, *p["subs"]]}
    assert placed == set(cat["techniques"])


def test_iso_numbering_only():
    iso = F.framework_catalogue()["iso"]
    assert [(c["ref"], c["controls"]) for c in iso["2022"]] == [("A.5", 37), ("A.6", 8), ("A.7", 14), ("A.8", 34)]
    assert [c["ref"] for c in iso["2013"]] == [f"A.{n}" for n in range(5, 19)]
    assert sum(c["categories"] for c in iso["2013"]) == 35
    # the grid agrees with the parser: the last control of each 2022 theme parses as 2022, the next one does not
    for c in iso["2022"]:
        assert F.iso_refs(f"ISO 27001:2022 A.{c['clause']}.{c['controls']}")["refs"][0]["version"] == "2022"
        assert F.iso_refs(f"ISO 27001:2022 A.{c['clause']}.{c['controls'] + 1}")["refs"][0]["version"] == "invalid"
