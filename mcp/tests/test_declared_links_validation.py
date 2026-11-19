"""Round 4: validation of the links the agent declares with `enabled_by` (api/declared_links.py) — explicit ATT&CK
transition table, forward / self references, unknown ids, non-live findings, unknown nodes, cycles."""
from __future__ import annotations

import pytest

from api import declared_links as dl


def F(fid, tech, tactic=None, status="exploited", enabled_by=None, node_id=None):
    v = {"id": fid, "title": fid, "status": status, "mitre_attack_id": tech}
    if tactic:
        v["mitre_tactic"] = tactic
    if enabled_by:
        v["enabled_by"] = enabled_by
    if node_id:
        v["node_id"] = node_id
    return v


@pytest.mark.parametrize("src,dst,ok", [
    ("credential-access", "lateral-movement", True), ("initial-access", "privilege-escalation", True),
    ("credential-access", "initial-access", True), ("lateral-movement", "credential-access", True),
    ("impact", "initial-access", True), ("exfiltration", "credential-access", True),     # round 5: no false rejects
    ("collection", "initial-access", True), ("collection", "execution", True), ("persistence", "initial-access", True),
    ("impact", "impact", True),
    ("credential-access", "reconnaissance", False), ("impact", "resource-development", False),   # only odd orders warn
])
def test_plausibility_table(src, dst, ok):
    assert dl.coherent([src], [dst]) is ok


def test_every_attack_tactic_is_in_the_table():
    bundle = pytest.importorskip("api.attack_tactics").bundle
    assert set(bundle()["tactics"]) == set(dl.UNUSUAL)


def test_references_resolve_by_id_dedup_key_short_title_or_endpoint():
    vulns = [{"id": "vuln_a", "title": "SQL Injection", "short_title": "SQLi login", "endpoint": "http://shop/rest/user/login"},
             {"id": "vuln_b", "title": "SQL Injection", "dedup_key": "sqli:/search"},
             {"id": "vuln_c", "title": "SQL Injection", "dedup_key": "sqli:/search", "duplicate_of": "vuln_b"},
             {"id": "vuln_d", "title": "X", "endpoint": "http://shop/x"}, {"id": "vuln_e", "title": "Y", "endpoint": "http://shop/x"}]
    r = lambda ref, me="vuln_z": dl.resolve_one(ref, vulns, me)  # noqa: E731
    assert r("vuln_a") == ("vuln_a", "ok") and r("sqli LOGIN") == ("vuln_a", "ok")
    assert r("http://shop/rest/user/login") == ("vuln_a", "ok")
    assert r("sqli:/search") == ("vuln_b", "ok")                        # a dedup group = its canonical finding
    assert r("SQL Injection") == (None, "unknown")                      # never the free title
    assert r("http://shop/x") == (None, "ambiguous")
    assert r("vuln_a", "vuln_a") == (None, "self") and r("SQLi login", "vuln_a") == (None, "self")
    w = dl.push_warnings(["vuln_a", "later_one", "http://shop/x"], vulns, "vuln_z")
    assert len(w) == 2 and any("kept" in x for x in w) and any("several" in x for x in w)


def test_valid_and_flagged_links():
    pytest.importorskip("api.attack_tactics")  # ATT&CK plausibility needs the MITRE extract (not shipped in Community)
    vulns = [
        F("A", "T1190", "initial-access"),                                   # SQLi
        F("B", "T1078", "privilege-escalation", enabled_by=["A"]),          # uses A's token
        F("C", "T1486", "impact"),
        F("D", "T1190", "initial-access", enabled_by=["C"]),                # impact feeds access: plausible (round 5)
        F("E", None, enabled_by=["A"]),                                     # untagged CONSUMER: kept, warned
        F("U", None),
        F("V", "T1078", "privilege-escalation", enabled_by=["U"]),          # untagged ENABLING finding: warned (40-paths-v2)
        F("G", "T1078", "privilege-escalation", enabled_by=["H", "G", "nope"]),   # forward, self, unknown
        F("H", "T1190", "initial-access"),
        F("I", "T1078", "privilege-escalation", status="unconfirmed", enabled_by=["A"]),
        F("J", "T1078", "privilege-escalation", enabled_by=["A"], node_id="ghost"),
        F("K", "T1592", "reconnaissance", enabled_by=["A"]),                # odd order: warning only
    ]
    got = {(l["producer"], l["consumer"]): l for l in dl.validate(vulns, known_nodes={"web"})}
    assert got[("A", "B")]["valid"] and got[("A", "B")]["level"] == "declared" and got[("A", "B")]["warnings"] == []
    assert got[("C", "D")]["valid"] and got[("C", "D")]["warnings"] == []
    assert got[("A", "E")]["valid"] and got[("A", "E")]["warnings"] == ["consumer-untagged"]
    # 40-paths-v2: ATT&CK is context only — a missing tag is a warning, never a verdict on the link
    assert got[("U", "V")]["valid"] and got[("U", "V")]["warnings"] == ["enabling-finding-untagged"]
    # architecture D: pushed after the declaration = forward in time, a rejected declaration (listed, never used)
    assert not got[("H", "G")]["valid"] and got[("H", "G")]["flags"] == ["forward-reference"]
    assert (got[("H", "G")]["state"], got[("H", "G")]["reason"]) == ("rejected_declaration", "forward_reference")
    assert got[("G", "G")]["state"] == got[("nope", "G")]["state"] == "rejected_declaration"
    assert got[("A", "B")]["state"] == "declared_by_agent" and got[("A", "B")]["reason"] is None
    assert got[("G", "G")]["flags"] == ["self-reference"]
    assert got[("nope", "G")]["flags"] == ["unknown-finding"]
    assert got[("A", "I")]["flags"] == ["not-live:I"]
    assert got[("A", "J")]["flags"] == ["unknown-node:J"]
    assert got[("A", "K")]["valid"] and got[("A", "K")]["warnings"] == ["tactic-order-unusual"]
    assert dl.flag_label(got[("A", "I")]["flags"]).startswith("not used for paths")


# probe r3/attck.py — universal chains as an agent tags them (round4-critique § 2): none is blocked any more
UNIVERSAL = {
    "product tampering (impact) -> session hijack": ("T1565.001", None, "T1185", None),
    "Kerberoast -> lateral SMB": ("T1558.003", None, "T1021.002", None),
    "credentials file on a share (collection) -> valid accounts": ("T1039", None, "T1078", None),
    "GPP cpassword -> DCSync": ("T1552.006", None, "T1003.006", None),
    "IMDS creds via SSRF -> S3 read": ("T1552.005", None, "T1530", None),
    "S3 data -> valid cloud accounts": ("T1530", None, "T1078.004", None),
    "firmware extraction (collection) -> command execution": ("T1005", None, "T1059", None),
    "exfiltration -> valid accounts": ("T1567", None, "T1078", None),
    "account access removal (impact) -> lateral": ("T1531", None, "T1021", None),
    "ICS: unauthorized command message -> modify parameter": ("T0855", "TA0104", "T0836", "TA0106"),
    "ICS without a declared tactic": ("T0855", None, "T0836", None),
    "Mobile: stored app data -> valid accounts": ("T1409", "TA0035", "T1078", None),
    "web shell (persistence) -> new initial access": ("T1505.003", None, "T1190", None),
    "sudo -> credential dump": ("T1548.003", None, "T1003.008", None),
}


@pytest.mark.parametrize("name", sorted(UNIVERSAL))
def test_universal_chains_are_never_blocked(name):
    pt, pta, ct, cta = UNIVERSAL[name]
    vulns = [F("P", pt, pta), F("C", ct, cta, enabled_by=["P"])]
    (l,) = dl.validate(vulns)
    assert l["valid"], (name, l)


def test_ics_and_mobile_tactics_are_understood():
    assert dl.tactics_info({"mitre_attack_id": "T0855", "mitre_tactic": "TA0104"}) == (["execution"], "unchecked")
    assert dl.tactics_info({"mitre_attack_id": "T1409", "mitre_tactic": "Collection"})[0] == ["collection"]
    assert dl.tactics_info({}) == ([], "untagged")


def test_a_cycle_in_an_edited_store_is_reported_never_blocking():
    # architecture D: in push order one side of a cycle is always forward in time (rejected); an edited store whose
    # declarations are both dated after both pushes yields a cycle: CONTRACT-D final-review clarification — reported
    # as a « cycle » warning, never a demotion (each edge keeps its own state; assembly walks simple paths only)
    vulns = [F("A", "T1078", "credential-access", enabled_by=["B"]), F("B", "T1078", "credential-access", enabled_by=["A"])]
    got = {(l["producer"], l["consumer"]): l for l in dl.validate(vulns)}
    assert got[("B", "A")]["flags"] == ["forward-reference"] and got[("A", "B")]["valid"]
    vulns[0] = dict(vulns[0], enabled_by_at={"B": 2})
    got = {(l["producer"], l["consumer"]): l for l in dl.validate(vulns)}
    assert got[("A", "B")]["valid"] and got[("B", "A")]["valid"]
    assert "cycle" in got[("A", "B")]["warnings"] and "cycle" in got[("B", "A")]["warnings"]
    assert "cycle" not in got[("A", "B")]["flags"] + got[("B", "A")]["flags"]
    assert dl._cycle_nodes({"x": ["y"], "y": ["z"], "z": ["x"], "w": ["x"]}) == {"x", "y", "z"}


def test_a_duplicate_declaring_its_original_is_not_a_chain():
    vulns = [F("X1", "T1190", "initial-access"), dict(F("X2", "T1190", "initial-access", enabled_by=["X1"]), duplicate_of="X1"),
             dict(F("Y1", "T1190", "initial-access"), dedup_key="sqli:/login"),
             dict(F("Y2", "T1213", "collection", enabled_by=["Y1"]), dedup_key="sqli:/login")]
    got = {(l["producer"], l["consumer"]): l for l in dl.validate(vulns)}
    assert got[("X1", "X2")]["flags"] == ["same-dedup-group"] and not got[("X1", "X2")]["valid"]
    assert not got[("Y1", "Y2")]["valid"]
