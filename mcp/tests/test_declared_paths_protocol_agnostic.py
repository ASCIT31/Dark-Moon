"""Round 4 (owner): the attack-path method is UNIVERSAL. Three chains — web, Active Directory, IoT — built ONLY from
findings carrying an ATT&CK technique / tactic and `enabled_by` (no request, no tool output, no protocol-specific
field) give paths through the same code: each step is « declared by the agent, not verified by the server », the path's
level is its weakest step, the simulation and Fix first see the chain and say its level. Incoherent, forward, self and
cyclic declarations are listed and never used."""
from __future__ import annotations

import pytest

from api import attack_paths


def F(fid, title, tech, tactic, node, enabled_by=None, severity="high", status="exploited"):
    v = {"id": fid, "title": title, "severity": severity, "status": status, "category": "x", "campaign_id": "camp_decl",
         "mitre_attack_id": tech, "mitre_tactic": tactic, "node_id": node, "endpoint": f"{node}"}
    if enabled_by:
        v["enabled_by"] = enabled_by
    return v


def nodes_for(vulns):
    ns = {}
    for v in vulns:
        ns.setdefault(v["node_id"], {"id": v["node_id"], "label": v["node_id"], "type": "host", "vulnerability_ids": []})
        ns[v["node_id"]]["vulnerability_ids"].append(v["id"])
    return list(ns.values())


# a TRUE web chain (round 5): the SQL injection logs in as the administrator; only the admin token opens /api/Users
WEB = [F("W1", "SQL injection in login: bypass as the administrator", "T1190", "initial-access", "shop"),
       F("W2", "Admin-only user list read with the administrator token", "T1213", "collection", "shop-db", ["W1"],
         severity="critical")]
AD = [F("A1", "AS-REP roasting of brandon.stark", "T1558.004", "credential-access", "dc-north"),
      F("A2", "Cracked AS-REP hash (weak password)", "T1110.002", "credential-access", "dc-north", ["A1"]),
      F("A3", "Password reuse: local admin on castelblack", "T1021.002", "lateral-movement", "castelblack", ["A2"]),
      F("A4", "DCSync of the domain", "T1003.006", "credential-access", "dc-sevenkingdoms", ["A3"], severity="critical")]
IOT = [F("I1", "Hardcoded credentials in the firmware image", "T1552.001", "credential-access", "iotgoat-fw"),
       F("I2", "Telnet root login with the firmware credentials", "T1078.003", "initial-access", "iotgoat", ["I1"],
         severity="critical")]


@pytest.mark.parametrize("name,vulns,first,last", [("web", WEB, "W1", "W2"), ("ad", AD, "A1", "A4"), ("iot", IOT, "I1", "I2")])
def test_each_chain_is_an_agent_declared_path(name, vulns, first, last):
    camp, nodes = {"id": "camp_decl"}, nodes_for(vulns)
    doc = attack_paths.build_paths(camp, nodes, [], vulns, include_steps=True)
    paths = [p for p in doc["paths"] if last in p["finding_ids"] and first in p["finding_ids"]]
    assert paths, name
    p = paths[0]
    # round 5 (honesty): its own provenance, a hypothesis, never « observed »
    assert (p["provenance"], p["hypothesis"], p["level"]) == ("agent-declared", True, "declared_by_agent")
    assert "not verified by the server" in p["level_label"] and "not verified by the server" in p["note"]
    assert set(p["finding_ids"]) == {v["id"] for v in vulns}
    impacts = [s["impact"] for s in p["steps"] if (s.get("impact") or {}).get("rule") == "D"]
    assert len(impacts) == len(vulns) - 1 and all(i["level"] == "declared_by_agent" for i in impacts)
    assert all(i["reason"] == "missing_data" for i in impacts)       # architecture D: no run facts in these fixtures
    links = [l for l in doc["observed_links"] if l["kind"] == "D"]
    assert all(l["level"] == "declared_by_agent" and l["ranked"] for l in links) and len(links) == len(vulns) - 1
    assert doc["summary"]["proven_paths"] == 0 and doc["summary"]["declared_paths"] == 1
    assert "observed" not in doc["summary"]["provenances"]
    # the simulation tells the cut apart, never as a proven path
    sim = attack_paths.simulate(camp, nodes, [], vulns, [first])
    assert p["id"] not in sim["declared_interrupted"]      # 40-paths-v2: a declared link is never « broken » by a fix
    sim = attack_paths.simulate(camp, nodes, [], vulns, [last])
    assert p["id"] in sim["declared_interrupted"] and p["id"] not in sim["proven_interrupted"]
    assert sim["proven_paths_before"] == 0
    # ranking and Fix first never rest on it
    assert doc["ranking"]["allowed"] is False
    reasons = " ".join(" ".join(i.get("reasons") or []) for i in doc["fix_first"]["items"])
    assert "chain" not in reasons and "observed:" not in reasons


@pytest.mark.parametrize("bad", [
    [F("X1", "SQLi", "T1190", "initial-access", "h", ["X1"])],                                                   # self
    [F("X1", "A", "T1078", "credential-access", "h", ["X2"]), F("X2", "B", "T1078", "credential-access", "h", ["X1"])],
])
def test_invalid_declarations_never_make_a_path(bad):
    doc = attack_paths.build_paths({"id": "camp_decl"}, nodes_for(bad), [], bad, include_steps=True)
    used = [l for l in doc["observed_links"] if l["kind"] == "D" and l["ranked"]]
    rejected = [l for l in doc["observed_links"] if l["kind"] == "D" and not l["ranked"]]
    multi = [p for p in doc["paths"] if p["provenance"] in ("observed", "agent-declared") and len(p["finding_ids"]) > 1
             and any((s.get("impact") or {}).get("rule") == "D" for s in p.get("steps") or [])]
    if len(bad) == 2 and bad[0].get("enabled_by") == ["X2"] and bad[1].get("enabled_by") == ["X1"]:
        assert len(used) <= 1                                     # the cycle: the forward half is rejected
    else:
        assert used == [] and multi == [] and rejected
        assert any(i["kind"] == "declared-links-not-used" for i in doc["issues"])


def test_an_observed_link_on_the_same_pair_wins():
    from api.attack_paths_observed import derive_observed_input
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.U2lnbmF0dXJlU2lnbmF0dXJlU2ln"
    w1 = dict(WEB[0], category="sql_injection", evidence={"raw_response": f'{{"token":"{tok}"}}', "raw_request": "POST /rest/user/login"})
    w2 = dict(WEB[1], evidence={"raw_request": f"GET /rest/basket/2\nAuthorization: Bearer {tok}"})
    obs = derive_observed_input(nodes_for([w1, w2]), [w1, w2], "camp_decl")
    kinds = [l["kind"] for l in obs["links"] if l["consumer"] == "W2"]
    assert "R1" in kinds and "D" not in kinds


def test_a_producer_pushed_later_is_a_forward_reference_unless_added_later():
    """Architecture D (CONTRACT-D): a reference to a finding pushed AFTER the declaration is « forward in time »:
    listed as rejected_declaration, never a path edge. The same reference added by a later re-push is valid."""
    vulns = [F("X1", "Admin user list", "T1213", "collection", "h2", ["sqli-login"]),
             dict(F("X2", "SQLi login bypass", "T1190", "initial-access", "h1"), dedup_key="sqli-login")]
    doc = attack_paths.build_paths({"id": "camp_decl"}, nodes_for(vulns), [], vulns, include_steps=True)
    (l,) = [l for l in doc["observed_links"] if l["kind"] == "D"]
    assert l["producers"] == ["X2"] and not l["ranked"] and l["level"] == "rejected_declaration"
    assert l["verification"]["reason"] == "forward_reference"
    assert not any(p["provenance"] == "agent-declared" for p in doc["paths"])
    vulns[0] = dict(vulns[0], enabled_by_at={"sqli-login": 2})          # declared by a re-push after X2 existed
    doc = attack_paths.build_paths({"id": "camp_decl"}, nodes_for(vulns), [], vulns, include_steps=True)
    (l,) = [l for l in doc["observed_links"] if l["kind"] == "D"]
    assert l["ranked"] and l["level"] == "declared_by_agent"
    assert any(p["provenance"] == "agent-declared" for p in doc["paths"])


def test_a_chain_open_registration_makes_doubtful_stays_declared_and_says_so():
    """Negative fixture (round-1 A1): SQLi → the tester's OWN basket. Open registration already gives any account, so
    the link may be false; the server cannot know: it is listed as declared, warned, never proven."""
    def H(v):
        return dict(v, endpoint=f"http://shop.local:3000/{v['id']}")
    vulns = [H(F("N0", "Open user registration", "T1078", "initial-access", "shop")),
             H(F("N1", "SQL injection in login", "T1190", "initial-access", "shop")),
             H(F("N2", "Basket read with a session token", "T1213", "collection", "shop", ["N1"]))]
    doc = attack_paths.build_paths({"id": "camp_decl"}, nodes_for(vulns), [], vulns, include_steps=True)
    (l,) = [l for l in doc["observed_links"] if l["kind"] == "D"]
    assert l["ranked"] and "open-registration" in l["warnings"] and l["level"] == "declared_by_agent"
    assert doc["summary"]["proven_paths"] == 0 and doc["summary"]["declared_paths"] >= 1
