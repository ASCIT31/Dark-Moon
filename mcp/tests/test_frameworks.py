"""api/frameworks.py (darkmoon-frameworks/v1: ATT&CK / feasibility / EBIOS RM / ATLAS / ISO): proof credentials are a
signal only, owner links, difficulty bound."""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import glob
import json
import os
from pathlib import Path

import pytest

from api import frameworks as F

AV_N = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
AV_N_PRL = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
AV_N_ACH = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
DATA = Path(F.__file__).parent / "frameworks_data"


def vuln(i, status="confirmed", vec=AV_N, tid="T1190", cat="sql_injection", agent="php", iso="A.8.28 Secure Coding", **kw):
    return {"id": f"v{i}", "status": status, "cvss_vector": vec, "mitre_attack_id": tid, "category": cat,
            "discovered_by_agent": agent, "iso27001_control": iso, "title": f"t{i}", **kw}


# --- vendored references, licences, lineage -----------------------------------------------------

def test_vendored_tables_carry_version_licence_hash():
    for cat in (F.attack_catalog(), F.atlas_catalog()):
        assert cat["version"] and cat["license"] and cat["copyright"] and len(cat["source_sha256"]) == 64
    assert (F.attack_catalog()["version"], F.atlas_catalog()["version"]) == ("20.0", "2026.10")


def test_licence_texts_are_shipped():
    attack = (F.ATTACK_DIR / "LICENSE.txt").read_text()   # the single ATT&CK licence (shared with P2)
    assert "royalty-free license" in attack and "The MITRE Corporation" in attack
    atlas = (DATA / "LICENSE-ATLAS.txt").read_text()
    assert "Apache License" in atlas and "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in atlas
    assert "Copyright 2021-2026 MITRE" in atlas
    assert "sha256" in (DATA / "README-PROVENANCE.md").read_text()


def test_every_crosswalk_atlas_id_exists_and_fields_are_closed():
    cw, techs = F.llm_crosswalk(), F.atlas_catalog()["techniques"]
    for cat, e in cw["categories"].items():
        for t in e["atlas"]:
            assert t["id"] in techs, f"{cat}: {t['id']} absent from ATLAS {F.atlas_catalog()['version']}"
            assert t["max_relation"] in cw["relations"] and t["source"] in cw["sources"]


def test_lineage_is_consistent_with_the_official_diff():
    cw, cat = F.llm_crosswalk(), F.atlas_catalog()
    removed = cat["removed_since_previous"]
    lineage = {k: v for k, v in cw["lineage"].items() if not k.startswith("_")}
    assert set(lineage) == set(removed)                      # every removed ID is documented, no invented one
    for old, l in lineage.items():
        assert l["old_name"] == removed[old]
        assert l["successor"] is None or l["successor"] in cat["techniques"]
        if l["basis"] == "same_name":
            assert cat["techniques"][l["successor"]]["name"] == l["old_name"]
    used = {t["id"] for e in cw["categories"].values() for t in e["atlas"]}
    assert not used & set(removed)
    for e in cw["categories"].values():
        for t in e["atlas"]:
            if "replaces" in t:                              # 'renumbered' must point to a removed ID whose successor is this one
                assert t["source"] == "owasp-cited-renumbered"
                assert t["replaces"] in removed and lineage[t["replaces"]]["successor"] == t["id"]
            if t["source"] == "owasp-cited-renumbered":
                assert "replaces" in t


def test_t0137_003_is_curated_not_renumbered():
    e = F.llm_crosswalk()["categories"]["llm_training_data_extraction"]["atlas"][0]
    assert e["id"] == "AML.T0137.003" and e["source"] == "curated" and "replaces" not in e


def test_crosswalk_is_labelled_curated_not_official():
    assert "NOT an official" in F.llm_crosswalk()["status"]


# --- ATT&CK ------------------------------------------------------------------------------------

def test_attack_name_and_tactics_from_catalog_and_name_issue():
    v = vuln(1, tid="T1185", mitre_attack_name="Browser Session Forgery")
    ref = F.attack_ref(v)
    assert ref["name"] == "Browser Session Hijacking" and ref["agent_name_differs"] and ref["tactics"] == ["collection"]
    m = F.attack_matrix([v])
    assert any(i["kind"] == "agent-technique-name-differs" and i["official_name"] == "Browser Session Hijacking" for i in m["issues"])


def test_subtechnique_display_name_is_composed_and_prefixed_agent_name_accepted():
    ref = F.attack_ref(vuln(1, tid="T1552.001", mitre_attack_name="Unsecured Credentials: Credentials In Files"))
    assert ref["name"] == "Unsecured Credentials: Credentials In Files" and not ref["agent_name_differs"]


def test_revoked_id_is_mapped_through_official_revoked_by():
    ref = F.attack_ref(vuln(1, tid="T1562.001"))
    assert ref["state"] == "revoked_replaced" and ref["agent_id"] == "T1562.001" and ref["id"] == "T1685"
    m = F.attack_matrix([vuln(1, tid="T1562.001")])
    di = next(t for t in m["tactics"] if t["name"] == "Defense Impairment")
    assert di["techniques"][0]["technique_id"] == "T1685" and di["techniques"][0]["via_revoked_by"] == ["v1"]
    assert any(i["kind"] == "attack-id-revoked-replaced" for i in m["issues"])


@pytest.mark.parametrize("tid,final", [("T1073", "T1574.001"), ("T1150", "T1647"), ("T1162", "T1647")])
def test_revocation_chain_is_followed_to_a_live_technique(tid, final):
    ref = F.attack_ref(vuln(1, tid=tid))
    assert ref["state"] == "revoked_replaced" and ref["id"] == final
    assert not F.attack_catalog()["techniques"][ref["id"]]["revoked"]


def test_duplicate_findings_count_once_in_a_cell():
    a = vuln(1, title="Same", campaign_id="c", target_id="t", endpoint="http://h/x", category="information_disclosure")
    b = vuln(2, title="Same", campaign_id="c", target_id="t", endpoint="http://h/x", category="information_disclosure")
    cell = next(t for t in F.attack_matrix([a, b])["tactics"] if t["techniques"])["techniques"][0]
    assert cell["finding_ids"] == ["v1", "v2"] and cell["distinct_findings"] == 1


def test_attack_unknown_missing_reported_and_matrix_order():
    m = F.attack_matrix([vuln(1, tid="T9999"), vuln(2, tid=None), vuln(3)])
    assert m["coverage"]["unknown"] == 1 and m["coverage"]["missing"] == 1 and m["coverage"]["valid"] == 1
    assert [t["name"] for t in m["tactics"]][:3] == ["Reconnaissance", "Resource Development", "Initial Access"]
    assert m["tactics"][-1]["name"] == "Impact" and m["counts_not_additive"] is True


def test_attack_matrix_excludes_false_positive_and_remediated():
    m = F.attack_matrix([vuln(1, status="false_positive"), vuln(2, status="remediated")])
    assert m["coverage"]["findings"] == 0 and "never 'protected'" in m["reading"]


# --- CVSS parsing / prerequisite / feasibility DM-FEAS-1 ---------------------------------------------

@pytest.mark.parametrize("vec,state", [
    (AV_N, "ok"), ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "ok"),
    (None, "absent"), ("", "absent"), (42, "invalid"), ("CVSS:2.0/AV:N", "unsupported"),
    ("CVSS:4.0 base score 9.2 (advisory)", "invalid"), (AV_N + "/AV:L", "invalid"), (AV_N.lower(), "invalid"),
    ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N", "invalid"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N", "invalid"),                       # m-3: base metrics S/C/I/A missing
    (AV_N + "/ZZ:Q", "invalid"),                                          # m-3: unknown metric
    (AV_N + "/E:P/RL:O", "ok"),                                           # temporal metrics are legal
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", "invalid"),                    # 4.0 without its impact metrics
])
def test_vector_states(vec, state):
    assert F.parse_vector(vec)["state"] == state


@pytest.mark.parametrize("status,vec,level", [
    ("exploited", AV_N, 4), ("exploited", AV_N_PRL, 3), ("exploited", "", 3), ("exploited", "garbage", 3),
    ("confirmed", AV_N, 2), ("confirmed", AV_N_ACH, 1), ("confirmed", AV_N_PRL, 1), ("confirmed", "", 1),
    ("unconfirmed", AV_N, None),
])
def test_feasibility_rule(status, vec, level):
    assert F.feasibility(vuln(1, status=status, vec=vec))["level"] == level


def test_feasibility_is_not_called_likelihood():
    f = F.feasibility(vuln(1, status="exploited"))
    assert f["rule"] == "DM-FEAS-1" and "vraisembl" not in f["label"].lower()


# Real cases. Credentials in the proof never change the level (signal only).
JWT_NONE = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."


@pytest.mark.parametrize("title,status,evidence,level,seen", [
    ("JWT alg:none signature bypass", "exploited", {"raw_request": f"GET /rest/basket HTTP/1.1\nAuthorization: Bearer {JWT_NONE}"}, 4, False),
    ("JWT algorithm confusion RS256->HS256", "exploited", {"commands": ['curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.x" http://t/api']}, 4, True),
    ("SQLi auth bypass", "exploited", {"commands": ['curl -s http://t/rest/x -H "Authorization: Bearer <stolen_admin_token>"']}, 4, False),
    ("Session fixation", "confirmed", {"commands": ['curl -b "PHPSESSID=aaaaaaaaaaaaaaaaaaaaaaaaaa1" http://t/']}, 2, True),
    ("Missing security headers", "confirmed", {"commands": ["nuclei -u http://127.0.0.1:19111 -t http/misconfiguration"]}, 2, False),
    ("Open user registration", "exploited", {"commands": ["nuclei -u http://172.25.0.4:3000 -tags exposure"]}, 4, False),
    ("sqlmap", "exploited", {"commands": ['sqlmap -u "http://x/?id=1" --batch']}, 4, False),
    ("Cookie banner", "confirmed", {"raw_request": "GET / HTTP/1.1\nCookie: language=en; welcomebanner_status=dismiss"}, 2, True),
    ("Basic auth", "exploited", {"commands": ["curl -u tester:Passw0rd http://gitea/api/v1/user"]}, 4, True),
])
def test_credentials_in_proof_are_a_signal_never_a_downgrade(title, status, evidence, level, seen):
    v = vuln(1, status=status, vec=AV_N, title=title, evidence=evidence)
    f = F.feasibility(v)
    assert f["level"] == level and f["prerequisite"]["basis"] == "agent_cvss_3.1"
    assert f["prerequisite"]["credentials_seen_in_proof"]["seen"] is seen


def test_forged_and_placeholder_tokens_are_listed_as_excluded():
    s = F.proof_credentials_signal({"evidence": {"raw_request": f"Authorization: Bearer {JWT_NONE}"}})
    assert s == {"seen": False, "kinds": [], "excluded": ["authorization:forged_jwt_alg_none"]}


def test_same_finding_type_same_level_across_campaigns():
    # Juice Shop SQLi auth bypass, 2 campaigns: one proof carries a cookie, the other does not -> same level
    a = vuln(1, status="exploited", title="SQL Injection Authentication Bypass - Admin Login", campaign_id="c1")
    b = vuln(2, status="exploited", title="SQL Injection Authentication Bypass - Admin Login", campaign_id="c2",
             evidence={"raw_request": "POST /rest/user/login HTTP/1.1\nCookie: language=en"})
    feas, issues = F.feasibility_index([a], scope=[a, b])
    feas2, _ = F.feasibility_index([b], scope=[a, b])
    assert feas["v1"]["level"] == feas2["v2"]["level"] == 4 and issues == []


def test_same_cve_conflict_is_resolved_on_the_defender_side_and_reported():
    a = vuln(1, status="exploited", vec=AV_N, cve="CVE-2026-60004")
    b = vuln(2, status="exploited", vec=AV_N_PRL, cve="CVE-2026-60004")
    feas, issues = F.feasibility_index([a, b])
    assert feas["v1"]["level"] == feas["v2"]["level"] == 4          # highest feasibility: never hide a risk
    assert feas["v2"]["prerequisite"]["own"] == {"required": True, "basis": "agent_cvss_3.1"}
    assert len(issues) == 1 and issues[0]["kind"] == "same_type_different_prereq" and issues[0]["finding_ids"] == ["v1", "v2"]
    assert issues[0]["values"] == [("False", "agent_cvss_3.1"), ("True", "agent_cvss_3.1")]
    feas, _ = F.feasibility_index([vuln(4, cve="CWE-79", title="a"), vuln(5, cve="CWE-79", vec=AV_N_PRL, title="b")])
    assert feas["v4"]["level"] != feas["v5"]["level"]       # CWE is not a CVE and the titles differ: no consolidation


def test_project_scope_consolidates_but_returns_only_the_campaign_findings():
    a = vuln(1, status="confirmed", vec=AV_N_PRL, cve="CVE-2026-1111")
    b = vuln(2, status="confirmed", vec=AV_N, cve="CVE-2026-1111")
    feas, issues = F.feasibility_index([a], scope=[a, b])
    assert list(feas) == ["v1"] and feas["v1"]["level"] == 2 and issues[0]["other_campaign_findings"] == 1


def test_agent_declared_prerequisites_closed_vocabulary():
    assert F.feasibility(vuln(1, status="exploited", vec=AV_N_PRL, prerequisites=["account_self_registrable"]))["level"] == 4
    assert F.feasibility(vuln(1, status="exploited", vec=AV_N, prerequisites=["account"]))["level"] == 3
    assert F.prerequisite(vuln(1, prerequisites=["made_up"]))["basis"] == "agent_cvss_3.1"     # outside the vocabulary: ignored


def test_min_attacker_profile_is_not_a_risk_source():
    assert F.min_attacker_profile(vuln(1)) == "external_unauthenticated"
    assert F.min_attacker_profile(vuln(1, vec=AV_N_PRL)) == "authenticated_user"
    assert F.min_attacker_profile(vuln(1, vec="")) is None


# --- EBIOS RM ----------------------------------------------------------------------------------

def test_scales_are_the_anssi_fiche_8_wording():
    assert F.V_LABELS == {0: "Invraisemblable", 1: "Peu vraisemblable", 2: "Vraisemblable", 3: "Très vraisemblable", 4: "Quasi-certain"}
    assert F.PR_LABELS[4] == "Quasi-certaine" and F.DIF_LABELS[0] == "Négligeable" and F.G_LABELS[3] == "Grave"
    assert F.GRID[4] == [4, 4, 3, 2, 1] and F.GRID[0] == [1, 1, 1, 0, 0]
    assert "Fiche méthode 8" in F.EBIOS_SOURCE


def _path(pid="ap_1", steps=(("v1", "T1190"), ("v2", "T1059.004")), hypothesis=False, status="open"):
    return {"id": pid, "title": "x", "status": status, "hypothesis": hypothesis, "provenance": "observed",
            "certainty": "exploited", "objective": {"node_id": "host-main", "label": "h"},
            "steps": [{"n": i + 1, "node_label": "n", "satisfied_by": [[f]], "technique": {"id": t}, "proof": "exploited"}
                      for i, (f, t) in enumerate(steps)]}


def _cand(vs, ctx=None, paths=None, **kw):
    return F.ebios_view({"paths": paths or [_path()]}, vs, ctx, **kw)["candidate_paths"][0]


def _key(vs, paths=None):
    return _cand(vs, paths=paths)["link_key"]


def test_candidate_path_has_difficulty_bound_and_indicative_grid_column_only():
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited", vec=AV_N_PRL), vuln(3)]
    eb = F.ebios_view({"paths": [_path()]}, vs)
    c = eb["candidate_paths"][0]
    assert c["candidate_id"].startswith("CAND-") and c["path_id"] == "ap_1" and F.LINK_KEY_RE.match(c["link_key"])
    assert c["difficulty_proposed"] == {"state": "proposed_upper_bound", "level": 1, "label": "Faible",
                                        "rule": "DM-DIF-1 (upper bound) + fiche 8 Max/Min"}
    assert c["probability_of_success"]["state"] == "to_assess" and "Min/Max" in c["probability_of_success"]["note"]
    lk = c["likelihood"]
    assert lk["state"] == "indicative_grid_column" and lk["grid_column"] == {"4": 4, "3": 3, "2": 3, "1": 2, "0": 1}
    assert "range" not in lk and "level" not in lk and "+1" not in lk["note"] and "augmentée d'un niveau" in lk["note"]
    assert c["gravity"]["state"] == "to_assess" and c["risk"] is None and c["strategic_scenario"] is None
    assert [u["finding_id"] for u in eb["unlinked_vulnerabilities"]] == ["v3"]
    assert "likelihood" not in eb["unlinked_vulnerabilities"][0]
    assert {"probability_of_success", "likelihood_validation", "strategic_scenarios"} <= set(eb["needs_owner_input"])


def test_f1_step_never_yields_moderate_difficulty_nor_cuts_v4():
    # verified, not exploited (F1): no difficulty is proposed, so the upper V bound is never reduced from a non-observation
    assert F.FEAS_TO_DIF[1] is None
    vs = [vuln(1, status="exploited"), vuln(2, status="confirmed", vec=AV_N_ACH)]
    c = _cand(vs)
    assert c["difficulty_proposed"] == {"state": "not_proposed", "level": None, "label": None,
                                        "rule": "DM-DIF-1 (upper bound) + fiche 8 Max/Min"}
    assert c["likelihood"]["state"] == "not_proposed" and "not demonstrated" in c["likelihood"]["reason"]
    for d in (0, 1):                                            # every proposable column still reaches V4
        assert max(F.GRID[p][d] for p in range(5)) == 4


def test_link_key_is_campaign_independent_and_carries_owner_inputs_over():
    v1 = [vuln(1, status="exploited", campaign_id="c1"), vuln(2, status="exploited", campaign_id="c1")]
    v2 = [{**vuln(7, status="exploited"), "campaign_id": "c2"}, {**vuln(8, status="exploited"), "campaign_id": "c2"}]
    p1 = _path("ap_aaaaaaaaaaaa", steps=(("v1", "T1190"), ("v2", "T1059.004")))
    p2 = _path("ap_bbbbbbbbbbbb", steps=(("v7", "T1190"), ("v8", "T1059.004")))
    k1, k2 = _key(v1, [p1]), _key(v2, [p2])
    assert k1 == k2 and "ap_" not in k1 and "c1" not in k1
    ctx = {"feared_events": [{"id": "ER-01", "label": "Fuite des données clients", "gravity": 3, "criterion": "C", "link_keys": [k1]}]}
    assert _cand(v2, ctx, [p2])["gravity"]["level"] == 3       # the next campaign keeps the owner's link
    other = _path("ap_cccccccccccc", steps=(("v7", "T1190"), ("v8", "T1005")))
    assert _key(v2, [other]) != k1                              # different chain, different key


def test_candidate_id_is_stable_when_other_paths_disappear():
    vs = [vuln(i, status="exploited") for i in (1, 2, 3, 4)]
    vs[2]["category"] = vs[3]["category"] = "xxe"
    p1, p2 = _path("ap_1"), _path("ap_2", steps=(("v3", "T1190"), ("v4", "T1005")))
    both = F.ebios_view({"paths": [p1, p2]}, vs)["candidate_paths"]
    only2 = F.ebios_view({"paths": [{**p1, "status": "interrupted_by_retest"}, p2]}, vs)["candidate_paths"]
    assert both[1]["candidate_id"] == only2[0]["candidate_id"] and both[1]["link_key"] == only2[0]["link_key"]


def test_two_paths_with_the_same_content_are_ambiguous_and_get_no_owner_input():
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    k = _key(vs)
    ctx = {"feared_events": [{"id": "ER-01", "label": "x", "gravity": 4, "criterion": "D", "link_keys": [k]}]}
    eb = F.ebios_view({"paths": [_path("ap_1"), _path("ap_2")]}, vs, ctx)
    assert all(c["link_key_ambiguous"] and c["gravity"]["state"] == "to_assess" for c in eb["candidate_paths"])
    assert sum(1 for i in eb["issues"] if i["kind"] == "link_key_ambiguous") == 2


def test_single_technique_path_is_not_a_candidate():
    vs = [vuln(1, status="exploited")]
    eb = F.ebios_view({"paths": [_path(steps=(("v1", "T1190"), ("v1", "T1190")))]}, vs)
    assert eb["counts"]["candidate_paths"] == 0 and eb["counts"]["single_step_paths"] == 1
    assert eb["single_step_paths"][0]["steps"][0]["merged_steps"] == [1, 2]


def test_difficulty_uses_anssi_max_min_rule():
    vs = [vuln(1, status="exploited"), vuln(2, status="confirmed", vec=AV_N_ACH), vuln(3, status="exploited"),
          vuln(4, status="exploited", vec=AV_N_PRL)]
    p = _path()
    p["steps"][1]["satisfied_by"] = [["v2"], ["v3"]]           # easiest alternative wins (min), F1 alternative ignored
    assert _cand(vs, paths=[p])["difficulty_proposed"]["level"] == 0
    p["steps"][1]["satisfied_by"] = [["v4"]]                   # hardest step of the chain counts (max)
    assert _cand(vs, paths=[p])["difficulty_proposed"]["level"] == 1


def test_unconfirmed_step_or_hypothesis_gives_no_proposal():
    vs = [vuln(1, status="exploited"), vuln(2, status="unconfirmed")]
    assert "lead" in _cand(vs)["likelihood"]["reason"]
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    assert _cand(vs, paths=[_path(hypothesis=True)])["likelihood"]["state"] == "not_proposed"


def test_risk_needs_owner_gravity_validated_likelihood_and_strategic_link():
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    k = _key(vs)
    ctx = {"updated_by": "rssi", "updated_at": "2026-11-03T10:00:00Z", "risk_sources": [{"id": "SR-01", "label": "Cybercriminel"}],
           "feared_events": [{"id": "ER-01", "label": "Fuite", "gravity": 3, "criterion": "C", "link_keys": [k]}],
           "path_assessments": {k: {"probability_of_success": 2}}}
    c = _cand(vs, ctx)
    assert c["likelihood"]["state"] == "proposed" and c["likelihood"]["level"] == 3 and c["likelihood"]["label"] == "Très vraisemblable"
    assert c["gravity"]["level"] == 3 and c["gravity"]["feared_events"][0]["criterion"] == "C" and c["risk"] is None
    ctx["path_assessments"][k].update(risk_source_adjustment=1, risk_source="SR-01")   # fiche 8: +1 by the risk source, RSSI decision
    c = _cand(vs, ctx)
    assert (c["likelihood"]["base_level"], c["likelihood"]["level"]) == (3, 4) and c["likelihood"]["state"] == "proposed"
    assert c["risk"] is None                                   # still a proposal
    ctx["path_assessments"][k].update(likelihood_validated=2)
    assert _cand(vs, ctx)["risk"] is None                      # validated but not linked to a strategic scenario
    ctx["path_assessments"][k].update(strategic_scenario="SS-01 Exfiltration par un cybercriminel")
    c = _cand(vs, ctx)
    assert c["likelihood"]["validated"] == {"level": 2, "label": "Vraisemblable", "state": "owner_validated",
                                            "by": "rssi", "at": "2026-11-03T10:00:00Z"}
    assert c["risk"] == {"gravity": 3, "likelihood": 2, "state": "owner_validated"} and c["risk_source"] == "SR-01"


@pytest.mark.parametrize("adj", [2, -1, True, "1"])
def test_risk_source_adjustment_is_at_most_one_level(adj):
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    k = _key(vs)
    eb = F.ebios_view({"paths": [_path()]}, vs, {"path_assessments": {k: {"probability_of_success": 2, "risk_source_adjustment": adj}}})
    assert eb["candidate_paths"][0]["likelihood"]["state"] == "indicative_grid_column"
    assert any(i["kind"] == "path-assessment-invalid" for i in eb["issues"])


@pytest.mark.parametrize("fe", [
    {"id": "ER", "label": "x", "gravity": True, "criterion": "C", "link_keys": ["lk_0000000000000000"]},
    {"id": "ER", "label": "x", "gravity": 3.0, "criterion": "C", "link_keys": ["lk_0000000000000000"]},
    {"id": "ER", "label": "x", "gravity": 5, "criterion": "C", "link_keys": ["lk_0000000000000000"]},
    {"id": "ER", "label": "x", "gravity": 3, "criterion": "X", "link_keys": ["lk_0000000000000000"]},
    {"id": "ER", "label": "x", "gravity": 3, "criterion": "C", "link_keys": "lk_0000000000000000"},
    {"id": "ER", "label": "x", "gravity": 3, "criterion": "C", "link_keys": ["ap_123"]},
    {"label": "x", "gravity": 3, "criterion": "C", "link_keys": ["lk_0000000000000000"]},
    {"id": "ER 01 <script>", "label": "x", "gravity": 3, "criterion": "C", "link_keys": []},
    {"id": "ER", "label": "x" * 201, "gravity": 3, "criterion": "C", "link_keys": []},
    {"id": "ER", "label": "a\nb", "gravity": 3, "criterion": "C", "link_keys": []},
    {"id": "ER", "label": "x", "gravity": 3, "criterion": "C", "link_keys": [], "business_value": "VM-404"},
    "ER-01",
])
def test_invalid_feared_events_are_rejected_not_coerced(fe):
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    eb = F.ebios_view({"paths": [_path()]}, vs, {"feared_events": [fe]})
    assert eb["candidate_paths"][0]["gravity"]["state"] == "to_assess" and eb["context"]["feared_events"] == []
    assert any(i["kind"] == "feared-event-invalid" for i in eb["issues"])


def test_duplicate_feared_event_ids_are_rejected_never_overwritten():
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    k = _key(vs)
    ctx = {"feared_events": [{"id": "ER-1", "label": "a", "gravity": 4, "criterion": "C", "link_keys": [k]},
                             {"id": "ER-1", "label": "b", "gravity": 1, "criterion": "D", "link_keys": [k]}]}
    eb = F.ebios_view({"paths": [_path()]}, vs, ctx)
    assert eb["candidate_paths"][0]["gravity"]["state"] == "to_assess"        # neither G4 nor G1, no silent winner
    assert [i for i in eb["issues"] if i["kind"] == "feared-event-duplicate-id"][0]["id"] == "ER-1"
    for field in ("business_values", "risk_sources"):
        _, iss = F.validate_context({field: [{"id": "X", "label": "a"}, {"id": "X", "label": "b"}]})
        assert iss[0]["kind"] == f"{field}-duplicate-id"


def test_unknown_or_empty_links_are_reported():
    _, iss = F.validate_context({"feared_events": [{"id": "ER-1", "label": "a", "gravity": 2, "criterion": "I", "link_keys": []}]})
    assert iss[0]["kind"] == "feared-event-unlinked" and iss[0]["link_keys"] == []
    ctx = {"feared_events": [{"id": "ER-1", "label": "a", "gravity": 2, "criterion": "I", "link_keys": ["lk_00000000000000aa"]}],
           "path_assessments": {"lk_00000000000000bb": {"probability_of_success": 1}}}
    _, iss = F.validate_context(ctx, known_link_keys={"lk_0000000000000001"})
    kinds = {i["kind"]: i for i in iss}
    assert kinds["feared-event-unlinked"]["link_keys"] == ["lk_00000000000000aa"]
    assert kinds["stale_owner_link"]["link_key"] == "lk_00000000000000bb"


def test_path_assessment_strict_fields():
    k = "lk_0000000000000001"
    for bad in ({"probability_of_success": "high"}, {"likelihood_validated": 5}, {"strategic_scenario": 3},
                {"strategic_scenario": "  "}, {"risk_source": "SR-404"}, {"assessed_by": "mallory"}):
        clean, iss = F.validate_context({"path_assessments": {k: bad}})
        assert clean["path_assessments"] == {} and iss[0]["kind"] == "path-assessment-invalid", bad


def test_author_and_date_come_from_the_stored_context_not_from_assessments():
    clean, _ = F.validate_context({"updated_by": "admin", "updated_at": "2026-11-03T10:00:00Z", "assessed_by": "mallory"})
    assert clean["updated_by"] == "admin" and "assessed_by" not in clean


def test_gravity_link_is_exact_key_no_substring():
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited")]
    k = _key(vs)
    near = k[:-1] + ("0" if k[-1] != "0" else "1")
    ctx = {"feared_events": [{"id": "ER", "label": "x", "gravity": 4, "criterion": "D", "link_keys": [near]}]}
    assert _cand(vs, ctx)["gravity"]["state"] == "to_assess"


def test_severity_never_becomes_gravity():
    vs = [vuln(1, status="exploited", severity="critical"), vuln(2, status="exploited", severity="critical")]
    assert _cand(vs)["gravity"]["level"] is None


MALFORMED = [
    ({"paths": [{"id": "p", "status": "open", "steps": [{"satisfied_by": [None]}]}]}, None),
    ({"paths": [{"id": "p", "status": "open", "steps": [{"satisfied_by": [["v1"]], "technique": "T1190"}]}]}, None),
    ({"paths": [{"id": "p", "status": "open", "objective": "n1", "steps": []}]}, None),
    ({"paths": [{"status": "open", "steps": []}]}, None),
    ({"paths": [_path()]}, {"feared_events": {"id": "x"}}),
    ({"paths": [_path()]}, ["not", "a", "dict"]),
    ({"paths": [_path()]}, {"path_assessments": ["x"]}),
    ({"paths": [_path()]}, {"path_assessments": {"lk_0000000000000001": {"probability_of_success": "high"}}}),
    ({"paths": [_path()]}, {"path_assessments": {3: {}}, "feared_events": [{"id": "E", "label": "x" * 10 ** 6}]}),
    ({"paths": "nope"}, None), (None, None), ({"paths": [None, 3, "x"]}, None),
    ({"paths": [{"id": "p", "status": "open", "steps": [None, {"satisfied_by": "v1"}]}]}, None),
]


@pytest.mark.parametrize("doc,ctx", MALFORMED)
def test_malformed_input_never_crashes(doc, ctx):
    vs = [vuln(1, status="exploited"), vuln(2), None, "x", {"id": 3}, {"no": "id"}]
    eb = F.ebios_view(doc, vs, ctx)
    assert isinstance(eb["issues"], list) and "counts" in eb


@pytest.mark.parametrize("bad", [None, "x", [None, 1, {"id": None}], [{"id": "v1", "status": 3, "cvss_vector": ["x"],
                                  "mitre_attack_id": 7, "category": None, "evidence": "str", "cve": 5, "iso27001_control": 9}]])
def test_other_views_tolerate_malformed_findings(bad):
    F.attack_matrix(bad); F.atlas_view(bad, bad, bad); F.iso_view(bad); F.feasibility_index(bad)


# --- ATLAS -------------------------------------------------------------------------------------

REAL_AGENTS = [{"agent": "headless-browser", "findings": 9, "level": 0, "status": "completed"},
               {"agent": "php", "findings": 9, "level": 0, "status": "completed"}]   # camp_20261103_e5eda97d


def test_atlas_states_on_real_agent_shape():
    web = [vuln(1)]
    assert F.atlas_view(web, [])["state"] == "unknown"
    assert F.atlas_view(web, None)["state"] == "unknown"
    assert F.atlas_view(web, REAL_AGENTS)["state"] == "not_tested"
    llm_ok = REAL_AGENTS + [{"agent": "llm", "findings": 0, "level": 1, "status": "completed"}]
    assert F.atlas_view(web, llm_ok)["state"] == "tested_no_ai_finding"
    for st in ("failed", "running", None):
        assert F.atlas_view(web, REAL_AGENTS + [{"agent": "llm", "status": st}])["state"] == "ai_test_incomplete"


def test_not_tested_label_never_says_not_applicable():
    for lab in F.STATE_LABELS.values():
        assert "not applicable" not in lab.lower() and "non applicable" not in lab.lower()


def test_ai_surface_detected_but_not_tested():
    nodes = [{"id": "svc-ollama", "label": "Ollama 0.5", "port": 11434}]
    a = F.atlas_view([vuln(1)], REAL_AGENTS, nodes)
    assert a["state"] == "ai_surface_not_tested" and a["ai_surface_hint_nodes"] == ["svc-ollama"]


@pytest.mark.parametrize("node", [
    {"id": "n", "service": "http", "product": "Open WebUI"}, {"id": "n", "details": "LiteLLM proxy"},
    {"id": "n", "label": "api", "endpoint": "/api/generate"}, {"id": "n", "title": "x", "endpoint": "/api/chat"},
])
def test_ai_surface_hints_read_service_product_details(node):
    assert F.atlas_view([vuln(1)], REAL_AGENTS, [node])["state"] == "ai_surface_not_tested"


def test_atlas_relation_follows_proof_and_names_are_composed():
    vs = [vuln(1, status="exploited", cat="prompt_injection_direct", agent="llm"),
          vuln(2, status="confirmed", cat="prompt_injection_direct", agent="llm"),
          vuln(3, status="exploited", cat="llm_unbounded_consumption", agent="llm"),
          vuln(4, cat="llm_improper_output_handling", agent="llm"), vuln(5, cat="weird", agent="llm")]
    a = F.atlas_view(vs, [{"agent": "llm", "status": "completed"}])
    by = {x["finding_id"]: x for x in a["ai_findings"]}
    assert by["v1"]["atlas"][0]["relation"] == "demonstrated" and by["v2"]["atlas"][0]["relation"] == "enabled"
    assert by["v1"]["atlas"][0]["name"] == "LLM Prompt Injection: Direct" and by["v1"]["owasp_llm"] == "LLM01:2025"
    assert {t["relation"] for t in by["v3"]["atlas"]} == {"enabled"}        # never demonstrated (no flooding)
    assert by["v4"]["no_atlas_equivalent"] is True
    assert [u["finding_id"] for u in a["unmapped_ai_findings"]] == ["v5"]


def test_web_findings_never_mapped_to_atlas_even_with_ai_words():
    v = vuln(1, cat="information_disclosure", title="Model configuration exposed (LLM prompt)")
    assert F.atlas_view([v], REAL_AGENTS)["ai_findings"] == []


# --- ISO ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("A.14.2.5", [("A.14.2.5", "2013")]),
    ("A.8.28 Secure Coding", [("A.8.28", "2022")]),
    ("A.8.5", [("A.8.5", "2022")]),
    ("A.8.3 Information Access Restriction", [("A.8.3", "ambiguous")]),
    ("A.6.1 Internal organization", [("A.6.1", "ambiguous")]),
    ("A.8.2 Information classification", [("A.8.2", "ambiguous")]),
    ("A.9.4", [("A.9.4", "2013")]),
    ("ISO 27001:2013 A.8.9", [("A.8.9", "invalid")]),
    ("ISO/IEC 27001:2022 A.8.3", [("A.8.3", "2022")]),
    ("A.8.3 / A.14.2.5 Secure system engineering", [("A.8.3", "ambiguous"), ("A.14.2.5", "2013")]),
    ("A.8.28 Secure Coding / A.8.2 Privileged", [("A.8.28", "2022"), ("A.8.2", "2022")]),
    ("CA.8.28", []), ("DATA.8.9", []), ("A.8.280", []),
    ("A.99.99.99", [("A.99.99.99", "invalid")]),
    ("a.8.28 secure coding", [("A.8.28", "2022")]), ("8.28 Secure coding", [("A.8.28", "2022")]),
    ("Annex A 5.15", [("A.5.15", "2022")]),
])
def test_iso_version_detection(raw, expected):
    assert [(r["ref"], r["version"]) for r in F.iso_refs(raw)["refs"]] == expected


@pytest.mark.parametrize("raw,ref,version,conflict", [
    ("ISO 27001:2013 A.8.28", "A.8.28", "invalid", True),      # A.8 has 3 categories in 2013
    ("ISO 27001:2022 A.12.6.1", "A.12.6.1", "2013", True),     # 2013 numbering under a 2022 label
    ("27001:2013 / 27001:2022 A.8.9", "A.8.9", "ambiguous", True),
    ("A.9.5", "A.9.5", "invalid", False),                       # A.9 has 4 categories in 2013
])
def test_iso_explicit_version_conflicts(raw, ref, version, conflict):
    p = F.iso_refs(raw)
    assert [(r["ref"], r["version"]) for r in p["refs"]] == [(ref, version)]
    assert any(i["kind"] == "explicit_version_conflict" for i in p["issues"]) is conflict


def test_iso_unparsed_vs_missing_and_reading():
    assert F.iso_refs(None)["state"] == "missing" and F.iso_refs("CA.8.28")["state"] == "unparsed"
    v = F.iso_view([vuln(1, iso="A.14.2.5"), vuln(2, iso=None), vuln(3, iso="garbage")])
    assert v["coverage"]["iso2013_only"] == 1 and v["coverage"]["missing"] == 1 and v["coverage"]["unparsed"] == 1
    assert "indicatif" in v["reading"] and "pas une non-conformité" in v["reading"]
    assert v["matrix_2022_available"] is False


# --- real data (copy) -----------------------------------------------------------------------------

REAL = Path(os.environ.get("P5_REAL_DATA", "/nonexistent"))


@pytest.mark.skipif(not (REAL / "vulnerabilities").exists(), reason="real data copy not provided (P5_REAL_DATA)")
def test_real_data_coverage_measured():
    vs = [v for p in glob.glob(str(REAL / "vulnerabilities" / "*.json")) for v in json.load(open(p))]
    m = F.attack_matrix(vs)
    assert m["coverage"]["valid"] / m["coverage"]["findings"] > 0.99
    assert F.atlas_view(vs, [])["ai_findings"] == []
    iso = F.iso_view(vs)
    assert iso["coverage"]["iso2013_only"] > iso["coverage"]["iso2022"] and iso["matrix_2022_available"] is False
    by_project = {}
    for v in vs:
        by_project.setdefault(v.get("project_id"), []).append(v)
    levels = {}
    for pv in by_project.values():
        for c in {v["campaign_id"] for v in pv}:
            feas, _ = F.feasibility_index([v for v in pv if v["campaign_id"] == c], scope=pv)
            for v in pv:
                if v["id"] in feas and F.finding_type_key(v):
                    levels.setdefault((v["project_id"], F.finding_type_key(v), v["status"]), set()).add(feas[v["id"]]["level"])
    assert all(len(x) == 1 for x in levels.values())          # MAJ-1: same type + same status -> same F level
    gitea = {lv for (p, k, s), lv_ in levels.items() if k == "cve:CVE-2026-60004" for lv in lv_}
    assert gitea == {4}
    camp = json.load(open(REAL / "campaigns" / "camp_20261103_e5eda97d.json"))
    assert F.atlas_view([], camp["agents_dispatched"])["state"] == "not_tested"


def test_feasibility_by_finding_covers_every_live_finding_on_a_path_or_not():
    vs = [vuln(1, status="exploited"), vuln(2, status="exploited", vec=AV_N_PRL), vuln(3), vuln(4, status="unconfirmed"),
          vuln(5, status="remediated")]
    eb = F.ebios_view({"paths": [_path()]}, vs)
    m = eb["feasibility_by_finding"]
    assert set(m) == {"v1", "v2", "v3", "v4"}                      # remediated is not live
    assert m["v1"] == {"level": 4, "label": F.FEAS_LABELS[4]} and m["v2"]["level"] == 3
    assert m["v3"]["level"] == 2 and m["v4"] == {"level": None, "label": "non cotée (piste)"}
    assert sum(1 for x in m.values() if x["level"]) == sum(v for k, v in eb["feasibility_distribution"].items() if k != "not_rated")
