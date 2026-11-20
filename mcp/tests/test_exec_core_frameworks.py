"""Framework technical assessment and application profile (exec_core.frameworks_assess, exec_core.profile), shared by
Community and Pro (same file in both editions, same fixture, same expected output).

Covers: framework declared not applicable, applicability undetermined, no control assessed, one control assessed,
contradictory evidence, AI Act without an AI system, NIS2 without sector information, GDPR with unconfirmed personal
data, ISO without ISMS information, profile provenance, old projects without a profile, the wording rules, the ISO
title deny-list, navigation without dangling ids and the parity fixture.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api.exec_core import actions as A  # noqa: E402
from api.exec_core import framework_catalogues as K  # noqa: E402
from api.exec_core import frameworks_assess as FA  # noqa: E402
from api.exec_core import profile as P  # noqa: E402
from api.exec_core import score, stats  # noqa: E402

FIX = MCP / "tests" / "fixtures" / "exec_core" / "frameworks"
GOLDEN = MCP / "tests" / "fixtures" / "exec_core"

# sha256[:20] of the normalised multi-word control titles of ISO/IEC 27001:2022 Annex A. Hashed so that this
# repository does not carry the titles either; the test fails if any of them appears in a catalogue text.
ISO_TITLE_HASHES = {
    "031fc334670c47beb847", "09cfa7cf7bff5ca62ca2", "0d1db5f0fef774468bc0", "12d95915e20f81b38314",
    "132115fd42f558dc7c06", "1996849612333b13e139", "1a00d95aef590d85bfec", "1a139657e53c7a513d81",
    "1a3a742a69e6f03c05d1", "1b1e72b3ae8026232416", "1bdd272faf0000136550", "233b3e4c49d71cf41bef",
    "23783610ccddeefc0f9b", "24cf5f2359df04ab9528", "24e5a56242e0e1baba86", "2597987e78699cf4bc2e",
    "26019930c8db9ccd6179", "2b856c0103e46c851e6a", "2d0de199efb6e18a6ba5", "2e78dde26a496e6a50d4",
    "2eef3f124f8ee827c838", "3184dbacfc2c1bc506e2", "319219a54409c0c13184", "3427b291f7894fd5f68a",
    "34b25aff7156930d05ff", "350e939bf69855e2d744", "37cc212118ead8bc8c42", "390c604ed126674d852f",
    "3ce56d5d754e88c660a6", "40b037709cfbbc7fc8bb", "42a79213bb1f787b4e78", "4b2d86ab5a850a7f7a48",
    "4d6dd9a0aa09802ce442", "4f2bdf47c2512b49af57", "53c7a87059a352e34603", "565e495fabb1d7b58494",
    "5970530283987b4d5911", "59a0dc1343cdf6bb7a31", "5e09ed4fdac12800856c", "5e8999dc88353660f9c7",
    "64bb17443f5a9dfb43e9", "667819a160edafc90fc7", "6a19823bf22fcf01cf20", "705c30c1493498dd2ce8",
    "74d878f72c7bb781fa60", "7a256504aa13a4a681af", "7ace00c9a51c3c96b2c7", "7afab707f48b5980b9ac",
    "7be96c1162c0c7bc6430", "7c4258ae141a2f879014", "7f6b803b4ebee40698ed", "82328e24217b53965567",
    "8a0cf92f23ade9d9ac86", "922a22791986b33ebc63", "93d85f6a73be3a0f29bb", "9645a6a85837c0923cc5",
    "985fdab98f69df31f9a8", "991b211626b72e143047", "9e4ade0698e0e4ea82a1", "a0a3280094c04abcfee8",
    "a3d6b96c4fb395e9cc02", "a3e3134e92f65b984696", "a8bb06e14c2371e30484", "ab0f40a81300238bad70",
    "ad4b0d58e0291133984f", "ae9c4ce6834096fd54a1", "aff2e8583531c54b17af", "b2eb806c51233eb23c32",
    "b317f739822e740c8223", "b6113b65eb026a1f7690", "bce56360af562bf49ee3", "c52c541a95c514748433",
    "ccfcf312f131cd8e411e", "cdcb83c8d138fff165e1", "ce7e9e0849c506dd63af", "cea3b2d5873b69ab58b7",
    "d31c38007fd9b96caa7e", "d825cfe636a38fd71ed6", "e2938e56ead6575c098d", "e49a0e99ccc64ef4e0b5",
    "e7196fe0110f8e449367", "e8de6750fc546480e584", "eac77c6e0f77a7695e49", "ed41261a34128551ca29",
    "eeb9b6498eab33d71b2f", "ef6e6e680c13bacdd0ec", "f110e8836961379e6d59", "f46e47de1d8debdef5ba",
    "f5f7d7b4a8fad10cb7e0", "f918d7759aeea050718c", "fd8b5cad71c90549baf0",
}


def _sig(**kw):
    s = {"schema": "darkmoon-coverage-signals/1", "campaign_kind": "full", "campaign_kind_source": "default",
         "started_at": "2026-11-01T09:00:00Z", "finalized_at": "2026-11-01T10:00:00Z",
         "measured_duration_seconds": 3600, "agents_dispatched": [{"agent": "php"}, {"agent": "headless-browser"}],
         "agents_source": "opencode_sessions", "assets_registered": 2, "commands_executed": 50,
         "workflows_executed": 0}
    s.update(kw)
    return s


def _camp(status="completed", signals=True, **kw):
    c = {"id": "camp_t", "project_id": "proj_t", "target_id": "tg", "status": status}
    if signals:
        c["coverage_signals"] = _sig(**kw)
    return c


def _v(i, cat="sql_injection", sev="high", st="confirmed", **kw):
    return {"id": i, "title": f"t {i}", "category": cat, "severity": sev, "status": st, "endpoint": f"/x/{i}",
            "target_id": "tg", **kw}


def _profile(**declared):
    clean, issues = P.validate_declared(declared)
    assert not issues, issues
    return P.view(clean)


def _fw(doc, name):
    return next(f for f in doc["frameworks"] if f["framework"] == name)


def _ctl(doc, key):
    fw, cid = key.split(":", 1)
    return next(c for c in _fw(doc, fw)["controls"] if c["control_id"] == cid)


def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


# ── applicability ──

def test_applicability_undetermined_without_profile():
    doc = FA.assess({"campaign": _camp(), "findings": [_v("a")]})
    for fw in doc["frameworks"]:
        assert fw["applicability"]["status"] == "to_confirm"
        assert fw["applicability"]["basis_provenance"] == "unknown"


def test_framework_declared_not_applicable_still_lists_the_evidence():
    doc = FA.assess({"campaign": _camp(), "findings": [_v("a")],
                     "profile": _profile(personal_data="no", iso27001_isms_scope="out_of_scope")})
    g = _fw(doc, "gdpr")
    assert g["applicability"]["status"] == "not_applicable_declared"
    assert g["applicability"]["basis_value"] == "no"
    assert g["counts"]["weakness_observed"] == 1   # the technical facts stay visible, for information
    assert _fw(doc, "iso27001")["applicability"]["status"] == "not_applicable_declared"


def test_iso_without_isms_information_is_to_confirm():
    doc = FA.assess({"campaign": _camp(), "findings": [], "profile": _profile(personal_data="yes")})
    iso = _fw(doc, "iso27001")["applicability"]
    assert iso["status"] == "to_confirm" and iso["basis_field"] == "iso27001_isms_scope"
    assert _fw(doc, "gdpr")["applicability"]["status"] == "declared_by_customer"


def test_nis2_without_sector_information():
    doc = FA.assess({"campaign": _camp(), "findings": []})
    assert _fw(doc, "nis2")["applicability"]["status"] == "to_confirm"
    doc = FA.assess({"campaign": _camp(), "findings": [], "profile": _profile(sector="energy")})
    n = _fw(doc, "nis2")["applicability"]
    assert n["status"] == "to_confirm" and "entity type" in n["text"]
    doc = FA.assess({"campaign": _camp(), "findings": [],
                     "profile": _profile(sector="energy", nis2_entity_type="essential")})
    assert _fw(doc, "nis2")["applicability"]["status"] == "declared_by_customer"


def test_gdpr_with_unconfirmed_personal_data():
    """Personal data seen by detection or inference never makes GDPR applicable: only a declaration does."""
    for prov in ("detected", "inferred", "unknown"):
        view = P.view()
        view["fields"]["personal_data"].update({"value": "yes", "provenance": prov})
        doc = FA.assess({"campaign": _camp(), "findings": [], "profile": view})
        g = _fw(doc, "gdpr")["applicability"]
        assert g["status"] == "to_confirm" and g["basis_value"] is None, prov
    doc = FA.assess({"campaign": _camp(), "findings": [], "profile": _profile(personal_data="unknown")})
    assert _fw(doc, "gdpr")["applicability"]["status"] == "to_confirm"


def test_ai_act_without_ai_system():
    nodes = [{"id": "n1", "label": "Ollama", "port": 11434}]
    doc = FA.assess({"campaign": _camp(), "findings": [], "nodes": nodes})
    ai = _fw(doc, "ai_act")
    assert ai["applicability"]["status"] == "to_confirm"          # detection never decides
    assert ai["detection"]["ai_component_detected"] is True and ai["detection"]["node_ids"] == ["n1"]
    doc = FA.assess({"campaign": _camp(), "findings": [], "nodes": nodes, "profile": _profile(ai_system_declared="no")})
    assert _fw(doc, "ai_act")["applicability"]["status"] == "not_applicable_declared"
    doc = FA.assess({"campaign": _camp(), "findings": [],
                     "profile": _profile(ai_system_declared="yes", ai_risk_class="limited_risk")})
    assert _fw(doc, "ai_act")["applicability"]["status"] == "not_applicable_declared"
    doc = FA.assess({"campaign": _camp(), "findings": [],
                     "profile": _profile(ai_system_declared="yes", ai_risk_class="high_risk")})
    assert _fw(doc, "ai_act")["applicability"]["status"] == "declared_by_customer"
    # without the llm agent the AI controls are never « none observed »
    assert all(c["state"] != "none_observed_in_tested_scope" for c in _fw(doc, "ai_act")["controls"])


# ── control states ──

def test_no_control_assessed_without_recorded_coverage():
    for camp in (_camp(signals=False), _camp(status="aborted"), _camp(campaign_kind="short"),
                 _camp(agents_source="tool_calls_only"), _camp(measured_duration_seconds=120),
                 _camp(agents_dispatched=[{"agent": "pentest"}, {"agent": "general"}])):
        doc = FA.assess({"campaign": camp, "findings": []})
        assert doc["coverage"]["coverage_ok"] is False
        for fw in doc["frameworks"]:
            assert fw["counts"]["weakness_observed"] == fw["counts"]["none_observed_in_tested_scope"] == 0
            assert fw["counts"]["not_tested"] + fw["counts"]["not_technically_assessable"] == len(fw["controls"])
        assert "conclusion" in FA.summary_line(doc)


def test_one_control_assessed():
    doc = FA.assess({"campaign": _camp(signals=False), "findings": [_v("t1", "cryptographic_weakness", "medium")]})
    observed = sorted(k for k, r in doc["navigation"]["controls"].items() if r["state"] == "weakness_observed")
    assert observed == ["gdpr:Art.32(1)(a)", "iso27001:A.5.14", "iso27001:A.8.24", "nis2:Art.21(2)(h)"]
    c = _ctl(doc, "iso27001:A.8.24")
    assert c["finding_ids"] == ["t1"] and c["proof"] == {"exploited": 0, "confirmed": 1, "unconfirmed": 0}
    assert _ctl(doc, "iso27001:A.8.26")["state"] == "not_tested"   # no coverage: silence is not « none observed »


def test_none_observed_only_for_classes_an_agent_exercised():
    doc = FA.assess({"campaign": _camp(), "findings": []})
    assert doc["coverage"]["coverage_ok"] is True
    assert _ctl(doc, "iso27001:A.8.26")["state"] == "none_observed_in_tested_scope"
    assert _ctl(doc, "iso27001:A.8.24")["state"] == "not_tested"          # nobody tested cryptography
    assert "cryptography" in _ctl(doc, "iso27001:A.8.24")["why"]
    assert _ctl(doc, "iso27001:A.8.6")["state"] == "not_tested"           # no availability test is ever run
    assert _ctl(doc, "iso27001:A.8.15")["state"] == "not_technically_assessable"
    # a single specialised agent is enough here (the agent floor of the rating is replaced per class)
    one = FA.assess({"campaign": _camp(agents_dispatched=[{"agent": "php"}]), "findings": []})
    assert one["coverage"]["coverage_ok"] is True
    unknown = FA.assess({"campaign": _camp(agents_dispatched=[{"agent": "mystery"}, {"agent": "other"}]),
                         "findings": []})
    assert unknown["coverage"]["coverage_ok"] is False and unknown["coverage"]["unknown_agents"] == ["mystery", "other"]


def test_contradictory_evidence():
    fs = [_v("ok", "sql_injection", "critical", "exploited"),
          _v("fp", "sql_injection", "high", "false_positive"),
          _v("held", "sqli", "high", "exploited", quarantined=True),
          _v("unc", "weak_tls", "low", "unconfirmed"),
          _v("cite", "csrf", "medium", "confirmed", iso27001_control="A.12.4.1 / A.8.15")]
    doc = FA.assess({"campaign": _camp(), "findings": fs})
    c = _ctl(doc, "iso27001:A.8.28")
    assert c["state"] == "weakness_observed" and c["finding_ids"] == ["ok"]
    assert c["excluded_finding_ids"] == ["fp", "held"] and "not counted" in c["excluded_note"]
    t = _ctl(doc, "iso27001:A.8.24")
    assert t["state"] == "weakness_observed" and t["to_confirm"] is True
    log = _ctl(doc, "iso27001:A.8.15")       # cited by the agent, still not assessable by a test
    assert log["state"] == "not_technically_assessable" and log["cited_by_findings"] == ["cite"]
    assert "cite" in _ctl(doc, "iso27001:A.8.26")["finding_ids"]
    # a false positive alone never makes a control « weakness observed », and is not hidden either
    only_fp = FA.assess({"campaign": _camp(), "findings": [_v("fp", "xss", "high", "false_positive")]})
    x = _ctl(only_fp, "iso27001:A.8.26")
    assert x["state"] == "none_observed_in_tested_scope" and x["excluded_finding_ids"] == ["fp"]


def test_mapping_bases_are_deterministic():
    assert FA.finding_class(_v("a", "whatever", cwe="CWE-89"))[1] == "cwe"
    assert FA.finding_class(_v("a", "whatever", mitre_attack_id="T1110.003"))[1] == "attack_technique"
    assert FA.finding_class(_v("a", "graphql_batching")) == (None, "unmapped")
    cites = FA.iso_citations("ISO 27001:2013 A.14.2.5, A.9.4.2 and 8.28")
    assert {(c["cited"], c["control_id"]) for c in cites} == {("A.14.2.5", "A.8.27"), ("A.9.4.2", "A.8.5"),
                                                              ("A.8.28", "A.8.28")}
    idor = [r["control"] for r in FA.controls_for_finding(_v("a", "idor"))]
    pe = [r["control"] for r in FA.controls_for_finding(_v("a", "privilege_escalation"))]
    assert "iso27001:A.8.3" in idor and "iso27001:A.8.2" not in idor      # an IDOR is not a privilege escalation
    assert "iso27001:A.8.2" in pe and "iso27001:A.5.15" in pe
    v = _v("a", "rce", iso27001_control="A.9.4.2")
    assert FA.controls_for_finding(v) == FA.controls_for_finding(copy.deepcopy(v))
    assert any(r["control"] == "iso27001:A.8.5" and r["basis"] == ["agent_citation:iso_2013_crosswalk"]
               for r in FA.controls_for_finding(v))


def test_actions_carry_related_controls_from_counted_findings_only():
    vs = [_v("a", "sql_injection"), _v("b", "xss", st="false_positive")]
    doc = {"fix_first": {"source": "reported-severity-x-proof", "items": [], "open_findings": 1},
           "triage": {"groups_all": [{"fix_id": "f1", "finding_ids": ["a", "b"], "rank": 1, "head_finding_id": "a",
                                      "label": "x"}]}, "paths": [], "ranking": {"fixes": []}}
    a = A.build_actions("camp_t", doc, vs)[0]
    assert a["related_controls"] == FA.related_controls(["a"], vs)
    assert "iso27001:A.8.28" in a["related_controls"]


def test_findings_score_and_stats_are_untouched():
    fs = [_v("a"), _v("b", "weak_tls", st="unconfirmed")]
    before = (copy.deepcopy(fs), stats.compute_stats(fs), score.cyber_score({"campaign": _camp(), "findings": fs}))
    FA.assess({"campaign": _camp(), "findings": fs, "profile": _profile(personal_data="yes")})
    assert (fs, stats.compute_stats(fs), score.cyber_score({"campaign": _camp(), "findings": fs})) == before


# ── wording, catalogue licence, navigation ──

def _all_outputs():
    fx = json.loads((FIX / "assessment_parity.json").read_text(encoding="utf-8"))
    yield FA.assess(_parity_bundle(fx))
    yield FA.assess({"campaign": _camp(), "findings": []})
    yield FA.assess({"campaign": _camp(signals=False), "findings": [_v("a")]})
    yield P.view()
    yield {"line": FA.summary_line(FA.assess(_parity_bundle(fx)))}


def test_wording_rules():
    forbidden = re.compile(r"(?i)compliant|compliance score|conformit|\d+\s*%|\bgrade\b|certified")
    for out in _all_outputs():
        for s in _strings(out):
            assert not forbidden.search(s), s


def test_iso_catalogue_ships_identifiers_not_titles():
    def norm(s):
        return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()
    iso = next(f for f in K.FRAMEWORKS if f["framework"] == "iso27001")
    texts = [c["text"] for f in K.FRAMEWORKS for c in f["controls"]]
    texts += [c.get("why", "") for f in K.FRAMEWORKS for c in f["controls"]]
    texts += [f["scope_note"] for f in K.FRAMEWORKS] + [FA.READING] + FA.COMMON_LIMITS
    texts += [x for v in FA.FRAMEWORK_LIMITS.values() for x in v]
    for t in texts:
        w = norm(t).split()
        for n in range(2, 9):
            for i in range(len(w) - n + 1):
                h = hashlib.sha256(" ".join(w[i:i + n]).encode()).hexdigest()[:20]
                assert h not in ISO_TITLE_HASHES, f"ISO title text in the catalogue: {t!r}"
    assert all(re.fullmatch(r"A\.[5-8]\.\d{1,2}", c["id"]) for c in iso["controls"])
    for f in K.FRAMEWORKS:
        assert f["source"]["url"].startswith("https://")
        if f["kind"] != "standard":
            assert re.fullmatch(r"3\d{4}[RL]\d{4}", f["source"]["celex"])
    gdpr = {c["id"] for c in next(f for f in K.FRAMEWORKS if f["framework"] == "gdpr")["controls"]}
    assert not any(i.startswith(("Art.33", "Art.34")) for i in gdpr)
    assert [x["framework"] for x in K.EXCLUDED] == ["nist_csf_2"]


def test_navigation_has_no_dangling_ids():
    fx = json.loads((FIX / "assessment_parity.json").read_text(encoding="utf-8"))
    doc = FA.assess(_parity_bundle(fx))
    nav = doc["navigation"]
    fids = {v["id"] for v in fx["findings"]}
    aids = {a["action_id"] for a in fx["actions"]}
    pids = {p for a in fx["actions"] for p in a["related_attack_paths"]}
    keys = {f"{f['framework']}:{c['id']}" for f in K.FRAMEWORKS for c in f["controls"]}
    assert set(nav["controls"]) == keys
    for k, r in nav["controls"].items():
        assert set(r["finding_ids"]) <= set(nav["findings"]) and set(r["action_ids"]) <= set(nav["actions"])
        assert set(r["attack_path_ids"]) <= set(nav["attack_paths"]) | set()
        for f in r["finding_ids"]:
            assert k in nav["findings"][f]["control_keys"]          # reverse lookup agrees
    for f, r in nav["findings"].items():
        assert f in fids and set(r["control_keys"]) <= keys and set(r["action_ids"]) <= aids
        assert r["evidence"]["finding_id"] == f
    for a, r in nav["actions"].items():
        assert a in aids and set(r["finding_ids"]) <= set(nav["findings"]) and set(r["attack_path_ids"]) <= pids
        assert set(r["control_keys"]) <= keys
    for p, r in nav["attack_paths"].items():
        assert p in pids and set(r["action_ids"]) <= aids
    for fw in doc["frameworks"]:
        for c in fw["controls"]:
            assert set(c["finding_ids"]) <= fids and set(c["action_ids"]) <= aids and set(c["attack_path_ids"]) <= pids
    assert set(doc["unmapped_finding_ids"]) <= fids and set(doc["excluded_finding_ids"]) <= fids


# ── profile ──

def test_profile_provenance():
    det = P.detected_stack([{"name": "PHP", "version": "8.1", "category": "language"},
                            {"name": "MySQL", "category": "database"}],
                           [{"id": "n", "technology": "nginx", "version": "1.25"}], "camp_t")
    clean, issues = P.validate_declared({"languages": {"value": ["PHP", "Go"]}, "business_purpose": None,
                                         "personal_data": {"value": "yes", "provenance": "detected"},
                                         "criticality": "extreme", "rto": "4h", "business_owner": "jane@corp.example",
                                         "technical_owner": "+33 6 12 34 56 78", "nope": 1})
    kinds = {i.get("field"): i["kind"] for i in issues}
    assert kinds == {"business_purpose": "profile-field-invalid", "personal_data": "profile-field-invalid",
                     "criticality": "profile-field-invalid", "business_owner": "profile-field-invalid",
                     "technical_owner": "profile-field-invalid", "nope": "profile-field-unknown"}
    view = P.view(clean, det, "proj_t")
    f = view["fields"]
    assert f["languages"] == {**f["languages"], "value": ["PHP", "Go"], "provenance": "declared_by_customer"}
    assert f["databases"]["value"] == ["MySQL"] and f["databases"]["provenance"] == "detected"
    assert f["infrastructure"]["value"] == ["nginx 1.25"] and view["detected"]["confirmed"] is False
    assert f["business_purpose"]["value"] is None and f["business_purpose"]["provenance"] == "unknown"
    assert f["personal_data"]["provenance"] == "unknown"
    assert f["rto"]["value"] == "4h" and "not assessed" in f["rto"]["note"]
    assert view["provenance_counts"]["declared_by_customer"] == 2
    # the API path refuses client-side stamps; the file path keeps them
    _, iss = P.validate_declared({"sla": {"value": "99.9", "at": "2026-01-01"}}, allow_stamps=False)
    assert iss and "unknown keys" in iss[0]["problems"][0]
    ok, iss = P.validate_declared({"sla": {"value": "99.9", "at": "2026-01-01", "by_role": "CIO"}})
    assert not iss and ok["sla"]["by_role"] == "CIO"
    facts = P.applicability_facts(P.view({**ok, **P.validate_declared({"sector": "health"})[0]}, det))
    assert facts["sector"]["value"] == "health" and facts["personal_data"]["value"] is None


def test_old_projects_without_profile():
    v = P.view(None, None, "proj_old")
    assert all(f["provenance"] == "unknown" and f["value"] is None for f in v["fields"].values())
    assert set(v["fields"]) == set(P.FIELDS)
    assert v["provenance_counts"]["unknown"] == len(P.FIELDS)
    doc = FA.assess({"campaign": _camp(), "findings": [], "profile": None})
    assert {f["applicability"]["status"] for f in doc["frameworks"]} == {"to_confirm"}


def test_profile_validation_bounds():
    assert P.validate_value("rto", "90 m") == ("90min", None)
    assert P.validate_value("rpo", "1 week")[1]
    assert P.validate_value("last_verification_date", "2026-02-30")[1]
    assert P.validate_value("last_verification_date", "2026-02-28") == ("2026-02-28", None)
    assert P.validate_value("description", "a\x1b[31mb")[0] == "a[31mb"
    assert P.validate_value("data_categories", ["x"] * 31)[1]
    assert P.validate_value("data_categories", ["a", "a", "b"]) == (["a", "b"], None)
    assert P.validate_value("sector", "Energy") == ("energy", None)
    assert P.validate_declared("nope")[1][0]["kind"] == "profile-invalid"


# ── parity fixture (same expected output in Community and Pro) ──

def _parity_bundle(fx):
    clean, issues = P.validate_declared(fx["declared"])
    assert not issues
    view = P.view(clean, P.detected_stack(fx["technologies"], fx["nodes"], fx["campaign"]["id"]),
                  fx["campaign"]["project_id"])
    return {"campaign": fx["campaign"], "findings": fx["findings"], "nodes": fx["nodes"], "actions": fx["actions"],
            "profile": view}


def _parity_outputs():
    fx = json.loads((FIX / "assessment_parity.json").read_text(encoding="utf-8"))
    b = _parity_bundle(fx)
    return {"profile": b["profile"], "assessment": FA.assess(b)}


def test_parity_fixture_gives_the_expected_outputs():
    got = json.loads(json.dumps(_parity_outputs(), sort_keys=True))
    want = json.loads((FIX / "expected_assessment.json").read_text(encoding="utf-8"))
    assert got == want


def test_parity_fixture_decisions():
    out = _parity_outputs()
    doc = out["assessment"]
    assert _fw(doc, "gdpr")["applicability"]["status"] == "declared_by_customer"       # verified by the DPO
    assert _fw(doc, "gdpr")["applicability"]["basis_provenance"] == "verified"
    assert _fw(doc, "nis2")["applicability"]["status"] == "to_confirm"                 # sector only
    assert _fw(doc, "ai_act")["applicability"]["status"] == "to_confirm"               # AI declared, risk class not
    assert _fw(doc, "iso27001")["applicability"]["status"] == "to_confirm"
    assert _ctl(doc, "ai_act:Art.15(5)-manipulation")["finding_ids"] == ["vuln_pi"]
    assert _ctl(doc, "ai_act:Art.15(5)-confidentiality")["state"] == "none_observed_in_tested_scope"   # llm agent ran
    assert "vuln_closed" in _ctl(doc, "iso27001:A.8.8")["finding_ids"]                 # declared closed: still observed
    assert doc["unmapped_finding_ids"] == ["vuln_log"]
    assert doc["coverage"]["unknown_agents"] == ["unknown-helper"]
    assert out["profile"]["fields"]["frameworks"]["provenance"] == "detected"
    assert out["profile"]["fields"]["languages"]["provenance"] == "declared_by_customer"


def test_assessment_of_the_real_dvga_run():
    """The anonymised real DVGA full run (reconstructed coverage): every observed control is backed by findings."""
    d = json.loads((GOLDEN / "real_dvga_full_reconstructed.json").read_text(encoding="utf-8"))["input"]
    doc = FA.assess({"campaign": d["campaign"], "findings": d["findings"]})
    iso = _fw(doc, "iso27001")
    assert iso["counts"]["weakness_observed"] >= 10 and doc["coverage"]["coverage_ok"] is True
    assert _ctl(doc, "iso27001:A.8.24")["state"] == "weakness_observed"
    assert _ctl(doc, "ai_act:Art.15(5)-manipulation")["state"] == "not_tested"     # no llm agent on DVGA
    as_stored = json.loads((GOLDEN / "real_dvga_full_as_stored.json").read_text(encoding="utf-8"))["input"]
    legacy = FA.assess({"campaign": as_stored["campaign"], "findings": as_stored["findings"]})
    assert all(f["counts"]["none_observed_in_tested_scope"] == 0 for f in legacy["frameworks"])


def test_summary_line_follows_the_declared_applicability():
    """R2 B-1 (the reviewer's reproduction): a profile declaring no AI system, not in NIS2 scope and no personal data,
    with one prompt-injection and one SQL injection finding: the executive line never names the AI Act, GDPR or NIS2;
    a framework to confirm is named without counts; the AI Act appears only for a declared high-risk AI system."""
    vs = [{"id": "a", "category": "prompt_injection", "severity": "high", "status": "exploited", "target_id": "t",
           "title": "Prompt injection"},
          {"id": "b", "category": "sql_injection", "severity": "high", "status": "exploited", "target_id": "t",
           "title": "SQL injection"}]
    camp = {"id": "c", "status": "completed"}

    def line(decl):
        clean, issues = P.validate_declared(decl)
        assert not issues
        return FA.summary_line(FA.assess({"campaign": camp, "findings": vs, "profile": P.view(clean, None, "p")}))
    out = line({"ai_system_declared": "no", "nis2_entity_type": "not_in_scope", "personal_data": "no"})
    assert "AI Act" not in out and "GDPR" not in out and "NIS2" not in out
    assert "ISO/IEC 27001" in out and "applicability to confirm" in out and "control" not in out
    out = line({})
    assert "AI Act" not in out and "with a weakness observed" not in out
    out = line({"ai_system_declared": "yes", "ai_risk_class": "high_risk", "personal_data": "yes"})
    assert "EU AI Act (EU) 2024/1689, art. 15 (1 control with a weakness observed)" in out
    assert "GDPR (EU) 2016/679, art. 32 and 25 (" in out and "NIS2" in out and "applicability to confirm" in out


def test_catalogue_paraphrases_reviewed_by_counsel():
    """R2 M-1 / M-2: no legal qualification of a breach; NIS2 21(2)(j) is about multi-factor or continuous
    authentication; AI Act 15(1) names accuracy, robustness and cybersecurity."""
    gdpr = next(f for f in K.FRAMEWORKS if f["framework"] == "gdpr")
    assert "is not a personal data breach" not in gdpr["scope_note"] and "assessed by the controller" in gdpr["scope_note"]
    j = next(c for f in K.FRAMEWORKS if f["framework"] == "nis2" for c in f["controls"] if c["id"] == "Art.21(2)(j)")
    assert "multi-factor or continuous authentication" in j["text"] and "session" not in (j.get("classes") or [])
    a15 = next(c for f in K.FRAMEWORKS if f["framework"] == "ai_act" for c in f["controls"] if c["id"] == "Art.15(1)")
    assert "robustness and cybersecurity" in a15["text"]


if __name__ == "__main__":   # regenerate the expected outputs after a deliberate change
    (FIX / "expected_assessment.json").write_text(
        json.dumps(_parity_outputs(), indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print("expected_assessment.json written")
