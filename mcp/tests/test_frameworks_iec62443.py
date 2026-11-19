"""IEC 62443-3-3 view (16/11/2026): derived on the server from what findings already carry; numbering + Darkmoon
summaries only; indicative, never a conformity or security-level verdict."""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json
import re

from api import frameworks as F
from api import report_annex

CW = F.iec62443_crosswalk()
SR_IDS = [s["id"] for s in CW["system_requirements"]]


def _v(i, title, category="", iso=None, status="confirmed"):
    return {"id": i, "title": title, "category": category, "iso27001_control": iso, "status": status, "severity": "high"}


def test_crosswalk_is_well_formed():
    assert [f["id"] for f in CW["foundational_requirements"]] == [f"FR {i}" for i in range(1, 8)]
    assert len(SR_IDS) == 52 and len(set(SR_IDS)) == 52
    for r in CW["rules"]:
        re.compile(r["match"])
        assert r["srs"] and all(s in SR_IDS for s in r["srs"])
    assert all(s in SR_IDS for v in CW["iso2022_fallback"].values() for s in v)
    assert all(s["fr"] in {f["id"] for f in CW["foundational_requirements"]} for s in CW["system_requirements"])


def test_no_iec_text_only_numbering_and_own_summaries():
    # the summaries are short Darkmoon sentences, never long passages
    assert all(len(s["summary"]) <= 120 for s in CW["system_requirements"])
    assert "no IEC/ISA text" in CW["note"]
    assert any(l["framework"] == "IEC 62443" for l in F.framework_licences())


def test_typical_findings_map_to_the_expected_requirements():
    cases = [
        (_v("a", "SQL injection in product search", "sql_injection"), {"SR 3.5"}),
        (_v("b", "Stored XSS in reviews", "xss_stored"), {"SR 3.5"}),
        (_v("c", "Default admin credentials accepted"), {"SR 1.5", "SR 1.7"}),
        (_v("d", "IDOR on /api/orders/{id}", "idor"), {"SR 2.1"}),
        (_v("e", "Unauthenticated access to user data via /rest/memories", "information_disclosure"), {"SR 1.1", "SR 4.1"}),
        (_v("f", "Verbose error pages expose stack traces", "information_disclosure"), {"SR 3.7", "SR 4.1"}),
        (_v("g", "SSRF in the image proxy", "ssrf"), {"SR 5.2", "SR 3.5"}),
        (_v("h", "Weak TLS ciphers (TLSv1.0)"), {"SR 4.3"}),
        (_v("i", "Outdated jQuery with known vulnerabilities"), {"SR 7.8"}),
    ]
    for v, expected in cases:
        got = {r["sr"] for r in F.iec62443_refs(v)}
        assert expected <= got, (v["title"], got)


def test_known_false_positives_stay_out():
    # a CORS header is not access control; a /ftp/ URL path is not an FTP service
    cors = {r["sr"] for r in F.iec62443_refs(_v("x", "Overly permissive CORS: Access-Control-Allow-Origin: *", "security_misconfiguration"))}
    assert "SR 2.1" not in cors and "SR 7.6" in cors
    ftp = {r["sr"] for r in F.iec62443_refs(_v("y", "Sensitive file exposure via /ftp/ directory listing", "information_disclosure"))}
    assert "SR 7.7" not in ftp and "SR 4.1" in ftp


def test_iso_fallback_only_when_no_rule_matches():
    only_iso = F.iec62443_refs(_v("z", "Something unusual", "other", iso="A.8.24"))
    assert [(r["sr"], r["basis"]) for r in only_iso] == [("SR 4.3", "iso")]
    with_rule = F.iec62443_refs(_v("w", "SQL injection", "sql_injection", iso="A.8.24"))
    assert all(r["basis"] != "iso" for r in with_rule)


def test_view_counts_and_excludes_false_positives():
    vulns = [_v("a", "SQL injection", "sql_injection"), _v("b", "nothing to see", "other"),
             _v("c", "IDOR", "idor", status="false_positive")]
    d = F.iec62443_view(vulns)
    assert d["coverage"]["findings"] == 2 and d["coverage"]["mapped"] == 1 and d["unmapped_finding_ids"] == ["b"]
    fr3 = next(f for f in d["foundational"] if f["id"] == "FR 3")
    assert fr3["finding_ids"] == ["a"] and fr3["requirements"][0]["id"] == "SR 3.5"
    assert "pas une non-conformité" in d["reading"]


def test_catalogue_lists_every_requirement_under_its_fr():
    c = F.framework_catalogue()["iec62443"]
    assert [f["id"] for f in c["foundational"]] == [f"FR {i}" for i in range(1, 8)]
    assert sum(len(f["requirements"]) for f in c["foundational"]) == 52


def test_annex_has_the_iec_section_and_the_per_finding_row():
    vulns = [_v("a", "SQL injection in search", "sql_injection")]
    fw = {"attack": {"tactics": []}, "atlas": {}, "iso": {}, "ebios": {}, "iec62443": F.iec62443_view(vulns),
          "findings": {"a": {"title": "SQL injection in search"}}}
    md = report_annex.frameworks_section(fw, F.framework_catalogue())
    assert "### IEC 62443-3-3 (system requirements)" in md and "`SR 3.5`" in md and "inputs are validated before use" in md
    assert "Not observed in this campaign: FR 1 IAC" in md


from tests.test_report_markdown_safety import storage  # noqa: E402,F401  (isolated data dirs)
from api import live_push, json_storage  # noqa: E402


def test_generated_report_carries_the_iec_row_per_finding(storage):  # noqa: F811
    cid = live_push.init_live_campaign(session_id="MCPCONST", target_host="10.0.0.5", target_ip="10.0.0.5", project_name="t")["campaign_id"]
    json_storage.save_vulnerabilities(cid, [{"id": "vuln_1", "campaign_id": cid, "severity": "high", "status": "confirmed",
                                             "category": "sql_injection", "title": "SQL injection in search", "endpoint": "http://10.0.0.5/q"}])
    md = live_push._generate_report_from_db(cid, live_push.load_campaign(cid))
    assert "| **IEC 62443-3-3** | `SR 3.5` |" in md
