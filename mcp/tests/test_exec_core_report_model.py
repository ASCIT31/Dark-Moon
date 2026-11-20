"""Report model (``exec_core.report_model``, schema darkmoon-report/v2) and its Markdown rendering
(``exec_core.report_markdown``), shared by Community and Pro (same file in both editions, same fixture, same expected
model).

Covers: the mission's section order and stable ids, a source for every number, the parity fixture run through each
edition's own attack-path engine giving the same model except the documented edition-specific fields, the numbers of
the Markdown equal to the model's (score, counts, actions, framework state counts), internal links, the agent's text
only quoted, Unicode, untrusted text neutralised, missing fields, score not available, long tables, no compliance
wording, schema key names that the field-wise redaction never reads as secrets.

After a deliberate change: ``python3 tests/test_exec_core_report_model.py`` rewrites the expected model.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api import attack_paths, cvss31  # noqa: E402
from api.exec_core import actions as A  # noqa: E402
from api.exec_core import frameworks_assess as FA  # noqa: E402
from api.exec_core import profile as P  # noqa: E402
from api.exec_core import report_markdown as RMD  # noqa: E402
from api.exec_core import report_model as RM  # noqa: E402
from api.exec_core import score as S  # noqa: E402

FIX = MCP / "tests" / "fixtures" / "exec_core" / "report"
NOW = "2026-11-20T11:05:00Z"
MASKING = "Fixture: evidence as stored."


def _fx():
    return json.loads((FIX / "report_parity.json").read_text(encoding="utf-8"))


def _inputs(fx=None, **over):
    fx = fx or _fx()
    c, vs, nodes = fx["campaign"], fx["findings"], fx["nodes"]
    ap = attack_paths.build_paths(c, copy.deepcopy(nodes), [], copy.deepcopy(vs), include_steps=True,
                                  retest_verdicts=None, now=NOW)
    plan_paths = attack_paths.build_paths(c, copy.deepcopy(nodes), [], copy.deepcopy(vs), include_steps=False,
                                          retest_verdicts=None, now=NOW)
    plan = A.build_plan(c["id"], plan_paths, vs)
    declared, issues = P.validate_declared(fx["declarations"])
    assert not issues, issues
    prof = P.view(declared, P.detected_stack(fx["technologies"], nodes, c["id"]), c["project_id"])
    acts = [{"action_id": a["action_id"], "finding_ids": a["finding_ids"],
             "related_attack_paths": a["related_attack_paths"]} for a in plan["actions"]]
    assessment = FA.assess({"campaign": c, "findings": vs, "nodes": nodes, "profile": prof, "actions": acts})
    doc = {"edition": "fixture", "generated_at": NOW, "campaign": c, "target": fx["target"], "project": fx["project"],
           "findings": vs, "cvss": {v["id"]: cvss31.assess(v) for v in vs},
           "score": S.cyber_score({"campaign": c, "findings": vs}), "plan": plan, "assessment": assessment,
           "profile": prof, "attack_paths": ap, "annex": {}, "masking": MASKING}
    doc.update(over)
    return doc


def _model(**over):
    return RM.build(_inputs(**over))


def strip_edition_specific(model):
    """The model without the fields documented as edition-specific (``report_model.EDITION_SPECIFIC``)."""
    m = copy.deepcopy(model)
    m.pop("edition", None)
    out = []
    for s in m["sections"]:
        if s["id"] == "attack_paths":
            s = {"id": s["id"], "title": s["title"]}
        elif s["id"] == "evidence_methodology":
            s.pop("privacy", None)
            s.pop("masking", None)
            s["blocks"] = [b for b in s["blocks"] if not (b.get("type") == "subsection" and b.get("id") == "privacy-placeholders")]
        elif s["id"] == "treatment_plan":
            s.pop("verification", None)
        elif s["id"] == "limitations":
            for blk in s["blocks"]:
                if blk.get("type") == "list":
                    blk["items"] = [x for x in blk["items"] if x not in RM.COMMUNITY_LIMITS]
        for blk in s.get("blocks") or []:     # who declared a profile field: an account (Pro) or the local file
            if blk.get("type") == "table" and (blk.get("columns") or [None] * 3)[2:3] in (["Provenance"],
                                                                                        ["Provenance"]):
                blk["rows"] = [r[:2] + ["Declared" if str(r[2]).startswith("Declared") else r[2]] + r[3:]
                               for r in blk["rows"]]
        if "blocks" in s:
            s["blocks"] = [b for b in s["blocks"] if b.get("id") not in ("verification-note", "masking-note")]
        out.append(s)
    m["sections"] = out
    return json.loads(json.dumps(m, sort_keys=True))


def _section_md(md, sid):
    m = re.search(rf"<!-- dm-section: {sid.replace('_', '-')} -->\n(.*?)(?=\n<!-- dm-section: |\Z)", md, re.S)
    assert m, sid
    return m.group(1)


def _keys(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield str(k), path
            yield from _keys(v, f"{path}.{k}")
    elif isinstance(o, list):
        for v in o:
            yield from _keys(v, path)


# ── structure ────────────────────────────────────────────────────────────────────────────────────────────────────


def test_section_order_and_ids():
    m = _model()
    assert m["schema_version"] == "darkmoon-report/v2" and m["language"] == "en"
    assert [s["id"] for s in m["sections"]] == [
        "cyber_score", "method_coverage", "executive_summary", "application_profile", "business_impact",
        "critical_risks", "framework_assessment", "resilience", "treatment_plan", "attack_paths",
        "detailed_findings", "evidence_methodology", "limitations"]
    assert m["section_order"] == [s["id"] for s in m["sections"]]


def test_every_number_has_a_source():
    for s in _model()["sections"]:
        for name, n in s["numbers"].items():
            assert set(n) == {"value", "source"} and n["source"], (s["id"], name)
        for b in s["blocks"]:
            if b["type"] in ("table", "kpis", "facts"):
                assert b.get("source") or b["type"] == "kpis", (s["id"], b.get("id"))
            if b["type"] == "kpis":
                assert all(i.get("source") for i in b["items"])


def test_parity_fixture_gives_the_expected_model():
    """Each edition runs its own attack-path engine: the models are identical except the documented fields."""
    got = strip_edition_specific(_model())
    want = json.loads((FIX / "expected_model.json").read_text(encoding="utf-8"))
    assert got == want


def _override_model():
    fx = _fx()
    mc = json.loads((FIX / "maintenance_override.json").read_text(encoding="utf-8"))["maintenance_check"]
    fx["campaign"] = {**fx["campaign"], "maintenance_check": mc}
    return RM.build(_inputs(fx))


def _method_section(model):
    return json.loads(json.dumps(next(s for s in model["sections"] if s["id"] == "method_coverage"), sort_keys=True))


def test_maintenance_override_golden_case():
    """Owner decision 20/11: an administrator override of the maintenance policy is a fact of the method and coverage
    table, with a short factual paragraph (never a « not covered » line); the rest of the report is unchanged."""
    m = _override_model()
    got = _method_section(m)
    assert got == json.loads((FIX / "expected_method_coverage_override.json").read_text(encoding="utf-8"))
    facts = {r["label"]: r["value"] for b in got["blocks"] if b["type"] == "facts" for r in b["rows"]}
    assert facts["Maintenance policy at launch"].startswith("Outside the maintenance policy (blackout date, outside "
                                                            "every window) — launched by an administrator override: ada")
    assert any(b.get("id") == "maintenance-override" for b in got["blocks"])
    nc = next(b for b in got["blocks"] if b.get("id") == "not-covered")
    assert "maintenance" not in json.dumps(nc).lower()
    base = strip_edition_specific(_model())
    other = strip_edition_specific(m)
    assert [s for s in other["sections"] if s["id"] != "method_coverage"] == \
        [s for s in base["sections"] if s["id"] != "method_coverage"]
    md = _section_md(RMD.render(m), "method_coverage")
    assert "Maintenance policy at launch" in md and "Emergency patch validation agreed" in md
    assert RM.MAINTENANCE_OVERRIDE_NOTE in md


def test_maintenance_row_without_a_record():
    facts = {r["label"]: r["value"] for b in _method_section(_model())["blocks"] if b["type"] == "facts"
             for r in b["rows"]}
    assert facts["Maintenance policy at launch"] == "Not recorded (the campaign predates the maintenance record)"


def test_counts_follow_the_one_stats_function():
    m = _model()
    # 8 stored: false positive and held finding counted nowhere, informational counted
    assert m["counts"]["total_findings"] == 6
    assert m["counts"]["critical"] == 1 and m["counts"]["high"] == 2 and m["counts"]["info"] == 1
    det = next(s for s in m["sections"] if s["id"] == "detailed_findings")
    listed = [b["finding_id"] for b in det["blocks"] if b["type"] == "finding"]
    assert "vuln_fp" not in listed and "vuln_held" not in listed and len(listed) == 6
    notes = " ".join(b.get("text", "") for b in det["blocks"] if b["type"] == "note")
    assert "Held for review: 1" in notes and "Not listed: 1" in notes


def test_cvss_recomputed_with_the_agent_value_marked_reported():
    m = _model()
    det = next(s for s in m["sections"] if s["id"] == "detailed_findings")
    xss = next(b for b in det["blocks"] if b.get("finding_id") == "vuln_xss")
    cv = next(f["value"] for f in xss["facts"] if f["label"] == "CVSS 3.1")
    assert xss["cvss"]["computed"] == cvss31.base_score(xss["cvss"]["vector"]) and xss["cvss"]["status"] == "mismatch"
    assert "computed from the vector" in cv and "reported by the agent: 8.8" in cv


def test_score_status_and_not_rated():
    rated = _model()
    cs = rated["sections"][0]
    assert cs["status"] == "rated" and isinstance(cs["score"], int) and cs["grade"] in "ABCDE"
    fx = _fx()
    fx["campaign"].pop("coverage_signals")
    nr = RM.build(_inputs(fx))
    cs = nr["sections"][0]
    assert cs["status"] == "not_rated" and cs["score"] is None and cs["grade"] is None
    assert "score" not in cs["numbers"]
    md = RMD.render(nr)
    sec = _section_md(md, "cyber_score")
    assert "| Cyber Score | Not rated |" in sec and "/ 100" not in sec


def test_agent_text_is_only_quoted_and_labelled():
    m = _model()
    es = next(s for s in m["sections"] if s["id"] == "executive_summary")
    quotes = [b for b in es["blocks"] if b["type"] == "quote"]
    assert len(quotes) == 1 and quotes[0]["source"] == "testing_agent" and "not verified" in quotes[0]["label"]
    md = RMD.render(m)
    outside = re.sub(r"(?ms)^(`{3,})[^\n]*\n.*?^\1\s*$", "", md)          # evidence sits in fences (never rendered)
    assert "<script>" not in outside and "&lt;script&gt;" in outside
    assert "*" + RM.AGENT_SUMMARY_LABEL + "*" in _section_md(md, "executive_summary")


def test_business_impact_and_resilience_are_declared_only():
    m = _model()
    bi = next(s for s in m["sections"] if s["id"] == "business_impact")
    assert bi["blocks"][0]["text"] == RM.NO_IMPACT_NOTE
    txt = json.dumps(bi).lower()
    for word in ("roi", "return on investment:", "€", "$", "loss of", "estimated impact"):
        assert word not in txt.replace("return on investment. this", "")
    res = next(s for s in m["sections"] if s["id"] == "resilience")
    rows = next(b for b in res["blocks"] if b.get("id") == "resilience-declared")["rows"]
    assert ["Recovery time objective (RTO)", "4h", "Declared by the organisation"] in rows
    assert "does not assess" in res["blocks"][0]["text"]


def test_application_profile_unknown_is_shown_as_unknown():
    m = _model(profile=None)
    ap = next(s for s in m["sections"] if s["id"] == "application_profile")
    rows = next(b for b in ap["blocks"] if b.get("id") == "profile-fields")["rows"]
    assert all(r[1] == "Unknown" and r[2] == "Not provided" for r in rows)
    assert ap["numbers"]["fields_unknown"]["value"] == len(P.FIELDS)


def test_framework_section_has_no_compliance_wording():
    m = _model()
    fw = next(s for s in m["sections"] if s["id"] == "framework_assessment")
    forbidden = re.compile(r"(?i)compliant|compliance score|conformit|\d+\s*%|\bgrade\b|certified")
    for s in re.findall(r'"([^"]*)"', json.dumps(fw, ensure_ascii=False)):
        assert not forbidden.search(s), s
    md = _section_md(RMD.render(m), "framework_assessment")
    assert not forbidden.search(md)


def test_attack_path_vocabulary_is_the_legend():
    m = _model()
    ap = next(s for s in m["sections"] if s["id"] == "attack_paths")
    assert set(ap["numbers"]) == {"evidence_backed_paths", "possible_paths"}
    head = ap["blocks"][0]["text"]
    assert "Evidence-Backed Attack Path" in head and "Possible Attack Path" in head
    engine_note = (_inputs()["attack_paths"] or {}).get("note")
    written = [b for b in ap["blocks"] if not (b["type"] == "paragraph" and b["text"] == engine_note)]
    assert "proven" not in json.dumps(written).lower()


# ── Markdown ─────────────────────────────────────────────────────────────────────────────────────────────────────


def test_markdown_numbers_equal_the_model():
    m = _model()
    md = RMD.render(m)
    nums = RM.numbers_of(m)
    for sid, ns in nums.items():
        sec = _section_md(md, sid)
        for name, value in ns.items():
            if value is None or name in ("score_status",):
                continue
            assert re.search(rf"(?<![\d.]){re.escape(str(value))}(?!\d|\.\d)", sec), (sid, name, value)
    cs = _section_md(md, "cyber_score")
    assert f"| Cyber Score | {nums['cyber_score']['score']} / 100 |" in cs
    assert f"| Grade | {nums['cyber_score']['grade']} |" in cs
    es = _section_md(md, "executive_summary")
    c = m["counts"]
    for sev, label in (("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Informational")):
        assert re.search(rf"^\| {label} \| {c[sev]} \|", es, re.M), sev
    assert re.search(rf"^\| Total \| {c['total_findings']} \| {c['exploited']} \|", es, re.M)
    tp = _section_md(md, "treatment_plan")
    rows = [ln for ln in tp.split("\n") if re.match(r"^\| \d+ \| \[", ln)]
    assert len(rows) == nums["treatment_plan"]["actions"]
    fw = _section_md(md, "framework_assessment")
    sec = next(s for s in m["sections"] if s["id"] == "framework_assessment")
    for row in next(b for b in sec["blocks"] if b.get("id") == "framework-states")["rows"]:
        assert "| " + " | ".join(RMD.cell(x) for x in row) + " |" in fw


def test_markdown_section_markers_and_internal_links():
    md = RMD.render(_model())
    assert re.findall(r"<!-- dm-section: ([a-z-]+) -->\n## ", md) == [x.replace("_", "-") for x in RM.SECTION_IDS]
    links, anchors = set(RMD.internal_links(md)), set(RMD.anchors(md))
    assert links and links <= anchors, links - anchors
    for fid in ("vuln_sqli", "vuln_xss", "vuln_nosev"):
        assert RM.finding_anchor(fid) in anchors


def test_markdown_is_deterministic_and_neutralises_untrusted_text():
    a, b = RMD.render(_model()), RMD.render(_model())
    assert a == b
    assert "中文 ✓" in a and "« clients »" in a                          # Unicode kept
    assert "Stored XSS \\| in 'comments'" in a                             # a pipe cannot break a table
    assert "\n# not a heading" not in a and "<img" not in a                # headings and HTML from data neutralised
    sheet = a.split('<a id="finding-vuln_sqli"></a>')[1].split("<a id=")[0]
    resp = sheet.split("#### Response")[1]
    assert re.search(r"^````http$", resp, re.M) and "break-out attempt" in resp   # holding ``` -> a longer fence


def test_missing_fields_and_unrecognised_severity():
    m = _model(findings=[{"id": "vuln_bare"}], plan=None, assessment=None, profile=None, attack_paths=None, score=None,
               cvss={}, campaign={"id": "camp_bare", "status": "stopped"}, target=None, project=None)
    md = RMD.render(m)
    det = next(s for s in m["sections"] if s["id"] == "detailed_findings")
    sheet = next(b for b in det["blocks"] if b["type"] == "finding")
    assert dict((f["label"], f["value"]) for f in sheet["facts"])["Severity"] == "Not recognised"
    assert "| Cyber Score | Not rated |" in md and "partial results" in md
    assert "The treatment plan is not available" in md and "No attack path is recorded" in md
    assert "The framework technical assessment is not available" in md


def test_long_tables():
    fx = _fx()
    base = fx["findings"][3]
    fx["findings"] = [dict(base, id=f"vuln_{i:04d}", title=f"Missing header {i} " + "x" * 200,
                           endpoint=f"http://app.local/p{i}") for i in range(300)]
    m = RM.build(_inputs(fx))
    md = RMD.render(m)
    rows = re.findall(r"^\| \d+ \| \[vuln_\d{4}\]", _section_md(md, "detailed_findings"), re.M)
    assert len(rows) == 300
    assert all(len(ln) < 2000 for ln in md.split("\n") if ln.startswith("| "))


def test_review_fixes_in_the_report():
    """Cross-review fixes rendered by the model: proof attributed to the agent (R1 H-1 / R2 H-2), test references
    without ISO 27001 (R2 H-1), due date / owner / effort of each action (R1 H-3 / R3 D1), both durations labelled
    (R3 D2), the rating method summarised from the code (R1 H-2), what holds the rating (R3 D4)."""
    m = _model()
    assert m["campaign"]["methodology"] == "Test references: NIST SP 800-115, OWASP WSTG"
    det = next(s for s in m["sections"] if s["id"] == "detailed_findings")
    assert "reported by the testing agent, with evidence on file" in det["blocks"][0]["text"]
    assert "proof levels, counts and CVSS scores are the server's" not in det["blocks"][0]["text"]
    mc = next(s for s in m["sections"] if s["id"] == "method_coverage")
    facts = {r["label"]: r["value"] for b in mc["blocks"] if b.get("type") == "facts" for r in b["rows"]}
    assert facts["Test references"] == "Test references: NIST SP 800-115, OWASP WSTG"
    assert facts["Measured activity (server clock, used by the rating)"].startswith("60 min")
    assert facts["Duration on the campaign record (agent-declared on older campaigns)"] == "60 min"
    method = next(b for b in mc["blocks"] if b.get("id") == "rating-method")["blocks"][0]["items"]
    assert any("critical 30, high 15, medium 5, low 2" in x for x in method)
    tp = next(s for s in m["sections"] if s["id"] == "treatment_plan")
    table = next(b for b in tp["blocks"] if b.get("id") == "treatment-actions")
    assert table["columns"][-1] == "Due date" and "Effort" in table["columns"] and "Owner" in table["columns"]
    md = RMD.render(m)
    assert "ISO 27001 / " not in md and "**Method:** Test references" in md
    assert "fix immediately" not in md


def test_not_applicable_frameworks_are_not_assessed_in_the_report():
    fx = _fx()
    fx["declarations"] = {**fx["declarations"], "ai_system_declared": "no", "personal_data": "no"}
    m = RM.build(_inputs(fx))
    fw = next(s for s in m["sections"] if s["id"] == "framework_assessment")
    rows = {r[0]: r for b in fw["blocks"] if b.get("id") == "framework-states" for r in b["rows"]}
    assert rows["EU AI Act (EU) 2024/1689, art. 15"][2:] == ["not assessed"] * 4
    assert rows["GDPR (EU) 2016/679, art. 32 and 25"][2:] == ["not assessed"] * 4
    assert not any(k.startswith(("ai_act_", "gdpr_")) for k in fw["numbers"])
    ai = next(b for b in fw["blocks"] if b.get("id") == "framework-ai_act")
    assert all(b.get("type") != "table" for b in ai["blocks"])
    ex = next(s for s in m["sections"] if s["id"] == "executive_summary")
    assert not any("AI Act" in str(b.get("text")) or "GDPR" in str(b.get("text")) for b in ex["blocks"])


def test_community_profile_provenance_says_local_file():
    m = RM.build({**_inputs(), "edition": "community"})
    prof = next(s for s in m["sections"] if s["id"] == "application_profile")
    cells = {r[2] for b in prof["blocks"] if b.get("id") == "profile-fields" for r in b["rows"]}
    assert any(c.startswith("Declared in the local profile file") for c in cells)
    pro = RM.build({**_inputs(), "edition": "pro"})
    cells = {r[2] for b in next(s for s in pro["sections"] if s["id"] == "application_profile")["blocks"]
             if b.get("id") == "profile-fields" for r in b["rows"]}
    assert not any("local profile file" in c for c in cells)


def test_schema_keys_are_not_secret_looking():
    """The field-wise redaction masks a whole value by its KEY name (password, token, credential, key pairs, pin,
    cookie…). No structural key of the model may look like one (the editions also check with the engine itself)."""
    secret_last = {"password", "passwd", "passphrase", "pass", "pwd", "secret", "token", "tokens", "apikey", "cookie",
                   "cookies", "credential", "credentials", "creds", "jwt", "authorization", "ntlm", "nthash", "lmhash",
                   "phpsessid", "jsessionid", "passcode", "otp", "pin", "bearer"}
    for k, path in _keys(_model()):
        words = [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", k).lower()) if w]
        assert not (words and words[-1] in secret_last), (k, path)
        assert k not in ("key", "name"), (k, path)       # {"name"|"key": <secret name>, "value": x} pairs


if __name__ == "__main__":
    (FIX / "expected_model.json").write_text(
        json.dumps(strip_edition_specific(_model()), indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print("expected_model.json written")
    (FIX / "expected_method_coverage_override.json").write_text(
        json.dumps(_method_section(_override_model()), indent=1, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")
    print("expected_method_coverage_override.json written")
