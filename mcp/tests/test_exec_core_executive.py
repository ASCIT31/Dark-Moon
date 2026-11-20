"""exec_core 1.3.1, shared by Community and Pro (same file in both editions).

1. ``legend.path_kind_of``: one classification of attack paths for every surface. A derived path is evidence-backed only
   when the engine CHECKED its claims against the recorded evidence; a declared or inferred path never is.
2. ``static_text``: Darkmoon's own catalogue / legend texts are never masked by the secret redaction, and real
   credentials in evidence still are (both directions, with the edition's real redaction engine).
3. ``executive``: the one executive block (H8) is a selection of exec_core documents, computed nowhere else.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api.exec_core import executive as X  # noqa: E402
from api.exec_core import framework_catalogues as K  # noqa: E402
from api.exec_core import legend as L  # noqa: E402
from api.exec_core import report_markdown as MD  # noqa: E402
from api.exec_core import report_model as RM  # noqa: E402
from api.exec_core import static_text as ST  # noqa: E402

SECRET = "Zq8vLm2pXr7Tn4-not-a-real-password"
A85 = next(c["text"] for f in K.FRAMEWORKS for c in f["controls"] if c["id"] == "A.8.5")


def _engine():
    """The edition's redaction engine: Pro's MCP copy, else the copy vendored next to the Community explorer."""
    try:
        from api import evidence_redaction as mod  # type: ignore
        return mod
    except Exception:  # noqa: BLE001
        pass
    vendor = MCP.parent / "conf" / "plugins" / "darkmoon-explorer" / "_vendor"
    if (vendor / "evidence_redaction.py").is_file():
        if str(vendor) not in sys.path:
            sys.path.append(str(vendor))
        import evidence_redaction as mod  # type: ignore
        return mod
    pytest.skip("no redaction engine in this tree")


def _mask(engine):
    m = getattr(engine, "mask", None)
    return m if callable(m) else (lambda s: engine.redact_text(s)[0])


# ── 1. path kinds ────────────────────────────────────────────────────────────────────────────────────────────────


def _path(prov, hyp=False, corr=None):
    p = {"id": "p", "provenance": prov, "hypothesis": hyp}
    if corr is not None:
        p["corroboration"] = corr
    return p


@pytest.mark.parametrize("path, kind", [
    (_path("observed"), "evidence_backed"),
    (_path("observed", hyp=True), "possible"),
    (_path("derived", corr={"status": "corroborated", "unverified": [], "checked": True}), "evidence_backed"),
    (_path("derived", corr={"status": "corroborated", "unverified": [], "checked": False}), "possible"),  # legacy/demo
    (_path("derived", corr={"status": "corroborated", "unverified": []}), "possible"),        # no check recorded
    (_path("derived", corr={"status": "claimed", "unverified": ["reuse a -> b is declared only"], "checked": True},
           hyp=True), "possible"),
    (_path("derived", corr={"status": "corroborated", "unverified": ["x"], "checked": True}), "possible"),
    (_path("derived"), "possible"),                                                          # pre-RT-04 record
    (_path("declared"), "possible"),                     # a declared chain is never a proven exploitation
    (_path("agent-declared"), "possible"),
    (_path("inferred"), "possible"),
    (_path("whatever"), "possible"),
    (None, "possible"),
])
def test_path_kind_of(path, kind):
    assert L.path_kind_of(path) == kind
    if isinstance(path, dict):
        assert RM.path_kind(path) == kind          # the report model and the executive block use the same rule


def test_paths_summary_counts_with_the_same_rule():
    doc = {"paths": [_path("observed"), _path("declared"), _path("inferred", hyp=True),
                     _path("derived", corr={"status": "corroborated", "unverified": [], "checked": True}),
                     _path("derived", corr={"status": "corroborated", "unverified": [], "checked": False})]}
    s = X.paths_summary(doc)
    assert (s["evidence_backed"], s["possible"]) == (2, 3)
    assert s["labels"] == {"possible": "Possible Attack Path", "evidence_backed": "Evidence-Backed Attack Path"}
    assert X.paths_summary({"paths": None}) is None


def test_engine_marks_whether_derived_claims_were_checked():
    """The engine writes ``corroboration.checked`` (False only when nothing was matched: legacy flag or labelled demo)."""
    src = (MCP / "api" / "attack_paths.py").read_text(encoding="utf-8")
    assert '"checked": not legacy_claims' in src


# ── 2. static texts vs the secret redaction ──────────────────────────────────────────────────────────────────────


def test_catalogue_texts_are_static():
    assert A85 in ST.STATIC_TEXTS
    assert "authentication bypass" in A85
    assert all(len(s) >= ST.MIN_LENGTH and " " in s for s in ST.STATIC_TEXTS)
    assert ST.is_static(L.PATH_KIND["possible"]["meaning"])
    assert not ST.is_static(f"password={SECRET}")


def test_catalogue_text_kept_and_real_credentials_still_masked_in_documents():
    eng = _engine()
    doc = {"controls": [{"control_id": "A.8.5", "text": A85, "why": A85},
                        {"control_id": "x", "text": f"default credentials admin:{SECRET}"}],
           "evidence": {"raw_response": f'{{"password": "{SECRET}"}}'},
           "note": f"{A85} password={SECRET}"}
    out = ST.masked_obj(doc, eng.redact_obj)
    assert out["controls"][0]["text"] == A85 == out["controls"][0]["why"]
    flat = repr(out)
    assert SECRET not in flat                                   # evidence, prose and a look-alike sentence: masked
    assert out["note"] != doc["note"]                           # a text that merely CONTAINS a static text is masked
    assert ST.restore_static({"a": [A85]}, {"a": ["x"]}) == {"a": [A85]}
    assert ST.restore_static({"a": "x"}, {"a": "y"}) == {"a": "y"}


def test_catalogue_cell_kept_and_real_credentials_still_masked_in_markdown():
    eng = _engine()
    md = "\n".join([
        "| Control | State | Findings | What a test observes / why |",
        "|---|---|---|---|",
        f"| [A.8.5](#finding-v1) | Weakness observed | 6 | {MD.cell(A85)} |",
        f"| A.8.12 | Weakness observed | 1 | credentials admin:{SECRET} |",
        "",
        A85,
        "",
        "```",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA0Zq8vLm2pXr7Tn4abcdefghijklmnopqrstuvwxyz0123456789",
        "-----END RSA PRIVATE KEY-----",
        "```",
        f"password: {SECRET}",
    ])
    out = ST.mask_text(md, _mask(eng))
    assert f"| {MD.cell(A85)} |" in out
    assert "\n" + A85 + "\n" in out
    assert SECRET not in out
    assert "MIIEowIBAAKCAQEA0Zq8vLm2pXr7Tn4" not in out          # multi-line secret masked as one piece
    assert "⟦dm-static-" not in out
    # without any static text, mask_text is exactly the masker
    plain = f"user admin password {SECRET}"
    assert ST.mask_text(plain, _mask(eng)) == _mask(eng)(plain)


def test_without_the_static_rule_the_engine_masks_the_catalogue_sentence():
    """The false positive this module exists for (the engine reads « Login … handling: authentication » as a pair)."""
    eng = _engine()
    raw = eng.redact_obj({"text": A85})["text"]
    kept = ST.masked_obj({"text": A85}, eng.redact_obj)["text"]
    assert kept == A85
    assert raw == A85 or "redacted" in raw


def test_placeholder_in_untrusted_text_never_leaks():
    out = ST.mask_text(f"{A85}\nx ⟦dm-static-0⟧ y ⟦dm-static-99⟧", lambda s: s)
    assert "⟦dm-static-99⟧" not in out


# ── 3. executive block ───────────────────────────────────────────────────────────────────────────────────────────


def _plan(n=5):
    acts = []
    for i in range(1, n + 1):
        acts.append({"action_id": f"act_{i:016x}", "priority": i, "title": f"Fix {i}", "severity": "high",
                     "proof": "confirmed", "status": "applied" if i == 2 else "proposed",
                     "status_label": "Applied — not verified" if i == 2 else "Proposed",
                     "status_text": "Declared applied by ops, 2026-11-20 — not verified" if i == 2 else "Proposed",
                     "status_verified": False, "finding_ids": ["v1", "v2"],
                     "expected_impact": {"findings_covered": 2, "attack_paths_interrupted": 1, "text": "Findings covered: 2"}})
    return {"label": "Prioritized Treatment Plan", "definition": "d", "plain": "p", "verification": "retest",
            "actions": acts, "statuses": [{"value": "proposed", "label": "Proposed"},
                                          {"value": "applied", "label": "Applied — not verified"}]}


def test_campaign_block_is_a_selection():
    score = {"score_status": "rated", "score": 41, "grade": "D", "assessment_coverage": {"sentence": "full campaign"},
             "evidence_summary": {"by_severity": {"high": 2}, "by_proof": {"confirmed": 2}, "counted_findings": 2,
                                  "to_confirm": ["v9"]}}
    fa = {"summary_line": "Technical findings relevant to: GDPR (1 control with a weakness observed).",
          "reading": "r", "coverage": {"coverage_ok": True},
          "frameworks": [{"framework": "gdpr", "label": "GDPR", "applicability": {"status": "to_confirm", "label": "x"},
                          "counts": {"weakness_observed": 1}, "finding_ids": ["v1"], "action_ids": ["a"]}]}
    b = X.campaign_block({"id": "c1", "project_id": "p1", "status": "completed"}, score, _plan(), fa,
                         {"paths": [_path("observed"), _path("declared")]}, {"plan": "/x"})
    assert b["schema_version"] == "darkmoon-executive/1"
    assert (b["score"]["grade"], b["score"]["status_label"], b["score"]["coverage_sentence"]) == ("D", "Rated", "full campaign")
    assert [a["priority"] for a in b["treatment_plan"]["top_actions"]] == [1, 2, 3]
    assert b["treatment_plan"]["actions_total"] == 5
    assert b["treatment_plan"]["top_actions"][1]["status_label"] == "Applied — not verified"
    assert b["treatment_plan"]["top_actions"][0]["last_retest"] is None   # a retest wording travels with its retest
    assert b["frameworks"]["summary_line"].startswith("Technical findings relevant to")
    assert (b["attack_paths"]["evidence_backed"], b["attack_paths"]["possible"]) == (1, 1)
    assert b["evidence"]["to_confirm"] == 1
    assert b["legend"] == L.legend()
    assert b["links"] == {"plan": "/x"}
    assert "compliant" not in repr(b).lower()


def test_not_rated_block_has_no_number_and_missing_parts_are_none():
    b = X.campaign_block({"id": "c1"}, None, None, None, None)
    assert (b["score"]["score"], b["score"]["grade"], b["score"]["status_label"]) == (None, None, "Not rated")
    assert b["treatment_plan"] is b["frameworks"] is b["attack_paths"] is None
    assert b["maintenance"]["decision"] == "not_recorded"


def test_campaign_block_shows_a_maintenance_override():
    mc = {"decision": "blocked", "projects": [{"reasons": ["outside-window"]}], "source": "launch", "enforced": True,
          "override": {"override": True, "by": "ada", "at": "2026-11-20T14:03:09Z", "reason": "Agreed with the owner"}}
    m = X.campaign_block({"id": "c1", "maintenance_check": mc}, None, None, None, None)["maintenance"]
    assert (m["decision"], m["overridden"], m["by"], m["at"], m["reason"]) == (
        "outside", True, "ada", "2026-11-20 14:03 UTC", "Agreed with the owner")
    assert m["text"].startswith("Outside the maintenance policy (outside every window) — launched by an administrator")


def test_project_block_uses_the_reference_campaign():
    camps = [{"id": "c1", "date": "2026-11-01", "status": "completed"}, {"id": "c2", "date": "2026-11-10", "status": "running"}]
    ref = {"score_status": "rated", "score": 70, "grade": "B",
           "reference": {"campaign_id": "c1", "assessed_at": "t", "assessment_coverage": {"sentence": "s"}}}
    b = X.project_block({"id": "p1", "name": "P"}, ref, camps, {"score_status": "not_rated"}, _plan(2), "c1")
    assert (b["score"]["grade"], b["reference_campaign_id"], b["reference_campaign_date"]) == ("B", "c1", "2026-11-01")
    assert b["latest_campaign"]["campaign_id"] == "c2" and b["latest_campaign"]["status_label"] == "Not rated"
    assert X.plan_campaign_id(None, camps[1]) is None             # a running campaign has no plan yet
    assert X.plan_campaign_id(None, camps[0]) == "c1"
    assert X.plan_campaign_id("c9", camps[0]) == "c9"
