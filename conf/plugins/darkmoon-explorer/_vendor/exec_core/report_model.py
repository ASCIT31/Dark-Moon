"""The one report model of Darkmoon (schema ``darkmoon-report/v2``), both editions.

A JSON document built ONLY from server data: the stats of ``exec_core.stats``, the Cyber Score document
(``exec_core.score``), the Prioritized Treatment Plan (``exec_core.actions``), the framework technical assessment
(``exec_core.frameworks_assess``), the application profile view (``exec_core.profile``), the attack-path document of
the edition's engine, the CVSS recomputed by the server from each vector, and sections the report annex already
builds (infrastructure map, technique mappings) passed in as Markdown. The only prose written by a model is the
testing agent's executive summary, quoted and labelled as such.

The Markdown file, the web report page and the PDF are renderings of this one document (``report_markdown`` here,
the client's PDF composer in Pro); none of them computes a number.

Every section has a stable ``id``, a ``title``, ``blocks`` (typed: paragraph, note, quote, facts, kpis, table, list,
figure, markdown, subsection, finding) and ``numbers`` (``{name: {"value", "source"}}``: every figure the section
states, with where it comes from). Key names never contain a secret word (the field-wise redaction masks a whole value
by its key name: see the redaction tests of each edition).

Pure Python standard library, no I/O (``exec_core`` rule).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import frameworks_assess as _fa
from . import identity, legend as _legend, profile as _profile, stats as _stats

SCHEMA_VERSION = "darkmoon-report/v2"
LANGUAGE = "en"

# (id, title) in the reading order of the report
SECTIONS: Tuple[Tuple[str, str], ...] = (
    ("cyber_score", "Cyber Score"),
    ("method_coverage", "Method and test coverage"),
    ("executive_summary", "Executive summary"),
    ("application_profile", "Application profile"),
    ("business_impact", "Business context and exposure"),
    ("critical_risks", "Critical risks"),
    ("framework_assessment", "Framework technical assessment"),
    ("resilience", "Resilience and availability"),
    ("treatment_plan", "Prioritized Treatment Plan"),
    ("attack_paths", "Attack paths"),
    ("detailed_findings", "Detailed findings"),
    ("evidence_methodology", "Evidence and methodology"),
    ("limitations", "Limitations"),
)
SECTION_IDS = tuple(s for s, _ in SECTIONS)

# Fields that legitimately differ between the editions on the same data (documented; the parity tests ignore them).
EDITION_SPECIFIC = (
    "edition",
    "sections.attack_paths",                      # Pro observes evidence-backed paths; Community only has hypotheses
    "sections.evidence_methodology.privacy",      # Pro privacy placeholders legend (Community stores no legend)
    "sections.evidence_methodology.masking",      # how evidence is masked on output in each edition
    "sections.treatment_plan.verification",       # Pro: completed retests; Community: declarations only
    "blocks with id verification-note / masking-note",   # the sentences stating the two edition differences above
)

SEV_ORDER = ("critical", "high", "medium", "low", "info")
PROOF_ORDER = ("exploited", "confirmed", "unconfirmed")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")
_EVIDENCE_LIMIT = 600
_LINE_LIMIT = 500
_MAX_ITEMS = 40

AGENT_SUMMARY_LABEL = "Written by the testing agent (quoted as written, not verified by the server)."
AGENT_TEXT_NOTE = ("Titles, descriptions, technical analyses and remediation texts of the findings are written by the "
                   "testing agents and quoted as written; severities, proof levels, counts and CVSS scores are the "
                   "server's.")
NO_IMPACT_NOTE = ("Darkmoon does not estimate business impact, financial loss or return on investment. This section "
                  "lists only the facts the organisation declared and the counts measured by this campaign; relating "
                  "them is the system owner's decision.")
RESILIENCE_NOTE = ("Recovery and availability figures are declared by the organisation and shown as declared: Darkmoon "
                   "does not test recovery, backups or load, and does not assess these figures.")
REPORT_LIMITS = [
    "This report results from an automated assessment: findings may include false positives, and the absence of a "
    "finding does not prove the absence of a weakness.",
    "It describes the target at the time of the campaign and only its tested scope.",
    "Recommendations quoted from the testing agents must be validated by the system owner before being applied.",
]


# ── small helpers ────────────────────────────────────────────────────────────────────────────────────────────────


def text(value: Any, limit: int = 0) -> str:
    """One clean string: control characters out, Unicode kept, bounded."""
    s = _CTRL.sub("", "" if value is None else str(value)).strip()
    if limit and len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s


def _n(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _num(value: Any, source: str) -> Dict[str, Any]:
    return {"value": value, "source": source}


def _plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _sev_label(s: Any) -> str:
    return _legend.severity_label(s) or "Not recognised"


def _proof_label(s: Any) -> str:
    return _legend.evidence_label(s)


def _human_duration(seconds: Any) -> Optional[str]:
    s = _n(seconds)
    if s <= 0:
        return None
    return f"{s} s" if s < 120 else f"{round(s / 60)} min"


def _section(sid: str, blocks: List[Dict[str, Any]], numbers: Optional[Dict[str, Any]] = None,
             sources: Iterable[str] = (), **extra: Any) -> Dict[str, Any]:
    title = dict(SECTIONS)[sid]
    out = {"id": sid, "title": title, "sources": sorted(set(sources)), "numbers": numbers or {}, "blocks": blocks}
    out.update(extra)
    return out


def finding_anchor(fid: Any) -> str:
    return "finding-" + re.sub(r"[^A-Za-z0-9_-]", "-", str(fid or ""))[:80]


def action_anchor(aid: Any) -> str:
    return "action-" + re.sub(r"[^A-Za-z0-9_-]", "-", str(aid or ""))[:80]


def path_anchor(pid: Any) -> str:
    return "path-" + re.sub(r"[^A-Za-z0-9_-]", "-", str(pid or ""))[:80]


# ── 1. Cyber Score ───────────────────────────────────────────────────────────────────────────────────────────────


def _cyber_score(score: Dict[str, Any]) -> Dict[str, Any]:
    st = score.get("score_status") or "not_rated"
    st_info = _legend.SCORE_STATUS.get(st, _legend.SCORE_STATUS["not_rated"])
    cov = score.get("assessment_coverage") or {}
    rated = st in ("rated", "limited") and score.get("score") is not None
    blocks: List[Dict[str, Any]] = []
    numbers: Dict[str, Any] = {"score_status": _num(st, "exec_core.score")}
    if rated:
        grade = score.get("grade")
        numbers["score"] = _num(score.get("score"), "exec_core.score")
        numbers["grade"] = _num(grade, "exec_core.score")
        blocks.append({"type": "kpis", "items": [
            {"id": "score", "label": "Cyber Score", "value": f"{score.get('score')} / 100", "source": "exec_core.score"},
            {"id": "grade", "label": "Grade", "value": grade, "source": "exec_core.score"},
            {"id": "status", "label": "Status", "value": st_info["label"], "source": "exec_core.score"}]})
        blocks.append({"type": "paragraph", "text": f"Grade {grade}: {_legend.GRADE.get(grade, '')}.".replace(": .", ".")})
    else:
        blocks.append({"type": "kpis", "items": [
            {"id": "score", "label": "Cyber Score", "value": "Not rated", "source": "exec_core.score"},
            {"id": "status", "label": "Status", "value": st_info["label"], "source": "exec_core.score"}]})
    blocks.append({"type": "paragraph", "text": st_info["meaning"]})
    if cov.get("sentence"):
        blocks.append({"type": "paragraph", "text": "Coverage recorded by the server: " + text(cov["sentence"])})
    else:
        blocks.append({"type": "paragraph", "text": "Coverage recorded by the server: none (the campaign predates the "
                                                    "coverage record, or it was not recorded)."})
    reasons = [text(r.get("sentence") or r.get("code")) for r in score.get("status_reasons") or [] if isinstance(r, dict)]
    if reasons:
        blocks.append({"type": "subsection", "id": "cyber-score-reasons", "title": "Why the rating is limited or absent",
                       "blocks": [{"type": "list", "items": reasons}]})
    caps = [c for c in score.get("caps") or [] if isinstance(c, dict)]
    if rated and caps:
        rows = [[text(c.get("rule")).replace("_", " "), str(c.get("cap")), str(len(c.get("finding_ids") or []))] for c in caps]
        blocks.append({"type": "subsection", "id": "cyber-score-caps", "title": "Caps by worst evidence", "blocks": [
            {"type": "table", "id": "score-caps", "columns": ["Rule", "Maximum score", "Findings"], "rows": rows,
             "source": "exec_core.score"}]})
        numbers["caps"] = _num(len(caps), "exec_core.score")
    if rated:
        numbers["penalty_total"] = _num(score.get("penalty_total"), "exec_core.score")
        blocks.append({"type": "paragraph", "text": (
            f"Sum of the penalties of the weakness classes: {score.get('penalty_total')} (rating = 100 minus this sum, "
            f"bounded 0 to 100, then the caps by worst evidence"
            + (" and the cap of a limited test" if st == "limited" else "") + ").")})
    lim = [text(x) for x in score.get("limitations") or [] if x]
    if lim:
        blocks.append({"type": "subsection", "id": "cyber-score-limitations", "title": "Limitations of the rating",
                       "blocks": [{"type": "list", "items": lim}]})
    tr = score.get("trend")
    if isinstance(tr, dict) and tr.get("available"):
        diffs = "; ".join(text(d) for d in tr.get("scope_differences") or [])
        blocks.append({"type": "paragraph", "text": (
            f"Trend: {text(tr.get('direction'))} ({_n(tr.get('delta')):+d}) against the previous rated full campaign "
            f"{text(tr.get('previous_campaign_id'))} ({tr.get('previous_score')} / 100)"
            + (f"; scope differences: {diffs}." if diffs else "."))})
        numbers["trend_delta"] = _num(_n(tr.get("delta")), "exec_core.score")
    elif isinstance(tr, dict) and tr.get("reason"):
        blocks.append({"type": "paragraph", "text": "Trend: not available (" + text(tr.get("reason")) + ")."})
    blocks.append({"type": "note", "text": "An exposure rating of what this campaign found in its tested scope "
                                           f"(methodology {text(score.get('methodology_version')) or 'darkmoon-cyber-score/1'}); "
                                           "not a security level, a compliance statement or a probability."})
    return _section("cyber_score", blocks, numbers, ["exec_core.score"],
                    status=st, score=score.get("score") if rated else None, grade=score.get("grade") if rated else None)


# ── 2. Method and coverage ───────────────────────────────────────────────────────────────────────────────────────


def _method_coverage(campaign: Dict[str, Any], score: Dict[str, Any], stats: Dict[str, Any],
                     assessment: Optional[Dict[str, Any]], annex: Dict[str, Any], target: str) -> Dict[str, Any]:
    cov = score.get("assessment_coverage") or {}
    st = text(campaign.get("status")) or "unknown"
    rows: List[List[str]] = [
        ["Target (in scope)", target or "unknown"],
        ["Campaign", text(campaign.get("id"))],
        ["Campaign status", st],
        ["Campaign kind", text(cov.get("campaign_kind")) or "unknown"],
        ["Started", text(cov.get("started_at") or campaign.get("date")) or "unknown"],
        ["Finalised", text(cov.get("finalized_at")) or "not recorded"],
        ["Measured duration", (f"{_human_duration(cov.get('measured_duration_seconds'))} "
                               f"({_n(cov.get('measured_duration_seconds'))} s)")
         if _human_duration(cov.get("measured_duration_seconds")) else "not recorded"],
        ["Test agents dispatched", ", ".join(text(a) for a in cov.get("specialised_agents") or cov.get("agents_dispatched") or [])
         or "not recorded"],
        ["Assets registered", str(cov.get("assets_registered")) if cov.get("present") else "not recorded"],
        ["Toolbox commands executed", str(cov.get("commands_executed")) if cov.get("present") else "not recorded"],
        ["Declared methodology", text(campaign.get("methodology")) or "not declared"],
    ]
    numbers: Dict[str, Any] = {}
    if cov.get("present"):
        numbers.update({
            "measured_duration_seconds": _num(_n(cov.get("measured_duration_seconds")), "coverage_signals"),
            "agents_dispatched": _num(len(cov.get("specialised_agents") or cov.get("agents_dispatched") or []), "coverage_signals"),
            "assets_registered": _num(_n(cov.get("assets_registered")), "coverage_signals"),
            "commands_executed": _num(_n(cov.get("commands_executed")), "coverage_signals"),
        })
    ex = stats.get("excluded") or {}
    numbers["findings_counted"] = _num(_n(stats.get("total_findings")), "exec_core.stats")
    numbers["findings_quarantined"] = _num(_n(ex.get("quarantined")), "exec_core.stats")
    numbers["findings_false_positive"] = _num(_n(ex.get("false_positive")), "exec_core.stats")
    blocks: List[Dict[str, Any]] = [
        {"type": "paragraph", "text": "Facts recorded by the Darkmoon server during the campaign (not declared by the "
                                      "agents)."},
        {"type": "facts", "rows": [{"label": k, "value": v} for k, v in rows], "source": "campaign record + coverage_signals"},
        {"type": "paragraph", "text": (f"Findings counted: {_n(stats.get('total_findings'))}. Held for privacy review "
                                       f"(not counted): {_n(ex.get('quarantined'))}. Marked false positive (not counted): "
                                       f"{_n(ex.get('false_positive'))}.")},
    ]
    fl = cov.get("floors") or {}
    if fl:
        blocks.append({"type": "paragraph", "text": (
            "Coverage floor of the rating: "
            f"{_human_duration(fl.get('min_duration_seconds')) or '-'} measured, {fl.get('min_agents')} specialised agents, "
            f"{fl.get('min_assets')} asset registered, {fl.get('min_commands')} toolbox commands.")})
    fcov = (assessment or {}).get("coverage") or {}
    if fcov.get("sentence"):
        blocks.append({"type": "paragraph", "text": "Framework coverage: " + text(fcov.get("sentence"))})
    if annex.get("infrastructure"):
        blocks.append({"type": "subsection", "id": "assets-mapped", "title": "Assets mapped by this campaign", "blocks": [
            {"type": "markdown", "source": "report_annex.infrastructure_section", "markdown": annex["infrastructure"]}]})
    return _section("method_coverage", blocks, numbers, ["campaign record", "coverage_signals", "exec_core.stats",
                                                         *(["report_annex.infrastructure_section"] if annex.get("infrastructure") else [])])


# ── 3. Executive summary ─────────────────────────────────────────────────────────────────────────────────────────


def _severity_sentence(stats: Dict[str, Any]) -> str:
    parts = [f"{_n(stats.get(k))} {k}" for k in SEV_ORDER if _n(stats.get(k))]
    total = _n(stats.get("total_findings"))
    if not total:
        return "No finding was counted in the tested scope of this campaign (not a proof that none exists)."
    sev_sum = sum(_n(stats.get(k)) for k in SEV_ORDER)
    unrated = total - sev_sum
    tail = f", {unrated} without a recognised severity" if unrated > 0 else ""
    return (f"{_plural(total, 'finding')} counted in the tested scope ({', '.join(parts) or 'none rated'}{tail}); "
            f"{_n(stats.get('exploited'))} exploited, {_n(stats.get('confirmed'))} confirmed, "
            f"{_n(stats.get('unconfirmed'))} to confirm.")


def _executive_summary(campaign: Dict[str, Any], stats: Dict[str, Any], score: Dict[str, Any],
                       plan: Optional[Dict[str, Any]], assessment: Optional[Dict[str, Any]],
                       path_counts: Dict[str, int]) -> Dict[str, Any]:
    st = score.get("score_status") or "not_rated"
    rating = (f"Cyber Score {score.get('score')} / 100, grade {score.get('grade')} ({_legend.SCORE_STATUS[st]['label'].lower()})."
              if st in ("rated", "limited") and score.get("score") is not None else "Cyber Score: not rated.")
    blocks: List[Dict[str, Any]] = [{"type": "paragraph", "text": rating},
                                    {"type": "paragraph", "text": _severity_sentence(stats)}]
    numbers: Dict[str, Any] = {"findings_counted": _num(_n(stats.get("total_findings")), "exec_core.stats")}
    for k in SEV_ORDER:
        numbers[k] = _num(_n(stats.get(k)), "exec_core.stats")
    for k in PROOF_ORDER:
        numbers[k] = _num(_n(stats.get(k)), "exec_core.stats")
    rows = [[_sev_label(k), str(_n(stats.get(k))), str(_n((stats.get("exploited_by_severity") or {}).get(k)))]
            for k in SEV_ORDER]
    rows.append(["Total", str(_n(stats.get("total_findings"))), str(_n(stats.get("exploited")))])
    blocks.append({"type": "table", "id": "findings-by-severity", "columns": ["Severity", "Findings", "Exploited"],
                   "rows": rows, "source": "exec_core.stats"})
    blocks.append({"type": "paragraph", "text": (
        f"Attack paths: {path_counts.get('evidence_backed', 0)} evidence-backed, {path_counts.get('possible', 0)} possible "
        "(hypotheses). Attack paths are not part of the rating.")})
    actions = list((plan or {}).get("actions") or [])
    if actions:
        top = actions[:3]
        blocks.append({"type": "subsection", "id": "top-actions", "title": "First actions of the treatment plan", "blocks": [
            {"type": "list", "items": [f"{a.get('priority')}. {text(a.get('title'), 160)} ({text((a.get('expected_impact') or {}).get('text'))})"
                                       for a in top],
             "links": [action_anchor(a.get("action_id")) for a in top]}]})
        numbers["actions"] = _num(len(actions), "exec_core.actions")
    if assessment:
        blocks.append({"type": "paragraph", "text": "Frameworks: " + text(_fa.summary_line(assessment))})
    summary = text(campaign.get("executive_summary"))
    if summary:
        blocks.append({"type": "quote", "label": AGENT_SUMMARY_LABEL, "text": summary, "source": "testing_agent"})
    else:
        blocks.append({"type": "note", "text": "No executive summary was written by the testing agent."})
    return _section("executive_summary", blocks, numbers, ["exec_core.stats", "exec_core.score", "exec_core.actions",
                                                           "exec_core.frameworks_assess", "testing_agent (quoted)"])


# ── 4. Application profile ───────────────────────────────────────────────────────────────────────────────────────

FIELD_LABEL = {
    "description": "Description", "business_purpose": "Business purpose", "business_owner": "Business owner (role)",
    "technical_owner": "Technical owner (role)", "business_processes": "Business processes",
    "user_categories": "User categories", "data_categories": "Data categories", "personal_data": "Personal data",
    "languages": "Languages", "frameworks": "Frameworks", "databases": "Databases", "infrastructure": "Infrastructure",
    "external_dependencies": "External dependencies", "criticality": "Criticality",
    "availability_requirement": "Availability requirement", "rto": "Recovery time objective (RTO)",
    "rpo": "Recovery point objective (RPO)", "sla": "Service level (SLA)", "data_residency": "Data residency",
    "sector": "Sector", "nis2_entity_type": "NIS2 entity type", "iso27001_isms_scope": "ISO/IEC 27001 ISMS scope",
    "ai_system_declared": "AI system declared", "ai_risk_class": "AI risk class",
    "last_verification_date": "Last verification date",
}


def _field_value(f: Dict[str, Any]) -> str:
    v = f.get("value")
    if v is None or v == [] or v == "":
        return "Unknown"
    if isinstance(v, list):
        return ", ".join(text(x, 120) for x in v[:_MAX_ITEMS]) or "Unknown"
    return text(v, 300)


def _field_rows(profile: Optional[Dict[str, Any]], names: Iterable[str]) -> List[List[str]]:
    fields = (profile or {}).get("fields") or {}
    rows = []
    for name in names:
        f = fields.get(name) if isinstance(fields.get(name), dict) else {"value": None, "provenance": "unknown"}
        prov = f.get("provenance") if f.get("provenance") in _profile.PROVENANCES else "unknown"
        rows.append([FIELD_LABEL.get(name, name), _field_value(f), _profile.PROVENANCE_LABEL[prov]])
    return rows


def _application_profile(profile: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    names = list(_profile.FIELDS)
    counts = dict((profile or {}).get("provenance_counts") or {p: 0 for p in _profile.PROVENANCES})
    if not profile:
        counts["unknown"] = len(names)
    blocks: List[Dict[str, Any]] = [
        {"type": "paragraph", "text": ("Business facts come only from the organisation; detected technologies are what the "
                                       "agents reported, not confirmed. A field nobody provided is shown as Unknown.")},
        {"type": "table", "id": "profile-fields", "columns": ["Field", "Value", "Provenance"],
         "rows": _field_rows(profile, names), "source": "exec_core.profile"},
    ]
    blocks.append({"type": "table", "id": "profile-provenance", "columns": ["Provenance", "Fields"],
                   "rows": [[_profile.PROVENANCE_LABEL[p], str(_n(counts.get(p)))] for p in _profile.PROVENANCES],
                   "source": "exec_core.profile"})
    if not profile:
        blocks.insert(0, {"type": "note", "text": "No application profile is recorded for this project: every field is unknown."})
    numbers = {f"fields_{p}": _num(_n(counts.get(p)), "exec_core.profile") for p in _profile.PROVENANCES}
    return _section("application_profile", blocks, numbers, ["exec_core.profile"])


# ── 5. Business context and exposure ─────────────────────────────────────────────────────────────────────────────


def _business_impact(profile: Optional[Dict[str, Any]], stats: Dict[str, Any], score: Dict[str, Any],
                     path_counts: Dict[str, int], plan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    names = ("business_purpose", "business_processes", "user_categories", "data_categories", "personal_data",
             "criticality")
    rows = _field_rows(profile, names)
    declared = [r for r in rows if r[2] in (_profile.PROVENANCE_LABEL["declared_by_customer"], _profile.PROVENANCE_LABEL["verified"])]
    ev = score.get("evidence_summary") or {}
    xs = stats.get("exploited_by_severity") or {}
    measured = [
        ["Findings counted", str(_n(stats.get("total_findings")))],
        ["Critical or high findings", str(_n(stats.get("critical")) + _n(stats.get("high")))],
        ["Critical or high findings exploited", str(_n(xs.get("critical")) + _n(xs.get("high")))],
        ["Weakness classes with an open finding", str(_n(ev.get("weakness_classes")))],
        ["Evidence-backed attack paths", str(path_counts.get("evidence_backed", 0))],
        ["Actions in the treatment plan", str(len((plan or {}).get("actions") or []))],
    ]
    numbers = {
        "declared_business_facts": _num(len(declared), "exec_core.profile"),
        "critical_high": _num(_n(stats.get("critical")) + _n(stats.get("high")), "exec_core.stats"),
        "critical_high_exploited": _num(_n(xs.get("critical")) + _n(xs.get("high")), "exec_core.stats"),
        "weakness_classes": _num(_n(ev.get("weakness_classes")), "exec_core.score"),
        "evidence_backed_paths": _num(path_counts.get("evidence_backed", 0), "attack-path engine"),
    }
    blocks = [{"type": "note", "text": NO_IMPACT_NOTE},
              {"type": "table", "id": "business-facts", "columns": ["Declared fact", "Value", "Provenance"], "rows": rows,
               "source": "exec_core.profile"},
              {"type": "table", "id": "measured-exposure", "columns": ["Measured by this campaign", "Count"],
               "rows": measured, "source": "exec_core.stats + exec_core.score + attack-path engine + exec_core.actions"}]
    if not declared:
        blocks.insert(1, {"type": "paragraph", "text": "No business fact was declared by the organisation for this "
                                                       "project: the business context is unknown."})
    else:
        blocks.insert(1, {"type": "paragraph", "text": f"Business facts declared by the organisation: {len(declared)} "
                                                       f"of {len(rows)}."})
    return _section("business_impact", blocks, numbers, ["exec_core.profile", "exec_core.stats", "exec_core.score",
                                                         "attack-path engine", "exec_core.actions"])


# ── 6. Critical risks ────────────────────────────────────────────────────────────────────────────────────────────


def _critical_risks(score: Dict[str, Any], titles: Dict[str, str]) -> Dict[str, Any]:
    comps = [c for c in score.get("components") or [] if isinstance(c, dict)]
    comps = sorted(comps, key=lambda c: (-float(c.get("class_penalty") or 0), str(c.get("weakness_class"))))
    rows, links = [], []
    for c in comps[:10]:
        units = [u for u in c.get("units") or [] if isinstance(u, dict)]
        head = max(units, key=lambda u: float(u.get("penalty") or 0)) if units else {}
        fids = sorted({f for u in units for f in u.get("finding_ids") or []})
        hid = head.get("head_finding_id")
        rows.append([text(c.get("weakness_class")).replace("_", " "), _sev_label(head.get("severity")),
                     _proof_label(head.get("proof")), str(len(fids)),
                     str(sum(_n(u.get("distinct_weaknesses")) for u in units)),
                     text(titles.get(hid) or hid or "", 120)])
        links.append(finding_anchor(hid) if hid else None)
    blocks: List[Dict[str, Any]] = [{"type": "paragraph", "text": (
        "Weakness classes ordered by their weight in the Cyber Score (severity reported by the agent, proof on file, "
        "distinct weaknesses). The worst finding of each class is named; every finding is in Detailed findings.")}]
    blocks.append({"type": "paragraph", "text": f"Weakness classes with an open finding in the rating: {len(comps)}."})
    if rows:
        blocks.append({"type": "table", "id": "critical-risks", "columns": ["Weakness class", "Worst severity", "Proof",
                                                                          "Findings", "Distinct weaknesses", "Worst finding"],
                       "rows": rows, "row_links": links, "source": "exec_core.score components"})
        if len(comps) > 10:
            blocks.append({"type": "paragraph", "text": f"{len(comps) - 10} further weakness classes are listed in the "
                                                        "rating breakdown of the API."})
    else:
        blocks.append({"type": "paragraph", "text": "No open finding weighs in the rating of this campaign."})
    ev = score.get("evidence_summary") or {}
    tc = ev.get("to_confirm") or []
    if tc:
        blocks.append({"type": "paragraph", "text": f"Findings reported without enough proof, listed as to confirm: "
                                                    f"{len(tc)}."})
    numbers = {"weakness_classes": _num(len(comps), "exec_core.score"), "to_confirm": _num(len(tc), "exec_core.score")}
    return _section("critical_risks", blocks, numbers, ["exec_core.score"])


# ── 7. Framework technical assessment ────────────────────────────────────────────────────────────────────────────


def _framework_assessment(assessment: Optional[Dict[str, Any]], annex: Dict[str, Any]) -> Dict[str, Any]:
    if not assessment:
        blocks: List[Dict[str, Any]] = [{"type": "note", "text": "The framework technical assessment is not available "
                                                                 "for this campaign."}]
        return _section("framework_assessment", blocks, {}, [])
    states = list(_fa.STATES)
    blocks = [{"type": "note", "text": text(assessment.get("reading") or _fa.READING)}]
    rows = []
    numbers: Dict[str, Any] = {}
    for fw in assessment.get("frameworks") or []:
        c = fw.get("counts") or {}
        app = fw.get("applicability") or {}
        rows.append([text(fw.get("label")), text(app.get("label") or _fa.APPLICABILITY_LABEL.get(app.get("status"), "")),
                     *[str(_n(c.get(s))) for s in states]])
        for s in states:
            numbers[f"{fw.get('framework')}_{s}"] = _num(_n(c.get(s)), "exec_core.frameworks_assess")
    blocks.append({"type": "table", "id": "framework-states", "columns": ["Framework", "Applicability",
                                                                        *[_fa.STATE_LABEL[s] for s in states]],
                   "rows": rows, "source": "exec_core.frameworks_assess"})
    blocks.append({"type": "paragraph", "text": text(_fa.summary_line(assessment))})
    for fw in assessment.get("frameworks") or []:
        ctrl_rows, links = [], []
        for ct in fw.get("controls") or []:
            if ct.get("state") == "not_technically_assessable":
                continue
            fids = ct.get("finding_ids") or []
            ctrl_rows.append([text(ct.get("control_id")), text(ct.get("state_label") or _fa.STATE_LABEL.get(ct.get("state"), "")),
                              str(len(fids)), text(ct.get("why") or ct.get("text"), 200)])
            links.append(finding_anchor(fids[0]) if fids else None)
        nta = sum(1 for ct in fw.get("controls") or [] if ct.get("state") == "not_technically_assessable")
        sub = [{"type": "paragraph", "text": text((fw.get("applicability") or {}).get("text"))}]
        if ctrl_rows:
            sub.append({"type": "table", "id": f"controls-{fw.get('framework')}",
                        "columns": ["Control", "State", "Findings", "What a test observes / why"],
                        "rows": ctrl_rows, "row_links": links, "source": "exec_core.frameworks_assess"})
        if nta:
            sub.append({"type": "paragraph", "text": f"{_plural(nta, 'control')} not assessable by a technical test "
                                                     "(organisational or process measures) are not listed."})
        lim = [text(x) for x in fw.get("limitations") or []]
        if lim:
            sub.append({"type": "list", "items": lim})
        src = fw.get("source") or {}
        if src.get("reference"):
            sub.append({"type": "paragraph", "text": "Source: " + text(src.get("reference"))
                        + (f" ({text(src.get('url'))})" if src.get("url") else "")})
        blocks.append({"type": "subsection", "id": f"framework-{fw.get('framework')}", "title": text(fw.get("label")),
                       "blocks": sub})
    if annex.get("frameworks"):
        blocks.append({"type": "subsection", "id": "technique-mappings",
                       "title": "Technique and reference mappings (ATT&CK, ATLAS, ISO references, IEC 62443-3-3, EBIOS RM)",
                       "blocks": [{"type": "markdown", "source": "report_annex.frameworks_section",
                                   "markdown": annex["frameworks"]}]})
    return _section("framework_assessment", blocks, numbers, ["exec_core.frameworks_assess",
                                                              *(["report_annex.frameworks_section"] if annex.get("frameworks") else [])])


# ── 8. Resilience ────────────────────────────────────────────────────────────────────────────────────────────────


def _resilience(profile: Optional[Dict[str, Any]], assessment: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    rows = _field_rows(profile, ("criticality", "availability_requirement", "rto", "rpo", "sla"))
    declared = sum(1 for r in rows if r[1] != "Unknown")
    blocks: List[Dict[str, Any]] = [
        {"type": "note", "text": RESILIENCE_NOTE},
        {"type": "table", "id": "resilience-declared", "columns": ["Declared figure", "Value (declared, not assessed)",
                                                                  "Provenance"],
         "rows": rows, "source": "exec_core.profile"}]
    avail = []
    for fw in (assessment or {}).get("frameworks") or []:
        for ct in fw.get("controls") or []:
            if "availability" in (ct.get("classes") or []):
                avail.append([text(fw.get("label")), text(ct.get("control_id")), text(ct.get("state_label"))])
    if avail:
        blocks.append({"type": "table", "id": "availability-controls", "columns": ["Framework", "Control", "State"],
                       "rows": avail, "source": "exec_core.frameworks_assess"})
    numbers = {"declared_figures": _num(declared, "exec_core.profile")}
    return _section("resilience", blocks, numbers, ["exec_core.profile", "exec_core.frameworks_assess"])


# ── 9. Prioritized Treatment Plan ────────────────────────────────────────────────────────────────────────────────


def _declared(d: Any) -> str:
    if not isinstance(d, dict):
        return "unknown"
    v = d.get("value")
    if v in (None, "", "unknown"):
        return "unknown"
    return text(v, 80) + (" (declared)" if d.get("provenance") else "")


def _treatment_plan(plan: Optional[Dict[str, Any]], titles: Dict[str, str], paths: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    if not plan:
        return _section("treatment_plan", [{"type": "note", "text": "The treatment plan is not available for this "
                                                                    "campaign."}], {"actions": _num(0, "exec_core.actions")},
                        ["exec_core.actions"], verification="unknown")
    actions = list(plan.get("actions") or [])
    summ = plan.get("summary") or {}
    blocks: List[Dict[str, Any]] = [
        {"type": "paragraph", "text": text(plan.get("definition"))},
        {"type": "paragraph", "text": text(plan.get("plain"))},
        {"type": "paragraph", "text": f"Order: {text(plan.get('basis_label'))}. {text(plan.get('basis_note'), 600)}".strip()},
        {"type": "note", "id": "verification-note",
         "text": text(plan.get("verification_note")) or "Verified statuses come only from a completed retest."},
    ]
    blocks.append({"type": "paragraph", "text": (f"Actions: {len(actions)} · findings covered: "
                                                 f"{_n(summ.get('findings_covered'))} of {_n(summ.get('open_findings'))} "
                                                 "open findings.")})
    by_status = [[k.replace("_", " "), str(_n(v))] for k, v in sorted((summ.get("by_status") or {}).items()) if _n(v)]
    if by_status:
        blocks.append({"type": "table", "id": "treatment-status", "columns": ["Status", "Actions"], "rows": by_status,
                       "source": "exec_core.actions"})
    rows, links = [], []
    for a in actions:
        rows.append([str(a.get("priority")), text(a.get("title"), 120), _sev_label(a.get("severity")),
                     str(len(a.get("finding_ids") or [])), str(len(a.get("related_attack_paths") or [])),
                     text(a.get("status_label") or a.get("status")), _declared(a.get("owner"))])
        links.append(action_anchor(a.get("action_id")))
    if rows:
        blocks.append({"type": "table", "id": "treatment-actions",
                       "columns": ["Priority", "Action", "Severity", "Findings", "Attack paths", "Status", "Owner"],
                       "rows": rows, "row_links": links, "source": "exec_core.actions"})
    else:
        blocks.append({"type": "paragraph", "text": "No open finding to treat in the tested scope."})
    for a in actions:
        imp = a.get("expected_impact") or {}
        fids = [str(f) for f in a.get("finding_ids") or []]
        rel = [str(p) for p in a.get("related_attack_paths") or []]
        verified = bool(a.get("status_verified"))
        rt = a.get("recommended_treatment") or {}
        facts = [
            {"label": "Priority", "value": str(a.get("priority"))
             + (f" (tie of {a.get('tie_size')})" if _n(a.get("tie_size")) > 1 else "")},
            {"label": "Objective", "value": text(a.get("explanation"), 600) or "-"},
            {"label": "Findings covered", "value": str(len(fids))},
            {"label": "Attack paths concerned", "value": str(len(rel))},
            {"label": "Expected impact", "value": text(imp.get("text")) or "-"},
            {"label": "Status", "value": text(a.get("status_text") or a.get("status_label") or a.get("status"))},
            {"label": "Owner", "value": _declared(a.get("owner"))},
            {"label": "Service interruption risk", "value": _declared(a.get("service_interruption_risk"))},
            {"label": "Treatment type", "value": text((a.get("treatment_type") or {}).get("label")) or "unknown"},
            {"label": "Verification required", "value": (
                "No: verified by a completed retest" if verified and a.get("status") == "verified_resolved"
                else "Yes: a completed retest or a new campaign must show the effect")},
        ]
        sub: List[Dict[str, Any]] = [{"type": "facts", "rows": facts, "source": "exec_core.actions"}]
        if fids:
            sub.append({"type": "list", "title": "Findings",
                        "items": [f"{f} · {text(titles.get(f) or f, 140)}" for f in fids[:_MAX_ITEMS]],
                        "links": [finding_anchor(f) for f in fids[:_MAX_ITEMS]]})
            if len(fids) > _MAX_ITEMS:
                sub.append({"type": "paragraph", "text": f"{len(fids) - _MAX_ITEMS} further findings are covered."})
        if rel:
            sub.append({"type": "list", "title": "Attack paths concerned",
                        "items": [text((paths.get(p) or {}).get("title") or p, 140) for p in rel[:_MAX_ITEMS]],
                        "links": [path_anchor(p) for p in rel[:_MAX_ITEMS]]})
        if rt.get("text"):
            sub.append({"type": "quote", "label": text(rt.get("label")) or "Recommended by the testing agent",
                        "text": text(rt.get("text"), 2000), "source": "testing_agent"})
        else:
            sub.append({"type": "paragraph", "text": "No remediation text was recorded by the testing agent for these findings."})
        blocks.append({"type": "subsection", "id": action_anchor(a.get("action_id")),
                       "title": f"{a.get('priority')}. {text(a.get('title'), 160)}", "blocks": sub})
    numbers = {"actions": _num(len(actions), "exec_core.actions"),
               "findings_covered": _num(_n(summ.get("findings_covered")), "exec_core.actions"),
               "open_findings": _num(_n(summ.get("open_findings")), "exec_core.actions")}
    by = summ.get("by_status") or {}
    for k in sorted(by):
        if _n(by.get(k)):
            numbers[f"status_{k}"] = _num(_n(by.get(k)), "exec_core.actions")
    return _section("treatment_plan", blocks, numbers, ["exec_core.actions"],
                    verification=text(plan.get("verification")) or "unknown")


# ── 10. Attack paths ─────────────────────────────────────────────────────────────────────────────────────────────


def path_kind(p: Dict[str, Any]) -> str:
    """Legend kind of a path: a hypothesis (flag) or anything not observed is a Possible Attack Path."""
    if p.get("hypothesis"):
        return "possible"
    return _legend.path_kind(p.get("provenance"))


_SAFE_LABEL = re.compile(r"[^A-Za-z0-9 .,:/_+@&'=()\-À-ſ«»·→]")


def mermaid_label(value: Any, limit: int = 46) -> str:
    s = re.sub(r"\s+", " ", _SAFE_LABEL.sub(" ", str(value or "")).replace("%", " ")).strip()
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s or "unnamed"


def _path_figure(paths: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    seen = set()
    for p in paths:
        kind = path_kind(p)
        labels = {s.get("node_id"): s.get("node_label") for s in p.get("steps") or [] if isinstance(s, dict) and s.get("node_id")}
        for end in ("entry", "objective"):
            e = p.get(end) or {}
            if e.get("node_id"):
                labels.setdefault(e.get("node_id"), e.get("label"))
        es = [e for e in p.get("edges") or [] if isinstance(e, dict)]
        if not es:
            chain = [n for n in p.get("node_ids") or [] if n]
            es = [{"from": a, "to": b} for a, b in zip(chain, chain[1:])]
        for e in es:
            a, b = e.get("from"), e.get("to")
            if not a or not b or (a, b, kind) in seen:
                continue
            seen.add((a, b, kind))
            for nid in (a, b):
                if nid not in nodes:
                    nodes[nid] = {"id": f"n{len(nodes)}", "label": mermaid_label(labels.get(nid) or nid)}
            tech = (e.get("technique") or {}).get("id") if isinstance(e.get("technique"), dict) else None
            edges.append({"from": nodes[a]["id"], "to": nodes[b]["id"], "kind": kind,
                          "label": mermaid_label(("evidence-backed" if kind == "evidence_backed" else "possible")
                                                 + (" · " + str(tech) if tech else ""))})
    if not edges:
        return None
    lines = ["%% figure: attack-paths", "flowchart LR"]
    lines += [f'  {n["id"]}["{n["label"]}"]' for n in nodes.values()]
    for e in edges:
        arrow = "==>" if e["kind"] == "evidence_backed" else "-.->"
        lines.append(f'  {e["from"]} {arrow}|"{e["label"]}"| {e["to"]}')
    return {"type": "figure", "figure_id": "attack-paths", "format": "mermaid", "mermaid": "\n".join(lines),
            "nodes": list(nodes.values()), "edges": edges,
            "caption": ("Thick arrows: steps of an Evidence-Backed Attack Path. Dotted arrows: steps of a Possible "
                        "Attack Path (a hypothesis, not observed).")}


def _attack_paths(ap: Optional[Dict[str, Any]], titles: Dict[str, str], annex: Dict[str, Any]) -> Dict[str, Any]:
    paths = [p for p in (ap or {}).get("paths") or [] if isinstance(p, dict)]
    counts = {"evidence_backed": 0, "possible": 0}
    for p in paths:
        counts[path_kind(p)] += 1
    interrupted = sum(1 for p in paths if p.get("status") == "interrupted_by_retest")
    leg = _legend.PATH_KIND
    blocks: List[Dict[str, Any]] = [
        {"type": "paragraph", "text": (f"{_plural(counts['evidence_backed'], 'Evidence-Backed Attack Path')} · "
                                       f"{_plural(counts['possible'], 'Possible Attack Path')}"
                                       + (f" · {interrupted} interrupted by a retest" if interrupted else "") + ".")},
        {"type": "list", "items": [f"{leg['evidence_backed']['label']}: {leg['evidence_backed']['meaning']}",
                                   f"{leg['possible']['label']}: {leg['possible']['meaning']}"]},
        {"type": "note", "text": "Attack paths are not part of the Cyber Score; they are shown beside it with their "
                                 "evidence status."},
    ]
    if (ap or {}).get("note"):
        blocks.append({"type": "paragraph", "text": text(ap.get("note"), 600)})
    fig = _path_figure(paths)
    if fig:
        blocks.append(fig)
    for kind in ("evidence_backed", "possible"):
        rows_p = [p for p in paths if path_kind(p) == kind]
        if not rows_p:
            continue
        rows, links = [], []
        for p in rows_p:
            rows.append([text(p.get("title"), 120), text((p.get("entry") or {}).get("label"), 60) or "-",
                         text((p.get("objective") or {}).get("label"), 60) or "-", text(p.get("criticality")) or "-",
                         str(len(p.get("finding_ids") or []))])
            links.append(path_anchor(p.get("id")))
        sub: List[Dict[str, Any]] = [{"type": "table", "id": f"paths-{kind}", "columns": ["Path", "Entry", "Objective",
                                                                                        "Criticality", "Findings"],
                                      "rows": rows, "row_links": links, "source": "attack-path engine"}]
        for p in rows_p:
            steps = [s for s in p.get("steps") or [] if isinstance(s, dict)]
            srows = []
            for s in steps:
                fids = [f.get("id") for f in s.get("findings") or [] if isinstance(f, dict) and f.get("id")]
                if not fids and s.get("finding_id"):
                    fids = [s.get("finding_id")]
                tech = s.get("technique") if isinstance(s.get("technique"), dict) else {}
                srows.append([str(s.get("n") or ""), text(s.get("node_label"), 80) or "-", text(s.get("plain"), 160) or "-",
                              text(tech.get("id")) or "-", text(s.get("proof")) or "-",
                              ", ".join(text(titles.get(f) or f, 80) for f in fids) or "-"])
            psub: List[Dict[str, Any]] = [{"type": "paragraph", "text": (
                f"{leg[kind]['label']} · provenance {text(p.get('provenance')) or 'unknown'}"
                + (" · interrupted by a retest" if p.get("status") == "interrupted_by_retest" else ""))}]
            if p.get("note"):
                psub.append({"type": "paragraph", "text": text(p.get("note"), 400)})
            if srows:
                psub.append({"type": "table", "id": f"steps-{p.get('id')}", "columns": ["Step", "Asset", "What happens",
                                                                                      "Technique", "Proof", "Findings"],
                             "rows": srows, "source": "attack-path engine"})
            sub.append({"type": "subsection", "id": path_anchor(p.get("id")), "title": text(p.get("title"), 160),
                        "blocks": psub})
        blocks.append({"type": "subsection", "id": f"paths-{kind.replace('_', '-')}",
                       "title": leg[kind]["label"] + "s", "blocks": sub})
    if not paths:
        blocks.append({"type": "paragraph", "text": "No attack path is recorded for this campaign."})
    if annex.get("attack_chains"):
        blocks.append({"type": "subsection", "id": "attack-chains", "title": "Attack chains declared by the agents",
                       "blocks": [{"type": "markdown", "source": "attack_chains.render_report_section",
                                   "markdown": annex["attack_chains"]}]})
    if annex.get("declared_links"):
        blocks.append({"type": "subsection", "id": "declared-links", "title": "Links declared by the agents",
                       "blocks": [{"type": "markdown", "source": "report_annex_local.declared_links_markdown",
                                   "markdown": annex["declared_links"]}]})
    numbers = {"evidence_backed_paths": _num(counts["evidence_backed"], "attack-path engine"),
               "possible_paths": _num(counts["possible"], "attack-path engine")}
    return _section("attack_paths", blocks, numbers, ["attack-path engine", "exec_core.legend"],
                    path_counts=counts)


# ── 11. Detailed findings ────────────────────────────────────────────────────────────────────────────────────────


def _cvss_text(c: Dict[str, Any]) -> Tuple[str, str]:
    """(table cell, sheet value): the score the server recomputed from the vector; the agent's value as « reported »."""
    sc, rep, st = c.get("score"), c.get("reported"), c.get("status")
    if isinstance(sc, (int, float)):
        cell = f"{sc:.1f}"
        if st == "mismatch" and isinstance(rep, (int, float)):
            return f"{cell} (reported {rep:.1f})", f"{cell} (computed from the vector; reported by the agent: {rep:.1f})"
        return cell, f"{cell} (computed from the vector)"
    if isinstance(rep, (int, float)):
        return f"{rep:.1f} (reported)", f"{rep:.1f} (reported by the agent; no valid vector)"
    return "N/A", "N/A"


def _evidence_of(v: Dict[str, Any]) -> Dict[str, Any]:
    ev = v.get("evidence") if isinstance(v.get("evidence"), dict) else {}
    out: Dict[str, Any] = {}
    if ev.get("withheld"):
        return {"withheld": True}
    req = text(ev.get("raw_request") or ev.get("request"))
    resp = text(ev.get("raw_response") or ev.get("response"))
    cmds = [text(c, _LINE_LIMIT) for c in (ev.get("commands") or [])[:_MAX_ITEMS] if c] if isinstance(ev.get("commands"), list) else []
    logs = [text(c, _LINE_LIMIT) for c in (ev.get("logs") or [])[:_MAX_ITEMS] if c] if isinstance(ev.get("logs"), list) else []
    if req:
        out["raw_request"] = req[:_EVIDENCE_LIMIT]
    if resp:
        out["raw_response"] = resp[:_EVIDENCE_LIMIT]
    if cmds:
        out["commands"] = cmds
    if logs:
        out["logs"] = logs
    return out


def _detailed_findings(listed: List[Dict[str, Any]], cvss: Dict[str, Dict[str, Any]],
                       finding_actions: Dict[str, str], finding_controls: Dict[str, List[str]],
                       stats: Dict[str, Any]) -> Dict[str, Any]:
    rows, links, sheets = [], [], []
    for i, v in enumerate(listed, 1):
        fid = str(v.get("id") or f"finding-{i}")
        c = cvss.get(fid) or {}
        cell, sheet_cvss = _cvss_text(c)
        sev = identity.severity_of(v)
        rows.append([str(i), fid, text(v.get("title"), 90), _sev_label(sev), cell, _proof_label(identity.proof_of(v)),
                     text(v.get("endpoint"), 60) or "-"])
        links.append(finding_anchor(fid))
        facts = [
            {"label": "ID", "value": fid},
            {"label": "Severity", "value": _sev_label(sev)},
            {"label": "Proof", "value": _proof_label(identity.proof_of(v))},
            {"label": "CVSS 3.1", "value": sheet_cvss},
            {"label": "CVSS vector", "value": text(v.get("cvss_vector")) or "N/A"},
            {"label": "Category", "value": text(v.get("category")) or "N/A"},
            {"label": "Weakness class", "value": identity.weakness_class(v).replace("_", " ")},
            {"label": "Endpoint", "value": text(v.get("endpoint"), 300) or "N/A"},
        ]
        for lab, key in (("Component", "plugin_or_component"), ("MITRE ATT&CK", "mitre_attack_id"),
                         ("ISO 27001 (cited by the agent)", "iso27001_control"), ("CWE", "cwe"), ("CVE", "cve")):
            if v.get(key):
                val = text(v.get(key), 200)
                if key == "mitre_attack_id" and v.get("mitre_attack_name"):
                    val += f" {text(v.get('mitre_attack_name'), 120)}"
                facts.append({"label": lab, "value": val})
        facts.append({"label": "Discovered by", "value": text(v.get("discovered_by_agent")) or "N/A"})
        if v.get("discovered_at"):
            facts.append({"label": "Discovered at", "value": text(v.get("discovered_at"))})
        if identity.is_closed(v):
            facts.append({"label": "Declared closed", "value": "Declared closed during the campaign (not verified)"})
        ev = v.get("evidence") if isinstance(v.get("evidence"), dict) else {}
        sheet = {"type": "finding", "id": finding_anchor(fid), "finding_id": fid, "title": text(v.get("title"), 300),
                 "severity": sev, "proof": identity.proof_of(v),
                 "cvss": {"computed": c.get("score"), "reported": c.get("reported"), "status": c.get("status") or "none",
                          "vector": text(v.get("cvss_vector")) or None},
                 "facts": facts,
                 "description": text(v.get("description"), 4000) or None,
                 "analysis": text(ev.get("explanation"), 4000) or None,
                 "remediation": text(v.get("remediation"), 4000) or None,
                 "evidence": _evidence_of(v),
                 "action": finding_actions.get(fid), "controls": finding_controls.get(fid, [])}
        sheets.append(sheet)
    blocks: List[Dict[str, Any]] = [{"type": "note", "text": AGENT_TEXT_NOTE}]
    if rows:
        blocks.append({"type": "table", "id": "findings-table", "columns": ["#", "ID", "Title", "Severity", "CVSS",
                                                                          "Proof", "Endpoint"],
                       "rows": rows, "row_links": links, "source": "findings store + cvss31 recompute"})
        blocks.extend(sheets)
    else:
        blocks.append({"type": "paragraph", "text": "No finding is listed for this campaign."})
    ex = stats.get("excluded") or {}
    if _n(ex.get("quarantined")):
        blocks.append({"type": "note", "text": f"Held for review: {_n(ex.get('quarantined'))} finding(s) are not "
                                               "included in this report nor in its counts: their text still holds "
                                               "privacy placeholders the platform could not restore safely. An operator "
                                               "must review them before they are reported."})
    if _n(ex.get("false_positive")):
        blocks.append({"type": "note", "text": f"Not listed: {_n(ex.get('false_positive'))} finding(s) marked false "
                                               "positive are not included in this report nor in its counts."})
    mism = sum(1 for v in listed if (cvss.get(str(v.get("id"))) or {}).get("status") == "mismatch")
    numbers = {"findings_listed": _num(len(listed), "findings store"),
               "cvss_mismatch": _num(mism, "cvss31 recompute")}
    return _section("detailed_findings", blocks, numbers, ["findings store", "cvss31 recompute", "exec_core.identity"])


# ── 12. Evidence and methodology ─────────────────────────────────────────────────────────────────────────────────


def _evidence_methodology(stats: Dict[str, Any], listed: List[Dict[str, Any]], privacy_md: str,
                          masking: str) -> Dict[str, Any]:
    with_ev = sum(1 for v in listed if _evidence_of(v) and not _evidence_of(v).get("withheld"))
    sev_rows = [["Critical", "9.0 to 10.0", "Direct compromise of the system or its data."],
                ["High", "7.0 to 8.9", "Significant compromise likely."],
                ["Medium", "4.0 to 6.9", "Exploitable under conditions or with limited impact."],
                ["Low", "0.1 to 3.9", "Minor weakness."],
                ["Informational", "0.0", "Observation without direct security impact."]]
    proof_rows = [[v["label"], v["meaning"]] for v in _legend.EVIDENCE_STATUS.values()]
    path_rows = [[v["label"], v["meaning"]] for v in _legend.PATH_KIND.values()]
    blocks: List[Dict[str, Any]] = [
        {"type": "paragraph", "text": (
            "Every count of this report comes from one stats function: findings held for privacy review and findings "
            "marked false positive are counted nowhere; informational findings are counted but weigh nothing in the "
            "rating. The severity shown is the one reported by the agent (aliases normalised); the CVSS 3.1 score shown "
            "is recomputed by the server from the vector, with the agent's value marked « reported » when it differs.")},
        {"type": "subsection", "id": "severity-scale", "title": "Severity scale", "blocks": [
            {"type": "table", "id": "severity-scale", "columns": ["Severity", "CVSS 3.1 base score", "Meaning"],
             "rows": sev_rows, "source": "exec_core.legend + CVSS 3.1 specification"}]},
        {"type": "subsection", "id": "proof-levels", "title": "Proof levels", "blocks": [
            {"type": "table", "id": "proof-levels", "columns": ["Level", "Meaning"], "rows": proof_rows,
             "source": "exec_core.legend"}]},
        {"type": "subsection", "id": "path-kinds", "title": "Attack path vocabulary", "blocks": [
            {"type": "table", "id": "path-kinds", "columns": ["Kind", "Meaning"], "rows": path_rows,
             "source": "exec_core.legend"}]},
        {"type": "paragraph", "text": f"Findings with evidence on file in this report: {with_ev} of {len(listed)}."},
    ]
    masking_block = {"type": "paragraph", "id": "masking-note", "text": masking}
    blocks.append(masking_block)
    privacy = None
    if privacy_md:
        privacy = {"type": "subsection", "id": "privacy-placeholders", "title": "Privacy placeholders in evidence",
                   "blocks": [{"type": "markdown", "source": "live_push._privacy_legend_section", "markdown": privacy_md}]}
        blocks.append(privacy)
    numbers = {"findings_with_evidence": _num(with_ev, "findings store"),
               "findings_listed": _num(len(listed), "findings store"),
               "findings_counted": _num(_n(stats.get("total_findings")), "exec_core.stats")}
    return _section("evidence_methodology", blocks, numbers, ["exec_core.legend", "exec_core.stats", "findings store"],
                    privacy=bool(privacy_md), masking=masking)


# ── 13. Limitations ──────────────────────────────────────────────────────────────────────────────────────────────


def _limitations(score: Dict[str, Any], assessment: Optional[Dict[str, Any]], campaign: Dict[str, Any]) -> Dict[str, Any]:
    items: List[str] = []
    st = str(campaign.get("status") or "").lower()
    if st and st not in ("completed", "complete", "done", "finished"):
        items.append(f"The campaign did not complete (status: {text(st)}): the findings cover what was tested before it "
                     "ended.")
    for r in score.get("status_reasons") or []:
        if isinstance(r, dict) and r.get("sentence"):
            items.append(text(r["sentence"]))
    items += [text(x) for x in score.get("limitations") or [] if x]
    items += [text(x) for x in _fa.COMMON_LIMITS]
    fcov = (assessment or {}).get("coverage") or {}
    if fcov and not fcov.get("coverage_ok") and fcov.get("sentence"):
        items.append("Framework assessment: " + text(fcov.get("sentence")))
    items += REPORT_LIMITS
    seen, out = set(), []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return _section("limitations", [{"type": "list", "items": out}], {},
                    ["exec_core.score", "exec_core.frameworks_assess", "report model"])


# ── assembly ─────────────────────────────────────────────────────────────────────────────────────────────────────


def build(inp: Dict[str, Any]) -> Dict[str, Any]:
    """The report model of one campaign. ``inp`` (all precomputed by the edition's storage adapter):

    ``edition`` (pro | community), ``generated_at`` (server time, ISO), ``campaign`` (record), ``target`` (record or
    None), ``project`` (record or None), ``findings`` (stored findings, any status), ``cvss`` ({finding id:
    cvss31.assess}), ``score`` (Cyber Score document), ``plan`` (treatment plan document), ``assessment`` (framework
    assessment), ``profile`` (profile view), ``attack_paths`` (attack-path document, provenance all, with steps),
    ``annex`` ({infrastructure, frameworks, declared_links}: Markdown from the report annex builders),
    ``privacy_legend`` (Markdown, Pro), ``masking`` (one sentence: how evidence is masked in this edition).
    """
    campaign = dict(inp.get("campaign") or {})
    findings = [v for v in inp.get("findings") or [] if isinstance(v, dict)]
    stats = _stats.compute_stats(findings)
    listed, _excl = _stats.split(findings)
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    cvss = {str(k): (v or {}) for k, v in (inp.get("cvss") or {}).items()}

    def _sort_key(v: Dict[str, Any]) -> Tuple[int, float, str]:
        c = cvss.get(str(v.get("id"))) or {}
        sc = c.get("score") if isinstance(c.get("score"), (int, float)) else (c.get("reported") or 0)
        return (order.get(identity.severity_of(v), 9), -float(sc or 0), str(v.get("id") or ""))

    listed = sorted(listed, key=_sort_key)
    titles = {str(v.get("id")): text(v.get("title"), 200) for v in findings if v.get("id")}
    score = inp.get("score") or {"score_status": "not_rated", "status_reasons": [], "limitations": []}
    plan = inp.get("plan")
    assessment = inp.get("assessment")
    profile = inp.get("profile")
    ap = inp.get("attack_paths") or {}
    annex = {k: str(v) for k, v in (inp.get("annex") or {}).items() if v}
    target = inp.get("target") or {}
    host = text(target.get("host") or target.get("name") or campaign.get("target_id")) or "unknown"
    paths = {str(p.get("id")): p for p in ap.get("paths") or [] if isinstance(p, dict) and p.get("id")}
    finding_actions: Dict[str, str] = {}
    for a in (plan or {}).get("actions") or []:
        for f in a.get("finding_ids") or []:
            finding_actions.setdefault(str(f), action_anchor(a.get("action_id")))
    finding_controls: Dict[str, List[str]] = {}
    for fid, nav in (((assessment or {}).get("navigation") or {}).get("findings") or {}).items():
        finding_controls[str(fid)] = [str(k) for k in (nav or {}).get("control_keys") or []]

    attack = _attack_paths(ap, titles, annex)
    path_counts = attack.pop("path_counts")
    sections = [
        _cyber_score(score),
        _method_coverage(campaign, score, stats, assessment, annex, host),
        _executive_summary(campaign, stats, score, plan, assessment, path_counts),
        _application_profile(profile),
        _business_impact(profile, stats, score, path_counts, plan),
        _critical_risks(score, titles),
        _framework_assessment(assessment, annex),
        _resilience(profile, assessment),
        _treatment_plan(plan, titles, paths),
        attack,
        _detailed_findings(listed, cvss, finding_actions, finding_controls, stats),
        _evidence_methodology(stats, listed, str(inp.get("privacy_legend") or ""),
                              text(inp.get("masking")) or "Evidence is reproduced as stored."),
        _limitations(score, assessment, campaign),
    ]
    status = str(campaign.get("status") or "").lower()
    return {
        "schema_version": SCHEMA_VERSION,
        "language": LANGUAGE,
        "edition": text(inp.get("edition")) or "unknown",
        "edition_specific": list(EDITION_SPECIFIC),
        "generated_at": text(inp.get("generated_at")) or None,
        "campaign": {"id": text(campaign.get("id")), "status": status or "unknown",
                     "target": host, "project_id": text(campaign.get("project_id")) or None,
                     "project_name": text((inp.get("project") or {}).get("name")) or None,
                     "date": text(campaign.get("date")) or None,
                     "methodology": text(campaign.get("methodology")) or None},
        "classification": "CONFIDENTIAL",
        "title": f"Security Assessment Report — {host}",
        "counts": {k: _n(stats.get(k)) for k in ("total_findings", *SEV_ORDER, *PROOF_ORDER)},
        "section_order": list(SECTION_IDS),
        "sections": sections,
        "legend": _legend.legend(),
    }


def numbers_of(model: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """{section id: {name: value}} — what the parity tests compare with the renderings."""
    return {s["id"]: {k: v.get("value") for k, v in (s.get("numbers") or {}).items()} for s in model.get("sections") or []}
