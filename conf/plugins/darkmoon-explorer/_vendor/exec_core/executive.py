"""The executive block (review H8) of a campaign and of a project, both editions.

One block = the grade or « Not rated » / « Limited test », one coverage sentence, the first three actions of the
Prioritized Treatment Plan, one collapsed regulatory line; the details stay on their own views. This module selects
and labels parts of documents exec_core already computed (``score.cyber_score``, ``project.reference_score``,
``actions.build_plan``, ``frameworks_assess.assess``, attack-path kinds of ``legend.path_kind_of``): it computes no
score, no order and no percentage. The edition adapters (Pro ``exec_presentation``, Community ``executive_local``)
load the documents and add their own links.

Pure Python standard library, no I/O (``exec_core`` rule).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import legend as _legend

EXECUTIVE_VERSION = "darkmoon-executive/1"
PROJECT_EXECUTIVE_VERSION = "darkmoon-project-executive/1"
TOP_ACTIONS = 3


def score_block(doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The score part of the block: number/grade or none, with the shared legend's words (never recomputed)."""
    doc = doc or {}
    st = str(doc.get("score_status") or "not_rated")
    meta = _legend.SCORE_STATUS.get(st, _legend.SCORE_STATUS["not_rated"])
    grade = doc.get("grade")
    cov = doc.get("assessment_coverage") or {}
    return {
        "score": doc.get("score"),
        "grade": grade,
        "grade_meaning": _legend.GRADE.get(grade) if grade else None,
        "score_status": st,
        "status_label": meta["label"],
        "status_meaning": meta["meaning"],
        "status_reasons": [{"code": r.get("code"), "text": r.get("text")} for r in doc.get("status_reasons") or []
                           if isinstance(r, dict)],
        "caps_applied": [{"rule": c.get("rule"), "cap": c.get("cap")} for c in doc.get("caps_applied") or []
                         if isinstance(c, dict)],
        "assessed_at": doc.get("assessed_at"),
        "methodology_version": doc.get("methodology_version"),
        "coverage_sentence": cov.get("sentence"),
        "campaign_kind": cov.get("campaign_kind"),
        "trend": doc.get("trend"),
        "limitations": list(doc.get("limitations") or []),
    }


def action_row(a: Dict[str, Any]) -> Dict[str, Any]:
    imp = a.get("expected_impact") or {}
    return {
        "action_id": a.get("action_id"), "priority": a.get("priority"), "title": a.get("title"),
        "severity": a.get("severity"), "proof": a.get("proof"),
        "status": a.get("status"), "status_label": a.get("status_label"), "status_text": a.get("status_text"),
        "status_verified": bool(a.get("status_verified")),
        # the completed retest a retest wording comes from (« Not reproduced at retest » only with it)
        "last_retest": a.get("last_retest"),
        "findings_covered": imp.get("findings_covered", len(a.get("finding_ids") or [])),
        "attack_paths_interrupted": imp.get("attack_paths_interrupted"),
        "impact_text": imp.get("text"),
    }


def plan_summary(plan: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not plan:
        return None
    actions = [a for a in plan.get("actions") or [] if isinstance(a, dict)]
    by_status: Dict[str, int] = {}
    for a in actions:
        by_status[str(a.get("status"))] = by_status.get(str(a.get("status")), 0) + 1
    labels = {s.get("value"): s.get("label") for s in plan.get("statuses") or [] if isinstance(s, dict)}
    return {
        "label": plan.get("label"), "definition": plan.get("definition"), "plain": plan.get("plain"),
        "actions_total": len(actions),
        "by_status": [{"status": k, "label": labels.get(k, k), "count": v} for k, v in by_status.items()],
        "top_actions": [action_row(a) for a in actions[:TOP_ACTIONS]],
        "verification": plan.get("verification"),
    }


def frameworks_summary(fa: Optional[Dict[str, Any]], summary_line: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not fa:
        return None
    return {
        "summary_line": summary_line if summary_line is not None else fa.get("summary_line"),
        "reading": fa.get("reading"),
        "coverage_ok": bool((fa.get("coverage") or {}).get("coverage_ok")),
        "frameworks": [{"framework": f.get("framework"), "label": f.get("label"),
                        "applicability": (f.get("applicability") or {}).get("status"),
                        "applicability_label": (f.get("applicability") or {}).get("label"),
                        "counts": f.get("counts") or {},
                        "findings": len(f.get("finding_ids") or []), "actions": len(f.get("action_ids") or [])}
                       for f in fa.get("frameworks") or [] if isinstance(f, dict)],
    }


def paths_summary(paths_doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(paths_doc, dict) or not isinstance(paths_doc.get("paths"), list):
        return None
    kinds = {"possible": 0, "evidence_backed": 0}
    for p in paths_doc["paths"]:
        if isinstance(p, dict):
            kinds[_legend.path_kind_of(p)] += 1
    return {"possible": kinds["possible"], "evidence_backed": kinds["evidence_backed"],
            "labels": {k: v["label"] for k, v in _legend.PATH_KIND.items()}}


def campaign_block(campaign: Dict[str, Any], score: Optional[Dict[str, Any]], plan: Optional[Dict[str, Any]],
                   assessment: Optional[Dict[str, Any]], paths_doc: Optional[Dict[str, Any]],
                   links: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The executive document of one campaign. A part that could not be built is ``None`` (the block says so)."""
    ev = (score or {}).get("evidence_summary") or {}
    return {
        "schema_version": EXECUTIVE_VERSION,
        "campaign_id": campaign.get("id"),
        "project_id": campaign.get("project_id"),
        "target_id": campaign.get("target_id"),
        "campaign_status": campaign.get("status"),
        "date": campaign.get("date"),
        "score": score_block(score),
        "evidence": {"by_severity": ev.get("by_severity") or {}, "by_proof": ev.get("by_proof") or {},
                     "counted_findings": ev.get("counted_findings"), "to_confirm": len(ev.get("to_confirm") or [])},
        "attack_paths": paths_summary(paths_doc),
        "treatment_plan": plan_summary(plan),
        "frameworks": frameworks_summary(assessment),
        "legend": _legend.legend(),
        "links": dict(links or {}),
    }


def latest_campaign(campaigns: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    xs = sorted([c for c in campaigns if isinstance(c, dict) and not c.get("is_subagent")],
                key=lambda c: (str(c.get("date") or ""), str(c.get("id") or "")))
    return xs[-1] if xs else None


def latest_row(latest: Optional[Dict[str, Any]], latest_score: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The latest campaign of the project with its own score status (it may differ from the reference: a retest, a
    short run, a running campaign are never the reference)."""
    if not latest:
        return None
    st = str((latest_score or {}).get("score_status") or "not_rated")
    meta = _legend.SCORE_STATUS.get(st, _legend.SCORE_STATUS["not_rated"])
    return {"campaign_id": latest.get("id"), "date": latest.get("date"), "status": latest.get("status"),
            "score_status": st, "status_label": meta["label"],
            "score": (latest_score or {}).get("score"), "grade": (latest_score or {}).get("grade")}


def plan_campaign_id(reference_id: Optional[str], latest: Optional[Dict[str, Any]]) -> Optional[str]:
    """Whose plan the project block shows: the reference campaign's, else the latest campaign unless it is running."""
    if reference_id:
        return reference_id
    if latest and str(latest.get("status") or "").lower() != "running":
        return latest.get("id")
    return None


def project_block(project: Dict[str, Any], reference: Optional[Dict[str, Any]], campaigns: List[Dict[str, Any]],
                  latest_score: Optional[Dict[str, Any]], plan: Optional[Dict[str, Any]],
                  plan_cid: Optional[str], links: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The executive document of one project: the score of its reference campaign (``project.reference_score``, no
    averaging), its date and coverage, the trend among comparable campaigns, the latest assessment, and the first
    actions of the plan of ``plan_cid``."""
    ref = reference or {}
    latest = latest_campaign(campaigns)
    ref_id = (ref.get("reference") or {}).get("campaign_id")
    by_id = {c.get("id"): c for c in campaigns if isinstance(c, dict)}
    st = str(ref.get("score_status") or "not_rated")
    meta = _legend.SCORE_STATUS.get(st, _legend.SCORE_STATUS["not_rated"])
    refc = ref.get("reference") or {}
    return {
        "schema_version": PROJECT_EXECUTIVE_VERSION,
        "project_id": project.get("id"),
        "name": project.get("name"),
        "score": {
            "score": ref.get("score"), "grade": ref.get("grade"),
            "grade_meaning": _legend.GRADE.get(ref.get("grade")) if ref.get("grade") else None,
            "score_status": st, "status_label": meta["label"], "status_meaning": meta["meaning"],
            "reason": ref.get("reason"),
            "assessed_at": refc.get("assessed_at"),
            "coverage_sentence": (refc.get("assessment_coverage") or {}).get("sentence"),
            "trend": ref.get("trend"),
            "limitations": list(ref.get("limitations") or []),
        },
        "reference_campaign_id": ref_id,
        "reference_campaign_date": (by_id.get(ref_id) or {}).get("date") if ref_id else None,
        "latest_campaign": latest_row(latest, latest_score),
        "campaigns_considered": ref.get("campaigns_considered") or [],
        "plan_campaign_id": plan_cid,
        "treatment_plan": plan_summary(plan),
        "links": dict(links or {}),
    }
