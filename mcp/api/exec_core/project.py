"""Project reference score: the score of the latest rated full campaign of the project's target.

No averaging, no aggregation: one project = one target, and its reference campaign is the most recent campaign whose
score status is ``rated`` and kind ``full``. Its date and coverage are carried with the number. The trend compares the
reference with the previous rated full campaign of the same target only; scope differences are listed.
Pure, no I/O: input = the bundles ``{"campaign", "findings"}`` of the target's campaigns.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import score as _score

PROJECT_VERSION = "darkmoon-project-score/1"


def _kind(c: Dict[str, Any]) -> str:
    sig = c.get("coverage_signals")
    return str(sig.get("campaign_kind") or "") if isinstance(sig, dict) else "full"   # legacy record: a campaign


def reference_campaign(campaigns: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The campaign open-weakness counts read: the target's last complete FULL campaign (a record without coverage
    signals predates campaign kinds and counts as full), else its last complete campaign, else its latest one.
    A retest or a short run never hides the findings of the last full assessment. Sub-agent records are ignored."""
    camps = sorted([c for c in campaigns or [] if isinstance(c, dict) and not c.get("is_subagent")],
                   key=lambda c: (str(c.get("date", "")), str(c.get("id", ""))))
    complete = [c for c in camps if str(c.get("status", "")).lower() in _score.COMPLETE]
    full = [c for c in complete if _kind(c) == "full"]
    return (full or complete or camps or [None])[-1]


def _date(bundle: Dict[str, Any]) -> str:
    c = bundle.get("campaign") or {}
    return str(c.get("date") or "")


def reference_score(bundles: List[Dict[str, Any]]) -> Dict[str, Any]:
    camps = [b for b in (bundles or []) if isinstance(b, dict) and isinstance(b.get("campaign"), dict)
             and not b["campaign"].get("is_subagent")]
    camps.sort(key=lambda b: (_date(b), str(b["campaign"].get("id") or "")))
    docs = [_score.cyber_score(b) for b in camps]
    considered = [{"campaign_id": d["campaign_id"], "date": _date(b), "score_status": d["score_status"],
                   "campaign_kind": (d["assessment_coverage"] or {}).get("campaign_kind"),
                   "reasons": [r["code"] for r in d["status_reasons"]]}
                  for b, d in zip(camps, docs)]
    rated = [d for d in docs if _score.comparable(d)]
    targets = sorted({str(b["campaign"].get("target_id") or "") for b in camps})
    out: Dict[str, Any] = {
        "schema": PROJECT_VERSION,
        "target_ids": targets,
        "campaigns_considered": considered,
        "reference": None,
        "trend": None,
    }
    if len(targets) > 1:
        out["limitations"] = ["The project spans several targets; the reference is chosen per target."]
    if not rated:
        out["score_status"] = "not_rated"
        out["score"] = None
        out["grade"] = None
        out["reason"] = "No rated full campaign for this target yet."
        return out
    ref = rated[-1]
    out.update({
        "score_status": "rated",
        "score": ref["score"],
        "grade": ref["grade"],
        "reference": {"campaign_id": ref["campaign_id"], "assessed_at": ref["assessed_at"],
                      "assessment_coverage": ref["assessment_coverage"]},
        "source_campaign_ids": [ref["campaign_id"]],
    })
    prev = [d for d in rated[:-1] if d.get("target_id") == ref.get("target_id")]
    if prev:
        out["trend"] = _score.trend_between(ref, prev[-1])
    return out
