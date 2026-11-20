"""Executive block, Darkmoon Community (read-only): the same documents as Pro's ``GET /campaigns/{id}/executive`` and
``GET /projects/{id}/executive``.

The block is ``exec_core.executive`` (shared with Pro); this module only loads the documents from the local store:
Cyber Score (``exec_score``, same file in both editions), Prioritized Treatment Plan (``treatment_local``: the owner's
own declarations file), framework technical assessment (``framework_local``), attack paths (``attack_paths_local``).
Nothing here writes; every part that cannot be built is ``None``. Masking is the caller's (the terminal explorer runs
the documents through the redaction engine, fail closed).
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from api import exec_score
from api.exec_core import executive as X
from api.json_storage import is_safe_id, load_campaign, load_campaigns, load_project

_log = logging.getLogger(__name__)

Filter = Optional[Callable[[Dict[str, Any]], Dict[str, Any]]]


def _plan(campaign_id: str, finding_filter: Filter) -> Optional[Dict[str, Any]]:
    try:
        from api.treatment_local import plan_doc
        return plan_doc(campaign_id, finding_filter=finding_filter)
    except Exception:  # noqa: BLE001 — a part that cannot be built is None, never invented
        _log.warning("executive: treatment plan unavailable", exc_info=True)
        return None


def campaign_doc(campaign_id: str, finding_filter: Filter = None) -> Optional[Dict[str, Any]]:
    """The executive document of ``campaign_id`` or None (malformed id / unknown campaign)."""
    if not is_safe_id(campaign_id):
        return None
    camp = load_campaign(campaign_id)
    if not camp:
        return None
    score = exec_score.campaign_score(campaign_id)
    plan = fa = paths = None
    if str(camp.get("status") or "").lower() != "running":   # the analysis exists once the run ends
        plan = _plan(campaign_id, finding_filter)
        try:
            from api.framework_local import assessment_doc
            fa = assessment_doc(campaign_id, finding_filter=finding_filter)
        except Exception:  # noqa: BLE001
            _log.warning("executive: framework assessment unavailable", exc_info=True)
        try:
            from api.attack_paths_local import attack_paths_doc
            paths = attack_paths_doc(campaign_id, "all", False, finding_filter=finding_filter)
        except Exception:  # noqa: BLE001
            _log.warning("executive: attack paths unavailable", exc_info=True)
    links = {"treatment_plan": f"plan {campaign_id}", "framework_assessment": f"frameworks {campaign_id}",
             "attack_paths": f"paths {campaign_id}", "report": f"report {campaign_id}",
             "profile": f"profile {camp['project_id']}" if camp.get("project_id") else None}
    return X.campaign_block({**camp, "id": campaign_id}, score, plan, fa, paths, links)


def project_doc(project_id: str, finding_filter: Filter = None) -> Optional[Dict[str, Any]]:
    """The executive document of ``project_id`` (reference campaign score, latest assessment, first actions)."""
    if not is_safe_id(project_id):
        return None
    proj = load_project(project_id)
    if not proj:
        return None
    ref = exec_score.project_score(project_id) or {}
    camps = [c for c in load_campaigns() if c.get("project_id") == project_id]
    latest = X.latest_campaign(camps)
    ref_id = (ref.get("reference") or {}).get("campaign_id")
    latest_score = exec_score.campaign_score(latest["id"]) if latest and latest.get("id") else None
    plan_cid = X.plan_campaign_id(ref_id, latest)
    plan = _plan(plan_cid, finding_filter) if plan_cid else None
    links = {"profile": f"profile {project_id}", "reference_campaign": f"executive {ref_id}" if ref_id else None}
    return X.project_block({**proj, "id": project_id}, ref, camps, latest_score, plan, plan_cid, links)
