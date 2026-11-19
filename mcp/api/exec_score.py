"""Thin storage adapter of exec_core: loads campaigns and findings from the edition's JSON store and calls the pure
core. No computation here; same file in Community and Pro (both stores expose the same loaders)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from api import json_storage
from api.exec_core import legend as _legend, project as _project, score as _score


def campaign_bundle(campaign_id: str) -> Optional[Dict[str, Any]]:
    camp = json_storage.load_campaign(campaign_id)
    if not camp:
        return None
    return {"campaign": camp, "findings": json_storage.load_vulnerabilities(campaign_id) or []}


def target_bundles(target_id: str) -> List[Dict[str, Any]]:
    out = []
    for c in json_storage.load_campaigns():
        if c.get("target_id") == target_id and not c.get("is_subagent") and c.get("id"):
            out.append({"campaign": c, "findings": json_storage.load_vulnerabilities(c["id"]) or []})
    return sorted(out, key=lambda b: (str(b["campaign"].get("date") or ""), str(b["campaign"].get("id"))))


def campaign_score(campaign_id: str) -> Optional[Dict[str, Any]]:
    """Score document of one campaign, with a trend against the previous rated full campaign of its target."""
    bundle = campaign_bundle(campaign_id)
    if bundle is None:
        return None
    camp = bundle["campaign"]
    previous = None
    tid = camp.get("target_id")
    if tid:
        date = str(camp.get("date") or "")
        earlier = [b for b in target_bundles(tid)
                   if b["campaign"].get("id") != campaign_id and str(b["campaign"].get("date") or "") < date]
        for b in reversed(earlier):
            doc = _score.cyber_score(b)
            if _score.comparable(doc):
                previous = doc
                break
    return _score.cyber_score(bundle, previous=previous)


def target_score(target_id: str) -> Dict[str, Any]:
    return _project.reference_score(target_bundles(target_id))


def project_score(project_id: str) -> Optional[Dict[str, Any]]:
    """One project = one target: the reference score of the project's target."""
    proj = json_storage.load_project(project_id)
    if not proj:
        return None
    tid = proj.get("target_id")
    if not tid:
        tids = sorted({c.get("target_id") for c in json_storage.load_campaigns()
                       if c.get("project_id") == project_id and c.get("target_id")})
        tid = tids[0] if len(tids) == 1 else None
    doc = target_score(tid) if tid else _project.reference_score([])
    return {**doc, "project_id": project_id}


def legend() -> Dict[str, Any]:
    return _legend.legend()
