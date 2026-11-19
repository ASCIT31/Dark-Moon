"""Framework technical assessment, Darkmoon Community (read-only).

The same exec_core document as Pro's ``GET /campaigns/{id}/framework-assessment``
(``exec_core.frameworks_assess.assess``), built from the local store: the campaign and its server-recorded coverage
signals, its findings and infrastructure, the actions of its Prioritized Treatment Plan and the project's profile
declared by the owner in ``profiles/<project_id>.json`` (``profile_local``). Nothing here writes.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from api.attack_paths_local import attack_paths_doc
from api.exec_core import actions as A
from api.exec_core import frameworks_assess as FA
from api.infrastructure_graph import build_infrastructure
from api.json_storage import is_safe_id, load_campaign
from api.profile_local import profile_view


def assessment_doc(campaign_id: str,
                   finding_filter: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """The assessment of ``campaign_id`` or None (malformed id / unknown campaign). ``finding_filter`` (the
    explorer's redaction) is applied to every finding before anything is derived from it."""
    if not is_safe_id(campaign_id):
        return None
    campaign = load_campaign(campaign_id)
    if not campaign:
        return None
    infra = build_infrastructure(campaign_id, campaign)
    vulns = [v for v in infra["vulnerabilities"] if isinstance(v, dict)]
    if finding_filter is not None:
        vulns = [finding_filter(v) for v in vulns]
    paths = attack_paths_doc(campaign_id, "all", False, finding_filter=finding_filter) or {}
    actions = A.build_actions(campaign_id, paths, vulns)
    prof = profile_view(campaign.get("project_id") or "") if campaign.get("project_id") else None
    doc = FA.assess({"campaign": campaign, "findings": vulns, "nodes": infra["nodes"],
                     "profile": prof[0] if prof else None,
                     "actions": [{"action_id": a["action_id"], "finding_ids": a["finding_ids"],
                                  "related_attack_paths": a["related_attack_paths"]} for a in actions]})
    doc["summary_line"] = FA.summary_line(doc)
    doc["profile_file"] = f"profiles/{campaign['project_id']}.json" if campaign.get("project_id") else None
    if prof and prof[1]:
        doc["profile_issues"] = prof[1]
    return doc
