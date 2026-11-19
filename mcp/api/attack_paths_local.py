"""
Attack paths of one campaign computed from the local store, without a web server.

Same document as Darkmoon Pro's ``GET /campaigns/{id}/attack-paths`` (schema darkmoon-attack-paths/v1): the
engine (``api.attack_paths``) reads the campaign, its infrastructure graph and its findings. Community has no
retest store and no run ledger, so no path is ever marked interrupted by a retest and every agent-declared link
stays ``declared_by_agent`` (a hypothesis, never a proof).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from api import attack_paths as engine
from api.infrastructure_graph import build_infrastructure
from api.json_storage import is_safe_id, load_campaign


def attack_paths_doc(campaign_id: str, provenance: str = "all", include_steps: bool = True) -> Optional[Dict[str, Any]]:
    """The attack-path document of ``campaign_id``, or None when the id is malformed or the campaign is unknown."""
    if not is_safe_id(campaign_id):
        return None
    campaign = load_campaign(campaign_id)
    if not campaign:
        return None
    infra = build_infrastructure(campaign_id, campaign)
    return engine.build_paths(campaign, infra["nodes"], infra["edges"], infra["vulnerabilities"],
                              provenance=provenance, include_steps=include_steps, retest_verdicts={})
