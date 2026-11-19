"""
Attack paths of one campaign computed from the local store, without a web server.

Same document as Darkmoon Pro's ``GET /campaigns/{id}/attack-paths`` (schema darkmoon-attack-paths/v1): the
engine (``api.attack_paths``) reads the campaign, its infrastructure graph and its findings. Community has no
retest store and no run ledger, so no path is ever marked interrupted by a retest and every agent-declared link
stays ``declared_by_agent`` (a hypothesis, never a proof).

The engine can also corroborate a link when the same value appears in the evidence of two findings (rules R1/R3).
In Darkmoon Pro that evidence comes from the server's own recording of the tool runs; in Community every evidence
field is text the agent wrote in ``dashboard_push_finding``. A match there is not an observation by the server, so
the engine only gets the SHAPE of the evidence (how many commands and requests, whether data was extracted), never
its text: paths then rest on agent declarations and topology inferences only, both labelled as hypotheses.
"""
from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Optional

from api import attack_paths as engine
from api.infrastructure_graph import build_infrastructure
from api.json_storage import is_safe_id, load_campaign

_WITHHELD = "[agent-written evidence: not used as proof]"
_EVIDENCE_TEXT_KEYS = ("raw_request", "raw_response", "request", "response", "extracted_data", "extractedData",
                       "commands", "command", "requests", "payloads", "logs", "screenshots", "explanation", "output")


def _shape_only(value: Any) -> Any:
    """Same shape (list length, presence), no content."""
    if isinstance(value, list):
        return [_WITHHELD] * len(value)
    return _WITHHELD if value else value


def _without_evidence_text(v: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(v)
    for key in _EVIDENCE_TEXT_KEYS:
        if key in out:
            out[key] = _shape_only(out[key])
    ev = out.get("evidence")
    for e in (ev if isinstance(ev, list) else [ev]):
        if isinstance(e, dict):
            for key in list(e):
                e[key] = _shape_only(e[key])
    return out


def attack_paths_doc(campaign_id: str, provenance: str = "all", include_steps: bool = True,
                     finding_filter: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """The attack-path document of ``campaign_id``, or None when the id is malformed or the campaign is unknown.

    ``finding_filter``: applied to every finding BEFORE the engine (e.g. the Terminal Explorer's redaction), so text
    the engine derives from titles (labels, step explanations) never carries what the filter removed."""
    if not is_safe_id(campaign_id):
        return None
    campaign = load_campaign(campaign_id)
    if not campaign:
        return None
    infra = build_infrastructure(campaign_id, campaign)
    vulns: List[Dict[str, Any]] = [_without_evidence_text(v) if isinstance(v, dict) else v
                                   for v in infra["vulnerabilities"]]
    if finding_filter is not None:
        vulns = [finding_filter(v) if isinstance(v, dict) else v for v in vulns]
    return engine.build_paths(campaign, infra["nodes"], infra["edges"], vulns,
                              provenance=provenance, include_steps=include_steps, retest_verdicts={})
