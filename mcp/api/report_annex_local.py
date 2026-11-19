"""
Report annex of one campaign computed from the local store, without a web server.

Darkmoon Pro shows the report annex (``api.report_annex.build_annex``) next to the written report in its dashboard.
Community has no dashboard, so the same sections are appended to the Markdown report written at finalisation:
remediation priorities, attack paths (with a Mermaid diagram), infrastructure map, fix first and framework mapping.

The inputs are the Community equivalents of the documents the annex reads in Pro:

- attack paths: ``api.attack_paths_local.attack_paths_doc`` (provenance all, with steps). The engine never sees
  agent-written evidence text there, so no path is proven: every path is a hypothesis (agent-declared or inferred) and
  the annex words it so;
- infrastructure: ``api.infrastructure_graph.build_infrastructure`` + the zone of each asset (``api.zones``) + the
  exposure of each asset by open, non-hypothesis paths (``annotate_path_exposure``);
- frameworks: ``frameworks_doc`` below (ATT&CK, ISO 27001, IEC 62443-3-3, MITRE ATLAS, EBIOS RM workshop-4 input)
  with the vendored catalogue (``api.frameworks.framework_catalogue``).

Community also lists the links the agents declared between findings (``enabled_by``), including the rejected
declarations, in the ATTACK PATHS section: it has no other view where an operator would see them.
"""
from __future__ import annotations

import copy
import logging
from typing import Any, Callable, Dict, List, Optional

from api.json_storage import is_safe_id, load_campaign, load_campaigns, load_vulnerabilities

_log = logging.getLogger("darkmoon.report")
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}


def _severity_max(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 5) <= _SEV_ORDER.get(b, 5) else b


def annotate_path_exposure(nodes: List[Dict[str, Any]], paths_doc: Optional[Dict[str, Any]]) -> None:
    """An asset with no finding of its own can still be the objective of open attack paths. ``risk_level`` stays
    « findings on this asset »; two fields say what reaches it:
      reached_by     = {paths, critical_paths, criticality, path_ids} | None
      effective_risk = max(risk_level, criticality of the open, non-hypothesis paths reaching it)
    Hypotheses never raise an asset's risk: in Community every path is one, so effective_risk == risk_level."""
    reach: Dict[str, Dict[str, Any]] = {}
    for p in (paths_doc or {}).get("paths") or []:
        if p.get("status") != "open" or p.get("hypothesis"):
            continue
        oid = (p.get("objective") or {}).get("node_id")
        if not oid:
            continue
        crit = str(p.get("criticality") or "none").lower()
        row = reach.setdefault(oid, {"paths": 0, "critical_paths": 0, "criticality": "none", "path_ids": []})
        row["paths"] += 1
        row["critical_paths"] += 1 if crit == "critical" else 0
        row["criticality"] = _severity_max(row["criticality"], crit if crit in _SEV_ORDER else "none")
        row["path_ids"].append(p.get("id"))
    for n in nodes:
        row = reach.get(n.get("id"))
        n["reached_by"] = row
        base = n.get("risk_level") or "none"
        n["effective_risk"] = _severity_max(base, row["criticality"]) if row else base


def infrastructure_doc(campaign_id: str, campaign: Dict[str, Any],
                       paths_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Nodes (with zone, ring, reached_by, effective_risk) and edges of the campaign's infrastructure graph."""
    from api.infrastructure_graph import build_infrastructure
    from api.zones import ring_of_zone, zone_of_node
    infra = build_infrastructure(campaign_id, campaign)
    nodes = copy.deepcopy(infra["nodes"])
    for n in nodes:
        n["zone"] = zone_of_node(n)
        n["ring"] = ring_of_zone(n["zone"])
    annotate_path_exposure(nodes, paths_doc)
    return {"campaign_id": campaign_id, "target_id": campaign.get("target_id"), "project_id": campaign.get("project_id"),
            "nodes": nodes, "edges": infra["edges"], "attack_paths": infra["attack_paths"]}


def _project_scope(campaign_id: str, campaign: Dict[str, Any], vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The findings of every campaign of the project (cross-campaign consolidation of the feasibility)."""
    project_id = campaign.get("project_id")
    if not project_id:
        return list(vulns)
    scope: List[Dict[str, Any]] = list(vulns)
    ids = sorted(c["id"] for c in load_campaigns()
                 if c.get("project_id") == project_id and not c.get("is_subagent") and c.get("id"))
    for cid in ids:
        if cid != campaign_id and is_safe_id(cid):
            scope += [v for v in load_vulnerabilities(cid) or [] if isinstance(v, dict)]
    return scope


def frameworks_doc(campaign_id: str, campaign: Dict[str, Any], paths_doc: Optional[Dict[str, Any]] = None,
                   nodes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """The framework views of one campaign (schema darkmoon-frameworks/v1), as Darkmoon Pro computes them, without the
    owner context of EBIOS RM (business values, feared events, risk sources): Community does not store one, so these
    stay « to assess »."""
    from api import frameworks as F
    from api.attack_paths_local import attack_paths_doc
    from api.infrastructure_graph import build_infrastructure
    infra = build_infrastructure(campaign_id, campaign)
    vulns = [v for v in infra["vulnerabilities"] if isinstance(v, dict)]
    nodes = nodes if nodes is not None else infra["nodes"]
    doc = paths_doc if paths_doc is not None else (attack_paths_doc(campaign_id, "all", True) or {})
    ebios = F.ebios_view(doc, vulns, None, _project_scope(campaign_id, campaign, vulns), None, nodes)
    live = F.live(vulns)
    return {
        "schema_version": F.SCHEMA_VERSION, "campaign_id": campaign_id, "project_id": campaign.get("project_id"),
        "attack": F.attack_matrix(vulns), "iso": F.iso_view(vulns), "iec62443": F.iec62443_view(vulns),
        "atlas": F.atlas_view(vulns, campaign.get("agents_dispatched"), nodes), "ebios": ebios,
        "findings": {v["id"]: {"title": (v.get("title") or "")[:300] or None, "severity": v.get("severity"),
                               "status": F._status(v)} for v in live if v.get("id")},
        "quarantined_excluded": sum(1 for v in vulns if F.held(v)),
        "licences": F.framework_licences(),
    }


# ── links declared by the agents (Community) ────────────────────────────────────────────────────────────────────


def declared_links_markdown(vulns_in_push_order: List[Dict[str, Any]]) -> str:
    """The links the agents declared (enabled_by) and the server's verdict on each, rejected ones included.
    ``vulns_in_push_order``: the findings in STORE order, never sorted: a reference to a finding pushed later is
    rejected. Empty string when no finding declares a link. Nothing here is presented as proof."""
    if not any(isinstance(v, dict) and v.get("enabled_by") for v in vulns_in_push_order):
        return ""
    from api.declared_links import LEVEL_LABELS, validate
    from api.report_annex import md_cell
    links = validate([v for v in vulns_in_push_order if isinstance(v, dict)])
    titles = {str(v.get("id")): str(v.get("title") or "") for v in vulns_in_push_order if isinstance(v, dict)}

    def cell(text: str, n: int = 60) -> str:
        text = " ".join(str(text).replace("|", "/").replace("`", "'").split())
        text = text[:n - 1] + "…" if len(text) > n else text
        return md_cell(text)  # raw HTML shown as text, images never fetched

    def name(fid: str) -> str:
        return f"{cell(titles[fid])} `{cell(fid, 24)}`" if titles.get(fid) else f"`{cell(fid, 24)}`"

    out = ["### Links declared by the agents", "",
           "> These links were **declared by the testing agents** (a finding whose result was used by a later one). "
           "The server did not observe them: each one is a hypothesis to verify, not a proof of an attack chain. "
           "Darkmoon Community does not verify links itself: no path is counted as proven.", "",
           "| Enabling finding | Used by | Status |", "|---|---|---|"]
    for link in links:
        producer, consumer = str(link.get("producer") or ""), str(link.get("consumer") or "")
        state = str(link.get("state") or "")
        label = LEVEL_LABELS.get(state, state)
        if link.get("reason"):
            label += f" ({link['reason']})"
        out.append(f"| {name(producer)} | {name(consumer)} | {cell(label, 90)} |")
    return "\n".join(out)


def _insert_after_section(content: str, heading: str, extra: str) -> str:
    """``extra`` at the end of the ``heading`` section (before the next ``## `` heading)."""
    start = content.find(heading)
    if start < 0:
        return content.rstrip("\n") + "\n\n" + extra + "\n"
    nxt = content.find("\n## ", start + len(heading))
    if nxt < 0:
        return content.rstrip("\n") + "\n\n" + extra + "\n"
    return content[:nxt].rstrip("\n") + "\n\n" + extra + "\n" + content[nxt:]


def annex_markdown(campaign_id: str, campaign: Dict[str, Any], vulns_in_push_order: List[Dict[str, Any]],
                   finding_filter: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None) -> str:
    """The annex sections of ``campaign_id`` as one Markdown string (a written report exists: no key figures and no
    findings sections, the report body carries them). Advisory: a failure of one input leaves its section out rather
    than failing the finalisation; if the attack-path document itself cannot be built, only the declared links are
    listed."""
    from api import report_annex
    from api.attack_paths_local import attack_paths_doc
    try:
        declared = declared_links_markdown(vulns_in_push_order)
    except Exception:
        _log.warning("declared-link list skipped", exc_info=True)
        declared = ""
    try:
        if not is_safe_id(campaign_id) or not load_campaign(campaign_id):
            raise ValueError("unknown campaign")
        ap = attack_paths_doc(campaign_id, "all", True, finding_filter) or {}
        infra = infrastructure_doc(campaign_id, campaign, ap)
    except Exception:
        _log.warning("report annex skipped", exc_info=True)
        if not declared:
            return ""
        return ("## ATTACK PATHS\n\n> The attack-path analysis could not be computed for this campaign; the links the "
                "agents declared are listed below.\n\n" + declared + "\n")
    fw: Optional[Dict[str, Any]] = None
    catalogue: Dict[str, Any] = {}
    try:  # the annex never fails because of the framework views: the section is left out
        from api import frameworks as F
        fw = frameworks_doc(campaign_id, campaign, ap, infra["nodes"])
        catalogue = F.framework_catalogue()
    except Exception:
        _log.warning("framework mapping skipped", exc_info=True)
        fw = None
    content = report_annex.build_annex(ap, infra, fw, catalogue, campaign=campaign, findings=None)["content"]
    if declared:
        content = _insert_after_section(content, "## ATTACK PATHS", declared)
    return content
