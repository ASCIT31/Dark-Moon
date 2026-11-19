"""
Darkmoon Dashboard — Live Push Module

Provides real-time incremental data push during a pentest campaign.
The LLM calls these functions via MCP tools as it discovers things.

Flow during a live pentest:
    1. init_live_campaign()   — called once at start
    2. push_finding()         — called each time a vuln is found
    3. push_infra_node()      — called each time an infra node is mapped
    4. finalize_campaign()    — called once at the end

Each call writes JSON to disk immediately so the API serves fresh data.
"""

import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_OPENCODE_DB = Path.home() / ".local" / "share" / "opencode" / "opencode-dev.db"


def _run_campaign_frag(fallback: str) -> str:
    """Per-RUN campaign key.

    The MCP ``SESSION_ID`` (what ``get_session()`` returns) is generated ONCE per
    long-lived MCP server process, so every ``opencode run`` served by the same
    process would otherwise resolve to the same ``camp_<day>_<session_id>`` and a
    second campaign on the same day/server would silently merge into the first
    (empty new project, findings landing in the previous campaign).

    A campaign == one ``opencode run`` == one ROOT opencode session (``parent_id``
    IS NULL). We key the campaign on the *latest* root session instead: unique per
    run, stable for the whole run (sub-agents open CHILD sessions, never new roots),
    and shared by the orchestrator and all its sub-agents — so idempotent reuse and
    sub-agent merge are preserved. Falls back to the passed ``session_id`` when the
    opencode DB is unavailable (never worse than before).
    """
    if not _OPENCODE_DB.exists():
        return fallback
    try:
        conn = sqlite3.connect(str(_OPENCODE_DB), timeout=2)
        try:
            cur = conn.execute(
                "SELECT id FROM session WHERE parent_id IS NULL "
                "ORDER BY time_created DESC LIMIT 1"
            )
            row = cur.fetchone()
        finally:
            conn.close()
        if row and row[0]:
            clean = str(row[0]).replace("ses_", "").replace("-", "")
            if len(clean) >= 8:
                return clean[:8]
            if clean:
                return clean
    except Exception:
        pass
    return fallback


def _is_subagent_session(session_id: str) -> bool:
    """Return True if this session is a sub-agent (has a parent_id in opencode DB).

    Strategy: build a set of 8-char hex fragments from all sub-agent session IDs,
    then check if session_id appears in that set.
    """
    if not _OPENCODE_DB.exists():
        return False
    try:
        conn = sqlite3.connect(str(_OPENCODE_DB), timeout=2)
        cur = conn.execute(
            "SELECT id FROM session WHERE parent_id IS NOT NULL"
        )
        subagent_sessions = [r[0] for r in cur.fetchall()]
        conn.close()

        for sid in subagent_sessions:
            clean = sid.replace("ses_", "").replace("-", "")
            # Generate all 8-char windows and check for match
            for i in range(len(clean) - 7):
                if clean[i:i + 8] == session_id:
                    return True
    except Exception:
        pass
    return False


def _find_parent_campaign_id(session_id: str) -> Optional[str]:
    """
    For a sub-agent session, find the campaign_id of the parent session.
    Returns the parent campaign_id string, or None if not found.

    Strategy: look up the parent session_id from the DB, then find a campaign
    whose session_id matches an 8-char fragment of the parent session.
    """
    if not _OPENCODE_DB.exists():
        return None
    try:
        conn = sqlite3.connect(str(_OPENCODE_DB), timeout=2)
        # Find the parent session_id for this sub-agent session
        cur = conn.execute(
            "SELECT parent_id FROM session WHERE parent_id IS NOT NULL"
        )
        all_parent_ids = [r[0] for r in cur.fetchall()]
        conn.close()

        # Build set of 8-char fragments for this session_id to find its parent row
        # Then find which parent_id corresponds to our session_id
        conn = sqlite3.connect(str(_OPENCODE_DB), timeout=2)
        cur = conn.execute(
            "SELECT id, parent_id FROM session WHERE parent_id IS NOT NULL"
        )
        rows = cur.fetchall()
        conn.close()

        parent_session_id = None
        for (sid, pid) in rows:
            clean_sid = sid.replace("ses_", "").replace("-", "")
            for i in range(len(clean_sid) - 7):
                if clean_sid[i:i + 8] == session_id:
                    parent_session_id = pid
                    break
            if parent_session_id:
                break

        if not parent_session_id:
            return None

        # Clean the parent session id to get 8-char fragment
        clean_parent = parent_session_id.replace("ses_", "").replace("-", "")
        parent_fragments = {clean_parent[i:i+8] for i in range(len(clean_parent) - 7)}

    except Exception:
        return None

    # Search all campaigns for one whose session_id matches a parent fragment
    from api.json_storage import load_campaigns
    for campaign in load_campaigns():
        camp_session = str(campaign.get("session_id", ""))
        if camp_session in parent_fragments:
            return campaign.get("id")

    return None

from api.json_storage import (
    INFRASTRUCTURE_DIR,
    VULNERABILITIES_DIR,
    REPORTS_DIR,
    load_project,
    load_target,
    save_project,
    save_target,
    save_campaign,
    load_campaign,
    find_target_by_host_or_ip,
    find_project_by_target_id,
    _read_json,
    _write_json,
    _resolve_inside,
    is_safe_id,
    load_report_content,
    locked,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _time_compact() -> str:
    return datetime.now(timezone.utc).strftime("%H%M")


def _safe_slug(value: str) -> str:
    return (
        str(value or "")
        .strip()
        .lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(".", "_")
    )


def _normalize_port_entry(port: Any) -> Dict[str, Any]:
    if isinstance(port, dict):
        return {
            "port": port.get("port") or port.get("number") or port.get("value"),
            "protocol": str(port.get("protocol", "tcp")).strip().lower(),
            "service": port.get("service") or port.get("name") or "",
            "product": port.get("product") or "",
            "version": port.get("version") or "",
        }

    return {
        "port": port,
        "protocol": "tcp",
        "service": "",
        "product": "",
        "version": "",
    }


def _normalize_technology_entry(tech: Any) -> Dict[str, Any]:
    if isinstance(tech, dict):
        return {
            "name": tech.get("name") or tech.get("product") or tech.get("technology") or "unknown",
            "version": tech.get("version") or "",
            "category": tech.get("category") or tech.get("type") or "technology",
        }

    return {
        "name": str(tech),
        "version": "",
        "category": "technology",
    }


def _build_stack_nodes(
    campaign_id: str,
    project_id: str,
    target_id: str,
    target_host: str,
    target_ip: str,
    os_info: str,
    ports: List[Dict[str, Any]],
    technologies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []

    target_node_id = f"target_{target_id}"
    target_label = target_host or target_ip or target_id

    nodes.append({
        "id": target_node_id,
        "node_type": "target",
        "label": target_label,
        "title": target_label,
        "host": target_host,
        "ip": target_ip,
        "campaign_id": campaign_id,
        "project_id": project_id,
        "target_id": target_id,
    })

    if os_info:
        nodes.append({
            "id": f"os_{target_id}_{_safe_slug(os_info)}",
            "node_type": "os",
            "label": os_info,
            "title": os_info,
            "value": os_info,
            "parent_node_id": target_node_id,
            "campaign_id": campaign_id,
            "project_id": project_id,
            "target_id": target_id,
        })

    for port_entry in ports or []:
        p = _normalize_port_entry(port_entry)
        if p["port"] in (None, ""):
            continue

        service_label = f'{p["port"]}/{p["protocol"]}'
        if p["service"]:
            service_label += f' - {p["service"]}'

        nodes.append({
            "id": f'svc_{target_id}_{p["port"]}_{p["protocol"]}',
            "node_type": "service",
            "label": service_label,
            "title": service_label,
            "port": p["port"],
            "protocol": p["protocol"],
            "service": p["service"],
            "product": p["product"],
            "version": p["version"],
            "parent_node_id": target_node_id,
            "campaign_id": campaign_id,
            "project_id": project_id,
            "target_id": target_id,
        })

    for tech_entry in technologies or []:
        t = _normalize_technology_entry(tech_entry)
        tech_label = t["name"] if not t["version"] else f'{t["name"]} {t["version"]}'
        nodes.append({
            "id": f'tech_{target_id}_{_safe_slug(t["name"])}_{_safe_slug(t["version"])}',
            "node_type": "technology",
            "label": tech_label,
            "title": tech_label,
            "name": t["name"],
            "version": t["version"],
            "category": t["category"],
            "parent_node_id": target_node_id,
            "campaign_id": campaign_id,
            "project_id": project_id,
            "target_id": target_id,
        })

    return nodes


def _merge_unique_ports(existing_ports: Optional[List[Dict[str, Any]]], new_ports: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()

    for source in (existing_ports or [], new_ports or []):
        for port in source if isinstance(source, list) else []:
            normalized = _normalize_port_entry(port)
            key = (
                normalized.get("port"),
                normalized.get("protocol"),
                normalized.get("service"),
                normalized.get("product"),
                normalized.get("version"),
            )
            if normalized.get("port") in (None, "") or key in seen:
                continue
            seen.add(key)
            merged.append(normalized)

    return merged


def _merge_unique_technologies(existing_technologies: Optional[List[Dict[str, Any]]], new_technologies: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()

    for source in (existing_technologies or [], new_technologies or []):
        for tech in source if isinstance(source, list) else []:
            normalized = _normalize_technology_entry(tech)
            key = (normalized.get("name"), normalized.get("version"), normalized.get("category"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(normalized)

    return merged


def _sync_target_metadata_from_node(campaign: Dict[str, Any], node: Dict[str, Any]) -> None:
    target_id = campaign.get("target_id")
    if not target_id:
        return

    target = load_target(target_id)
    if not target:
        return

    node_type = str(node.get("node_type", "")).strip().lower()
    updated = False

    if node_type == "service":
        merged_ports = _merge_unique_ports(
            target.get("ports"),
            [{
                "port": node.get("port"),
                "protocol": node.get("protocol", "tcp"),
                "service": node.get("service") or node.get("label") or "",
                "product": node.get("product") or "",
                "version": node.get("version") or "",
            }],
        )
        if merged_ports != target.get("ports", []):
            target["ports"] = merged_ports
            updated = True

    elif node_type == "technology":
        merged_techs = _merge_unique_technologies(
            target.get("technologies"),
            [{
                "name": node.get("name") or node.get("label") or node.get("title") or "unknown",
                "version": node.get("version") or "",
                "category": node.get("category") or "technology",
            }],
        )
        if merged_techs != target.get("technologies", []):
            target["technologies"] = merged_techs
            updated = True

    elif node_type == "os":
        os_value = str(node.get("value") or node.get("label") or node.get("title") or "").strip()
        if os_value and os_value != str(target.get("os", "")).strip():
            target["os"] = os_value
            updated = True

    if updated:
        target["last_seen"] = _now_iso()
        save_target(target)


def _normalize_campaign_status(status: str) -> str:
    normalized = str(status or "completed").strip().lower()
    aliases = {
        "cancelled": "aborted",
        "canceled": "aborted",
        "abort": "aborted",
        "done": "completed",
        "finish": "completed",
        "finished": "completed",
    }
    return aliases.get(normalized, normalized)


# -----------------------------------------------------------------------
# 1. Init campaign — creates project/target/campaign skeleton
# -----------------------------------------------------------------------

def _init_live_campaign_unlocked(
    session_id: str,
    target_host: str,
    target_ip: str,
    project_name: str = "Darkmoon Assessment",
    project_id: Optional[str] = None,
    target_id: Optional[str] = None,
    methodology: str = "ISO 27001 / NIST SP 800-115 / MITRE ATT&CK",
    ports: Optional[List[Dict[str, Any]]] = None,
    technologies: Optional[List[Dict[str, Any]]] = None,
    os_info: str = "",
    campaign_kind: Optional[str] = None,
) -> Dict[str, str]:
    """
    Initialize a live campaign. Creates project + target + campaign skeleton.
    Rule: 1 project = 1 target.
    ``campaign_kind`` (optional): full | retest | short, recorded in the coverage signals.
    """
    if not is_safe_id(f"camp_x_{session_id}"):  # refused before anything is written (no orphan project/target)
        return {"error": f"invalid session_id {str(session_id)[:40]!r}"}
    now = _now_iso()
    today = _today_compact()

    ports = ports or []
    technologies = technologies or []

    resolved_target = None

    if target_id:
        resolved_target = load_target(target_id)

    if not resolved_target:
        resolved_target = find_target_by_host_or_ip(target_host, target_ip)

    if resolved_target:
        target_id = resolved_target["id"]
    else:
        target_id = target_id or f"tgt_{uuid.uuid4().hex[:6]}"

    resolved_project = None

    if project_id:
        resolved_project = load_project(project_id)

    if not resolved_project:
        resolved_project = find_project_by_target_id(target_id)

    if not resolved_project and resolved_target and resolved_target.get("project_id"):
        resolved_project = load_project(resolved_target["project_id"])

    if resolved_project:
        project_id = resolved_project["id"]
    else:
        project_id = project_id or f"proj_{uuid.uuid4().hex[:6]}"

    existing_project = load_project(project_id)
    if existing_project and existing_project.get("target_id") not in (None, target_id):
        linked_project = find_project_by_target_id(target_id)
        if linked_project:
            project_id = linked_project["id"]
        else:
            project_id = f"proj_{uuid.uuid4().hex[:6]}"

    existing_project = load_project(project_id)
    if existing_project:
        # NEVER overwrite an existing project name — sub-agents must not rename
        # the project created by the orchestrator.
        existing_project["target_id"] = target_id
        existing_project.setdefault("description", f"Assessment on {target_host}")
        existing_project.setdefault("tags", [])
        save_project(existing_project)
    else:
        save_project({
            "id": project_id,
            "name": project_name,
            "description": f"Assessment on {target_host}",
            "created_at": now,
            "target_id": target_id,
            "tags": [],
        })

    existing_target = load_target(target_id)
    if existing_target:
        existing_target["project_id"] = project_id
        existing_target["host"] = target_host
        existing_target["ip"] = target_ip
        existing_target["ports"] = ports
        existing_target["technologies"] = technologies
        existing_target["os"] = os_info
        existing_target["status"] = existing_target.get("status", "scanned")
        existing_target["risk_level"] = existing_target.get("risk_level", "none")
        existing_target["last_seen"] = now
        existing_target.setdefault("first_seen", now)
        save_target(existing_target)
    else:
        save_target({
            "id": target_id,
            "project_id": project_id,
            "host": target_host,
            "ip": target_ip,
            "ports": ports,
            "technologies": technologies,
            "os": os_info,
            "status": "scanned",
            "risk_level": "none",
            "first_seen": now,
            "last_seen": now,
        })

    # Check if this session is a sub-agent
    is_subagent = _is_subagent_session(session_id)

    # If sub-agent: reuse the parent campaign instead of creating a new one
    parent_campaign_id = None
    if is_subagent:
        parent_campaign_id = _find_parent_campaign_id(session_id)

    if parent_campaign_id:
        # Sub-agent: push nodes into the PARENT campaign, don't create a new campaign
        stack_nodes = _build_stack_nodes(
            campaign_id=parent_campaign_id,
            project_id=project_id,
            target_id=target_id,
            target_host=target_host,
            target_ip=target_ip,
            os_info=os_info,
            ports=ports,
            technologies=technologies,
        )
        infra_path = _resolve_inside(INFRASTRUCTURE_DIR, parent_campaign_id)
        existing_nodes = _read_json(infra_path)
        if not isinstance(existing_nodes, list):
            existing_nodes = []
        existing_ids = {n["id"] for n in existing_nodes if n.get("id")}
        for n in stack_nodes:
            if n.get("id") and n["id"] not in existing_ids:
                existing_nodes.append(n)
        _write_json(infra_path, existing_nodes)

        return {
            "project_id": project_id,
            "target_id": target_id,
            "campaign_id": parent_campaign_id,
            "status": "subagent_merged_into_parent",
        }

    run_frag = _run_campaign_frag(session_id)
    campaign_id = f"camp_{today}_{run_frag}"

    campaign = {
        "id": campaign_id,
        "project_id": project_id,
        "target_id": target_id,
        "session_id": run_frag,
        "is_subagent": is_subagent,
        "date": now,
        "duration_seconds": 0,
        "status": "running",
        "methodology": methodology,
        "agents_dispatched": [],
        "cascade_depth": 0,
        "overall_risk": "none",
        "stats": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "exploited": 0,
            "confirmed": 0,
            "unconfirmed": 0,
        },
        "report_path": "",
        "executive_summary": "",
    }
    # coverage signals (exec_core score gate): a repeated init keeps the server start of the campaign
    from api import coverage_signals
    _prior = load_campaign(campaign_id)
    if _prior and isinstance(_prior.get("coverage_signals"), dict):
        campaign["coverage_signals"] = _prior["coverage_signals"]
        campaign["date"] = _prior.get("date") or campaign["date"]
    # a record that predates coverage signals never gets any; Community = single-user TUI: the run's root session
    # is the latest one when the campaign key is not a session prefix
    coverage_signals.on_init(campaign, campaign_kind, create=_prior is None, latest_root_fallback=True)
    save_campaign(campaign)

    # Only init empty vulns if file doesn't exist yet
    vuln_path = _resolve_inside(VULNERABILITIES_DIR, campaign_id)
    if not vuln_path.exists():
        _write_json(vuln_path, [])

    stack_nodes = _build_stack_nodes(
        campaign_id=campaign_id,
        project_id=project_id,
        target_id=target_id,
        target_host=target_host,
        target_ip=target_ip,
        os_info=os_info,
        ports=ports,
        technologies=technologies,
    )
    # Merge with existing infra nodes instead of overwriting
    infra_path = _resolve_inside(INFRASTRUCTURE_DIR, campaign_id)
    existing_nodes = _read_json(infra_path)
    if not isinstance(existing_nodes, list):
        existing_nodes = []
    existing_ids = {n["id"] for n in existing_nodes if n.get("id")}
    for n in stack_nodes:
        if n.get("id") and n["id"] not in existing_ids:
            existing_nodes.append(n)
    _write_json(infra_path, existing_nodes)

    return {
        "project_id": project_id,
        "target_id": target_id,
        "campaign_id": campaign_id,
        "status": "campaign_initialized",
    }


# -----------------------------------------------------------------------
# 2. Push a single finding (vulnerability) — incremental
# -----------------------------------------------------------------------

def _same_finding(finding: Dict[str, Any], vulns: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The stored finding a re-push designates: same dedup_key, else same title + endpoint + category (exact)."""
    key = finding.get("dedup_key")
    if key:
        hit = next((v for v in vulns if v.get("dedup_key") == key and not v.get("duplicate_of")), None)
        if hit is not None:
            return hit
    t = (str(finding.get("title") or "").strip(), str(finding.get("endpoint") or "").strip(),
         str(finding.get("category") or "").strip())
    if not all(t):
        return None
    return next((v for v in vulns if (str(v.get("title") or "").strip(), str(v.get("endpoint") or "").strip(),
                                       str(v.get("category") or "").strip()) == t), None)


_CONTENT_KEYS = ("status", "severity", "description", "evidence", "cvss_score", "remediation")


def _same_content(finding: Dict[str, Any], stored: Dict[str, Any]) -> bool:
    """True when a re-push carries nothing new besides its references (the fields an agent re-sends unchanged)."""
    def norm(v: Any) -> Any:
        return str(v).strip().lower() if isinstance(v, str) else v
    return all(norm(finding.get(k)) == norm(stored.get(k)) for k in _CONTENT_KEYS if k in finding)


# Lever 1 (enabled_by fill rate): the push reply reminds the agent of the last EXPLOITED findings of the campaign, by
# vuln_id (the form the enabled_by resolver always accepts; a cut title would not resolve). Built from the findings
# already loaded for the push: no extra read. One short line, at most RECENT_EXPLOITED_MAX chars, at most 3 items.
# Architecture D (17/11/2026, architecture D): same item count per reply (never a hint where there was none); the finding
# JUST pushed (when exploited) comes first — the oracle showed it is the most frequent true parent of the NEXT push and
# the old order excluded it — then the most recent exploited findings of the campaign. Measured on c5 / c6: +17 / -9
# characters over a whole campaign. The hint can only help the next push (it is in this push's reply).
RECENT_EXPLOITED_PREFIX = "recent exploited (use in enabled_by if relevant): "
RECENT_EXPLOITED_MAX = 200


def _hint_item(v: Dict[str, Any], campaign_id: str) -> Optional[str]:
    vid = str(v.get("id") or "")
    if (not vid or len(vid) > 24 or v.get("duplicate_of")
            or str(v.get("status") or "").strip().lower() != "exploited"
            or (v.get("campaign_id") and v.get("campaign_id") != campaign_id)):
        return None
    label = " ".join(str(v.get("short_title") or v.get("title") or "").replace(";", ",").split())
    if len(label) > 32:
        label = label[:31].rstrip() + "…"
    return f"{vid} · {label}" if label else vid


def recent_exploited_hint(vulns: List[Dict[str, Any]], self_finding: Dict[str, Any], campaign_id: str,
                          limit: int = 3) -> Optional[str]:
    self_id = str(self_finding.get("id") or "")
    skip = {self_id, str(self_finding.get("duplicate_of") or "")} - {""}
    items: List[str] = []
    for v in reversed(vulns):
        if len(items) >= limit:
            break
        if str(v.get("id") or "") in skip:
            continue
        it = _hint_item(v, campaign_id)
        if it:
            items.append(it)
    if not items:
        return None
    # constant length: the same NUMBER of items as before (never a hint where there was none); the finding just pushed,
    # when exploited, takes the first place and the oldest item leaves
    own = _hint_item(self_finding, campaign_id)
    if own:
        items = [own] + items[:len(items) - 1]
    return (RECENT_EXPLOITED_PREFIX + "; ".join(items))[:RECENT_EXPLOITED_MAX]


def _push_finding_unlocked(
    campaign_id: str,
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Push a single vulnerability finding to the dashboard.
    Appends to the campaign's vulnerabilities file and updates stats.
    """
    if not is_safe_id(campaign_id):  # traversal guard: same answer as an unknown id
        return {"error": f"Campaign {campaign_id!r} not found"}
    vuln_path = _resolve_inside(VULNERABILITIES_DIR, campaign_id)
    vulns = _read_json(vuln_path)
    if not isinstance(vulns, list):
        vulns = []

    campaign = load_campaign(campaign_id)
    if not campaign:
        return {"error": f"Campaign {campaign_id} not found"}

    if not finding.get("id"):
        finding["id"] = f"vuln_{uuid.uuid4().hex[:6]}"

    finding["campaign_id"] = campaign_id
    finding["project_id"] = campaign.get("project_id")
    finding["target_id"] = campaign.get("target_id")
    finding["severity"] = str(finding.get("severity", "info")).strip().lower()
    finding["status"] = str(finding.get("status", "unconfirmed")).strip().lower()

    # `enabled_by` = earlier findings whose result this exploitation used. Resolved HERE against the
    # findings already stored (so a forward reference cannot exist): vuln_id, then a unique short_title / dedup_key /
    # title. Unknown or ambiguous refs and self-references are dropped with a warning; validation (ATT&CK order, nodes)
    # happens at analysis time (api/declared_links.py).
    enabled_warnings: List[str] = []
    if finding.get("enabled_by"):
        from api.declared_links import clean_refs, push_warnings
        finding["enabled_by"] = clean_refs(finding.get("enabled_by"))
        enabled_warnings = push_warnings(finding["enabled_by"], vulns, finding["id"])
        # re-pushing the SAME finding only to add what enabled it updates it: no duplicate is created. A re-push
        # that also changes the finding (status, severity, description, evidence) is stored as a new finding, as
        # before, so nothing it carries is lost.
        same = _same_finding(finding, vulns)
        if same is not None and not _same_content(finding, same):
            same = None
        if same is not None and finding["enabled_by"]:
            from api.declared_links import resolve_one
            mine = [r for r in finding["enabled_by"] if resolve_one(r, vulns, str(same["id"]))[1] != "self"]
            merged = clean_refs(list(same.get("enabled_by") or []) + mine)
            added = [r for r in merged if r not in (same.get("enabled_by") or [])]
            same["enabled_by"] = merged
            # architecture D: a late addition is dated by the number of findings stored when it was declared (a
            # reference to a finding pushed after that is « forward in time »); the FIRST push keeps binding the run
            # position (run_id / push_seq are never moved by a re-push)
            at = dict(same.get("enabled_by_at") or {})
            for r in added:
                at.setdefault(r, len(vulns))
            same["enabled_by_at"] = at
            for k in ("run_id", "push_seq"):
                if finding.get(k) is not None and same.get(k) is None:
                    same[k] = finding[k]
            _write_json(vuln_path, vulns)
            out = {"vuln_id": same["id"], "campaign_id": campaign_id, "total_findings": len(vulns),
                   "status": "finding_updated", "enabled_by_added": added}
            if enabled_warnings:
                out["enabled_by_warnings"] = enabled_warnings
            return out
        if not finding["enabled_by"]:
            finding.pop("enabled_by")
        else:   # architecture D: declaration time of each reference = findings already stored (forward-in-time check)
            finding["enabled_by_at"] = {r: len(vulns) for r in finding["enabled_by"]}

    vulns.append(finding)
    _write_json(vuln_path, vulns)

    # the one stats function (exec_core.stats): quarantined / false-positive findings are counted nowhere
    from api.exec_core import stats as _core_stats
    stats = campaign.get("stats", {})
    stats.update(_core_stats.compute_stats(vulns))

    campaign["stats"] = stats
    from api import coverage_signals
    coverage_signals.note_agent(campaign, finding.get("discovered_by_agent"), "push_finding")

    # Derive the dispatch log from the findings store, exactly like the stats
    # above. An agent that pushed a finding demonstrably ran, so the log can be
    # rebuilt from evidence instead of being declared. Populating it only from
    # the agents_dispatched argument of finalize_campaign() lost the entire log
    # whenever a campaign never reached finalize, and left it empty even on
    # campaigns that completed but did not pass the argument [INC-012].
    # A richer list explicitly passed at finalize still wins over this one.
    seen: Dict[str, int] = {}
    for v in vulns:
        name = str(v.get("discovered_by_agent") or "").strip()
        if name:
            seen[name] = seen.get(name, 0) + 1
    if seen:
        previous = {
            a.get("agent"): a
            for a in campaign.get("agents_dispatched", [])
            if isinstance(a, dict)
        }
        campaign["agents_dispatched"] = [
            {
                "agent": name,
                "findings": count,
                "level": previous.get(name, {}).get("level", 0),
                "status": previous.get(name, {}).get("status", "completed"),
            }
            for name, count in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))
        ]

    campaign["overall_risk"] = _core_stats.overall_risk(stats)

    save_campaign(campaign)

    target_id = campaign.get("target_id")
    if target_id:
        target = load_target(target_id)
        if target:
            target["risk_level"] = campaign["overall_risk"]
            target["status"] = "vulnerable" if stats.get("exploited", 0) == 0 else "compromised"
            target["last_seen"] = _now_iso()
            save_target(target)

    result = {
        "vuln_id": finding["id"],
        "campaign_id": campaign_id,
        "total_findings": len(vulns),
        "status": "finding_pushed",
    }
    if enabled_warnings:
        result["enabled_by_warnings"] = enabled_warnings
    try:  # advice only: never fails a push
        hint = recent_exploited_hint(vulns[:-1], finding, campaign_id)
    except Exception:
        hint = None
    if hint:
        result["recent_exploited"] = hint
    return result


# -----------------------------------------------------------------------
# 3. Push an infrastructure node — incremental
# -----------------------------------------------------------------------

def _push_infra_node_unlocked(
    campaign_id: str,
    node: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Push a single infrastructure node to the dashboard.
    Appends to the campaign's infrastructure file.
    Also links the node to campaign + project + target.
    """
    if not is_safe_id(campaign_id):  # traversal guard: same answer as an unknown id
        return {"error": f"Campaign {campaign_id!r} not found"}
    infra_path = _resolve_inside(INFRASTRUCTURE_DIR, campaign_id)
    nodes = _read_json(infra_path)
    if not isinstance(nodes, list):
        nodes = []

    campaign = load_campaign(campaign_id)
    if not campaign:
        return {"error": f"Campaign {campaign_id} not found"}

    if not node.get("id"):
        node["id"] = f"node_{uuid.uuid4().hex[:6]}"

    node["campaign_id"] = campaign_id
    node["project_id"] = campaign.get("project_id")
    node["target_id"] = campaign.get("target_id")

    existing_ids = {n["id"] for n in nodes if n.get("id")}
    if node["id"] not in existing_ids:
        nodes.append(node)
        _write_json(infra_path, nodes)

    _sync_target_metadata_from_node(campaign, node)

    return {
        "node_id": node["id"],
        "campaign_id": campaign_id,
        "project_id": node.get("project_id"),
        "target_id": node.get("target_id"),
        "total_nodes": len(nodes),
        "status": "node_pushed",
    }


# -----------------------------------------------------------------------
# Report markdown safety
# -----------------------------------------------------------------------
# Every finding field is written by an LLM after reading the target, and the
# evidence (raw HTTP requests/responses, commands, logs) is captured from the
# target itself. None of it may turn into live markup when the report is
# rendered (markdown viewers): raw HTML is shown as text, images are never
# fetched, and raw evidence can never close the code block it sits in.

_HTML_ESC = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})
_MD_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_MD_CODE_SPAN = re.compile(r"(?<![\\`])(`+)(?!`)(.+?)(?<!`)\1(?!`)")


def _md_text_segment(text: str, cell: bool = False) -> str:
    """Plain markdown text: HTML escaped, images defused (no fetch on render)."""
    out = text.translate(_HTML_ESC).replace("![", "!\\[")
    if cell:
        out = out.replace("|", "&#124;")
    return out


def _md_spans(line: str) -> Optional[List[re.Match]]:
    """Inline code spans of one line, or None when the line has a backtick that is
    not part of a complete single-line span (it could pair with another line, or be
    escaped): the caller then escapes everything rather than guess."""
    if "|" in line:  # a table row splits code spans on pipes
        return None if "`" in line else []
    spans = list(_MD_CODE_SPAN.finditer(line))
    rest = _MD_CODE_SPAN.sub("", line)
    return None if "`" in rest else spans


def _md_line(line: str, cell: bool = False, keep_code: bool = True) -> str:
    """One line of LLM markdown: inline code spans kept verbatim, the rest escaped."""
    spans = _md_spans(line) if keep_code else None
    if not spans:
        return _md_text_segment(line, cell)
    out, pos = [], 0
    for m in spans:
        out.append(_md_text_segment(line[pos:m.start()], cell))
        out.append(m.group(0))
        pos = m.end()
    out.append(_md_text_segment(line[pos:], cell))
    return "".join(out)


def _md_inline(value: Any, cell: bool = False) -> str:
    """A single-line field (title, component, ...) inserted in a heading, list or table cell."""
    text = " ".join(str(value if value is not None else "").split())
    return _md_line(text, cell, keep_code=not (cell and "|" in text))


def _md_prose(value: Any) -> str:
    """A multi-line LLM field (description, explanation, remediation, summary):
    markdown formatting and fenced code are kept, raw HTML is shown as text, and a
    code block left open is closed so it cannot swallow the rest of the report."""
    out: List[str] = []
    block: List[str] = []

    def flush() -> None:
        # inline code is kept only when every backtick of the paragraph belongs to a
        # single-line span (a span may otherwise run across lines)
        keep = all(_md_spans(ln) is not None for ln in block)
        out.extend(_md_line(ln, keep_code=keep) for ln in block)
        block.clear()

    fence: Optional[str] = None
    for line in str(value if value is not None else "").replace("\r\n", "\n").split("\n"):
        if fence is not None:
            out.append(line)
            if re.match(r"^ {0,3}" + re.escape(fence) + r"[`~]*[ \t]*$", line):
                fence = None
            continue
        m = _MD_FENCE_OPEN.match(line)
        if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
            flush()
            fence = m.group(1)
            out.append(line[:m.start(2)] + m.group(2).translate(_HTML_ESC))
            continue
        if not line.strip():
            flush()
            out.append(line)
            continue
        block.append(line)
    flush()
    if fence is not None:
        out.append(fence)
    return "\n".join(out)


def _md_code(value: Any) -> str:
    """A single-line value shown as inline code (ids, endpoints, vectors) in a table
    cell: the backtick delimiter is longer than any backtick run in the value, and
    pipes stay escaped so the table cannot split the span."""
    text = " ".join(str(value if value is not None else "").split())
    text = re.sub(r"(\\*)\|", lambda m: m.group(1) + ("\\" if len(m.group(1)) % 2 == 0 else "") + "|", text)
    runs = [len(r) for r in re.findall(r"`+", text)]
    tick = "`" * (max(runs, default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{tick}{pad}{text}{pad}{tick}"


def _md_fence(body: str, lang: str = "") -> str:
    """Raw target data in a fenced code block whose fence is longer than any
    backtick run in the data: the data can never close the block."""
    runs = [len(r) for r in re.findall(r"`+", body)]
    fence = "`" * max(3, max(runs, default=0) + 1)
    if not body.endswith("\n"):
        body += "\n"
    return f"{fence}{lang}\n{body}{fence}\n\n"


def is_quarantined(v: Dict[str, Any]) -> bool:
    """A record held by a strict privacy policy (``quarantined`` and not reviewed by
    an operator) is kept out of the report. Community never sets the flag itself."""
    return bool(v.get("quarantined")) and not v.get("quarantine_reviewed_by")


# -----------------------------------------------------------------------
# 4. Report auto-generator (finalize always builds the report from the store)
# -----------------------------------------------------------------------

def _generate_report_from_db(
    campaign_id: str,
    campaign: Dict[str, Any],
    executive_summary: str = "",
) -> str:
    """
    Generate a full markdown report directly from the stored findings, then append
    the report annex (remediation priorities, attack paths, infrastructure map,
    fix first, framework mapping) computed from the campaign's own data.
    """
    from api.json_storage import VULNERABILITIES_DIR

    vuln_path = _resolve_inside(VULNERABILITIES_DIR, campaign_id)
    vulns: List[Dict[str, Any]] = _read_json(vuln_path) or []
    vulns = [v for v in vulns if isinstance(v, dict)]
    stored_order = list(vulns)  # push order: the declared-link checks (forward references) depend on it
    held = [v for v in vulns if is_quarantined(v)]
    vulns = [v for v in vulns if not is_quarantined(v)]

    target_id = campaign.get("target_id", "unknown")
    target = load_target(target_id)
    host = target.get("host", target_id) if target else target_id
    host = _md_inline(host)

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _cvss_num(v: Dict) -> float:
        # Defensive: an agent may push a non-numeric cvss_score ("9.8 (High)",
        # "N/A", ""). A bare float() there raises ValueError and fails the whole
        # report. Parse the leading number if present, else 0.
        raw = v.get("cvss_score")
        try:
            return float(raw)
        except (TypeError, ValueError):
            m = re.search(r"\d+(?:\.\d+)?", str(raw or ""))
            return float(m.group()) if m else 0.0

    from api import cvss31 as _cvss31

    def _cvss_shown(v: Dict) -> Any:
        """(table cell, detail cell, number used for ordering): the score recomputed from a valid vector is the
        one shown; the agent's number is shown as « reported » when it differs."""
        a = _cvss31.assess(v)
        if a["score"] is not None:
            cell = f"{a['score']:.1f}"
            if a["status"] == "mismatch":
                return (f"{cell} (reported {a['reported']:.1f})",
                        f"{cell} (computed from the vector; reported by the agent: {a['reported']:.1f})", a["score"])
            return cell, f"{cell} (computed from the vector)", a["score"]
        if v.get("cvss_score"):
            n = _cvss_num(v)
            return f"{n:.1f}", f"{n:.1f} (reported by the agent; no valid vector)", n
        return "N/A", "N/A", 0.0

    vulns = sorted(
        vulns,
        key=lambda v: (SEV_ORDER.get(str(v.get("severity", "info")).lower(), 9),
                       -_cvss_shown(v)[2]),
    )

    SEV_LABEL  = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "info": "INFO"}
    STAT_LABEL = {"exploited": "**EXPLOITED**", "confirmed": "Confirmed",
                  "unconfirmed": "Unconfirmed"}

    def sev(v: Dict) -> str:
        return SEV_LABEL.get(str(v.get("severity", "")).lower(), _md_inline(str(v.get("severity", "")).upper(), cell=True))

    def stat(v: Dict) -> str:
        return STAT_LABEL.get(str(v.get("status", "")).lower(), _md_inline(v.get("status", ""), cell=True))

    # the one stats function (exec_core.stats): held (quarantined) and false-positive findings are counted
    # nowhere, so the report, the campaign record and the API give the same numbers
    from api.exec_core import stats as _core_stats
    stats = _core_stats.compute_stats(vulns)
    counted = _core_stats.split(vulns)[0]
    exploited = stats.get("exploited", 0)
    confirmed = stats.get("confirmed", 0)
    now = _now_iso()

    L: List[str] = []
    A = L.append

    # ── MANAGEMENT SUMMARY ──────────────────────────────────────────
    overall_risk = _md_inline(str(campaign.get("overall_risk") or "unknown").upper())
    n_crit  = stats.get("critical", 0)
    n_high  = stats.get("high", 0)
    n_total = stats.get("total_findings", len(vulns))

    A(f"# Vulnerability Assessment Report — {host}\n\n")
    A(f"**Classification:** CONFIDENTIAL — Restricted to authorized personnel  \n")
    A(f"**Generated:** {now}  \n")
    A(f"**Target:** {host}  \n")
    A(f"**Campaign:** {campaign_id}  \n")
    # The campaign's declared methodology, not a fixed label: a synthetic or partial run must not be presented as a
    # full ISO 27001 / NIST SP 800-115 assessment in the report header.
    methodology = _md_inline(str(campaign.get("methodology") or "").strip() or "ISO 27001 / NIST SP 800-115 / MITRE ATT&CK")
    A(f"**Methodology:** {methodology}  \n")
    # A partial run says so in the report itself
    _st = str(campaign.get("status") or "").lower()
    _partial = {"stopped": "Stopped by the operator", "aborted": "Aborted", "error": "Ended with an error",
                "failed": "Failed", "running": "In progress"}.get(_st) or (_md_inline(_st.capitalize()) if _st and _st != "completed" else None)
    if _st == "running":
        A("**Status:** In progress — interim report: the run is still going, findings may be added  \n")
    elif _partial:
        A(f"**Status:** {_partial} — partial results: the run did not complete; the findings cover what was tested "
          f"before it ended  \n")
    A("\n---\n\n")

    A("## MANAGEMENT SUMMARY\n\n")
    A("> *For non-technical readers and decision-makers.*\n\n")

    if n_crit > 0:
        posture = f"🔴 CRITICAL — Immediate Action Required"
        _xsev = stats.get("exploited_by_severity") or {}
        _x_ch = int(_xsev.get("critical", 0)) + int(_xsev.get("high", 0))
        posture_text = (
            f"The automated assessment of **{host}** reported {n_crit} critical and {n_high} high severity "
            f"findings; {_x_ch} of them were exploited during the test (proof on file)."
        )
    elif n_high > 0:
        posture = f"🟠 HIGH — Urgent Remediation Required"
        posture_text = (
            f"The system tested (**{host}**) has significant security weaknesses. "
            f"{n_high} high severity vulnerabilities were identified requiring urgent attention."
        )
    elif int(stats.get("medium", 0) or 0) or int(stats.get("low", 0) or 0):
        posture = "🟡 MEDIUM — Security Improvements Needed"
        posture_text = (
            f"The system tested (**{host}**) has moderate security issues that should be addressed."
        )
    else:
        posture = "⚪ NO SIGNIFICANT FINDING — in the tested scope"
        posture_text = (
            f"No weakness above informational was reported in the tested scope of **{host}**; this is not a "
            "proof that none exists."
        )

    A(f"### Overall Security Posture: {posture}\n\n")
    A(f"{posture_text}\n\n")

    # Top 3 critical findings in plain language
    top3 = [v for v in vulns if str(v.get("severity","")).lower() == "critical"][:3]
    if top3:
        A("### Most Critical Issues\n\n")
        for i, v in enumerate(top3, 1):
            desc = (v.get("description") or "").strip()
            plain = desc[:200] + "..." if len(desc) > 200 else desc
            A(f"**{i}. {_md_inline(v.get('title',''))}**  \n{_md_prose(plain)}\n\n")

    A("### Required Actions\n\n")
    A("Order derived from the reported severity and the proof of the findings below; the deadlines are set by "
      "the system owner.\n\n")
    A("| Order | Action |\n|-------|--------|\n")
    _order = 0
    for _sk in ("critical", "high", "medium", "low"):
        _n = int(stats.get(_sk, 0) or 0)
        if not _n:
            continue
        _order += 1
        _nx = int((stats.get("exploited_by_severity") or {}).get(_sk, 0) or 0)
        A(f"| **{_order}** | Treat the {_n} {_sk} severity finding(s) ({_nx} exploited during the test) |\n")
    if _order:
        A(f"| **{_order + 1}** | Run a new full campaign to check the fixes |\n\n---\n\n")
    else:
        A("| **1** | No finding to treat in the tested scope |\n\n---\n\n")

    # ── EXECUTIVE SUMMARY ───────────────────────────────────────────
    A("## 1. EXECUTIVE SUMMARY\n\n")
    if executive_summary:
        A("> " + _md_prose(executive_summary).replace("\n", "\n> ") + "\n\n")
    A(f"**Overall Risk Level: {overall_risk}**\n\n")
    A("### Findings Summary\n\n")
    A("| Severity | Count | Exploited | Confirmed |\n|----------|-------|-----------|----------|\n")
    for s, label in [("critical","CRITICAL"),("high","HIGH"),("medium","MEDIUM"),("low","LOW"),("info","INFO")]:
        n   = stats.get(s, 0)
        exp = sum(1 for v in counted if str(v.get("severity","")).lower()==s and v.get("status")=="exploited")
        con = sum(1 for v in counted if str(v.get("severity","")).lower()==s and v.get("status")=="confirmed")
        A(f"| {label} | {n} | {exp} | {con} |\n")
    A(f"| **TOTAL** | **{n_total}** | **{exploited}** | **{confirmed}** |\n\n---\n\n")

    # ── FINDINGS TABLE ───────────────────────────────────────────────
    A("## 2. FINDINGS TABLE\n\n")
    A("| # | ID | Title | Severity | CVSS | Status | Endpoint |\n")
    A("|---|-----|-------|----------|------|--------|----------|\n")
    for i, v in enumerate(vulns):
        cvss  = _cvss_shown(v)[0]
        ep    = (v.get("endpoint") or "").replace("https://","").replace("http://","")
        ep    = ep[:50]+"..." if len(ep)>50 else ep
        title = v.get("title","")[:50]+"..." if len(v.get("title",""))>50 else v.get("title","")
        A(f"| {i+1} | {_md_code(v.get('id',''))} | {_md_inline(title, cell=True)} | {sev(v)} | {cvss} | {stat(v)} | {_md_code(ep)} |\n")
    A("\n---\n\n")

    # ── VULNERABILITY DETAILS ────────────────────────────────────────
    A("## 3. VULNERABILITY DETAILS\n\n")
    for i, v in enumerate(vulns):
        cvss_score = _cvss_shown(v)[1]
        cvss_vec   = v.get("cvss_vector") or "N/A"
        ev         = v.get("evidence") if isinstance(v.get("evidence"), dict) else {}
        commands   = ev.get("commands") or []
        raw_req    = str(ev.get("raw_request") or "").strip()
        raw_resp   = str(ev.get("raw_response") or "").strip()
        logs       = ev.get("logs") or []
        expl       = str(ev.get("explanation") or "").strip()
        remediation = str(v.get("remediation") or "").strip()
        ep         = v.get("endpoint","N/A")
        ep_d       = ep[:70]+"..." if len(ep)>70 else ep

        A(f"---\n\n### 3.{i+1} — {_md_inline(v.get('title',''))}\n\n")
        A("| Field | Value |\n|-------|-------|\n")
        A(f"| **ID** | {_md_code(v.get('id',''))} |\n")
        A(f"| **Severity** | {sev(v)} |\n")
        A(f"| **CVSS Score** | {cvss_score} |\n")
        A(f"| **CVSS Vector** | {_md_code(cvss_vec)} |\n")
        A(f"| **Status** | {_md_inline(str(v.get('status','')).upper(), cell=True)} |\n")
        A(f"| **Category** | {_md_code(v.get('category','N/A'))} |\n")
        if v.get("mitre_attack_id"):
            A(f"| **MITRE ATT&CK** | {_md_code(v['mitre_attack_id'])} — {_md_inline(v.get('mitre_attack_name',''), cell=True)} |\n")
        if v.get("iso27001_control"):
            A(f"| **ISO 27001** | {_md_code(v['iso27001_control'])} |\n")
        try:   # IEC 62443-3-3 requirement(s) concerned, derived by the server (same rules as the framework mapping)
            from api.frameworks import iec62443_refs
            _iec = ", ".join(r["sr"] for r in iec62443_refs(v))
        except Exception:
            _iec = ""
        if _iec:
            A(f"| **IEC 62443-3-3** | {_md_code(_iec)} |\n")
        A(f"| **Endpoint** | {_md_code(ep_d)} |\n")
        if v.get("plugin_or_component"):
            A(f"| **Component** | {_md_inline(v['plugin_or_component'], cell=True)} |\n")
        A(f"| **Discovered by** | {_md_code(v.get('discovered_by_agent','N/A'))} |\n")
        A(f"| **Discovered at** | {_md_inline(v.get('discovered_at','N/A'), cell=True)} |\n\n")

        desc = (v.get("description") or "").strip()
        if desc: A(f"#### Description\n\n{_md_prose(desc)}\n\n")
        if expl: A(f"#### Technical Analysis\n\n{_md_prose(expl)}\n\n")
        # raw target data: the fence is longer than any backtick run inside it
        if commands:
            A("#### Exploitation Commands\n\n" + _md_fence("\n".join(str(c)[:500] for c in commands), "bash"))
        if raw_req:  A("#### Raw Request\n\n" + _md_fence(raw_req[:600], "http"))
        if raw_resp: A("#### Raw Response\n\n" + _md_fence(raw_resp[:600], "http"))
        if logs:
            A("#### Evidence / Logs\n\n" + _md_fence("\n".join(str(l)[:500] for l in logs)))
        A(f"#### Remediation\n\n{_md_prose(remediation) if remediation else '> Not specified — contact the security team.'}\n\n")

    if held:
        A("---\n\n> **Held for review:** " + str(len(held)) + " finding(s) are not included in this report: "
          "they are held by the privacy policy until an operator reviews them.\n\n")

    # ── REMEDIATION ROADMAP ──────────────────────────────────────────
    A("---\n\n## 4. REMEDIATION ROADMAP\n\n")
    A("Grouped by reported severity; the deadlines are set by the system owner.\n\n")
    for priority, sev_key, timeframe, max_items in [
        ("P0", "critical", "Critical findings", 6),
        ("P1", "high",     "High findings",     6),
        ("P2", "medium",   "Medium findings",   5),
        ("P3", "low",      "Low findings",      3),
    ]:
        items = [v for v in vulns if str(v.get("severity","")).lower()==sev_key][:max_items]
        if not items: continue
        A(f"### {priority} — {timeframe}\n\n| Finding | Proof |\n|---------|-------|\n")
        for v in items:
            t = v.get("title","")[:60]+"..." if len(v.get("title",""))>60 else v.get("title","")
            A(f"| {_md_inline(t, cell=True)} | {stat(v)} |\n")
        A("\n")

    # ── REPORT ANNEX (computed from the campaign's own data) ─────────
    # Darkmoon Pro shows these sections next to the report in its dashboard; Community
    # has no dashboard, so they are part of the report file. Advisory: a failure leaves
    # the report without them rather than failing the finalisation.
    try:
        from api.report_annex_local import annex_markdown
        annex = annex_markdown(campaign_id, campaign, stored_order)
    except Exception:
        logging.getLogger("darkmoon.report").warning("report annex skipped", exc_info=True)
        annex = ""
    if annex:
        A("---\n\n" + annex.rstrip("\n") + "\n\n")

    A("---\n\n")
    A(f"*Report auto-generated by Darkmoon AI Security Platform*  \n")
    A(f"*Classification: CONFIDENTIAL — Restricted to authorized personnel*  \n")
    A(f"*Generated: {now}*  \n")
    A(f"*Campaign: {campaign_id} | Target: {host}*\n")

    return "".join(L)


# -----------------------------------------------------------------------
# 4. Finalize campaign
# -----------------------------------------------------------------------

def _measured_duration(campaign: Dict[str, Any], declared: Any) -> int:
    """Wall-clock seconds since the campaign was initialised (server clock); the duration the agent declares is
    only a fallback (the DVGA run of 62 min was finalised with the docstring's example value, 900 s)."""
    try:
        start = datetime.fromisoformat(str(campaign.get("date") or "").replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        measured = int((datetime.now(timezone.utc) - start).total_seconds())
        if measured > 0:
            return measured
    except (ValueError, TypeError):
        pass
    try:
        return max(0, int(declared or 0))
    except (ValueError, TypeError):
        return 0


def _finalize_campaign_unlocked(
    campaign_id: str,
    duration_seconds: int = 0,
    executive_summary: str = "",
    report_markdown: Optional[str] = None,
    agents_dispatched: Optional[List[Dict[str, Any]]] = None,
    final_status: str = "completed",
    rehydrate: Optional[Callable[[str], str]] = None,
) -> Dict[str, Any]:
    """
    Finalize a campaign and preserve the intended terminal status.
    Sub-agents must NOT overwrite the orchestrator's final report with partial content.
    """
    campaign = load_campaign(campaign_id)
    if not campaign:
        return {"error": f"Campaign {campaign_id} not found"}

    # Guard: if a good report (>10KB) already exists, never overwrite with shorter content.
    # This prevents sub-agents (headless-browser, php, etc.) from replacing the
    # orchestrator's full report with their own partial mini-report.
    existing_report_path = campaign.get("report_path", "")
    if existing_report_path:
        try:
            existing_content = load_report_content(existing_report_path) or ""
            if (existing_content
                    and len(existing_content) > 10000
                    and report_markdown is not None
                    and len(str(report_markdown).strip()) < len(existing_content)):
                # Sub-agent or secondary call with shorter content — preserve existing report.
                campaign["duration_seconds"] = max(
                    campaign.get("duration_seconds", 0), duration_seconds)
                if executive_summary:
                    campaign["executive_summary"] = executive_summary
                save_campaign(campaign)
                return {
                    "campaign_id": campaign_id,
                    "status": campaign.get("status", "running"),
                    "total_findings": campaign.get("stats", {}).get("total_findings", 0),
                    "overall_risk": campaign.get("overall_risk"),
                    "report_path": campaign.get("report_path", ""),
                }
        except Exception:
            pass

    normalized_status = _normalize_campaign_status(final_status)
    campaign["status"] = normalized_status
    campaign["duration_seconds"] = _measured_duration(campaign, duration_seconds)
    from api import coverage_signals
    coverage_signals.on_close(campaign)
    campaign["executive_summary"] = executive_summary

    if agents_dispatched:
        campaign["agents_dispatched"] = agents_dispatched
        cascade_depth = max((a.get("level", 0) for a in agents_dispatched), default=0)
        campaign["cascade_depth"] = cascade_depth

    # Detect if agent passed a file path / reference instead of actual content.
    # This happens when the agent says "See full report at /output/..." instead
    # of passing the actual markdown. In that case, auto-generate from the DB.
    # DEFINITIVE FIX (deterministic reports): the report BODY is ALWAYS generated
    # server-side from the stored findings, complete by construction. We never trust an
    # LLM-provided report_markdown for the body — it is non-deterministic and has produced
    # condensed/incomplete reports. The LLM's executive_summary (above) is still used.
    _is_reference = True  # always regenerate from DB, ignore any LLM-provided body

    if _is_reference:
        # Auto-generate the report from the DB findings
        report_markdown = _generate_report_from_db(campaign_id, campaign, executive_summary)

    # Restore real values before the local, CONFIDENTIAL report is written. Findings
    # are stored with placeholders (the model only ever sees those), so a
    # DB-generated report is full of IP_PRIVATE_001/DOMAIN_001/HOST_INTERNAL_001/...
    # until here. Rehydrating at the single write point covers both the
    # DB-generated body and the (unused) LLM-provided one.
    if rehydrate is not None and report_markdown:
        report_markdown = rehydrate(report_markdown)

    if report_markdown:
        target_id = campaign.get("target_id", "unknown")
        target = load_target(target_id)
        host = target.get("host", target_id) if target else target_id
        if rehydrate is not None and host:
            host = rehydrate(host)
        # filename-safe slug: a rehydrated host may be a URL (http://h:port) with
        # "/" and ":" that would break the report path. The report body keeps real values.
        host = re.sub(r"[^A-Za-z0-9._-]", "_", str(host)).strip("_")[:80] or "target"
        fname = f"pentest_report_{host}_{_today_compact()}-{_time_compact()}.md"
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / fname).write_text(report_markdown, encoding="utf-8")
        campaign["report_path"] = f"/reports/{fname}"

    save_campaign(campaign)

    # Growth signals (local, privacy-first, opt-out). This records only the
    # milestone *type* + timestamps/counts — never a target, host, finding or
    # campaign id — and powers the one-time Community star CTA. Fully guarded:
    # a growth error must never affect finalize. Honours DARKMOON_NO_TELEMETRY.
    try:
        if normalized_status == "completed":
            from api import growth
            growth.record_milestone("campaign_finalized")
            _stats = campaign.get("stats", {}) or {}
            if int(_stats.get("exploited", 0) or 0) > 0 or int(_stats.get("confirmed", 0) or 0) > 0:
                growth.record_milestone("validated_finding")
            if campaign.get("report_path"):
                growth.record_milestone("report_generated")
    except Exception:
        pass

    return {
        "campaign_id": campaign_id,
        "status": normalized_status,
        "total_findings": campaign.get("stats", {}).get("total_findings", 0),
        "overall_risk": campaign.get("overall_risk"),
        "report_path": campaign.get("report_path", ""),
    }


def _abort_campaign_unlocked(campaign_id: str, duration_seconds: int = 0, executive_summary: str = "") -> Dict[str, Any]:
    """Mark a campaign as aborted."""
    return _finalize_campaign_unlocked(
        campaign_id=campaign_id,
        duration_seconds=duration_seconds,
        executive_summary=executive_summary,
        final_status="aborted",
    )


# -----------------------------------------------------------------------
# Locked entry points: every read-modify-write of the store goes through one
# cross-process lock and _write_json is atomic, so concurrent pushes from
# parallel agents never lose a finding nor truncate a file.
# -----------------------------------------------------------------------

def init_live_campaign(*args, **kwargs) -> Dict[str, str]:
    with locked("store"):
        return _init_live_campaign_unlocked(*args, **kwargs)


def push_finding(campaign_id: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    with locked("store"):
        return _push_finding_unlocked(campaign_id, finding)


def push_infra_node(campaign_id: str, node: Dict[str, Any]) -> Dict[str, Any]:
    with locked("store"):
        return _push_infra_node_unlocked(campaign_id, node)


def finalize_campaign(*args, **kwargs) -> Dict[str, Any]:
    with locked("store"):
        return _finalize_campaign_unlocked(*args, **kwargs)


def abort_campaign(campaign_id: str, duration_seconds: int = 0, executive_summary: str = "") -> Dict[str, Any]:
    with locked("store"):
        return _abort_campaign_unlocked(campaign_id, duration_seconds, executive_summary)


for _locked_fn, _impl in ((init_live_campaign, _init_live_campaign_unlocked), (push_finding, _push_finding_unlocked),
                          (push_infra_node, _push_infra_node_unlocked), (finalize_campaign, _finalize_campaign_unlocked),
                          (abort_campaign, _abort_campaign_unlocked)):
    _locked_fn.__doc__ = _impl.__doc__
