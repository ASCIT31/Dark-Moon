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

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_OPENCODE_DB = Path.home() / ".local" / "share" / "opencode" / "opencode-dev.db"


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

def init_live_campaign(
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
) -> Dict[str, str]:
    """
    Initialize a live campaign. Creates project + target + campaign skeleton.
    Rule: 1 project = 1 target.
    """
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
        infra_path = INFRASTRUCTURE_DIR / f"{parent_campaign_id}.json"
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

    campaign_id = f"camp_{today}_{session_id}"

    campaign = {
        "id": campaign_id,
        "project_id": project_id,
        "target_id": target_id,
        "session_id": session_id,
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
    save_campaign(campaign)

    # Only init empty vulns if file doesn't exist yet
    vuln_path = VULNERABILITIES_DIR / f"{campaign_id}.json"
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
    infra_path = INFRASTRUCTURE_DIR / f"{campaign_id}.json"
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

def push_finding(
    campaign_id: str,
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Push a single vulnerability finding to the dashboard.
    Appends to the campaign's vulnerabilities file and updates stats.
    """
    vuln_path = VULNERABILITIES_DIR / f"{campaign_id}.json"
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

    vulns.append(finding)
    _write_json(vuln_path, vulns)

    stats = campaign.get("stats", {})
    stats["total_findings"] = len(vulns)

    for sev in ("critical", "high", "medium", "low", "info"):
        stats[sev] = sum(
            1 for v in vulns
            if str(v.get("severity", "info")).strip().lower() == sev
        )

    for st in ("exploited", "confirmed", "unconfirmed"):
        stats[st] = sum(
            1 for v in vulns
            if str(v.get("status", "unconfirmed")).strip().lower() == st
        )

    campaign["stats"] = stats

    if stats.get("critical", 0) > 0:
        campaign["overall_risk"] = "critical"
    elif stats.get("high", 0) > 0:
        campaign["overall_risk"] = "high"
    elif stats.get("medium", 0) > 0:
        campaign["overall_risk"] = "medium"
    elif stats.get("low", 0) > 0:
        campaign["overall_risk"] = "low"
    else:
        campaign["overall_risk"] = "none"

    save_campaign(campaign)

    target_id = campaign.get("target_id")
    if target_id:
        target = load_target(target_id)
        if target:
            target["risk_level"] = campaign["overall_risk"]
            target["status"] = "vulnerable" if stats.get("exploited", 0) == 0 else "compromised"
            target["last_seen"] = _now_iso()
            save_target(target)

    return {
        "vuln_id": finding["id"],
        "campaign_id": campaign_id,
        "total_findings": len(vulns),
        "status": "finding_pushed",
    }


# -----------------------------------------------------------------------
# 3. Push an infrastructure node — incremental
# -----------------------------------------------------------------------

def push_infra_node(
    campaign_id: str,
    node: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Push a single infrastructure node to the dashboard.
    Appends to the campaign's infrastructure file.
    Also links the node to campaign + project + target.
    """
    infra_path = INFRASTRUCTURE_DIR / f"{campaign_id}.json"
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
# 4. Report auto-generator (called when agent passes a path/reference)
# -----------------------------------------------------------------------

def _generate_report_from_db(
    campaign_id: str,
    campaign: Dict[str, Any],
    executive_summary: str = "",
) -> str:
    """
    Generate a full markdown report directly from the DB findings.
    Called automatically by finalize_campaign when the agent passes a file
    path or short reference instead of the actual report content.
    """
    from api.json_storage import VULNERABILITIES_DIR

    vuln_path = VULNERABILITIES_DIR / f"{campaign_id}.json"
    vulns: List[Dict[str, Any]] = _read_json(vuln_path) or []

    target_id = campaign.get("target_id", "unknown")
    target = load_target(target_id)
    host = target.get("host", target_id) if target else target_id

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(
        vulns,
        key=lambda v: (SEV_ORDER.get(str(v.get("severity", "info")).lower(), 9),
                       -float(v.get("cvss_score") or 0)),
    )

    SEV_LABEL  = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                  "low": "LOW", "info": "INFO"}
    STAT_LABEL = {"exploited": "**EXPLOITED**", "confirmed": "Confirmed",
                  "unconfirmed": "Unconfirmed"}

    def sev(v: Dict) -> str:
        return SEV_LABEL.get(str(v.get("severity", "")).lower(), str(v.get("severity", "")).upper())

    def stat(v: Dict) -> str:
        return STAT_LABEL.get(str(v.get("status", "")).lower(), str(v.get("status", "")))

    stats = campaign.get("stats", {})
    exploited = stats.get("exploited", 0)
    confirmed = stats.get("confirmed", 0)
    now = _now_iso()

    L: List[str] = []
    A = L.append

    # ── MANAGEMENT SUMMARY ──────────────────────────────────────────
    overall_risk = campaign.get("overall_risk", "unknown").upper()
    n_crit  = stats.get("critical", 0)
    n_high  = stats.get("high", 0)
    n_total = stats.get("total_findings", len(vulns))

    A(f"# Vulnerability Assessment Report — {host}\n\n")
    A(f"**Classification:** CONFIDENTIAL — Restricted to authorized personnel  \n")
    A(f"**Generated:** {now}  \n")
    A(f"**Target:** {host}  \n")
    A(f"**Campaign:** {campaign_id}  \n")
    A(f"**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  \n\n---\n\n")

    A("## MANAGEMENT SUMMARY\n\n")
    A("> *For non-technical readers and decision-makers.*\n\n")

    if n_crit > 0:
        posture = f"🔴 CRITICAL — Immediate Action Required"
        posture_text = (
            f"The system tested (**{host}**) presents an **extremely poor security posture**. "
            f"Our team confirmed {n_crit} critical and {n_high} high severity vulnerabilities, "
            "enabling complete compromise through multiple independent attack paths."
        )
    elif n_high > 0:
        posture = f"🟠 HIGH — Urgent Remediation Required"
        posture_text = (
            f"The system tested (**{host}**) has significant security weaknesses. "
            f"{n_high} high severity vulnerabilities were identified requiring urgent attention."
        )
    else:
        posture = "🟡 MEDIUM — Security Improvements Needed"
        posture_text = (
            f"The system tested (**{host}**) has moderate security issues that should be addressed."
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
            A(f"**{i}. {v.get('title','')}**  \n{plain}\n\n")

    A("### Required Actions\n\n")
    A("| Timeframe | Action |\n|-----------|--------|\n")
    if n_crit > 0:
        A("| **Today** | Block external access / take offline if possible |\n")
    A("| **This week** | Patch all critical and high severity findings |\n")
    A("| **2 weeks** | Address medium severity findings and security headers |\n")
    A("| **1 month** | Full code review and independent re-test |\n\n---\n\n")

    # ── EXECUTIVE SUMMARY ───────────────────────────────────────────
    A("## 1. EXECUTIVE SUMMARY\n\n")
    if executive_summary:
        A(f"> {executive_summary}\n\n")
    A(f"**Overall Risk Level: {overall_risk}**\n\n")
    A("### Findings Summary\n\n")
    A("| Severity | Count | Exploited | Confirmed |\n|----------|-------|-----------|----------|\n")
    for s, label in [("critical","CRITICAL"),("high","HIGH"),("medium","MEDIUM"),("low","LOW"),("info","INFO")]:
        n   = stats.get(s, 0)
        exp = sum(1 for v in vulns if str(v.get("severity","")).lower()==s and v.get("status")=="exploited")
        con = sum(1 for v in vulns if str(v.get("severity","")).lower()==s and v.get("status")=="confirmed")
        A(f"| {label} | {n} | {exp} | {con} |\n")
    A(f"| **TOTAL** | **{n_total}** | **{exploited}** | **{confirmed}** |\n\n---\n\n")

    # ── FINDINGS TABLE ───────────────────────────────────────────────
    A("## 2. FINDINGS TABLE\n\n")
    A("| # | ID | Title | Severity | CVSS | Status | Endpoint |\n")
    A("|---|-----|-------|----------|------|--------|----------|\n")
    for i, v in enumerate(vulns):
        cvss  = f"{v['cvss_score']:.1f}" if v.get("cvss_score") else "N/A"
        ep    = (v.get("endpoint") or "").replace("https://","").replace("http://","")
        ep    = ep[:50]+"..." if len(ep)>50 else ep
        title = v.get("title","")[:50]+"..." if len(v.get("title",""))>50 else v.get("title","")
        A(f"| {i+1} | `{v.get('id','')}` | {title} | {sev(v)} | {cvss} | {stat(v)} | `{ep}` |\n")
    A("\n---\n\n")

    # ── VULNERABILITY DETAILS ────────────────────────────────────────
    A("## 3. VULNERABILITY DETAILS\n\n")
    for i, v in enumerate(vulns):
        cvss_score = f"{v['cvss_score']:.1f}" if v.get("cvss_score") else "N/A"
        cvss_vec   = v.get("cvss_vector") or "N/A"
        ev         = v.get("evidence", {})
        commands   = ev.get("commands", [])
        raw_req    = (ev.get("raw_request") or "").strip()
        raw_resp   = (ev.get("raw_response") or "").strip()
        logs       = ev.get("logs", [])
        expl       = (ev.get("explanation") or "").strip()
        remediation = (v.get("remediation") or "").strip()
        ep         = v.get("endpoint","N/A")
        ep_d       = ep[:70]+"..." if len(ep)>70 else ep

        A(f"---\n\n### 3.{i+1} — {v.get('title','')}\n\n")
        A("| Field | Value |\n|-------|-------|\n")
        A(f"| **ID** | `{v.get('id','')}` |\n")
        A(f"| **Severity** | {sev(v)} |\n")
        A(f"| **CVSS Score** | {cvss_score} |\n")
        A(f"| **CVSS Vector** | `{cvss_vec}` |\n")
        A(f"| **Status** | {str(v.get('status','')).upper()} |\n")
        A(f"| **Category** | `{v.get('category','N/A')}` |\n")
        if v.get("mitre_attack_id"):
            A(f"| **MITRE ATT&CK** | `{v['mitre_attack_id']}` — {v.get('mitre_attack_name','')} |\n")
        if v.get("iso27001_control"):
            A(f"| **ISO 27001** | `{v['iso27001_control']}` |\n")
        A(f"| **Endpoint** | `{ep_d}` |\n")
        if v.get("plugin_or_component"):
            A(f"| **Component** | {v['plugin_or_component']} |\n")
        A(f"| **Discovered by** | `{v.get('discovered_by_agent','N/A')}` |\n")
        A(f"| **Discovered at** | {v.get('discovered_at','N/A')} |\n\n")

        desc = (v.get("description") or "").strip()
        if desc: A(f"#### Description\n\n{desc}\n\n")
        if expl: A(f"#### Technical Analysis\n\n{expl}\n\n")
        if commands:
            A("#### Exploitation Commands\n\n```bash\n")
            for cmd in commands: A(cmd[:500]+"\n")
            A("```\n\n")
        if raw_req:  A(f"#### Raw Request\n\n```http\n{raw_req[:600]}\n```\n\n")
        if raw_resp: A(f"#### Raw Response\n\n```http\n{raw_resp[:600]}\n```\n\n")
        if logs:
            A("#### Evidence / Logs\n\n```\n")
            for log in logs: A(log[:500]+"\n")
            A("```\n\n")
        A(f"#### Remediation\n\n{remediation if remediation else '> Not specified — contact the security team.'}\n\n")

    # ── REMEDIATION ROADMAP ──────────────────────────────────────────
    A("---\n\n## 4. REMEDIATION ROADMAP\n\n")
    for priority, sev_key, timeframe, max_items in [
        ("P0", "critical", "Immediate (< 24h)",       6),
        ("P1", "high",     "Short term (< 1 week)",   6),
        ("P2", "medium",   "Medium term (< 2 weeks)", 5),
        ("P3", "low",      "Long term (< 1 month)",   3),
    ]:
        items = [v for v in vulns if str(v.get("severity","")).lower()==sev_key][:max_items]
        if not items: continue
        A(f"### {priority} — {timeframe}\n\n| Finding | Effort |\n|---------|--------|\n")
        for v in items:
            t = v["title"][:60]+"..." if len(v.get("title",""))>60 else v.get("title","")
            A(f"| {t} | High |\n")
        A("\n")

    A("---\n\n")
    A(f"*Report auto-generated by Darkmoon AI Security Platform*  \n")
    A(f"*Classification: CONFIDENTIAL — Restricted to authorized personnel*  \n")
    A(f"*Generated: {now}*  \n")
    A(f"*Campaign: {campaign_id} | Target: {host}*\n")

    return "".join(L)


# -----------------------------------------------------------------------
# 4. Finalize campaign
# -----------------------------------------------------------------------

def finalize_campaign(
    campaign_id: str,
    duration_seconds: int = 0,
    executive_summary: str = "",
    report_markdown: Optional[str] = None,
    agents_dispatched: Optional[List[Dict[str, Any]]] = None,
    final_status: str = "completed",
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
    campaign["duration_seconds"] = duration_seconds
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

    if report_markdown:
        target_id = campaign.get("target_id", "unknown")
        target = load_target(target_id)
        host = target.get("host", target_id) if target else target_id
        fname = f"pentest_report_{host}_{_today_compact()}-{_time_compact()}.md"
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / fname).write_text(report_markdown, encoding="utf-8")
        campaign["report_path"] = f"/reports/{fname}"

    save_campaign(campaign)

    return {
        "campaign_id": campaign_id,
        "status": normalized_status,
        "total_findings": campaign.get("stats", {}).get("total_findings", 0),
        "overall_risk": campaign.get("overall_risk"),
        "report_path": campaign.get("report_path", ""),
    }


def abort_campaign(campaign_id: str, duration_seconds: int = 0, executive_summary: str = "") -> Dict[str, Any]:
    """Mark a campaign as aborted."""
    return finalize_campaign(
        campaign_id=campaign_id,
        duration_seconds=duration_seconds,
        executive_summary=executive_summary,
        final_status="aborted",
    )
