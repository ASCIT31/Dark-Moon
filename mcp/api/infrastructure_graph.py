"""
Infrastructure graph of one campaign (nodes, edges, finding attachment), built from the local store.

Taken from Darkmoon Pro's campaign view (the graph part only, no web API): the attack-path read model
(``api.attack_paths``) and the Terminal Explorer use the same nodes, edges and attachment.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from api.json_storage import load_infrastructure, load_target, load_vulnerabilities

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}

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
    """
    Accepts either:
      - int / str
      - {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.24"}
    """
    if isinstance(port, dict):
        return {
            "port": port.get("port") or port.get("number") or port.get("value"),
            "protocol": str(port.get("protocol", "tcp")).lower(),
            "service": port.get("service") or port.get("name") or "",
            "product": port.get("product") or "",
            "version": port.get("version") or "",
            "raw": port,
        }

    return {
        "port": port,
        "protocol": "tcp",
        "service": "",
        "product": "",
        "version": "",
        "raw": port,
    }


def _normalize_technology_entry(tech: Any) -> Dict[str, Any]:
    """
    Accepts either:
      - "nginx"
      - {"name": "nginx", "version": "1.24", "category": "web_server"}
    """
    if isinstance(tech, dict):
        return {
            "name": tech.get("name") or tech.get("product") or tech.get("technology") or "unknown",
            "version": tech.get("version") or "",
            "category": tech.get("category") or tech.get("type") or "technology",
            "raw": tech,
        }

    return {
        "name": str(tech),
        "version": "",
        "category": "technology",
        "raw": tech,
    }


def _build_target_stack_nodes(campaign: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build synthetic infrastructure nodes from target metadata:
    target -> os -> ports/services -> technologies
    """
    target_id = campaign.get("target_id")
    project_id = campaign.get("project_id")
    if not target_id:
        return []

    target = load_target(target_id)
    if not target:
        return []

    nodes: List[Dict[str, Any]] = []

    target_node_id = f"target_{target_id}"
    target_label = target.get("host") or target.get("ip") or target_id

    nodes.append({
        "id": target_node_id,
        "node_type": "target",
        "label": target_label,
        "title": target_label,
        "host": target.get("host"),
        "ip": target.get("ip"),
        "risk_level": target.get("risk_level", "none"),
        "status": target.get("status", "unknown"),
        "campaign_id": campaign.get("id"),
        "project_id": project_id,
        "target_id": target_id,
    })

    os_info = (target.get("os") or "").strip()
    if os_info:
        os_node_id = f"os_{target_id}_{_safe_slug(os_info)}"
        nodes.append({
            "id": os_node_id,
            "node_type": "os",
            "label": os_info,
            "title": os_info,
            "value": os_info,
            "parent_node_id": target_node_id,
            "campaign_id": campaign.get("id"),
            "project_id": project_id,
            "target_id": target_id,
        })

    for port_entry in target.get("ports", []) or []:
        port_data = _normalize_port_entry(port_entry)
        port_no = port_data.get("port")
        protocol = port_data.get("protocol") or "tcp"
        service = port_data.get("service") or ""
        product = port_data.get("product") or ""
        version = port_data.get("version") or ""

        if port_no in (None, ""):
            continue

        service_label = f"{port_no}/{protocol}"
        if service:
            service_label += f" - {service}"

        details = " ".join(part for part in [product, version] if part).strip()

        nodes.append({
            "id": f"svc_{target_id}_{port_no}_{protocol}",
            "node_type": "service",
            "label": service_label,
            "title": service_label,
            "port": port_no,
            "protocol": protocol,
            "service": service,
            "product": product,
            "version": version,
            "details": details,
            "parent_node_id": target_node_id,
            "campaign_id": campaign.get("id"),
            "project_id": project_id,
            "target_id": target_id,
        })

    for tech_entry in target.get("technologies", []) or []:
        tech = _normalize_technology_entry(tech_entry)
        name = tech.get("name", "unknown")
        version = tech.get("version", "")
        category = tech.get("category", "technology")

        label = name if not version else f"{name} {version}"

        nodes.append({
            "id": f"tech_{target_id}_{_safe_slug(name)}_{_safe_slug(version)}",
            "node_type": "technology",
            "label": label,
            "title": label,
            "name": name,
            "version": version,
            "category": category,
            "parent_node_id": target_node_id,
            "campaign_id": campaign.get("id"),
            "project_id": project_id,
            "target_id": target_id,
        })

    return nodes


def _merge_nodes(base_nodes: List[Dict[str, Any]], extra_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merge by node ID. Existing infrastructure nodes win over synthetic ones.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    for node in extra_nodes:
        node_id = node.get("id")
        if node_id:
            merged[node_id] = node

    for node in base_nodes:
        node_id = node.get("id")
        if node_id:
            merged[node_id] = node

    return list(merged.values())




def _severity_max(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 5) <= _SEV_ORDER.get(b, 5) else b


def _endpoint_host_port(ep: str):
    """(host, port as written) of an agent-written endpoint; never raises. PR 1A: a malformed port
    (``host:8080:50000``) used to make ``u.port`` raise, and the whole pair was dropped, losing the host for the node
    attachment; the host is now kept and the port kept as written (api/url_parts.py)."""
    from api.url_parts import port_text, safe_urlparse
    u = safe_urlparse(ep if ep.startswith("http") else "https://" + ep)
    return (u.hostname or "").lower(), port_text(u)


# Technology-specific attachment hints (written for OWASP Juice Shop). Only used
# when the finding carries no valid node_id, and can be switched off with
# DARKMOON_ATTACH_HEURISTICS=0. Each rule: endpoint substrings -> node keyword.
ATTACH_RULES = [
    {"name": "config", "endpoint": ("application-configuration", "/rest/admin"), "node": ("config",)},
    {"name": "ftp", "endpoint": ("/ftp",), "node": ("ftp",)},
    {"name": "jwt-keys", "endpoint": ("encryptionkeys", "jwt.pub"), "node": ("jwt", "encryptionkeys")},
    {"name": "metrics", "endpoint": ("/metrics",), "node": ("metric",)},
    {"name": "api-docs", "endpoint": ("api-docs", "swagger"), "node": ("swagger",)},
]
DB_LEAK_MARKERS = ("/rest/memories", "/api/users", "authentication-details", "password hash", "md5")


def _heuristics_enabled() -> bool:
    return os.environ.get("DARKMOON_ATTACH_HEURISTICS", "1").strip().lower() not in ("0", "false", "no", "off")


def _norm_host(value: Any) -> str:
    v = str(value or "").strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if v.startswith("["):
        return v.split("]", 1)[0].lstrip("[")
    if v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v


def _heuristic_node(vuln: Dict[str, Any], nodes_by_id) -> Optional[str]:
    ep = (vuln.get("endpoint") or "").lower()
    tx = ep + " " + (vuln.get("title") or "").lower()
    for rule in ATTACH_RULES:
        if any(k in ep for k in rule["endpoint"]):
            for n in nodes_by_id.values():
                blob = (n.get("id", "") + " " + (n.get("label") or "") + " " + (n.get("technology") or "")).lower()
                if any(k in blob for k in rule["node"]):
                    return n["id"]
    db_id = next((n["id"] for n in nodes_by_id.values()
                  if n.get("node_type") == "database"
                  or "database" in (n.get("label") or "").lower()
                  or str(n.get("id", "")).startswith("db")), None)
    if db_id and any(s in tx for s in DB_LEAK_MARKERS):
        return db_id
    return None


def _resolve_finding_node(vuln: Dict[str, Any], nodes_by_id, host_index, app_id, root_id):
    """Attach a finding to exactly one existing node (B-11). Order: the agent's
    valid node_id -> technology hints (optional) -> endpoint host:port -> host
    -> application -> root. Never invents infrastructure."""
    nid = (vuln.get("node_id") or "").strip()
    if nid and nid in nodes_by_id:
        return nid
    if _heuristics_enabled():
        hinted = _heuristic_node(vuln, nodes_by_id)
        if hinted:
            return hinted
    host, port = _endpoint_host_port((vuln.get("endpoint") or "").lower())
    if host and port and (host, port) in host_index:
        return host_index[(host, port)]
    if host and (host, None) in host_index:
        return host_index[(host, None)]
    return app_id or root_id


def _bfs(adj, a, b):
    if a == b:
        return [a]
    prev = {a: None}
    queue = [a]
    while queue:
        x = queue.pop(0)
        for y in adj.get(x, []):
            if y not in prev:
                prev[y] = x
                if y == b:
                    path = [y]
                    c = x
                    while c is not None:
                        path.insert(0, c)
                        c = prev[c]
                    return path
                queue.append(y)
    return None


def link_target_roots(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """B-07: the synthetic target node and the agent's own root(s) describe the
    same host. Link every parentless stored node whose host/ip matches the
    target to it with a `root` edge, so the graph is one tree, not two islands.
    Nodes are unchanged; only edges are added. Returns the added edges."""
    targets = [n for n in nodes if n.get("node_type") == "target" and str(n.get("id", "")).startswith("target_")]
    has_parent = {e["to"] for e in edges}
    added = []
    seen = {(e["from"], e["to"]) for e in edges}
    for t in targets:
        keys = {_norm_host(t.get("host")), _norm_host(t.get("ip"))} - {""}
        if not keys:
            continue
        for n in nodes:
            nid = n.get("id")
            if not nid or n is t or nid in has_parent or n.get("node_type") == "target":
                continue
            if n.get("parent_node_id") and any(m.get("id") == n.get("parent_node_id") for m in nodes):
                continue
            if {_norm_host(n.get("host")), _norm_host(n.get("ip"))} & keys:
                if (t["id"], nid) not in seen:
                    edge = {"from": t["id"], "to": nid, "type": "root"}
                    edges.append(edge)
                    added.append(edge)
                    seen.add((t["id"], nid))
                    has_parent.add(nid)
    return added


def _enrich_infrastructure(nodes, edges, vulns):
    """Attach every finding to one asset (node.vulnerability_ids), recompute each
    node's risk from its findings only (the agent's value is kept as
    declared_risk, B-11) and trace a path from every exposed root to each
    high/critical asset. Returns attack_paths (topology, kept for compatibility)."""
    nodes_by_id = {n["id"]: n for n in nodes if n.get("id")}
    host_index = {}
    for n in nodes:
        h = _norm_host(n.get("host"))
        if not h:
            continue
        host_index.setdefault((h, None), n["id"])
        if n.get("port"):
            host_index.setdefault((h, str(n.get("port"))), n["id"])
    app_id = next((n["id"] for n in nodes if n.get("node_type") == "application"), None)
    root_id = next((n["id"] for n in nodes if n.get("node_type") in ("target", "host")), None)

    for n in nodes:
        n["vulnerability_ids"] = []
        # review A m6: findings attached by the server rules (no valid agent node_id) are listed apart, so the UI says
        # « inferred » instead of presenting the attachment as a fact (additive, read-only)
        n["inferred_vulnerability_ids"] = []
        if "declared_risk" not in n:
            n["declared_risk"] = n.get("risk_level")
        n["risk_level"] = "none"
    assigned = set()
    for v in vulns:
        vid = v.get("id")
        if not vid or vid in assigned:
            continue
        nid = _resolve_finding_node(v, nodes_by_id, host_index, app_id, root_id)
        node = nodes_by_id.get(nid)
        if not node:
            continue
        node["vulnerability_ids"].append(vid)
        if (v.get("node_id") or "").strip() not in nodes_by_id:
            node["inferred_vulnerability_ids"].append(vid)
        assigned.add(vid)
        sev = str(v.get("severity") or "none").strip().lower()
        node["risk_level"] = _severity_max(node.get("risk_level") or "none", sev if sev in _SEV_ORDER else "none")

    adj: Dict[str, List[str]] = {n["id"]: [] for n in nodes if n.get("id")}
    incoming = set()
    for e in edges:
        if e["from"] in adj and e["to"] in adj:
            adj[e["from"]].append(e["to"])
            adj[e["to"]].append(e["from"])
            incoming.add(e["to"])
    # Entries: every root that is wired into the graph (target first).
    roots = [n["id"] for n in nodes if n.get("id") and n["id"] not in incoming and adj.get(n["id"])]
    roots.sort(key=lambda i: (nodes_by_id[i].get("node_type") != "target", i))
    if not roots and nodes:
        roots = [root_id or nodes[0]["id"]]
    paths = []
    for n in nodes:
        if not n.get("vulnerability_ids") or (n.get("risk_level") or "none") not in ("critical", "high"):
            continue
        best = None
        for entry in roots:
            if entry == n["id"]:
                continue
            p = _bfs(adj, entry, n["id"])
            if p and len(p) > 1 and (best is None or len(p) < len(best)):
                best = p
        if best:
            paths.append({"target": n["id"], "risk_level": n.get("risk_level"), "path": best})
    return paths


def build_infrastructure(campaign_id: str, campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Nodes, edges, attachment and topology paths of one campaign (shared by
    /infrastructure and /attack-paths so both use the same attachment)."""
    stored_nodes = load_infrastructure(campaign_id)
    synthetic_nodes = _build_target_stack_nodes(campaign)
    nodes = _merge_nodes(stored_nodes, synthetic_nodes)

    edge_type_map = {
        "service": "contains",
        "application": "runs",
        "plugin": "plugin",
        "theme": "theme",
        "endpoint": "endpoint",
        "tool_exposed": "exposed",
        "file_exposed": "exposed",
        "service_internal": "internal_service",
        "os": "runs_on",
        "technology": "stack",
        "target": "root",
    }

    edges = []
    seen_edges = set()
    valid_node_ids = {n["id"] for n in nodes if n.get("id")}

    for node in nodes:
        parent = node.get("parent_node_id")
        node_id = node.get("id")
        if parent and node_id:
            if parent not in valid_node_ids:
                continue
            edge_type = edge_type_map.get(node.get("node_type", ""), "contains")
            edge_key = (parent, node_id, edge_type)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                edges.append({"from": parent, "to": node_id, "type": edge_type})

    link_target_roots(nodes, edges)
    vulns = load_vulnerabilities(campaign_id)
    attack_paths = _enrich_infrastructure(nodes, edges, vulns)
    return {"nodes": nodes, "edges": edges, "attack_paths": attack_paths, "vulnerabilities": vulns}


