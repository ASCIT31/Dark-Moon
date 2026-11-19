"""Zone of an infrastructure asset (darkmoon-zones/v1): ONE rule for every map.

Internet -> edge -> applications -> data & secrets (+ tooling). The
server owns the classification: the node type first, and, for an asset that is not a host, what it holds (its
label or id names a database, a secret store, a backup...). Pure, no I/O.
"""
import re
from typing import Any, Dict

ZONES_VERSION = "darkmoon-zones/v1"
ZONES = ("internet", "edge", "app", "data", "tooling")
ZONE_LABELS = {"internet": "Internet", "edge": "Edge", "app": "Application", "data": "Data", "tooling": "Tooling"}

_BY_TYPE = {
    "target": "internet", "host": "internet", "ip": "internet", "cloud": "internet", "os": "internet", "domain": "internet",
    "service": "edge", "firewall": "edge", "load_balancer": "edge", "router": "edge", "switch": "edge", "vpn": "edge",
    "tls": "edge", "endpoint": "edge", "file_exposed": "edge",
    "application": "app", "api": "app", "cms": "app", "plugin": "app", "theme": "app", "service_internal": "app",
    "container": "app", "kubernetes": "app", "technology": "app",
    "database": "data", "auth": "data", "ldap": "data", "domain_controller": "data",
    "tool_exposed": "tooling", "iot_device": "tooling",
}
_DATA_HINT = re.compile(
    r"\b(db|database|data ?store|secrets?|keys?|credentials?|passwords?|vault|backups?|repositor(y|ies)|buckets?|storage)\b",
    re.IGNORECASE)
_HOSTS = {"target", "host", "ip", "domain"}


def zone_of_type(node_type: Any) -> str:
    return _BY_TYPE.get(str(node_type or ""), "tooling")


def zone_of_node(node: Dict[str, Any]) -> str:
    """Zone of one node: its type, then « data » when a non-host asset names what it holds."""
    by_type = zone_of_type(node.get("node_type"))
    if by_type == "data":
        return "data"
    text = f"{node.get('label') or ''} {re.sub(r'[-_]', ' ', str(node.get('id') or ''))}"
    if _DATA_HINT.search(text) and str(node.get("node_type") or "") not in _HOSTS:
        return "data"
    return by_type


def ring_of_zone(zone: str) -> int:
    """Orbital ring of a zone: 0 data & secrets, 1 applications, 2 internet-facing (edge and tooling included)."""
    return 0 if zone == "data" else 1 if zone == "app" else 2
