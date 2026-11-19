"""
Darkmoon — INFERRED attack paths (provenance ``inferred``, always ``hypothesis: true``).

The three proven provenances (declared, derived, observed) only keep a path when the campaign data proves each
link. Many campaigns hold serious, confirmed findings (an unauthenticated RCE matched on the runtime version, an
unvalidated upload, a session fixation…) whose evidence proves the weakness but not what an attacker gains with
it: they have no proven path at all. This module adds a separate, clearly labelled layer of POSSIBLE paths,
deduced with fixed, documented rules from the campaign's own data only:

- the real topology (infrastructure nodes, ``parent_node_id``, ``port``, ``node_type``, ``technology``);
- the real findings (category, title, severity, status) attached to those nodes by the server
  (``vulnerability_ids``, same attachment as /infrastructure).

Nothing is invented: no node, no finding, no edge outside the parent chain. Every path is a hypothesis: it is
never ranked, never counted as proven, never part of the insights or of « Fix first » (all of them already
exclude ``hypothesis`` records). docs/ATTACK-PATHS-INFERRED.md documents the rules.

Rules (one rule per finding, first match wins, in this order; unconfirmed findings never qualify; a finding
already on a proven path is never repeated as a hypothesis):

=========  ===============================================  ============================================
rule       qualifying finding (status exploited/confirmed)   objective
=========  ===============================================  ============================================
I-EXEC     code-execution category (severity >= medium) or   the host the node runs on (nearest ``host``
           a title naming code execution (severity >= high); ancestor, else ``target``), else the node
           an upload (>= medium) only when its title says
           the content was executed
I-CRED     authentication bypass / broken authentication /   the host when the node or one of its
           JWT / default, weak or hard-coded credentials /   ancestors is a remote-access service
           privilege escalation (>= medium), a disclosure    (ssh, rdp, telnet, winrm, smb, vnc),
           naming credentials or keys (>= high), or a title  else the node (account access)
           naming an authentication bypass, account
           takeover or impersonation (>= high)
I-SESSION  session fixation / hijacking (>= medium)          the node (a user's session, needs the
                                                             victim's action)
I-DATA     injection / traversal / XXE / IDOR / broken       the single database node of the same host
           access control / sensitive data / SSRF (>= high,  when the topology has exactly one, else the
           or exploited and >= medium)                       node (application data)
I-UPLOAD   unvalidated file upload (>= medium) whose title   the node (attacker-controlled files stored;
           does not show execution                           execution not shown)
=========  ===============================================  ============================================

Path shape: entry = the outermost node of the finding's parent chain below its host/target (the exposed service
or application; its ``port`` is named), one ``hop`` step per topology level down to the finding's node, one
``exploit`` step (the qualifying findings of that node, as alternatives), then one ``objective`` step when the
objective is another node. Exposure and hop steps need no finding (``satisfied_by: []``).

Pure functions, no I/O. Free text goes through ``attack_chains.redact_text``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from api.attack_chains import redact_text
from api.attack_paths_observed import ancestors_of, severity_of

PROVENANCE = "inferred"
MAX_INFERRED_PATHS = 40
_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
_PROVEN_STATUSES = ("exploited", "confirmed")

RULES: Dict[str, Dict[str, str]] = {
    "I-EXEC": {"label": "Code execution", "capability": "code execution"},
    "I-CRED": {"label": "Credentials or authentication bypass", "capability": "account access"},
    "I-SESSION": {"label": "Session takeover", "capability": "user session takeover (needs a victim's action)"},
    "I-DATA": {"label": "Data access", "capability": "application data access"},
    "I-UPLOAD": {"label": "Unvalidated file upload", "capability": "attacker-controlled files stored (execution not shown)"},
}
_RULE_ORDER = {r: i for i, r in enumerate(RULES)}

_EXEC_CATS = {"remote_code_execution", "rce", "command_injection", "os_command_injection", "code_injection", "ssti",
              "server_side_template_injection", "template_injection", "insecure_deserialization", "deserialization"}
_EXEC_TITLE = re.compile(r"\b(rce|remote code execution|command injection|code execution|web ?shell)\b", re.I)
# an upload reaches I-EXEC only when its title states that the uploaded content RAN; « webshell accepted » does not
_UPLOAD_EXEC_TITLE = re.compile(r"\b(rce|remote code execution|code execution|executed|execution)\b", re.I)
_UPLOAD_CATS = {"file_upload", "unrestricted_file_upload", "arbitrary_file_upload", "insecure_file_upload"}
_CRED_CATS = {"authentication_bypass", "broken_authentication", "jwt", "default_credentials", "weak_credentials",
              "hardcoded_credentials", "credential_exposure", "credentials_exposure", "exposed_credentials",
              "weak_password", "privilege_escalation"}
_DISCLOSURE_CATS = {"information_disclosure", "sensitive_data_exposure", "file_exposure", "file_disclosure"}
_TAKEOVER_TITLE = re.compile(r"authentication bypass|auth bypass|login bypass|account takeover|impersonation", re.I)
_CRED_TITLE = re.compile(r"\b(credentials?|passwords?|private keys?|api[ _-]?keys?|secret keys?|access tokens?)\b|\.env\b", re.I)
_SESSION_TITLE = re.compile(r"fixation|hijack", re.I)
_DATA_CATS = {"sql_injection", "nosql_injection", "path_traversal", "lfi", "local_file_inclusion", "xxe",
              "file_disclosure", "file_exposure", "idor", "broken_access_control", "sensitive_data_exposure", "ssrf"}
_REMOTE_ACCESS = re.compile(r"\b(ssh|rdp|telnet|winrm|smb|vnc|remote desktop)\b", re.I)
_REMOTE_PORTS = {22, 23, 445, 3389, 5900, 5985, 5986}
_DATABASE = re.compile(r"mysql|mariadb|postgres|sqlite|mongo|redis|mssql|sql server|oracle db|elasticsearch", re.I)
_DB_NODE_TYPES = {"service", "service_internal", "application", "database", "datastore"}

NOTE = ("Inferred path, not proven: deduced from the infrastructure topology and the confirmed findings of this "
        "campaign by rule {rule} ({label}). The campaign evidence does not show this chain end to end.")


def _red(text: Any, limit: int = 300) -> str:
    return redact_text(text, limit)[0]


def _cat(v: Dict[str, Any]) -> str:
    return re.sub(r"[\s-]+", "_", str(v.get("category") or "").strip().lower())


def _status(v: Dict[str, Any]) -> str:
    return str(v.get("status") or "unconfirmed").strip().lower()


def _sev_at_least(v: Dict[str, Any], level: str) -> bool:
    return _SEV.get(severity_of(v.get("severity")), 9) <= _SEV[level]


def classify(v: Dict[str, Any]) -> Optional[str]:
    """The inference rule a finding qualifies for (None when it drives no inferred path)."""
    if _status(v) not in _PROVEN_STATUSES:
        return None                        # an unconfirmed finding never starts an inferred path
    cat, title = _cat(v), str(v.get("title") or "")
    if cat in _UPLOAD_CATS:
        if not _sev_at_least(v, "medium"):
            return None
        return "I-EXEC" if _UPLOAD_EXEC_TITLE.search(title) else "I-UPLOAD"
    if (cat in _EXEC_CATS and _sev_at_least(v, "medium")) or (_EXEC_TITLE.search(title) and _sev_at_least(v, "high")):
        return "I-EXEC"
    if (cat in _CRED_CATS and _sev_at_least(v, "medium")) or (
            cat in _DISCLOSURE_CATS and _CRED_TITLE.search(title) and _sev_at_least(v, "high")) or (
            _TAKEOVER_TITLE.search(title) and _sev_at_least(v, "high")):
        return "I-CRED"
    if (cat == "session_fixation" or (cat.startswith("session") and _SESSION_TITLE.search(title))) and _sev_at_least(v, "medium"):
        return "I-SESSION"
    if cat in _DATA_CATS and (_sev_at_least(v, "high") or (_status(v) == "exploited" and _sev_at_least(v, "medium"))):
        return "I-DATA"
    return None


def _ntype(n: Optional[Dict[str, Any]]) -> str:
    return str((n or {}).get("node_type") or "").strip().lower()


def _port(n: Dict[str, Any]) -> Optional[int]:
    try:
        p = int(n.get("port"))
    except (TypeError, ValueError):
        return None
    return p if 0 < p < 65536 else None


def _host_of(node_id: str, nodes: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Nearest ``host`` on the parent chain (the node itself included), else the nearest ``target``."""
    chain = [node_id] + ancestors_of(node_id, nodes)
    return next((x for x in chain if _ntype(nodes.get(x)) == "host"), None) or \
        next((x for x in chain if _ntype(nodes.get(x)) == "target"), None)


def _entry_chain(node_id: str, nodes: Dict[str, Dict[str, Any]]) -> List[str]:
    """Parent chain from the outermost exposed node below the host/target down to the finding's node."""
    chain = list(reversed(ancestors_of(node_id, nodes))) + [node_id]
    while len(chain) > 1 and _ntype(nodes.get(chain[0])) in ("host", "target"):
        chain.pop(0)
    return chain


def _database_of(host_id: Optional[str], nodes: Dict[str, Dict[str, Any]]) -> Optional[str]:
    if not host_id:
        return None
    dbs = [n["id"] for n in nodes.values()
           if _ntype(n) in _DB_NODE_TYPES and host_id in ancestors_of(n["id"], nodes)
           and _DATABASE.search(f"{n.get('label') or ''} {n.get('technology') or ''}")]
    return dbs[0] if len(dbs) == 1 else None


def _remote_access(chain: List[str], nodes: Dict[str, Dict[str, Any]]) -> bool:
    for x in chain:
        n = nodes.get(x) or {}
        if _port(n) in _REMOTE_PORTS or _REMOTE_ACCESS.search(f"{n.get('label') or ''} {n.get('technology') or ''}"):
            return True
    return False


def _objective(rule: str, node_id: str, nodes: Dict[str, Dict[str, Any]]) -> Tuple[str, str]:
    """(objective node id, what is gained there)."""
    host = _host_of(node_id, nodes)
    if rule == "I-EXEC":
        return (host, "code execution on the host") if host else (node_id, "code execution in this asset")
    if rule == "I-CRED":
        chain = [node_id] + ancestors_of(node_id, nodes)
        if host and _remote_access(chain, nodes):
            return host, "remote login on the host"
        return node_id, RULES[rule]["capability"]
    if rule == "I-DATA":
        db = _database_of(host, nodes)
        return (db, "database read") if db and db != node_id else (node_id, RULES[rule]["capability"])
    return node_id, RULES[rule]["capability"]


def _label(nodes: Dict[str, Dict[str, Any]], node_id: str) -> str:
    n = nodes.get(node_id) or {}
    return _red(n.get("label") or n.get("host") or node_id, 160)


def _lead_key(v: Dict[str, Any]) -> tuple:
    try:
        cvss = float(v.get("cvss_score") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return (_SEV.get(severity_of(v.get("severity")), 9), 0 if _status(v) == "exploited" else 1,
            -(cvss if cvss == cvss else 0.0), str(v["id"]))


def derive_inferred(nodes_list: List[Dict[str, Any]], live: List[Dict[str, Any]], attached: Dict[str, str],
                    proven_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Inferred path records (engine record shape of attack_paths._analyse) + issues.

    ``live`` = the campaign's live findings (false positives, remediated and quarantined already removed);
    ``attached`` = finding id -> node id (server attachment); ``proven_records`` = the declared/derived/observed
    records: a finding already on a PROVEN path is not repeated as a hypothesis."""
    nodes = {n["id"]: n for n in nodes_list if isinstance(n, dict) and n.get("id")}
    covered: Set[str] = {x for r in proven_records if not r.get("hypothesis")
                         for st in r["steps"] for a in st["satisfied_by"] for x in a}

    groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    unattached: List[str] = []
    for v in sorted(live, key=lambda x: str(x["id"])):
        rule = classify(v)
        if not rule:
            continue
        fid = str(v["id"])
        node_id = attached.get(fid)
        if not node_id or node_id not in nodes:
            unattached.append(fid)       # no real node: no inferred path (nothing is placed by guess)
            continue
        if fid in covered:
            continue                      # already on a proven path: that path describes it
        obj, gained = _objective(rule, node_id, nodes)
        g = groups.setdefault((rule, node_id, obj), {"rule": rule, "node_id": node_id, "objective": obj,
                                                     "gained": gained, "findings": []})
        g["findings"].append(v)

    records: List[Dict[str, Any]] = []
    for (rule, node_id, obj), g in groups.items():
        fs = sorted(g["findings"], key=_lead_key)
        lead = fs[0]
        alts = [[str(v["id"])] for v in sorted(fs, key=lambda x: str(x["id"]))]
        chain = _entry_chain(node_id, nodes)
        host = _host_of(node_id, nodes)
        host_label = _label(nodes, host) if host else _red((nodes[node_id].get("host") or "the target"), 120)
        steps: List[Dict[str, Any]] = []
        entry = chain[0]
        port = _port(nodes[entry])
        steps.append({"node_id": entry, "satisfied_by": [], "kind": "exposure", "rule": rule,
                      "rationale": (f"Exposed: {_label(nodes, entry)} answers on port {port} of {host_label}"
                                    if port else f"Exposed: {_label(nodes, entry)} on {host_label}")
                      + " (in-scope target, reachable from the tester's position; from the infrastructure map)."})
        for parent, child in zip(chain, chain[1:]):
            steps.append({"node_id": child, "satisfied_by": [], "kind": "hop", "rule": rule,
                          "rationale": f"{_label(nodes, child)} runs behind {_label(nodes, parent)} (infrastructure topology)."})
        others = len(fs) - 1
        steps.append({"node_id": node_id, "satisfied_by": alts, "kind": "exploit", "rule": rule,
                      "rationale": (f"{RULES[rule]['label']}: {lead['id']} ({_status(lead)}, {severity_of(lead.get('severity'))})"
                                    + (f", or {others} other finding{'s' if others > 1 else ''} of the same kind on this asset" if others else "")
                                    + ".")})
        if obj != node_id:
            steps.append({"node_id": obj, "satisfied_by": alts, "kind": "objective", "rule": rule,
                          "rationale": (f"Inferred, not demonstrated: {g['gained']} — {_label(nodes, obj)} is "
                                        + ("the host this asset runs on (topology parent)." if obj == host
                                           else "the only database of this host in the topology.") )})
        crit = severity_of(lead.get("severity"))
        best = "exploited" if any(_status(v) == "exploited" for v in fs) else "confirmed"
        records.append({
            "source_id": f"inf-{rule}-{node_id}-{obj}", "provenance": PROVENANCE, "steps": steps,
            "entry_node_id": entry, "objective_node_id": obj,
            "criticality": crit if crit in _SEV else "info", "criticality_source": "default",
            "chain_title": None, "consumer": None, "hypothesis": True,
            "inferred_title": _red(lead.get("title") or "Finding", 160),
            "inference": {"rule": rule, "rule_label": RULES[rule]["label"], "capability": g["gained"],
                          "findings_certainty": best, "lead_finding_id": str(lead["id"]),
                          "note": NOTE.format(rule=rule, label=RULES[rule]["label"])},
        })
    records.sort(key=lambda r: (_SEV.get(r["criticality"], 9), _RULE_ORDER[r["inference"]["rule"]], r["source_id"]))
    issues: List[Dict[str, Any]] = []
    if len(records) > MAX_INFERRED_PATHS:
        issues.append({"kind": "inferred-capped", "message": f"{len(records)} inferred paths, the {MAX_INFERRED_PATHS} most severe are listed."})
        records = records[:MAX_INFERRED_PATHS]
    if unattached:
        issues.append({"kind": "inferred-unattached", "finding_ids": sorted(unattached),
                       "message": f"{len(unattached)} qualifying finding(s) are attached to no infrastructure node: no inferred path is drawn for them."})
    return {"records": records, "issues": issues}
