"""
Declared links between findings (`enabled_by`, round 4).

The agent says, on the finding it pushes, which EARLIER findings of the campaign produced what this exploitation used
(a token, a credential, a hash, a session, an access). The server does not take it on trust:
- references are kept as written (vuln_id, dedup_key, short_title or exact endpoint) and resolved LAZILY when the paths
  are built (round 5); the push only gives feedback (push_warnings). Architecture D: an unknown (or
  other-campaign), ambiguous, self or FORWARD reference (the producer was pushed after the declaration; a late addition is
  dated by its re-push, ``enabled_by_at``) is a ``rejected_declaration``, listed with its reason, never a path edge; a link
  whose producer or consumer is false_positive / remediated / withdrawn / merged is ``invalidated`` (kept, never counted);
- re-pushing the same finding (same dedup_key, or same title + endpoint + category) with enabled_by adds the
  references to the stored finding instead of creating a duplicate (api/live_push);
- at analysis (`validate`): both findings live, declared nodes exist, no cycle; ATT&CK tags and the tactic order are
  CONTEXT only (warnings, 40-paths-v2), never a verdict. An unusable link is kept and shown.

A usable declared link is a path step shown at once as ``declared_by_agent``; api/edge_verifier.qualify_edge may raise it
to observed_flow or causal_necessity_demonstrated by exact value attribution on the server's own records. Protocol-
agnostic by construction: nothing here reads HTTP, SMB or any tool output.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

MAX_REFS = 16


def _norm(s: Any) -> str:
    return " ".join(str(s or "").split()).casefold()


def _labels(v: Dict[str, Any]) -> List[str]:
    """What a reference may name besides the vuln_id: dedup_key, short_title, exact endpoint (round 5; never the
    free title — a generic title « SQL Injection » would change meaning with the order of the pushes)."""
    return [_norm(v[k]) for k in ("dedup_key", "short_title", "endpoint") if v.get(k) and _norm(v[k])]


def resolve_one(ref: Any, vulns: List[Dict[str, Any]], self_id: str) -> Tuple[Optional[str], str]:
    """(finding id, status) of one reference against the campaign's findings. status: ok | self | unknown | ambiguous.
    A dedup group resolves to its canonical member. Resolved LAZILY (at path build): a reference may name a finding
    pushed later; a label that becomes ambiguous is reported, never guessed."""
    r = str(ref or "").strip()[:200]
    if not r:
        return None, "unknown"
    if r == self_id:
        return None, "self"
    ids = {str(v.get("id")) for v in vulns if v.get("id")}
    if r in ids:
        return r, "ok"
    key = _norm(r)
    cands = [v for v in vulns if v.get("id") and key in _labels(v)]
    canon = {str(v.get("duplicate_of") or v["id"]) for v in cands}
    canon.discard(self_id)
    if not canon:
        return None, "self" if cands else "unknown"
    if len(canon) > 1:
        return None, "ambiguous"
    return next(iter(canon)), "ok"


def _canon(v: Dict[str, Any]) -> str:
    return str(v.get("duplicate_of") or v.get("id"))


def clean_refs(refs: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for raw in list(refs or [])[:MAX_REFS]:
        r = str(raw or "").strip()[:200]
        if r and r not in out:
            out.append(r)
    return out


def push_warnings(refs: Iterable[Any], stored: List[Dict[str, Any]], self_id: str) -> List[str]:
    """Push-time feedback only (the references are KEPT as written and resolved lazily at path build)."""
    out: List[str] = []
    for r in clean_refs(refs):
        _, st = resolve_one(r, stored, self_id)
        if st == "self":
            out.append(f"enabled_by {r!r}: a finding cannot enable itself; ignored")
        elif st == "ambiguous":
            out.append(f"enabled_by {r!r}: matches several findings; use its vuln_id")
        elif st == "unknown":
            out.append(f"enabled_by {r!r}: no finding of this campaign has this id, dedup_key, short_title or endpoint "
                       f"yet; kept, resolved when it is pushed")
    return out


def resolve_refs(refs: Iterable[Any], earlier: List[Dict[str, Any]], self_id: str) -> Tuple[List[str], List[str]]:
    """(resolved ids, warnings) against ``earlier`` — kept for callers of round 4; validate() resolves lazily."""
    ids, warnings = [], []
    for r in clean_refs(refs):
        fid, st = resolve_one(r, earlier, self_id)
        if fid and fid not in ids:
            ids.append(fid)
    return ids, push_warnings(refs, earlier, self_id)


# ---------------------------------------------------------------------------- ATT&CK: a PLAUSIBILITY filter
# What this is (round 5, round4-critique A1/A2): the tactics come from labels the AGENT wrote. Checking their order is a
# plausibility filter, NOT a validation of the link — measured on a real Juice Shop campaign, the round-4 table accepted
# 74 % of all ordered finding pairs and every false chain of round 1, while rejecting 18 % of the true ones. Hence:
# - the tactic order never blocks a link: an unusual order is a WARNING only;
# - a link is not used only when it is impossible: the references are broken (unknown, self, cycle), a finding is not
#   live, or a declared node does not exist (40-paths-v2: a missing ATT&CK tag is a warning, never a block);
# - Enterprise, ICS and Mobile tactics are all understood (a technique outside the vendored Enterprise v20 extract
#   keeps the tactic the agent declared, flagged « tactic unchecked »).
_ALL_ACTIVE = frozenset({"initial-access", "execution", "persistence", "privilege-escalation", "stealth",
                         "defense-impairment", "credential-access", "discovery", "lateral-movement", "collection",
                         "command-and-control", "exfiltration", "impact"})
# UNUSUAL[src] = target tactics whose order is odd for « the result of src was used by » (warning only). Everything
# else is plausible: impact, exfiltration and collection may feed further access (exfiltrated / collected credentials,
# a tampered object reused), persistence may give a new initial access (web shell).
UNUSUAL: Dict[str, frozenset] = {t: frozenset({"reconnaissance", "resource-development"}) for t in _ALL_ACTIVE}
UNUSUAL.update({"reconnaissance": frozenset(), "resource-development": frozenset({"reconnaissance"})})
# ATT&CK for ICS and Mobile tactics, mapped to the Enterprise stage they play in a chain. Tactic ids and names:
# MITRE ATT&CK®, © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE
# Corporation (ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
ICS_MOBILE_TACTICS: Dict[str, Tuple[str, str]] = {
    # ICS
    "TA0108": ("Initial Access", "initial-access"), "TA0104": ("Execution", "execution"),
    "TA0110": ("Persistence", "persistence"), "TA0111": ("Privilege Escalation", "privilege-escalation"),
    "TA0103": ("Evasion", "stealth"), "TA0102": ("Discovery", "discovery"),
    "TA0109": ("Lateral Movement", "lateral-movement"), "TA0100": ("Collection", "collection"),
    "TA0101": ("Command and Control", "command-and-control"), "TA0107": ("Inhibit Response Function", "impact"),
    "TA0106": ("Impair Process Control", "impact"), "TA0105": ("Impact", "impact"),
    # Mobile
    "TA0027": ("Initial Access", "initial-access"), "TA0041": ("Execution", "execution"),
    "TA0028": ("Persistence", "persistence"), "TA0029": ("Privilege Escalation", "privilege-escalation"),
    "TA0030": ("Defense Evasion", "stealth"), "TA0031": ("Credential Access", "credential-access"),
    "TA0032": ("Discovery", "discovery"), "TA0033": ("Lateral Movement", "lateral-movement"),
    "TA0035": ("Collection", "collection"), "TA0037": ("Command and Control", "command-and-control"),
    "TA0036": ("Exfiltration", "exfiltration"), "TA0034": ("Impact", "impact"),
}
_ICS_MOBILE_BY_NAME = {n.lower(): stage for _id, (n, stage) in ICS_MOBILE_TACTICS.items()}
LIVE = ("exploited", "confirmed")
LEVEL_DECLARED = "declared"
LEVEL_OBSERVED = "observed"
LEVEL_LABELS = {LEVEL_OBSERVED: "Observed by the server",
                LEVEL_DECLARED: "Declared by the agent, not verified by the server"}
# 40-paths-v2 (CONTRACT.md): the level of a declared link / of a path resting on one is decided by api/edge_verifier
from api.edge_verifier import STATE_LABELS as _STATE_LABELS  # noqa: E402
from api.edge_verifier import D_STATE_LABELS as _D_STATE_LABELS  # noqa: E402
from api.edge_verifier import DECLARED_BY_AGENT, INVALIDATED, REJECTED_DECLARATION  # noqa: E402
LEVEL_LABELS.update(_STATE_LABELS)
LEVEL_LABELS.update(_D_STATE_LABELS)
# R2 (open registration matched by endpoint): a historical server inference, never an observation (R2-ISOLATION.md)
LEVEL_LABELS["inferred"] = "Inferred by a historical server rule (open registration matched by endpoint) · not proven"


def tactics_info(finding: Dict[str, Any], b: Optional[Dict[str, Any]] = None) -> Tuple[List[str], str]:
    """(tactic stages, status) of a finding. status: « checked » (Enterprise v20 technique, declared tactic consistent
    or the technique's tactics), « unchecked » (the declared tactic, technique outside the Enterprise extract — ICS,
    Mobile, revoked…), « untagged » (no technique and no tactic)."""
    tech = str(finding.get("mitre_attack_id") or finding.get("mitre_id") or "").strip()
    tac = str(finding.get("mitre_tactic") or "").strip()
    if not tech and not tac:
        return [], "untagged"
    try:
        from api.attack_tactics import attack_block
        a = attack_block(finding, b)
    except Exception:  # noqa: BLE001 — extract missing
        a = {}
    if a.get("tactic_status") == "declared-consistent" and a.get("declared_tactic"):
        return [a["declared_tactic"]["shortname"]], "checked"
    if a.get("status") == "ok" and a.get("possible_tactics") and a.get("tactic_status") in ("undeclared", "missing"):
        return [t["shortname"] for t in a["possible_tactics"]], "checked"
    # the agent's declared tactic, Enterprise / ICS / Mobile, when the technique cannot check it
    low = tac.lower()
    if b is not None:
        for short, t in b.get("tactics", {}).items():
            if tac.upper() == t["id"] or low in (short, t["name"].lower()):
                return [short], "unchecked"
    if tac.upper() in ICS_MOBILE_TACTICS:
        return [ICS_MOBILE_TACTICS[tac.upper()][1]], "unchecked"
    if low in _ICS_MOBILE_BY_NAME:
        return [_ICS_MOBILE_BY_NAME[low]], "unchecked"
    if a.get("status") == "ok" and a.get("possible_tactics"):
        return [t["shortname"] for t in a["possible_tactics"]], "checked"
    return [], "unchecked"          # a tag exists (ICS / Mobile technique id…) but no tactic can be read: kept, warned


def tactics_of(finding: Dict[str, Any], b: Optional[Dict[str, Any]] = None) -> List[str]:
    return tactics_info(finding, b)[0]


def coherent(src: Iterable[str], dst: Iterable[str]) -> bool:
    """Plausible order: at least one (src, dst) pair that is not in UNUSUAL. Never a proof (see above)."""
    return any(d not in UNUSUAL.get(s, frozenset()) for s in src for d in dst)


def validate(vulns: List[Dict[str, Any]], known_nodes: Optional[Set[str]] = None,
             b: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Every declared link of a campaign with its checks. ``vulns`` in STORE order (= push order)."""
    try:
        from api.attack_tactics import bundle
        b = b or bundle()
    except Exception:  # noqa: BLE001
        b = None
    order = {str(v.get("id")): i for i, v in enumerate(vulns) if v.get("id")}
    vmap = {str(v.get("id")): v for v in vulns if v.get("id")}
    tac: Dict[str, Tuple[List[str], str]] = {}

    def info(fid: str) -> Tuple[List[str], str]:
        if fid not in tac:
            tac[fid] = tactics_info(vmap[fid], b)
        return tac[fid]

    out: List[Dict[str, Any]] = []
    for v in vulns:
        c = str(v.get("id") or "")
        if not c:
            continue                    # an id-less finding is never a link end: its references are skipped, never raise
        refs = v.get("enabled_by") if isinstance(v.get("enabled_by"), list) else []
        at = v.get("enabled_by_at") if isinstance(v.get("enabled_by_at"), dict) else {}
        seen_p: Set[str] = set()
        # one producer named by several references (id, endpoint…): the LATEST declaration dates the link (a late
        # addition by re-push makes it valid even if an earlier, forward reference named the same finding)
        latest: Dict[str, int] = {}
        for ref in clean_refs(refs):
            rid0, _st0 = resolve_one(ref, vulns, c)
            if rid0:
                when = at[ref] if isinstance(at.get(ref), int) else order[c]
                latest[rid0] = max(latest.get(rid0, when), when)
        for ref in clean_refs(refs):
            flags: List[str] = []           # blocking: the link is not used for paths
            warnings: List[str] = []        # plausibility only: shown, never blocking
            state, reason = DECLARED_BY_AGENT, None   # architecture D
            rid, st = resolve_one(ref, vulns, c)
            p = rid or ref
            if rid in seen_p:
                continue
            if rid:
                seen_p.add(rid)
            if st in ("self", "ambiguous", "unknown"):
                # unknown covers a reference to another campaign: references resolve within the campaign only
                flags.append({"self": "self-reference", "ambiguous": "ambiguous-reference", "unknown": "unknown-finding"}[st])
                state, reason = REJECTED_DECLARATION, {"self": "self_reference", "ambiguous": "ambiguous_reference",
                                                       "unknown": "unknown_finding"}[st]
            elif _canon(vmap[p]) == _canon(vmap[c]) or (vmap[p].get("dedup_key") and vmap[p].get("dedup_key") == vmap[c].get("dedup_key")):
                # a duplicate « enabled » by its own original is ONE weakness, not a chain (round5-critique M2)
                flags.append("same-dedup-group")
                state, reason = REJECTED_DECLARATION, "same_weakness"
            elif order[p] >= latest.get(p, order[c]):
                # the producer was pushed after the declaration was made (a late addition is dated by its re-push)
                flags.append("forward-reference")
                state, reason = REJECTED_DECLARATION, "forward_reference"
            else:
                retracted = [(role, _retraction(vmap[fid])) for role, fid in (("producer", p), ("consumer", c))]
                retracted = [(role, why) for role, why in retracted if why]
                if retracted:
                    # a withdrawn finding demotes its dependent links: kept in history, never counted, never qualified
                    flags.append("invalidated")
                    state, reason = INVALIDATED, f"{retracted[0][0]}_{retracted[0][1]}"
                for fid in (p, c):
                    if str(vmap[fid].get("status") or "").lower() not in LIVE:
                        flags.append(f"not-live:{fid}")
                (tp_, sp), (tc, sc) = info(p), info(c)
                if sp == "untagged":   # 40-paths-v2: ATT&CK is context only, never a verdict on the link
                    warnings.append("enabling-finding-untagged")
                if sc == "untagged":
                    warnings.append("consumer-untagged")
                if "unchecked" in (sp, sc):
                    warnings.append("tactic-unchecked")
                if tp_ and tc and not coherent(tp_, tc):
                    warnings.append("tactic-order-unusual")
                if known_nodes is not None:
                    for fid in (p, c):
                        nid = vmap[fid].get("node_id")
                        if nid and nid not in known_nodes:
                            flags.append(f"unknown-node:{fid}")
            out.append({"producer": p, "consumer": c, "valid": not flags, "flags": flags, "warnings": warnings,
                        "producer_tactics": tac.get(p, ([], ""))[0], "consumer_tactics": tac.get(c, ([], ""))[0],
                        "level": LEVEL_DECLARED, "state": state, "reason": reason})
    # a cycle among valid links needs a late re-push (or an edited store). architecture D final-review clarification: a
    # cycle is a property of the declared graph, never evidence against an edge. Its links keep their state and stay
    # usable; the « cycle » WARNING says so (non-blocking, never promoting) and path assembly walks simple paths only
    # (edge_verifier.bounded_chains), reporting the cycle as a cycle.
    valid = [l for l in out if l["valid"]]
    graph: Dict[str, List[str]] = {}
    for l in valid:
        graph.setdefault(l["producer"], []).append(l["consumer"])
    on_cycle = _cycle_nodes(graph)
    for l in valid:
        if l["producer"] in on_cycle and l["consumer"] in on_cycle:
            l["warnings"].append("cycle")
    return out


RETRACTED_STATUSES = ("false_positive", "withdrawn")   # architecture D: a remediated finding existed — its links stay declared (not live), never « invalidated »


def _retraction(v: Dict[str, Any]) -> Optional[str]:
    """Why a finding no longer supports a link: false_positive / remediated / withdrawn status, or merged into another."""
    st = str(v.get("status") or "").strip().lower()
    if st in RETRACTED_STATUSES:
        return st
    return "merged" if v.get("duplicate_of") else None


def _cycle_nodes(graph: Dict[str, List[str]]) -> Set[str]:
    """Nodes on a directed cycle (Tarjan-free: iterative DFS colouring, then the nodes of each back-edge's stack)."""
    colour: Dict[str, int] = {}
    on: Set[str] = set()
    for root in list(graph):
        if colour.get(root):
            continue
        stack: List[Tuple[str, int]] = [(root, 0)]
        path: List[str] = []
        while stack:
            node, i = stack.pop()
            if i == 0:
                colour[node] = 1
                path.append(node)
            nxt = graph.get(node, [])
            if i < len(nxt):
                stack.append((node, i + 1))
                m = nxt[i]
                if colour.get(m) == 1:
                    on.update(path[path.index(m):])
                elif not colour.get(m):
                    stack.append((m, 0))
            else:
                colour[node] = 2
                path.pop()
    return on


def flag_label(flags: List[str], warnings: Optional[List[str]] = None) -> str:
    if not flags:
        w = sorted(set(warnings or []))
        return "declared by the agent (ATT&CK plausibility: " + (", ".join(w) if w else "no warning") + ")"
    return "not used for paths: " + ", ".join(sorted(set(f.split(":")[0] for f in flags)))
