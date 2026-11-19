"""
Edge verification of declared links (40-paths-v2, architecture C — reports/40-paths-v2/CONTRACT.md).

The agent declares (``enabled_by`` + ``evidence_execution_ids``); the server's own execution records decide. Pure
functions, stdlib only, no I/O:

- ``executions_from_lines``: run-ledger lines (api/tool_provenance) -> contract execution records, one per server
  execution id (a command and the exchanges captured for it share the id);
- ``verify_edge(A, B, ledger)`` -> ``(state, reason, evidence_refs)``;
- ``bounded_chains``: bounded iterative DFS used to assemble paths (depth, count and time budget, truncation reason).

States: ``declared_unverified`` (with a reason) < ``observed_flow`` < ``causal_necessity_demonstrated``. An observed
flow says « the value left A's execution and reached B's successful execution », never « B needed it »; necessity
needs a recorded negative control. Nothing here reads a value: fingerprints and ids only.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

DECLARED_UNVERIFIED = "declared_unverified"
OBSERVED_FLOW = "observed_flow"
CAUSAL = "causal_necessity_demonstrated"
STATES = (DECLARED_UNVERIFIED, OBSERVED_FLOW, CAUSAL)
STATE_RANK = {DECLARED_UNVERIFIED: 0, OBSERVED_FLOW: 1, CAUSAL: 2}
STATE_LABELS = {
    DECLARED_UNVERIFIED: "Declared by the agent · not verified by the server",
    OBSERVED_FLOW: "Observed flow — the server recorded the value flowing from A's execution to B's successful execution",
    CAUSAL: "Necessity demonstrated — refused without the value, accepted with it, both recorded",
}
REASONS = ("not_declared", "cross_run", "unknown_execution", "execution_after_push", "no_execution_ids",
           "value_not_consumed", "ambiguous_origin", "exogenous_value", "consumer_not_success", "duplicate_finding",
           "cycle", "depth_exceeded")
OUTCOMES = ("success", "refused", "unknown")
OUTCOME_BASES = ("http_2xx", "http_refused", "refusal_signature", "exit_nonzero", "exit0_expected_output", "none")
# defence in depth (Phase 4): an outcome counts only with a basis that can support it; anything else is « unknown »
SUCCESS_BASES = frozenset({"http_2xx", "exit0_expected_output"})
REFUSAL_BASES = frozenset({"http_refused", "refusal_signature"})
MAX_HOPS = 3                 # consumed->producer links allowed between e_a and e_b (contract: depth <= 3)
_SEARCH_HOPS = 12            # explored further (budget-bounded) only to tell depth_exceeded from value_not_consumed
MAX_DEPTH, MAX_PATHS, BUDGET_S = 6, 100, 0.05


def execution_ref(ex: Any) -> Optional[str]:
    """Public execution id of a ledger ``ex`` value (the id shown to the agent: ``ex_<hex>``)."""
    s = str(ex or "").strip()
    if not s:
        return None
    return s if s.startswith("ex_") else "ex_" + s


# ---------------------------------------------------------------------------------------------------- ledger -> records
def _line_outcome(line: Dict[str, Any]) -> Tuple[str, str]:
    """(outcome, basis) of one ledger line: HTTP facts first, then the recorded command outcome."""
    facts = [e for e in line.get("e") or [] if isinstance(e, list) and len(e) == 6]
    if any(e[5] == "ok" and isinstance(e[3], int) and 200 <= e[3] < 300 for e in facts):
        return "success", "http_2xx"
    if any(e[5] == "refused" for e in facts):
        return "refused", "http_refused"
    if line.get("oc") in OUTCOMES and line.get("ob") in OUTCOME_BASES:
        return line["oc"], line["ob"]
    # legacy line (before 40-paths-v2): same mapping from the stored enums; exit 0 alone is never a success
    rc = line.get("rc")
    if line.get("o") == "refused" and line.get("os"):
        return "refused", "refusal_signature"
    if isinstance(rc, int) and rc != 0:
        return "unknown", "exit_nonzero"
    if rc == 0 and line.get("o") == "ok" and any(p[1] != "file-ref" for p in line.get("p") or [] if len(p) == 2):
        return "success", "exit0_expected_output"
    return "unknown", "none"


def _line_keys(line: Dict[str, Any]) -> List[str]:
    keys = [f"http|{e[0]}|{e[1]}|{e[2]}" for e in line.get("e") or [] if isinstance(e, list) and len(e) == 6]
    keys += [f"svc|{k}" for k in line.get("k") or []]
    return keys


def executions_from_lines(lines: Iterable[Dict[str, Any]], run_id: Optional[str]) -> List[Dict[str, Any]]:
    """Contract execution records of one run ledger. A line already in contract shape (``execution_id``) is taken as
    is; ledger lines are grouped by their server execution id ``ex`` (a line without one stands alone, under its
    ``cx`` ref, and can never be cited by an agent)."""
    out: List[Dict[str, Any]] = []
    groups: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    lines = list(lines or [])
    compacted = any(isinstance(ln, dict) and ln.get("compacted") for ln in lines)
    for ln in lines:
        if not isinstance(ln, dict):
            continue
        if ln.get("execution_id"):
            out.append(dict(ln, run_id=ln.get("run_id") or run_id))
            continue
        if not ln.get("cx") or ln.get("x") is False:
            continue
        key = execution_ref(ln.get("ex")) or str(ln["cx"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(ln)
    exec_of_cx = {ln["cx"]: k for k, g in groups.items() for ln in g}
    _rank = {"success": 2, "refused": 1, "unknown": 0}
    for key in order:
        g = groups[key]
        cmd = [ln for ln in g if not ln.get("src")]
        head = cmd[-1] if cmd else max(g, key=lambda ln: int(ln.get("seq") or 0))
        produced: Dict[str, str] = {}
        consumed: Dict[str, Dict[str, Any]] = {}
        presented: Set[str] = set()
        keys: List[str] = []
        outcomes = []
        for ln in g:
            lk = _line_keys(ln)
            keys += [k for k in lk if k not in keys]
            outcomes.append(_line_outcome(ln))
            presented.update(ln.get("i") or [])
            for p in ln.get("p") or []:
                if isinstance(p, list) and len(p) == 2:
                    produced.setdefault(p[0], p[1])
            for c in ln.get("c") or []:
                if not (isinstance(c, list) and len(c) >= 2):
                    continue
                prod = exec_of_cx.get(c[1])
                if prod and prod != key and c[0] not in consumed:
                    consumed[c[0]] = {"fp": c[0], "producer_execution_id": prod, "operation_keys": lk}
        # execution outcome: an HTTP 2xx anywhere wins, then an HTTP refusal, then the command's own outcome
        http = [o for o in outcomes if o[1] in ("http_2xx", "http_refused")]
        oc, ob = max(http, key=lambda o: _rank[o[0]]) if http else _line_outcome(head)
        out.append({
            "execution_id": key, "run_id": run_id, "seq": int(head.get("seq") or 0), "t": head.get("t"),
            "session": head.get("ses"), "produced": [{"fp": f, "kind": k} for f, k in produced.items()],
            "consumed": list(consumed.values()), "presented": sorted(presented),
            "outcome": oc, "outcome_basis": ob, "operation_keys": keys,
            # compaction dropped lines: « nothing without the value succeeded » can no longer be checked
            "run_compacted": compacted,
        })
    return out


# ---------------------------------------------------------------------------------------------------- normalisation
def _exec(e: Dict[str, Any]) -> Dict[str, Any]:
    produced = {}
    for p in e.get("produced") or []:
        if isinstance(p, dict) and p.get("fp"):
            produced[str(p["fp"])] = p.get("kind")
        elif isinstance(p, (list, tuple)) and p:
            produced[str(p[0])] = p[1] if len(p) > 1 else None
    consumed = []
    for c in e.get("consumed") or []:
        if isinstance(c, dict) and c.get("fp"):
            consumed.append((str(c["fp"]), str(c.get("producer_execution_id") or ""), list(c.get("operation_keys") or [])))
        elif isinstance(c, (list, tuple)) and len(c) >= 2:
            consumed.append((str(c[0]), str(c[1]), []))
    keys = list(e.get("operation_keys") or [])
    if e.get("operation_key"):
        keys.append(str(e["operation_key"]))
    try:
        seq = int(e.get("seq"))
    except (TypeError, ValueError):
        seq = None
    claimed, basis = e.get("outcome"), e.get("outcome_basis")
    outcome = ("success" if claimed == "success" and basis in SUCCESS_BASES else
               "refused" if claimed == "refused" and basis in REFUSAL_BASES else "unknown")
    return {"id": str(e.get("execution_id")), "run": e.get("run_id"), "seq": seq, "session": e.get("session"),
            "produced": produced, "consumed": consumed, "presented": {str(x) for x in e.get("presented") or []},
            "outcome": outcome, "claimed_success": claimed == "success", "keys": set(keys),
            "run_compacted": bool(e.get("run_compacted"))}


def _ledger_parts(ledger: Any) -> Tuple[List[Dict[str, Any]], Optional[List[Dict[str, Any]]]]:
    if isinstance(ledger, dict):
        return list(ledger.get("executions") or []), ledger.get("findings")
    return list(ledger or []), None


def _ids(f: Dict[str, Any], key: str) -> List[str]:
    v = f.get(key)
    return [str(x) for x in v if str(x).strip()] if isinstance(v, list) else []


def _reaches(findings: List[Dict[str, Any]], start: str, target: str) -> bool:
    """``start`` transitively declares ``target`` through enabled_by (bounded)."""
    by = {str(f.get("id")): _ids(f, "enabled_by") for f in findings if isinstance(f, dict) and f.get("id")}
    seen, stack = {start}, [start]
    while stack and len(seen) < 10_000:
        for nxt in by.get(stack.pop(), []):
            if nxt == target:
                return True
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False


# ---------------------------------------------------------------------------------------------------- the verifier
def _unverified(reason: str, refs: Optional[Dict[str, Any]] = None) -> Tuple[str, str, Dict[str, Any]]:
    return DECLARED_UNVERIFIED, reason, refs or {}


def verify_edge(a: Dict[str, Any], b: Dict[str, Any], ledger: Any,
                findings: Optional[List[Dict[str, Any]]] = None) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """State of the declared link « A enabled B » (CONTRACT.md). ``ledger`` = list of contract execution records, or
    ``{"executions": [...], "findings": [...]}`` (findings: used for the cycle check). Never raises on bad input: a
    record it cannot read is simply not evidence."""
    raw, more = _ledger_parts(ledger)
    findings = findings if findings is not None else more
    a, b = a or {}, b or {}
    a_id, b_id = str(a.get("id") or ""), str(b.get("id") or "")
    if not a_id or a_id not in _ids(b, "enabled_by"):
        return _unverified("not_declared")
    if (a_id == b_id or a.get("duplicate_of") or b.get("duplicate_of")
            or (a.get("dedup_key") and a.get("dedup_key") == b.get("dedup_key"))):
        return _unverified("duplicate_finding")
    if a_id in _ids(b, "enabled_by") and (b_id in _ids(a, "enabled_by") or (findings and _reaches(findings, a_id, b_id))):
        return _unverified("cycle")
    run_a, run_b = a.get("run_id"), b.get("run_id")
    if run_a and run_b and run_a != run_b:
        return _unverified("cross_run")
    ids_a, ids_b = _ids(a, "evidence_execution_ids"), _ids(b, "evidence_execution_ids")
    if not ids_a or not ids_b:
        return _unverified("no_execution_ids")
    if not run_a or run_a != run_b:
        return _unverified("cross_run")
    execs = [_exec(e) for e in raw if isinstance(e, dict) and e.get("execution_id")]
    run = [e for e in execs if e["run"] in (None, run_a) and e["seq"] is not None]
    # an id recorded twice is untrustworthy: never citable, never a link end (the copies still count as producers /
    # presenters in the ambiguity and exogeneity scans, which only ever make a link weaker). A record without a run_id
    # is not shown to belong to this run: same treatment (weakens, never evidence).
    seen: Dict[str, int] = {}
    for e in execs:
        seen[e["id"]] = seen.get(e["id"], 0) + 1
    by_id = {e["id"]: e for e in run if seen[e["id"]] == 1 and e["run"] == run_a}
    elsewhere = {e["id"] for e in execs if e["run"] not in (None, run_a)}
    elig: Dict[str, List[Dict[str, Any]]] = {}
    for side, ids, f in (("a", ids_a, a), ("b", ids_b, b)):
        known = [by_id[i] for i in ids if i in by_id]
        if not known:
            return _unverified("cross_run" if any(i in elsewhere for i in ids) else "unknown_execution")
        try:
            push = int(f.get("push_seq"))
        except (TypeError, ValueError):
            push = None
        before = [e for e in known if push is not None and e["seq"] < push]
        if not before:
            return _unverified("execution_after_push")
        elig[side] = before
    return _flow(elig["a"], elig["b"], run, by_id)


_CHECKS = ("depth_exceeded", "ambiguous_origin", "exogenous_value", "consumer_not_success")


def _link_issue(fp: str, prod: Dict[str, Any], cons: Dict[str, Any], run: List[Dict[str, Any]]) -> Optional[str]:
    """One recorded consumed->producer link: the producer must be the ONLY one before the consumer, and the value
    must not have been presented before (or by) the producer."""
    if any(e["id"] != prod["id"] and e["seq"] < cons["seq"] and fp in e["produced"] for e in run):
        return "ambiguous_origin"
    if any(e["id"] != cons["id"] and e["seq"] < cons["seq"] and any(c[0] == fp and c[1] != prod["id"] for c in e["consumed"])
           for e in run):
        return "ambiguous_origin"      # an earlier consumption names another producer of the same value
    # v was an INPUT (presented, or recorded as consumed) of an execution at or before the producer, the producer
    # included: the producer did not originate it
    if any(e["seq"] <= prod["seq"] and (fp in e["presented"] or any(c[0] == fp for c in e["consumed"])) for e in run):
        return "exogenous_value"
    return None


def _flow(ea_list: List[Dict[str, Any]], eb_list: List[Dict[str, Any]], run: List[Dict[str, Any]],
          by_id: Dict[str, Dict[str, Any]]) -> Tuple[str, Optional[str], Dict[str, Any]]:
    a_ids = {e["id"] for e in ea_list}
    best: Optional[Tuple[int, Optional[str], Dict[str, Any]]] = None   # (rank, reason, refs) of the best failing chain
    valid: List[Dict[str, Any]] = []                                   # refs of every valid chain
    for eb in sorted(eb_list, key=lambda e: (e["seq"], e["id"])):
        # backward DFS over recorded consumed->producer links, strictly earlier producers, bounded
        stack: List[Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any], Dict[str, Any]]]]] = [(eb, [])]
        budget = 20_000
        while stack and budget > 0:
            node, chain = stack.pop()
            for fp, prod_id, _keys in sorted(node["consumed"], key=lambda c: (c[1], c[0])):
                budget -= 1
                prod = by_id.get(prod_id)
                if (prod is None or prod["seq"] >= node["seq"] or any(prod["id"] == x[1]["id"] for x in chain)
                        or fp not in prod["produced"]):   # a consumption must name a producer that recorded the value
                    continue
                full = chain + [(fp, prod, node)]
                if prod["id"] in a_ids:
                    rank, reason = _judge(full, eb, run)
                    refs = {"executions": [prod["id"]] + [x[2]["id"] for x in reversed(full)],
                            "value_fp": full[-1][0][:12], "hops": len(full)}
                    if rank == len(_CHECKS):
                        into_b = next(c for c in eb["consumed"] if c[0] == full[0][0] and c[1] == full[0][1]["id"])
                        refs.update(_necessity(full[0][0], eb, into_b[2], run))
                        valid.append(refs)
                    elif best is None or rank > best[0]:
                        best = (rank, reason, refs)
                if len(full) < _SEARCH_HOPS and prod["id"] not in a_ids:
                    stack.append((prod, full))
    if valid:
        # several valid chains: the WEAKEST state wins (a causal claim must hold on every valid chain); the refs are
        # those of the chain that decided it (CONTRACT clarification 17/11/2026)
        weakest = next((r for r in valid if not r.get("negative_control")), valid[0])
        return (CAUSAL if weakest.get("negative_control") else OBSERVED_FLOW), None, weakest
    if best is None:
        return _unverified("value_not_consumed")
    return _unverified(best[1], best[2])


def _judge(chain: List[Tuple[str, Dict[str, Any], Dict[str, Any]]], eb: Dict[str, Any],
           run: List[Dict[str, Any]]) -> Tuple[int, Optional[str]]:
    """(rank, failing reason) of one candidate chain e_a -> ... -> e_b; rank = number of checks passed."""
    if len(chain) > MAX_HOPS:
        return 0, "depth_exceeded"
    issues = [_link_issue(fp, prod, cons, run) for fp, prod, cons in chain]
    if "ambiguous_origin" in issues:
        return 1, "ambiguous_origin"
    if "exogenous_value" in issues:
        return 2, "exogenous_value"
    intermediates = [cons for _fp, _prod, cons in chain[1:]]   # chain[0] is the link into e_b (built backward)
    if eb["outcome"] != "success" or any(x["outcome"] != "success" for x in intermediates):
        return 3, "consumer_not_success"
    return 4, None


def _necessity(fp: str, eb: Dict[str, Any], keys: List[str], run: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Negative control: another recorded execution of the run on the same target operation, WITHOUT the value, was
    refused, and none without it succeeded. The target is the operation of the CONSUMING exchange that carried the
    value; when the consumption names none, e_b's operation only if it has exactly one (otherwise which one carried
    the value is unknown). Never inferred: no operation key -> no control."""
    target = set(keys) or (eb["keys"] if len(eb["keys"]) == 1 else set())
    if not target or any(e.get("run_compacted") for e in run):
        return {"negative_control": None}   # compacted run: a dropped success without the value cannot be ruled out
    without = [e for e in run if e["id"] != eb["id"] and e["keys"] & target
               and fp not in e["presented"] and all(c[0] != fp for c in e["consumed"])]
    if any(e["outcome"] == "success" or e["claimed_success"] for e in without):   # any claimed success blocks
        return {"negative_control": None, "succeeded_without_value": sorted(e["id"] for e in without if e["outcome"] == "success")[:4]}
    refused = sorted((e for e in without if e["outcome"] == "refused"), key=lambda e: (e["seq"], e["id"]))
    return {"negative_control": refused[0]["id"] if refused else None}


# ---------------------------------------------------------------------------------------------------- architecture D
# reports/51-architecture-d-implementation/CONTRACT-D.md. The agent declares the link (B.enabled_by contains A); the
# server shows it at once as « declared by the agent » and may QUALIFY it, at zero token, only by exact value
# attribution: a value v (salted fingerprint) that A's and B's OWN pushed evidence present in full, produced by one
# recorded execution e_a and consumed FROM it by a successful recorded execution e_b. Session identity and chronology
# only restrict the candidates; nothing is attributed by endpoint, timestamp, similar text or shared session.
DECLARED_BY_AGENT = "declared_by_agent"
INVALIDATED = "invalidated"
REJECTED_DECLARATION = "rejected_declaration"
D_STATES = (DECLARED_BY_AGENT, OBSERVED_FLOW, CAUSAL)
D_STATE_RANK = {DECLARED_BY_AGENT: 0, OBSERVED_FLOW: 1, CAUSAL: 2}
D_STATE_LABELS = {
    DECLARED_BY_AGENT: "Declared by the agent · not verified by the server",
    OBSERVED_FLOW: STATE_LABELS[OBSERVED_FLOW],
    CAUSAL: STATE_LABELS[CAUSAL],
    INVALIDATED: "Invalidated — a finding of this link was withdrawn (kept in history, never counted)",
    REJECTED_DECLARATION: "Rejected declaration — the reference cannot be an edge of a path",
}
# closed set of reasons a declared link stays « declared by the agent » (abstention)
D_REASONS = ("not_declared", "duplicate_finding", "cross_run", "finding_not_live", "missing_data",
             "run_compacted", "session_unknown", "no_shared_value", "value_not_consumed", "execution_after_push",
             "ambiguous_origin", "exogenous_value", "several_findings", "consumer_not_success")
# order in which a failing candidate pair is reported (the furthest check reached wins)
_D_RANK = {"value_not_consumed": 0, "session_unknown": 1, "execution_after_push": 2, "several_findings": 3,
           "ambiguous_origin": 4, "exogenous_value": 5, "consumer_not_success": 6}
NOT_LIVE = frozenset({"false_positive", "remediated", "withdrawn"})


def _fps(f: Dict[str, Any]) -> Set[str]:
    return {str(x) for x in f.get("value_fps") or [] if str(x).strip()} if isinstance(f.get("value_fps"), list) else set()


def _push(f: Dict[str, Any]) -> Optional[int]:
    try:
        return int(f.get("push_seq"))
    except (TypeError, ValueError):
        return None


def _same(f: Dict[str, Any], ids: Set[str]) -> bool:
    return str(f.get("id")) in ids or str(f.get("duplicate_of") or "") in ids


def qualify_edge(a: Dict[str, Any], b: Dict[str, Any], ledger: Any, findings: Optional[List[Dict[str, Any]]] = None,
                 sessions: Optional[int] = None) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """State of the declared link A -> B under CONTRACT-D: (``declared_by_agent`` + reason) | ``observed_flow`` |
    ``causal_necessity_demonstrated``, with evidence refs. ``a`` / ``b``: findings with ``id``, ``run_id``,
    ``push_seq``, ``value_fps`` (server-computed at push), ``status``, ``enabled_by``. ``ledger``: contract execution
    records (or ``{"executions", "findings"}``). ``findings``: every finding of the campaign (« several possible
    findings for one execution »; a declared cycle is NOT a reason here: see declared_links.validate / path assembly). ``sessions``: number of agent sessions of the run (None = unknown). Pure,
    deterministic, never raises on bad input."""
    raw, more = _ledger_parts(ledger)
    findings = [f for f in (findings if findings is not None else more) or [] if isinstance(f, dict)]
    a, b = a or {}, b or {}
    a_id, b_id = str(a.get("id") or ""), str(b.get("id") or "")
    if not a_id or a_id not in _ids(b, "enabled_by"):
        return DECLARED_BY_AGENT, "not_declared", {}
    if (a_id == b_id or a.get("duplicate_of") or b.get("duplicate_of")
            or (a.get("dedup_key") and a.get("dedup_key") == b.get("dedup_key"))):
        return DECLARED_BY_AGENT, "duplicate_finding", {}
    # CONTRACT-D final-review clarification: an edge is qualified on ITS OWN evidence only. Belonging to a declared
    # cycle never demotes it (a cycle is a property of the declared graph, reported by path assembly, never walked).
    if any(str(f.get("status") or "").strip().lower() in NOT_LIVE for f in (a, b)):
        return DECLARED_BY_AGENT, "finding_not_live", {}
    run = a.get("run_id")
    if run and b.get("run_id") and run != b.get("run_id"):
        return DECLARED_BY_AGENT, "cross_run", {}
    pa, pb = _push(a), _push(b)
    if not run or run != b.get("run_id") or pa is None or pb is None:
        return DECLARED_BY_AGENT, "missing_data", {}
    # a record without an id (missing, empty or blank) is never a link end (CONTRACT-D clarification K2)
    execs = [_exec(e) for e in raw if isinstance(e, dict) and str(e.get("execution_id") or "").strip()]
    seen: Dict[str, int] = {}
    for e in execs:
        seen[e["id"]] = seen.get(e["id"], 0) + 1
    # records of this run only (a record without run_id is in no run); a reused id is never a link end
    recs = [e for e in execs if e["run"] == run and e["seq"] is not None]
    if not recs:
        return DECLARED_BY_AGENT, "missing_data", {}
    if any(e["run_compacted"] for e in recs):
        return DECLARED_BY_AGENT, "run_compacted", {}
    shared = sorted(_fps(a) & _fps(b))
    if not shared:
        return DECLARED_BY_AGENT, "no_shared_value", {}
    sa, sb = a.get("session"), b.get("session")
    if sessions != 1 and not (sa and sb):
        return DECLARED_BY_AGENT, "session_unknown", {}

    def session_issue(e: Dict[str, Any], f_session: Any) -> Optional[str]:
        """Session restricts, never attributes: a recorded conflict drops the candidate (« conflict »); in a run that
        is not known to have a single agent session, an execution without a recorded session is « unknown »."""
        es = e.get("session")
        if es and f_session and es != f_session:
            return "conflict"
        if sessions != 1 and not (es and f_session):
            return "session_unknown"
        return None

    ends = {e["id"]: e for e in recs if seen[e["id"]] == 1}
    # every record that may belong to the run weakens a link (a second producer / an earlier presentation), even a
    # run-less or duplicated one; only unique records of the run can be link ends
    scan = [e for e in execs if e["run"] in (None, run) and e["seq"] is not None]
    pair_ids = {a_id, b_id}
    others = [f for f in findings if f.get("id") and not _same(f, pair_ids)
              and str(f.get("status") or "").strip().lower() not in NOT_LIVE and _push(f) is not None]
    valid: List[Dict[str, Any]] = []
    best: Optional[Tuple[int, str, Dict[str, Any]]] = None
    for v in shared:
        for ea in sorted((e for e in ends.values() if v in e["produced"]), key=lambda e: (e["seq"], e["id"])):
            for eb in sorted(ends.values(), key=lambda e: (e["seq"], e["id"])):
                cons = [c for c in eb["consumed"] if c[0] == v and c[1] == ea["id"]]
                if not cons or eb["id"] == ea["id"]:
                    continue
                si = session_issue(ea, sa) or session_issue(eb, sb)
                if si == "conflict":
                    continue
                refs = {"executions": [ea["id"], eb["id"]], "value_fp": v[:12], "attribution": "exact_value"}
                issue: Optional[str] = si
                if issue is None and not (ea["seq"] < eb["seq"] and ea["seq"] < pa and eb["seq"] < pb):
                    issue = "execution_after_push"
                if issue is None and (pa > eb["seq"] or any(v in _fps(f) and _push(f) > ea["seq"] for f in others)):
                    issue = "several_findings"     # e_b could be A's own, or another finding presenting v owns e_a / e_b
                if issue is None:
                    issue = _link_issue(v, ea, eb, scan)
                if issue is None and eb["outcome"] != "success":
                    issue = "consumer_not_success"
                if issue is None:
                    refs.update(_necessity(v, eb, cons[0][2], scan))
                    valid.append(refs)
                elif best is None or _D_RANK[issue] > best[0]:
                    best = (_D_RANK[issue], issue, refs)
    if valid:
        # several qualifying values / executions: the WEAKEST state (a causal claim must hold on every one of them)
        weakest = next((r for r in valid if not r.get("negative_control")), valid[0])
        return (CAUSAL if weakest.get("negative_control") else OBSERVED_FLOW), None, weakest
    if best is None:
        return DECLARED_BY_AGENT, "value_not_consumed", {}
    return DECLARED_BY_AGENT, best[1], best[2]


# ---------------------------------------------------------------------------------------------------- path assembly
def bounded_chains(adj: Dict[str, List[str]], start: str, max_depth: int = MAX_DEPTH, max_paths: int = MAX_PATHS,
                   budget_s: float = BUDGET_S) -> Tuple[List[Tuple[str, ...]], Optional[str]]:
    """Maximal simple walks from ``start`` along ``adj`` (successors visited in sorted order: deterministic), at most
    ``max_depth`` edges each, at most ``max_paths`` walks, within ``budget_s``. Returns (walks, stop) with stop in
    {None, "count", "time", "depth"}; a walk cut by the depth bound is kept up to the bound and reported as « depth »."""
    deadline = time.perf_counter() + max(0.0, float(budget_s))
    out: List[Tuple[str, ...]] = []
    path, onpath = [start], {start}
    stack = [iter(sorted(set(adj.get(start, ()))))]
    extended = [False]
    stop: Optional[str] = None
    steps = 0
    while stack:
        nxt = next(stack[-1], None)
        if nxt is None:
            if not extended[-1] and len(path) > 1:
                out.append(tuple(path))
                if len(out) >= max_paths:
                    return out, "count"
            stack.pop()
            extended.pop()
            onpath.discard(path.pop())
            continue
        steps += 1
        if not steps & 63 and time.perf_counter() > deadline:
            return out, "time"
        if nxt in onpath:
            continue
        if len(path) > max_depth:
            if not extended[-1]:
                stop = stop or "depth"
            continue
        extended[-1] = True
        path.append(nxt)
        onpath.add(nxt)
        stack.append(iter(sorted(set(adj.get(nxt, ())))))
        extended.append(False)
    return out, stop
