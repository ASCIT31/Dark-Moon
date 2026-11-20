"""Prioritized Treatment Plan: treatment actions, their status machine and their history (both editions).

« Actions recommended in priority order to reduce security exposure, address related findings and interrupt relevant
attack paths. »

Actions are derived, never invented:

* one action = one item of the campaign's existing fix list (``fix_first`` of the attack-path document, built by
  ``fix_triage``); its findings are the item's ``finding_ids``. Two items are never merged because their titles look
  alike: the grouping rule stays the fix list's (same dedup key, same CVE/CWE, same injection parameter, same title on
  the same endpoint, within one exec_core fingerprint). When the fix list is ordered by attack paths it only holds the
  fixes on proven paths: the other open findings follow, grouped by the severity × proof list (``triage.groups_all``),
  in its order;
* ``priority`` is the position in that order (1 = first); ``rank`` is the fix list's rank (equal keys share a rank);
* ``recommended_treatment`` quotes the remediation text the testing agent wrote on the head finding, as such; no text
  is generated. Without a text the action says so;
* ``treatment_type`` is derived from the weakness class (to confirm by the owner), ``unknown`` when the class says
  nothing;
* ``expected_impact`` is counts only: findings covered, attack paths the fix interrupts in the server's simulation
  (``attack_paths_interrupted``), and among them the Evidence-Backed Attack Paths (``legend.path_kind_of``:
  ``evidence_backed_paths_interrupted``, the only count the impact text calls interrupted paths); never a risk
  reduction %. ``proven_attack_paths`` (key kept for compatibility) lists the Evidence-Backed Attack Paths only;
* ``related_controls`` = the framework controls the action's counted findings are technical evidence for
  (``frameworks_assess.related_controls``); dependencies, owner, approval requirement and service interruption risk
  are ``unknown`` unless a person declared them.

Status machine (``TRANSITIONS``). ``applied`` is a declaration, never a verification. ``verified_resolved``,
``partially_resolved`` and ``failed_verification`` come only from a completed retest campaign matched with the
exec_core identity (``retest.compute_verdicts``), on an action declared applied (``VERIFIABLE``); their labels say
« (not) reproduced at retest ». On an action not declared applied the retest is an observation (``last_retest``). The history is
append-only: stored entries are replayed in order, an entry that breaks the machine is reported and skipped, never
rewritten. Treatment states never change a finding, a statistic or the score: a campaign keeps its historical truth.
Pure, no I/O.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import frameworks_assess as _fa
from . import identity
from . import legend as _legend

PLAN_VERSION = "darkmoon-treatment-plan/1"
STATE_VERSION = "darkmoon-treatment-state/1"
LABEL = "Prioritized Treatment Plan"
DEFINITION = ("Actions recommended in priority order to reduce security exposure, address related findings and "
              "interrupt relevant attack paths.")
PLAIN = ("Start at the top: each action lists the findings it addresses and the attack paths it interrupts. "
         "Recording a treatment does not change the rating: only a new campaign or a completed retest shows its effect.")

STATUSES = ("proposed", "approved", "scheduled", "in_progress", "applied", "verification_pending",
            "verified_resolved", "partially_resolved", "failed_verification", "risk_accepted", "deferred")
RETEST_ONLY = frozenset({"verified_resolved", "partially_resolved", "failed_verification"})
# a completed retest changes the status only of an action declared applied (or already verified once); on any other
# action it is recorded in the history as an observation and shown as ``last_retest``, the status is kept
VERIFIABLE = frozenset({"applied", "verification_pending"}) | RETEST_ONLY
STATUS_LABEL = {
    "proposed": "Proposed",
    "approved": "Approved",
    "scheduled": "Scheduled",
    "in_progress": "In progress",
    "applied": "Applied — not verified",
    "verification_pending": "Verification pending",
    "verified_resolved": "Not reproduced at retest",
    "partially_resolved": "Partly reproduced at retest",
    "failed_verification": "Reproduced at retest",
    "risk_accepted": "Risk accepted",
    "deferred": "Deferred",
}
# manual transitions (an operator in Pro, the owner's local file in Community); RETEST_ONLY targets never appear here
TRANSITIONS = {
    "proposed": {"approved", "scheduled", "in_progress", "applied", "deferred", "risk_accepted"},
    "approved": {"proposed", "scheduled", "in_progress", "applied", "deferred", "risk_accepted"},
    "scheduled": {"approved", "in_progress", "applied", "deferred", "risk_accepted"},
    "in_progress": {"scheduled", "applied", "deferred", "risk_accepted"},
    "applied": {"in_progress", "verification_pending"},
    "verification_pending": {"applied", "in_progress"},
    "verified_resolved": {"in_progress"},
    "partially_resolved": {"in_progress", "applied", "deferred", "risk_accepted"},
    "failed_verification": {"in_progress", "applied", "deferred", "risk_accepted"},
    "risk_accepted": {"proposed", "approved", "scheduled", "in_progress"},
    "deferred": {"proposed", "approved", "scheduled", "in_progress"},
}
DECLARABLE = {
    "owner": "role or team alias (no personal name)",
    "approval_required": "true / false",
    "service_interruption_risk": "none / low / medium / high",
    "due_date": "YYYY-MM-DD",
    "risk_accepted_until": "YYYY-MM-DD",
}
INTERRUPTION_RISKS = ("none", "low", "medium", "high")
MAX_NOTE = 500
MAX_ROLE = 64
UNKNOWN = "unknown"

_TYPE_OF_CLASS = {
    "vulnerable_component": "update_component",
    "configuration": "configuration_change", "cryptography": "configuration_change",
    "sql_injection": "code_change", "nosql_injection": "code_change", "xss": "code_change", "csrf": "code_change",
    "ssrf": "code_change", "xxe": "code_change", "code_execution": "code_change", "file_access": "code_change",
    "file_upload": "code_change", "access_control": "code_change", "open_redirect": "code_change",
    "business_logic": "code_change", "input_validation": "code_change",
    "authentication": "code_or_configuration_change", "session": "code_or_configuration_change",
    "information_disclosure": "code_or_configuration_change", "availability": "code_or_configuration_change",
}
TREATMENT_TYPE_LABEL = {
    "update_component": "Update or replace the component",
    "configuration_change": "Configuration change",
    "code_change": "Code change",
    "code_or_configuration_change": "Code or configuration change",
    UNKNOWN: "Not determined",
}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ROLE = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


# ── actions ────────────────────────────────────────────────────────────────────────────────────────────────────────

def action_id(campaign_id: str, fix_id: str) -> str:
    """Stable for the same campaign and fix item: the same findings give the same id on every recompute."""
    return "act_" + hashlib.sha256(f"{campaign_id}|{fix_id}".encode()).hexdigest()[:16]


def _plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _head(ids: List[str], vmap: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    sev = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    proof = {"exploited": 3, "confirmed": 2, "unconfirmed": 1}
    known = [vmap[i] for i in ids if i in vmap]
    if not known:
        return None
    return sorted(known, key=lambda v: (-sev.get(identity.severity_of(v), 0), -proof.get(identity.proof_of(v), 0),
                                        str(v.get("id"))))[0]


def _recommended(ids: List[str], head: Optional[Dict[str, Any]], vmap: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    texts = {str(vmap[i].get("remediation") or "").strip() for i in ids if i in vmap}
    texts.discard("")
    text = str((head or {}).get("remediation") or "").strip()
    src_id = (head or {}).get("id")
    if not text and texts:                       # the head has none: the first member (id order) that has one
        for i in sorted(ids):
            t = str((vmap.get(i) or {}).get("remediation") or "").strip()
            if t:
                text, src_id = t, i
                break
    others = len(texts - {text})
    if not text:
        return {"text": None, "source": None, "finding_id": None, "other_texts": 0,
                "label": "No remediation text was recorded by the testing agent for these findings."}
    return {"text": text, "source": "testing_agent", "finding_id": src_id, "other_texts": others,
            "label": "Recommended by the testing agent (quoted as written, not verified)"
                     + (f"; {_plural(others, 'other finding text')} on the related findings" if others else "")}


def _treatment_type(head: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    wc = identity.weakness_class(head or {})
    t = _TYPE_OF_CLASS.get(wc, UNKNOWN)
    return {"value": t, "label": TREATMENT_TYPE_LABEL[t], "weakness_class": wc,
            "basis": "derived from the weakness class; to confirm by the system owner" if t != UNKNOWN
            else "the weakness class does not say which kind of change is needed"}


def _paths_index(paths_doc: Dict[str, Any]) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, List[str]]]:
    by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for p in (paths_doc or {}).get("paths") or []:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        for fid in set(str(x) for x in p.get("finding_ids") or []):
            by_finding.setdefault(fid, []).append(p)
    interrupts = {}
    for f in ((paths_doc or {}).get("ranking") or {}).get("fixes") or []:
        if isinstance(f, dict) and f.get("fix_id"):
            interrupts[str(f["fix_id"])] = sorted(str(x) for x in f.get("interrupts") or [])
    return by_finding, interrupts


def _candidates(paths_doc: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    """(basis, ordered fix items) — the fix list first, then the open findings it does not hold."""
    ff = (paths_doc or {}).get("fix_first") or {}
    tri = (paths_doc or {}).get("triage") or {}
    source = str(ff.get("source") or "none")
    groups = tri.get("groups_all")
    if groups is None:                           # older document: the shown items only
        groups = tri.get("items") or []
    out: List[Dict[str, Any]] = []
    covered: set = set()
    if source == "attack-paths":
        for it in ff.get("items") or []:
            ids = [str(x) for x in it.get("finding_ids") or []]
            out.append({**it, "finding_ids": ids, "_basis": "attack-paths"})
            covered.update(ids)
        for g in groups:
            ids = [str(x) for x in g.get("finding_ids") or [] if str(x) not in covered]
            if ids:
                out.append({**g, "finding_ids": ids, "breaks_paths": None, "_basis": "reported-severity-x-proof"})
                covered.update(ids)
    elif source != "none":
        for g in groups:
            ids = [str(x) for x in g.get("finding_ids") or []]
            out.append({**g, "finding_ids": ids, "_basis": "reported-severity-x-proof"})
    return source, out


def build_actions(campaign_id: str, paths_doc: Dict[str, Any], findings: Iterable[Any]) -> List[Dict[str, Any]]:
    """The campaign's actions in priority order (no status). ``paths_doc`` = the attack-path document (« all »
    provenance) built WITHOUT retest verdicts, so the plan keeps the campaign's own findings."""
    vmap = {str(v.get("id")): v for v in findings or [] if isinstance(v, dict) and v.get("id")}
    by_finding, interrupts = _paths_index(paths_doc)
    kind_of = {str(p["id"]): _legend.path_kind_of(p) for p in (paths_doc or {}).get("paths") or []
               if isinstance(p, dict) and p.get("id")}
    eb_total = sum(1 for k in kind_of.values() if k == "evidence_backed")
    _, cands = _candidates(paths_doc)
    actions = []
    for pos, it in enumerate(cands, 1):
        ids = it["finding_ids"]
        head = vmap.get(str(it.get("head_finding_id") or it.get("finding_id") or "")) or _head(ids, vmap)
        fix_id = str(it.get("fix_id"))
        related = sorted({p["id"] for i in ids for p in by_finding.get(i, [])})
        proven = sorted({p["id"] for i in ids for p in by_finding.get(i, []) if kind_of.get(str(p["id"])) == "evidence_backed"})
        if it["_basis"] == "attack-paths":
            broken = interrupts.get(fix_id, [])
            of_total = it.get("of_total")
        else:
            broken = sorted(str(x) for x in it.get("breaks_paths") or [])
            of_total = None
        n = len(ids)
        sev = it.get("severity") or identity.severity_of(head or {})
        proof = it.get("proof") or identity.proof_of(head or {})
        eb_broken = [pid for pid in broken if kind_of.get(str(pid)) == "evidence_backed"]
        if it["_basis"] == "attack-paths":
            expl = (f"Interrupts {it.get('breaks', len(broken))} of {of_total} known attack paths in the server's "
                    f"simulation (not applied), {len(eb_broken)} of them Evidence-Backed. "
                    f"Addresses {_plural(n, 'finding')}, worst {sev} ({proof}).")
        else:
            reasons = [str(r) for r in it.get("reasons") or []]
            expl = (f"Ordered by reported severity, then proof: {'; '.join(reasons) or sev + ', ' + proof}. "
                    f"Addresses {_plural(n, 'finding')}.")
            if it.get("fold") and (it["fold"] or {}).get("label"):
                expl += f" {it['fold']['label']}."
        impact_text = f"Findings covered: {n}"
        if broken or it["_basis"] == "attack-paths":
            impact_text += (f" · Evidence-Backed Attack Paths interrupted: {len(eb_broken)}"
                            + (f" of {eb_total}" if it["_basis"] == "attack-paths" else ""))
            if len(broken) > len(eb_broken):
                impact_text += f" · other attack paths interrupted (not evidence-backed): {len(broken) - len(eb_broken)}"
        actions.append({
            "action_id": action_id(campaign_id, fix_id),
            "fix_id": fix_id,
            "priority": pos,
            "rank": it.get("rank"),
            "tie_size": it.get("tie_size", 1),
            "basis": it["_basis"],
            "title": str(it.get("label") or (head or {}).get("title") or fix_id),
            "explanation": expl,
            "severity": sev,
            "proof": proof,
            "head_finding_id": str((head or {}).get("id") or (ids[0] if ids else "")) or None,
            "finding_ids": ids,
            "recommended_treatment": _recommended(ids, head, vmap),
            "treatment_type": _treatment_type(head),
            "related_attack_paths": related,
            "proven_attack_paths": proven,
            "interrupts_attack_paths": broken,
            "related_controls": _fa.related_controls(ids, vmap.values()),
            "related_controls_note": ("Framework controls these findings are technical evidence for (relevance only, "
                                      "not an audit opinion)."),
            "dependencies": [],
            "expected_impact": {"findings_covered": n, "attack_paths_interrupted": len(broken),
                                "attack_paths_total": of_total,
                                "evidence_backed_paths_interrupted": len(eb_broken),
                                "evidence_backed_paths_total": eb_total if it["_basis"] == "attack-paths" else None,
                                "text": impact_text},
        })
    return actions


# ── state: validation, replay, verification ────────────────────────────────────────────────────────────────────────

def _valid_date(s: Any) -> bool:
    if not isinstance(s, str) or not _DATE.match(s):
        return False
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _valid_at(s: Any) -> bool:
    if not isinstance(s, str) or not (10 <= len(s) <= 40):
        return False
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def validate_declared(fields: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Declared fields of an action: (clean, problems). Unknown keys and bad values are problems, never coerced."""
    if fields is None:
        return {}, []
    if not isinstance(fields, dict):
        return {}, ["declared: must be an object"]
    clean: Dict[str, Any] = {}
    errors = []
    for k, v in fields.items():
        if k not in DECLARABLE:
            errors.append(f"declared.{k}: unknown field")
        elif v is None:
            clean[k] = None                               # an explicit null withdraws a declaration
        elif k == "owner":
            if isinstance(v, str) and _ROLE.match(v.strip()) and v.strip():
                clean[k] = v.strip()
            else:
                errors.append("declared.owner: a role or team alias of 1 to 64 printable characters")
        elif k == "approval_required":
            if isinstance(v, bool):
                clean[k] = v
            else:
                errors.append("declared.approval_required: true or false")
        elif k == "service_interruption_risk":
            if v in INTERRUPTION_RISKS:
                clean[k] = v
            else:
                errors.append(f"declared.service_interruption_risk: one of {', '.join(INTERRUPTION_RISKS)}")
        elif k in ("due_date", "risk_accepted_until"):
            if _valid_date(v):
                clean[k] = v
            else:
                errors.append(f"declared.{k}: a date YYYY-MM-DD")
    return clean, errors


def validate_entry(e: Any) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """One stored or declared history entry: ``{at, by_role, status?, declared?, note?}`` (plus server fields)."""
    if not isinstance(e, dict):
        return None, ["entry: must be an object"]
    errors = []
    if not _valid_at(e.get("at")):
        errors.append("at: an ISO date or date-time")
    role = e.get("by_role")
    if not isinstance(role, str) or not role.strip() or not _ROLE.match(role.strip()):
        errors.append("by_role: a role of 1 to 64 printable characters")
    status = e.get("status")
    if status is not None and status not in STATUSES:
        errors.append(f"status: one of {', '.join(STATUSES)}")
    elif status in RETEST_ONLY:
        errors.append(f"status: {status} is set only by a completed retest")
    note = e.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > MAX_NOTE):
        errors.append(f"note: text of at most {MAX_NOTE} characters")
    declared, derr = validate_declared(e.get("declared"))
    errors += derr
    if status is None and not declared:
        errors.append("entry: a status or at least one declared field")
    if errors:
        return None, errors
    out = {"at": e["at"], "by_role": role.strip(), "source": e.get("source") or "declaration"}
    if status is not None:
        out["status"] = status
    if declared:
        out["declared"] = declared
    if note:
        out["note"] = note
    for k in ("seq", "by"):
        if k in e:
            out[k] = e[k]
    return out, []


def verification(action_finding_ids: List[str], retest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """What one COMPLETED retest says about one action, or None (retest not complete, or none of its findings in the
    retest's scope). ``retest`` = {retest_id, at, outcome, finding_ids (scope or None), verdicts: [compute_verdicts]}."""
    if not isinstance(retest, dict) or retest.get("outcome") != "complete" or not _valid_at(retest.get("at")):
        return None
    scope = retest.get("finding_ids")
    ids = [i for i in action_finding_ids if not scope or i in {str(x) for x in scope}]
    verdict = {str(v.get("finding_id")): v.get("verdict") for v in retest.get("verdicts") or []
               if isinstance(v, dict) and v.get("finding_id")}
    checked = [i for i in ids if i in verdict]
    if not checked:
        return None
    not_reproduced = [i for i in checked if verdict[i] == "fixed"]
    reproduced = [i for i in checked if verdict[i] != "fixed"]
    unchecked = [i for i in action_finding_ids if i not in checked]
    if reproduced and not not_reproduced:
        status = "failed_verification"
    elif not reproduced and not unchecked:
        status = "verified_resolved"
    else:
        status = "partially_resolved"
    return {"status": status, "at": retest["at"], "retest_id": retest.get("retest_id"),
            "retest_campaign_id": retest.get("retest_campaign_id"), "not_reproduced": not_reproduced,
            "reproduced": reproduced, "not_checked": unchecked}


def _ts(at: str) -> str:
    """Sort key of an ISO date or date-time: UTC, a date alone is its midnight UTC."""
    try:
        d = datetime.fromisoformat(str(at).replace("Z", "+00:00"))
    except ValueError:
        return str(at)
    if d.tzinfo is not None:
        d = d.astimezone(timezone.utc).replace(tzinfo=None)
    return d.isoformat()


def _date_of(at: str) -> str:
    return str(at or "")[:10]


def status_text(status: str, entry: Optional[Dict[str, Any]]) -> str:
    e = entry or {}
    role, date = e.get("by_role"), _date_of(e.get("at"))
    if status == "proposed" and not e:
        return "Proposed"
    if status == "applied":
        return f"Declared applied by {role}, {date} — not verified"
    if status == "verified_resolved":
        return f"Not reproduced at retest ({date})"
    if status == "partially_resolved":
        v = e.get("verification") or {}
        n = len(v.get("not_reproduced") or [])
        tot = n + len(v.get("reproduced") or []) + len(v.get("not_checked") or [])
        return f"Partly reproduced at retest ({date}): {n} of {_plural(tot, 'finding')} not reproduced"
    if status == "failed_verification":
        return f"Reproduced at retest ({date})"
    if status == "risk_accepted":
        until = (e.get("declared") or {}).get("risk_accepted_until")
        return f"Risk accepted by {role}, {date}" + (f" (until {until})" if until else "")
    return f"{STATUS_LABEL.get(status, status)} — {role}, {date}" if role else STATUS_LABEL.get(status, status)


def replay(entries: Iterable[Any], verifications: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """Replay an action's history: the stored/declared entries (append-only) and the retest verifications, in time
    order (a retest at the same instant comes after). Returns status, the entry that set it, the declared fields with
    who declared them, the full history and the entries that were skipped (with why)."""
    timeline: List[Tuple[str, int, int, Dict[str, Any]]] = []
    issues: List[Dict[str, Any]] = []
    for n, raw in enumerate(entries or []):
        e, errs = validate_entry(raw)
        if e is None:
            issues.append({"index": n, "problems": errs})
            continue
        timeline.append((e["at"], 0, n, e))
    for n, v in enumerate(verifications or []):
        timeline.append((v["at"], 1, n, {"at": v["at"], "source": "retest", "by_role": "retest",
                                         "status": v["status"], "verification": v}))
    timeline.sort(key=lambda t: (_ts(t[0]), t[1], t[2]))
    status, setter = "proposed", None
    declared: Dict[str, Any] = {}
    history: List[Dict[str, Any]] = []
    last_retest = None
    for _, kind, n, e in timeline:
        to = e.get("status")
        if kind == 1:
            last_retest = e
            if status not in VERIFIABLE:    # nothing declared applied: the retest is an observation, not a verification
                rec = dict(e)
                rec["observation"] = rec.pop("status")
                history.append(rec)
                continue
        if to and kind == 0 and to != status and to not in TRANSITIONS.get(status, set()):
            issues.append({"index": n, "problems": [f"transition {status} -> {to} is not allowed"]})
            continue
        rec = dict(e)
        if to:
            rec["from"], rec["to"] = status, to
            rec.pop("status", None)
            status, setter = to, e
        for k, v in (e.get("declared") or {}).items():
            if v is None:
                declared.pop(k, None)
            else:
                declared[k] = {"value": v, "by_role": e["by_role"], "at": e["at"]}
        history.append(rec)
    return {"status": status, "setter": setter, "declared": declared, "history": history, "issues": issues,
            "last_retest": last_retest}


def _declared_view(declared: Dict[str, Any]) -> Dict[str, Any]:
    def d(k: str) -> Dict[str, Any]:
        x = declared.get(k)
        if not x:
            return {"value": UNKNOWN, "provenance": None}
        return {"value": x["value"], "provenance": "declared", "by_role": x["by_role"], "at": x["at"]}
    return {"owner": d("owner"), "approval_required": d("approval_required"),
            "service_interruption_risk": d("service_interruption_risk"), "due_date": d("due_date"),
            "risk_accepted_until": d("risk_accepted_until")}


def _reattach(state_actions: Dict[str, Any], actions: List[Dict[str, Any]]) -> Tuple[Dict[str, str], List[str]]:
    """Stored states whose action id is no longer produced (the fix list changed: a finding released from privacy
    review, an operator false positive…) follow their findings: the current action sharing most of them (then the
    higher priority); both histories are replayed together, in time order. States with no shared finding are kept
    apart as orphaned, never dropped."""
    current = {a["action_id"] for a in actions}
    mapping: Dict[str, str] = {}
    orphaned = []
    for sid, s in sorted(state_actions.items()):
        if sid in current:
            continue
        old = {str(x) for x in (s or {}).get("finding_ids") or []}
        best = None
        for a in actions:
            k = len(old & set(a["finding_ids"]))
            if k and (best is None or k > best[0] or (k == best[0] and a["priority"] < best[1]["priority"])):
                best = (k, a)
        if best is not None:
            mapping[sid] = best[1]["action_id"]
        else:
            orphaned.append(sid)
    return mapping, orphaned


def build_plan(campaign_id: str, paths_doc: Dict[str, Any], findings: Iterable[Any],
               state: Optional[Dict[str, Any]] = None, retests: Optional[List[Dict[str, Any]]] = None,
               verification_available: bool = True) -> Dict[str, Any]:
    """The plan document. ``state`` = {"actions": {action_id: {"finding_ids", "history": [entries]}}} (Pro store or
    the Community declarations file, already parsed); ``retests`` = completed-retest records (see ``verification``).
    Edition differences are inputs only: Community passes no retest and ``verification_available=False``."""
    findings_l = [v for v in findings or [] if isinstance(v, dict)]
    actions = build_actions(campaign_id, paths_doc, findings_l)
    st_actions = dict(((state or {}).get("actions") or {}))
    st_actions = {str(k): v for k, v in st_actions.items() if isinstance(v, dict)}
    mapping, orphaned = _reattach(st_actions, actions)
    by_id: Dict[str, Dict[str, Any]] = {a["action_id"]: {"history": list((st_actions.get(a["action_id"]) or {})
                                                                         .get("history") or []), "from": []}
                                       for a in actions}
    for old, new in mapping.items():
        by_id[new]["history"] = list(st_actions[old].get("history") or []) + by_id[new]["history"]
        by_id[new]["from"].append(old)
    issues: List[Dict[str, Any]] = []
    counts = {s: 0 for s in STATUSES}
    covered = set()
    for a in actions:
        ver = [v for v in (verification(a["finding_ids"], r) for r in (retests or [])) if v]
        r = replay(by_id[a["action_id"]]["history"], ver)
        a["status"] = r["status"]
        a["status_label"] = STATUS_LABEL[r["status"]]
        a["status_text"] = status_text(r["status"], r["setter"])
        a["status_verified"] = r["status"] in RETEST_ONLY
        dv = _declared_view(r["declared"])
        a["owner"] = dv["owner"]
        a["approval_required"] = dv["approval_required"]
        a["service_interruption_risk"] = dv["service_interruption_risk"]
        a["due_date"] = dv["due_date"]
        a["risk_accepted_until"] = dv["risk_accepted_until"]
        a["history"] = r["history"]
        lr = r["last_retest"]
        a["last_retest"] = None if not lr else {
            "result": lr["status"], "label": STATUS_LABEL[lr["status"]], "text": status_text(lr["status"], lr),
            "at": lr["at"], "retest_id": lr["verification"].get("retest_id"),
            "retest_campaign_id": lr["verification"].get("retest_campaign_id")}
        if by_id[a["action_id"]]["from"]:
            a["state_carried_from"] = sorted(by_id[a["action_id"]]["from"])
        for i in r["issues"]:
            issues.append({"action_id": a["action_id"], **i})
        counts[r["status"]] += 1
        covered.update(a["finding_ids"])
    ff = (paths_doc or {}).get("fix_first") or {}
    source = str(ff.get("source") or "none")
    return {
        "schema_version": PLAN_VERSION,
        "campaign_id": campaign_id,
        "label": LABEL,
        "definition": DEFINITION,
        "plain": PLAIN,
        "basis": source,
        "basis_label": ff.get("label"),
        "basis_note": ff.get("note"),
        "actions": actions,
        "summary": {"actions": len(actions), "by_status": counts, "findings_covered": len(covered),
                    "open_findings": ff.get("open_findings", 0)},
        "verification": ("retest" if verification_available else "not_available"),
        "verification_note": ("Verified statuses come only from a completed retest: « Not reproduced at retest » is not "
                              "a proof of resolution." if verification_available else
                              "This edition does not run retests: statuses are declarations, never verified."),
        "score_effect": "none",
        "score_note": "Treatment statuses never change the findings, the counts or the rating of this campaign.",
        "orphaned_states": orphaned,
        "issues": issues,
    }
