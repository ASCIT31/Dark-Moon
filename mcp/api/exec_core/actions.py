"""Prioritized Treatment Plan: treatment actions, their status machine and their history (both editions).

« Actions recommended in priority order to reduce security exposure, address related findings and interrupt relevant
attack paths. »

Actions are derived, never invented:

* one action = one penalty unit of the Cyber Score: (asset, weakness class) of ``identity.unit_key`` — one root cause
  to fix, whatever the number of findings, agents or endpoints. Its findings are the open findings of that unit; the
  campaign's fix items (``fix_first`` of the attack-path document built by ``fix_triage``, then the severity × proof
  groups ``triage.groups_all``) are kept inside the action (``fix_ids``, ``findings``), never shown as separate
  actions;
* order: units holding a fix on an attack path first (most paths interrupted first), then worst reported severity,
  then proof; inside equal keys the position of the unit's first finding in the fix list. ``priority`` is the
  position (1 = first), ``rank`` is shared by equal keys and ``tie_size`` says how many share it;
* ``action_id`` = ``act_`` + SHA-256(campaign | ``unit`` | unit key)[:16]: stable for a campaign and a unit.
  Migration from the per-fix-item ids of exec_core <= 1.4 (``act_`` + SHA-256(campaign | fix id)): a stored state
  whose id is no longer produced follows its findings to the action holding most of them (``_reattach``); when
  several stored states land on one action and their replayed statuses differ, the action takes the least advanced
  one (``ADVANCEMENT``) and its history gains a ``merged`` entry naming each former state; no entry is dropped;
* ``title`` = the weakness class in words, then the head finding's title as the agent wrote it (never re-cased);
* ``recommended_treatment`` quotes the remediation text the testing agent wrote on the head finding, as such; no text
  is generated. Without a text the action says so;
* ``treatment_type`` and the indicative ``effort`` band (S / M / L, ``EFFORT_OF_CLASS``) are derived from the weakness
  class (indicative, to confirm by the system owner; never a cost or a duration);
* ``expected_impact`` is counts only: findings covered, attack paths the unit's fix items interrupt in the server's
  simulation (``attack_paths_interrupted``), and among them the Evidence-Backed Attack Paths (``legend.path_kind_of``:
  ``evidence_backed_paths_interrupted``, the only count the impact text calls interrupted paths); never a risk
  reduction %. ``proven_attack_paths`` (key kept for compatibility) lists the Evidence-Backed Attack Paths only;
* ``related_controls`` = the framework controls the action's counted findings are technical evidence for
  (``frameworks_assess.related_controls``); dependencies, owner, approval requirement and service interruption risk
  are ``unknown`` unless a person declared them.

Status machine (``TRANSITIONS``). ``applied`` is a declaration, never a verification. ``verified_resolved``,
``partially_resolved`` and ``failed_verification`` come only from a completed retest campaign matched with the
exec_core identity (``retest.compute_verdicts``) that passed the retest coverage gate (``retest_coverage``: assets
registered, toolbox commands executed, measured duration, and an agent of the action's findings dispatched), on an
action declared applied (``VERIFIABLE``); their labels say « (not) reproduced at retest ». A completed retest without
that coverage verifies nothing: it is recorded as an observation « Retest without coverage — not verified ».
``risk_accepted`` needs a named risk owner and an expiry date at most 12 months ahead (``validate_new_entry``, the
check of a new declaration); an acceptance past its date reads « Risk acceptance expired ». On an action not declared applied the retest is an observation (``last_retest``). The history is
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

PLAN_VERSION = "darkmoon-treatment-plan/2"
STATE_VERSION = "darkmoon-treatment-state/1"
LABEL = "Prioritized Treatment Plan"
DEFINITION = ("Actions recommended in priority order to reduce security exposure, address related findings and "
              "interrupt relevant attack paths.")
UNIT_NOTE = ("One action per weakness class and asset (the unit of the Cyber Score): the findings it lists share one root "
             "cause to fix.")
VERIFICATION_NOTE = ("Verified statuses come only from a completed retest that met its coverage gate (assets registered, "
                     "toolbox commands executed and an agent of the findings dispatched): « Not reproduced at retest » "
                     "is not a proof of resolution.")
EFFORT_NOTE = ("Effort bands (Small / Medium / Large) are indicative, by weakness class, to confirm by the system owner; "
               "they are not a cost or a duration.")
PLAN_VERSION_NOTE = "darkmoon-treatment-plan/2: one action per (asset, weakness class)"
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
    "risk_owner": "the accountable risk owner, named by the organisation (free text, not a platform role)",
    "approval_required": "true / false",
    "service_interruption_risk": "none / low / medium / high",
    "due_date": "YYYY-MM-DD",
    "risk_accepted_until": "YYYY-MM-DD",
}
INTERRUPTION_RISKS = ("none", "low", "medium", "high")
MAX_NOTE = 500
MAX_ROLE = 64
MAX_RISK_OWNER = 120
MAX_ACCEPTANCE_DAYS = 366      # at most 12 months (a leap year included)
UNKNOWN = "unknown"
# how far a status is along the fix: a merge of several former states keeps the least advanced one (a decision not to
# fix, risk accepted or deferred, never spreads to findings it was not taken for)
ADVANCEMENT = {"proposed": 0, "deferred": 0, "risk_accepted": 0, "approved": 1, "scheduled": 2, "in_progress": 3,
               "failed_verification": 3, "applied": 4, "verification_pending": 5, "partially_resolved": 5,
               "verified_resolved": 6}
RETEST_RESULT_LABEL = {"inconclusive": "Retest without coverage — not verified"}
EFFORT_VERSION = "darkmoon-effort-band/1"
EFFORT_LABEL = {"S": "Small", "M": "Medium", "L": "Large", UNKNOWN: "Not determined"}
EFFORT_PROVENANCE = "indicative, by weakness class — to confirm by the system owner"
# indicative effort band of a fix of one weakness class (no cost, no duration)
EFFORT_OF_CLASS = {
    "configuration": "S", "cryptography": "S", "information_disclosure": "S", "session": "S", "open_redirect": "S",
    "xxe": "S", "csrf": "M", "xss": "M", "sql_injection": "M", "nosql_injection": "M", "file_access": "M",
    "file_upload": "M", "ssrf": "M", "code_execution": "M", "authentication": "M", "vulnerable_component": "M",
    "availability": "M", "input_validation": "M", "access_control": "L", "business_logic": "L",
}

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
_ROLE_ANY = re.compile(r"^[^\x00-\x1f\x7f]+$")


# ── actions ────────────────────────────────────────────────────────────────────────────────────────────────────────

def action_id(campaign_id: str, fix_id: str) -> str:
    """Id of exec_core <= 1.4 (one action per fix item): kept to recognise stored states (migration)."""
    return "act_" + hashlib.sha256(f"{campaign_id}|{fix_id}".encode()).hexdigest()[:16]


def unit_action_id(campaign_id: str, unit: str) -> str:
    """Stable for the same campaign and penalty unit (asset|weakness class): the same root cause gives the same id on
    every recompute, whichever findings it holds."""
    return "act_" + hashlib.sha256(f"{campaign_id}|unit|{unit}".encode()).hexdigest()[:16]


def _plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_PROOF_RANK = {"exploited": 3, "confirmed": 2, "unconfirmed": 1}


def _head(ids: List[str], vmap: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    known = [vmap[i] for i in ids if i in vmap]
    if not known:
        return None
    return sorted(known, key=lambda v: (-_SEV_RANK.get(identity.severity_of(v), 0),
                                        -_PROOF_RANK.get(identity.proof_of(v), 0), str(v.get("id"))))[0]


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


def _treatment_type(wc: str) -> Dict[str, Any]:
    t = _TYPE_OF_CLASS.get(wc, UNKNOWN)
    return {"value": t, "label": TREATMENT_TYPE_LABEL[t], "weakness_class": wc,
            "basis": "derived from the weakness class; to confirm by the system owner" if t != UNKNOWN
            else "the weakness class does not say which kind of change is needed"}


def effort_band(wc: str) -> Dict[str, Any]:
    """Indicative effort band of a fix of this weakness class: S / M / L, never a cost or a duration."""
    band = EFFORT_OF_CLASS.get(str(wc or ""), UNKNOWN)
    return {"band": band, "label": EFFORT_LABEL[band], "provenance": EFFORT_PROVENANCE, "version": EFFORT_VERSION}


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


def legacy_action_ids(campaign_id: str, paths_doc: Dict[str, Any]) -> Dict[str, List[str]]:
    """{exec_core <= 1.4 action id: its findings} — one per fix item. A stored state or a Community declaration that
    names one of these ids follows its findings to the current action (migration, ``_reattach``)."""
    _, cands = _candidates(paths_doc)
    return {action_id(campaign_id, str(it["fix_id"])): list(it["finding_ids"]) for it in cands if it.get("fix_id")}


def _title(wc: str, head: Optional[Dict[str, Any]], n: int, fallback: str) -> str:
    """« <class in words> — <head finding title as written> (+k related findings) »: never re-cased, never cut here
    (renderings bound their cells)."""
    t = " ".join(str((head or {}).get("title") or "").split()) or fallback
    out = f"{_legend.weakness_class_label(wc)} — {t}"
    return out + (f" (+{_plural(n - 1, 'related finding')})" if n > 1 else "")


def build_actions(campaign_id: str, paths_doc: Dict[str, Any], findings: Iterable[Any],
                  target_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """The campaign's actions in priority order (no status), one per penalty unit (asset, weakness class).
    ``paths_doc`` = the attack-path document (« all » provenance) built WITHOUT retest verdicts, so the plan keeps the
    campaign's own findings. ``target_id`` = the campaign's target (a finding without one takes it, as in the score)."""
    tid = str(target_id or (paths_doc or {}).get("target_id") or "")
    vmap = {str(v.get("id")): v for v in findings or [] if isinstance(v, dict) and v.get("id")}
    by_finding, interrupts = _paths_index(paths_doc)
    kind_of = {str(p["id"]): _legend.path_kind_of(p) for p in (paths_doc or {}).get("paths") or []
               if isinstance(p, dict) and p.get("id")}
    eb_total = sum(1 for k in kind_of.values() if k == "evidence_backed")
    _, cands = _candidates(paths_doc)
    units: Dict[str, Dict[str, Any]] = {}
    for pos, it in enumerate(cands):
        for fid in it["finding_ids"]:
            v = vmap.get(fid) or {"id": fid}
            vv = {**v, "target_id": v.get("target_id") or tid}
            key = identity.unit_key(vv)
            u = units.setdefault(key, {"unit": key, "asset": identity.asset_key(vv),
                                       "weakness_class": identity.weakness_class(vv), "ids": [], "items": [],
                                       "first": pos})
            if fid not in u["ids"]:
                u["ids"].append(fid)
            if not any(x is it for x in u["items"]):
                u["items"].append(it)
    rows = []
    for u in units.values():
        ids = u["ids"]
        head = _head(ids, vmap)
        on_paths = [it for it in u["items"] if it["_basis"] == "attack-paths"]
        broken: set = set()
        of_total = None
        for it in u["items"]:
            if it["_basis"] == "attack-paths":
                broken.update(interrupts.get(str(it.get("fix_id")), []))
                if it.get("of_total") is not None:
                    of_total = max(of_total or 0, int(it.get("of_total") or 0))
            else:
                broken.update(str(x) for x in it.get("breaks_paths") or [])
        sev = identity.severity_of(head or {}) if head else (u["items"][0].get("severity") or UNKNOWN)
        proof = identity.proof_of(head or {}) if head else (u["items"][0].get("proof") or "unconfirmed")
        key = (0 if on_paths else 1, -len(broken) if on_paths else 0, -_SEV_RANK.get(sev, 0),
               -_PROOF_RANK.get(proof, 0))
        rows.append((key, u["first"], u["unit"], u, head, sorted(broken), of_total, sev, proof, bool(on_paths)))
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    ranks: Dict[Tuple[Any, ...], int] = {}
    sizes: Dict[Tuple[Any, ...], int] = {}
    for i, r in enumerate(rows, 1):
        ranks.setdefault(r[0], i)
        sizes[r[0]] = sizes.get(r[0], 0) + 1
    actions = []
    for pos, (key, _first, unit, u, head, broken, of_total, sev, proof, on_paths) in enumerate(rows, 1):
        ids = u["ids"]
        wc = u["weakness_class"]
        n = len(ids)
        related = sorted({p["id"] for i in ids for p in by_finding.get(i, [])})
        proven = sorted({p["id"] for i in ids for p in by_finding.get(i, [])
                         if kind_of.get(str(p["id"])) == "evidence_backed"})
        eb_broken = [pid for pid in broken if kind_of.get(str(pid)) == "evidence_backed"]
        what = f"{_plural(n, 'finding')} of the class {_legend.weakness_class_label(wc)} on {u['asset']}"
        if on_paths:
            expl = (f"Interrupts {len(broken)} of {of_total} known attack paths in the server's simulation (not "
                    f"applied), {len(eb_broken)} of them Evidence-Backed. Addresses {what}, worst {sev} ({proof}).")
        else:
            expl = f"Ordered by reported severity, then proof: worst {sev} ({proof}). Addresses {what}."
        impact_text = f"Findings covered: {n}"
        if broken or on_paths:
            impact_text += (f" · Evidence-Backed Attack Paths interrupted: {len(eb_broken)}"
                            + (f" of {eb_total}" if on_paths else ""))
            if len(broken) > len(eb_broken):
                impact_text += f" · other attack paths interrupted (not evidence-backed): {len(broken) - len(eb_broken)}"
        fix_ids = [str(it.get("fix_id")) for it in u["items"] if it.get("fix_id")]
        actions.append({
            "action_id": unit_action_id(campaign_id, unit),
            "unit": unit,
            "asset": u["asset"],
            "weakness_class": wc,
            "weakness_class_label": _legend.weakness_class_label(wc),
            "fix_id": fix_ids[0] if fix_ids else None,
            "fix_ids": fix_ids,
            "priority": pos,
            "rank": ranks[key],
            "tie_size": sizes[key],
            "basis": "attack-paths" if on_paths else "reported-severity-x-proof",
            "title": _title(wc, head, n, fix_ids[0] if fix_ids else unit),
            "explanation": expl,
            "severity": sev,
            "proof": proof,
            "head_finding_id": str((head or {}).get("id") or (ids[0] if ids else "")) or None,
            "finding_ids": ids,
            "findings": [{"finding_id": i, "title": str((vmap.get(i) or {}).get("title") or ""),
                          "severity": identity.severity_of(vmap.get(i) or {}),
                          "proof": identity.proof_of(vmap.get(i) or {}),
                          "endpoint": str((vmap.get(i) or {}).get("endpoint") or "")} for i in ids],
            "recommended_treatment": _recommended(ids, head, vmap),
            "treatment_type": _treatment_type(wc),
            "effort": effort_band(wc),
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
                                "evidence_backed_paths_total": eb_total if on_paths else None,
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
        elif k == "risk_owner":
            if isinstance(v, str) and v.strip() and len(v.strip()) <= MAX_RISK_OWNER and _ROLE_ANY.match(v.strip()):
                clean[k] = v.strip()
            else:
                errors.append(f"declared.risk_owner: the accountable risk owner, 1 to {MAX_RISK_OWNER} printable "
                              "characters")
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


def _date(s: Any) -> Optional[datetime]:
    try:
        return datetime.strptime(str(s or "")[:10], "%Y-%m-%d")
    except ValueError:
        return None


def validate_new_entry(e: Any, today: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """``validate_entry`` plus the rules a NEW declaration must meet (an operator's PATCH; stored history is replayed
    with ``validate_entry`` only, so an older entry is never dropped): accepting a risk needs a named risk owner
    (``declared.risk_owner``) and an expiry ``declared.risk_accepted_until`` after ``today`` and at most 12 months
    ahead; any declared expiry obeys the same bound."""
    clean, errors = validate_entry(e)
    if clean is None:
        return None, errors
    d = clean.get("declared") or {}
    now = _date(today)
    until = d.get("risk_accepted_until")
    if until is not None and now is not None:
        u = _date(until)
        if u is None or u <= now or (u - now).days > MAX_ACCEPTANCE_DAYS - 1:
            errors.append("declared.risk_accepted_until: a date after today and at most 12 months ahead")
    if clean.get("status") == "risk_accepted":
        if not d.get("risk_owner"):
            errors.append("declared.risk_owner: required to accept a risk (the accountable risk owner, not a platform "
                          "role)")
        if not until:
            errors.append("declared.risk_accepted_until: required to accept a risk (at most 12 months ahead)")
    return (None, errors) if errors else (clean, [])


RETEST_FLOOR = {"assets_registered": 1, "commands": 1, "measured_duration_seconds": 1}


def _norm_agent(name: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name or "").strip().lower()).strip("-")


def retest_coverage(retest: Dict[str, Any], agents: Iterable[Any] = ()) -> Dict[str, Any]:
    """The retest coverage gate: a completed retest verifies an action only when the server recorded, for the retest
    campaign, at least one registered asset, at least one toolbox command, a measured duration, and among the
    dispatched agents one of the agents that reported the action's findings (any specialised agent when none is
    named). ``retest["coverage"]`` = ``score.coverage_of`` of the retest campaign. Returns {ok, missing, text}."""
    cov = (retest or {}).get("coverage")
    missing: List[str] = []
    if not isinstance(cov, dict) or not cov.get("present"):
        missing.append("coverage not recorded")
    else:
        if int(cov.get("assets_registered") or 0) < RETEST_FLOOR["assets_registered"]:
            missing.append("no asset registered")
        if int(cov.get("commands_executed") or 0) + int(cov.get("workflows_executed") or 0) < RETEST_FLOOR["commands"]:
            missing.append("no toolbox command executed")
        if int(cov.get("measured_duration_seconds") or 0) < RETEST_FLOOR["measured_duration_seconds"]:
            missing.append("no measured duration")
        dispatched = {_norm_agent(a) for a in cov.get("agents_dispatched") or []}
        dispatched.discard("")
        wanted = {_norm_agent(a) for a in agents or []}
        wanted.discard("")
        if wanted and not (wanted & dispatched):
            missing.append("no agent of these findings dispatched (" + ", ".join(sorted(wanted)) + ")")
        elif not wanted and not cov.get("specialised_agents"):
            missing.append("no specialised agent dispatched")
    return {"ok": not missing, "missing": missing,
            "text": "retest coverage met" if not missing else "retest without coverage: " + "; ".join(missing)}


def verification(action_finding_ids: List[str], retest: Dict[str, Any],
                 agents: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
    """What one COMPLETED retest says about one action, or None (retest not complete, or none of its findings in the
    retest's scope). ``retest`` = {retest_id, at, outcome, finding_ids (scope or None), verdicts: [compute_verdicts],
    coverage: score.coverage_of(retest campaign)}. A retest below the coverage gate (``retest_coverage``) gives
    status ``inconclusive``: recorded, never a verification. ``agents`` = the agents that reported the findings."""
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
    gate = retest_coverage(retest, agents)
    if not gate["ok"]:
        status = "inconclusive"
    elif reproduced and not not_reproduced:
        status = "failed_verification"
    elif not reproduced and not unchecked:
        status = "verified_resolved"
    else:
        status = "partially_resolved"
    return {"status": status, "at": retest["at"], "retest_id": retest.get("retest_id"),
            "retest_campaign_id": retest.get("retest_campaign_id"), "not_reproduced": not_reproduced,
            "reproduced": reproduced, "not_checked": unchecked, "coverage_ok": gate["ok"],
            "coverage_missing": gate["missing"], "coverage_text": gate["text"]}


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


def _who(e: Dict[str, Any]) -> str:
    """The account that recorded an entry (Pro stamps it), else its role (Community local file)."""
    return str(e.get("by") or e.get("by_role") or "unknown")


def status_text(status: str, entry: Optional[Dict[str, Any]], declared: Optional[Dict[str, Any]] = None,
                today: Optional[str] = None) -> str:
    e = entry or {}
    role, date = e.get("by_role"), _date_of(e.get("at"))
    if status == "proposed" and not e:
        return "Proposed"
    if status == "inconclusive":
        v = e.get("verification") or {}
        return (f"Retest without coverage ({date}) — not verified"
                + (": " + "; ".join(v.get("coverage_missing") or []) if v.get("coverage_missing") else ""))
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
        dec = declared or {}
        until = ((dec.get("risk_accepted_until") or {}).get("value") if dec
                 else (e.get("declared") or {}).get("risk_accepted_until"))
        owner = ((dec.get("risk_owner") or {}).get("value") if dec else (e.get("declared") or {}).get("risk_owner"))
        if until and today and str(until) < str(today)[:10]:
            return (f"Risk acceptance expired on {until}"
                    + (f" (accepted by {owner}, recorded by {_who(e)} on {date})" if owner else ""))
        if not owner or not until:
            return (f"Risk accepted, recorded by {_who(e)} on {date} — incomplete: "
                    + " and ".join(x for x in ("no named risk owner" if not owner else "",
                                                "no expiry date" if not until else "") if x))
        return f"Risk accepted by {owner}, recorded by {_who(e)} on {date}, until {until}"
    return f"{STATUS_LABEL.get(status, status)} — {role}, {date}" if role else STATUS_LABEL.get(status, status)


def replay(entries: Iterable[Any], verifications: Iterable[Dict[str, Any]] = (),
           start: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
    st0 = start or {}
    status, setter = st0.get("status", "proposed"), st0.get("setter")
    declared: Dict[str, Any] = dict(st0.get("declared") or {})
    history: List[Dict[str, Any]] = list(st0.get("history") or [])
    last_retest = None
    for _, kind, n, e in timeline:
        to = e.get("status")
        if kind == 1:
            last_retest = e
            # nothing declared applied, or a retest below its coverage gate: an observation, not a verification
            if status not in VERIFIABLE or to == "inconclusive":
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
                declared[k] = {"value": v, "by_role": e["by_role"], "at": e["at"],
                               **({"by": e["by"]} if e.get("by") else {})}
        history.append(rec)
    return {"status": status, "setter": setter, "declared": declared, "history": history, "issues": issues,
            "last_retest": last_retest}


def _declared_view(declared: Dict[str, Any]) -> Dict[str, Any]:
    def d(k: str) -> Dict[str, Any]:
        x = declared.get(k)
        if not x:
            return {"value": UNKNOWN, "provenance": None}
        return {"value": x["value"], "provenance": "declared", "by_role": x["by_role"], "at": x["at"],
                **({"by": x["by"]} if x.get("by") else {})}
    return {"owner": d("owner"), "approval_required": d("approval_required"),
            "service_interruption_risk": d("service_interruption_risk"), "due_date": d("due_date"),
            "risk_accepted_until": d("risk_accepted_until"), "risk_owner": d("risk_owner")}


def _reattach(state_actions: Dict[str, Any], actions: List[Dict[str, Any]]) -> Tuple[Dict[str, str], List[str]]:
    """Stored states whose action id is no longer produced (the per-fix-item ids of exec_core <= 1.4, or a fix list
    that changed: a finding released from privacy review, an operator false positive…) follow their findings: the
    current action sharing most of them (then the higher priority). States with no shared finding are kept apart as
    orphaned, never dropped."""
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


def _last_at(entries: Iterable[Any]) -> str:
    ats = [str(e.get("at")) for e in entries or [] if isinstance(e, dict) and _valid_at(e.get("at"))]
    return max(ats, key=_ts) if ats else ""


def _merged_start(sources: List[Tuple[str, List[Any]]]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Several stored states carried onto one action. Same replayed status -> None (their histories are replayed
    together, in time order). Different statuses -> the start of the action's own replay: the least advanced status
    (``ADVANCEMENT``, then the status order), the declared fields of all of them (latest wins), every former history
    entry kept (``carried_from``) and one ``merged`` entry naming each former state and its status."""
    replayed = [(sid, replay(h)) for sid, h in sources]
    statuses = {r["status"] for _, r in replayed}
    if len(statuses) <= 1:
        return None, []
    least = min(statuses, key=lambda st: (ADVANCEMENT.get(st, 0), STATUSES.index(st)))
    history: List[Dict[str, Any]] = []
    declared: Dict[str, Any] = {}
    issues: List[Dict[str, Any]] = []
    for sid, r in replayed:
        for h in r["history"]:
            history.append({**h, "carried_from": sid})
        for k, v in r["declared"].items():
            if k not in declared or _ts(v["at"]) >= _ts(declared[k]["at"]):
                declared[k] = v
        for i in r["issues"]:
            issues.append({"carried_from": sid, **i})
    history.sort(key=lambda h: _ts(h.get("at")))
    at = _last_at([h for _, h0 in sources for h in h0]) or (history[-1]["at"] if history else "")
    merged = {"at": at, "source": "merge", "by_role": "system", "from": None, "to": least, "merged": True,
              "merged_from": [{"action_id": sid, "status": r["status"]} for sid, r in replayed],
              "note": ("Several former actions were merged into this one (one action per weakness class and asset): "
                       "the least advanced status is kept.")}
    history.append(merged)
    return {"status": least, "setter": merged, "declared": declared, "history": history}, issues


def build_plan(campaign_id: str, paths_doc: Dict[str, Any], findings: Iterable[Any],
               state: Optional[Dict[str, Any]] = None, retests: Optional[List[Dict[str, Any]]] = None,
               verification_available: bool = True, target_id: Optional[str] = None,
               today: Optional[str] = None) -> Dict[str, Any]:
    """The plan document. ``state`` = {"actions": {action_id: {"finding_ids", "history": [entries]}}} (Pro store or
    the Community declarations file, already parsed); ``retests`` = completed-retest records (see ``verification``).
    ``today`` (YYYY-MM-DD, the server's date) only marks risk acceptances past their date; without it none is marked.
    Edition differences are inputs only: Community passes no retest and ``verification_available=False``."""
    findings_l = [v for v in findings or [] if isinstance(v, dict)]
    vmap = {str(v.get("id")): v for v in findings_l if v.get("id")}
    actions = build_actions(campaign_id, paths_doc, findings_l, target_id)
    st_actions = dict(((state or {}).get("actions") or {}))
    st_actions = {str(k): v for k, v in st_actions.items() if isinstance(v, dict)}
    mapping, orphaned = _reattach(st_actions, actions)
    by_id: Dict[str, Dict[str, Any]] = {a["action_id"]: {"own": list((st_actions.get(a["action_id"]) or {})
                                                                      .get("history") or []), "from": []}
                                       for a in actions}
    for old, new in mapping.items():
        by_id[new]["from"].append(old)
    issues: List[Dict[str, Any]] = []
    counts = {s: 0 for s in STATUSES}
    expired = 0
    covered = set()
    for a in actions:
        rec = by_id[a["action_id"]]
        agents = sorted({str((vmap.get(i) or {}).get("discovered_by_agent") or "") for i in a["finding_ids"]} - {""})
        ver = [v for v in (verification(a["finding_ids"], r, agents) for r in (retests or [])) if v]
        sources = [(old, list(st_actions[old].get("history") or [])) for old in sorted(rec["from"])]
        # several former states on one action: merged first, the action's own entries are replayed after the merge
        start, merge_issues = _merged_start(sources) if len(sources) > 1 else (None, [])
        if start is None:
            r = replay([h for _, h in sources for h in h] + rec["own"], ver)
        else:
            r = replay(rec["own"], ver, start)
        dv = _declared_view(r["declared"])
        a["status"] = r["status"]
        a["status_label"] = STATUS_LABEL[r["status"]]
        a["status_text"] = status_text(r["status"], r["setter"], r["declared"], today)
        a["status_verified"] = r["status"] in RETEST_ONLY
        a["owner"] = dv["owner"]
        a["approval_required"] = dv["approval_required"]
        a["service_interruption_risk"] = dv["service_interruption_risk"]
        a["due_date"] = dv["due_date"]
        a["risk_accepted_until"] = dv["risk_accepted_until"]
        a["risk_owner"] = dv["risk_owner"]
        if r["status"] == "risk_accepted":
            until = dv["risk_accepted_until"]["value"]
            is_expired = bool(today and until != UNKNOWN and str(until) < str(today)[:10])
            a["risk_acceptance"] = {"risk_owner": dv["risk_owner"]["value"], "until": until,
                                    "recorded_by": _who(r["setter"] or {}), "recorded_at": (r["setter"] or {}).get("at"),
                                    "expired": is_expired,
                                    "complete": dv["risk_owner"]["value"] != UNKNOWN and until != UNKNOWN}
            if is_expired:
                a["status_label"] = "Risk acceptance expired"
                expired += 1
            if not a["risk_acceptance"]["complete"]:
                issues.append({"action_id": a["action_id"], "kind": "risk-acceptance-incomplete",
                               "problems": ["a risk acceptance needs a named risk owner and an expiry date"]})
        a["history"] = r["history"]
        lr = r["last_retest"]
        a["last_retest"] = None if not lr else {
            "result": lr["status"], "label": STATUS_LABEL.get(lr["status"]) or RETEST_RESULT_LABEL.get(lr["status"]),
            "text": status_text(lr["status"], lr),
            "at": lr["at"], "retest_id": lr["verification"].get("retest_id"),
            "retest_campaign_id": lr["verification"].get("retest_campaign_id"),
            "coverage_ok": lr["verification"].get("coverage_ok", True),
            "coverage_text": lr["verification"].get("coverage_text")}
        if rec["from"]:
            a["state_carried_from"] = sorted(rec["from"])
        for i in merge_issues + r["issues"]:
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
        "unit": UNIT_NOTE,
        "basis": source,
        "basis_label": ff.get("label"),
        "basis_note": ff.get("note"),
        "actions": actions,
        "summary": {"actions": len(actions), "by_status": counts, "findings_covered": len(covered),
                    "open_findings": ff.get("open_findings", 0), "risk_acceptance_expired": expired},
        "verification": ("retest" if verification_available else "not_available"),
        "verification_note": (VERIFICATION_NOTE if verification_available else
                              "This edition does not run retests: statuses are declarations, never verified."),
        "effort_note": EFFORT_NOTE,
        "score_effect": "none",
        "score_note": "Treatment statuses never change the findings, the counts or the rating of this campaign.",
        "orphaned_states": orphaned,
        "issues": issues,
    }
