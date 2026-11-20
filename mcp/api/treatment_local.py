"""Prioritized Treatment Plan, Darkmoon Community (read-only).

The plan is the same exec_core document as in Pro (``exec_core.actions.build_plan``), built from the local store.
No MCP tool and no API writes treatment statuses. The owner declares them in a file they edit themselves, read and
validated here on every read. The local agent has shell access in the same container, so this file is not
tamper-evident: Community declarations are shown as declared in a local file, never as verified.

    <data dir>/treatments/<campaign_id>.json      (data dir = ~/.local/share/opencode unless DARKMOON_DATA_DIR)

    {
      "schema_version": "darkmoon-treatment-declarations/1",
      "campaign_id": "<campaign_id>",
      "declarations": [
        {"action_id": "act_…", "at": "2026-11-20", "by_role": "web team lead", "status": "applied",
         "note": "patched in release 4.2"},
        {"action_id": "act_…", "at": "2026-11-21", "by_role": "CISO",
         "declared": {"owner": "web team", "approval_required": true, "service_interruption_risk": "low"}},
        {"action_id": "act_…", "at": "2026-11-22", "by_role": "CISO", "status": "risk_accepted",
         "declared": {"risk_owner": "Head of Payments", "risk_accepted_until": "2027-05-31"}}
      ]
    }

One action = one weakness class on one asset (exec_core 1.5). Action ids of exec_core <= 1.4 (one per fix item)
are still accepted: their entries follow their findings to the current action. A risk acceptance names the
accountable risk owner and an expiry at most 12 months ahead; without them it reads « incomplete », and past its
date « Risk acceptance expired ».

Rules: entries are replayed in time order through the exec_core status machine; an invalid entry (unknown action,
unknown field, bad date, a transition the machine refuses, a retest-only status) is reported in ``issues`` and
ignored, never coerced. ``applied`` reads « Declared applied by <role>, <date> — not verified ». Community runs no
retest, so no status is ever « verified ». Declarations never change a finding, a count or the score.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from api import json_storage as _js
from api.exec_core import actions as A
from api.json_storage import is_safe_id, load_campaign, load_vulnerabilities

DECLARATIONS_VERSION = "darkmoon-treatment-declarations/1"
MAX_FILE = 512 * 1024
MAX_ENTRIES = 2000
_ENTRY_KEYS = {"action_id", "at", "by_role", "status", "declared", "note"}


def declarations_path(campaign_id: str) -> Path:
    return Path(_js.DATA_DIR) / "treatments" / f"{campaign_id}.json"


def load_declarations(campaign_id: str, action_ids: Optional[set] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    """(state for exec_core, issues, file status: absent | read | unreadable). Never raises on a bad file."""
    issues: List[Dict[str, Any]] = []
    p = declarations_path(campaign_id)
    base = Path(_js.DATA_DIR) / "treatments"
    try:
        if not p.is_file():
            return {}, [], "absent"
        if p.resolve().parent != base.resolve() or p.stat().st_size > MAX_FILE:
            return {}, [{"kind": "declarations-unreadable", "problems": ["file refused (outside the store or too large)"]}], "unreadable"
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, [{"kind": "declarations-unreadable", "problems": ["the file is not valid JSON"]}], "unreadable"
    if not isinstance(doc, dict) or not isinstance(doc.get("declarations"), list):
        return {}, [{"kind": "declarations-unreadable", "problems": ["expected an object with a declarations list"]}], "unreadable"
    if doc.get("schema_version") not in (None, DECLARATIONS_VERSION):
        issues.append({"kind": "declarations-schema", "problems": [f"schema_version should be {DECLARATIONS_VERSION}"]})
    if doc.get("campaign_id") not in (None, campaign_id):
        return {}, [{"kind": "declarations-unreadable", "problems": ["campaign_id does not match this campaign"]}], "unreadable"
    actions: Dict[str, Dict[str, Any]] = {}
    for n, e in enumerate(doc["declarations"][:MAX_ENTRIES]):
        if not isinstance(e, dict):
            issues.append({"kind": "declaration-invalid", "index": n, "problems": ["entry: must be an object"]})
            continue
        unknown = sorted(set(e) - _ENTRY_KEYS)
        aid = e.get("action_id")
        problems = [f"unknown fields {unknown}"] if unknown else []
        if not isinstance(aid, str) or not aid.startswith("act_"):
            problems.append("action_id: an action id of this plan (act_…)")
        elif action_ids is not None and aid not in action_ids:
            problems.append("action_id: not an action of this plan")
        if problems:
            issues.append({"kind": "declaration-invalid", "index": n, "problems": problems})
            continue
        entry = {k: v for k, v in e.items() if k != "action_id"}
        entry["source"] = "declaration"
        actions.setdefault(aid, {"history": []})["history"].append(entry)
    if len(doc["declarations"]) > MAX_ENTRIES:
        issues.append({"kind": "declarations-truncated", "problems": [f"only the first {MAX_ENTRIES} entries are read"]})
    return {"actions": actions}, issues, "read"


def plan_doc(campaign_id: str, finding_filter: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """The plan of ``campaign_id`` or None (malformed id / unknown campaign). ``finding_filter`` (the explorer's
    redaction) is applied to every finding before anything is derived from it."""
    if not is_safe_id(campaign_id) or not load_campaign(campaign_id):
        return None
    from api.attack_paths_local import attack_paths_doc
    doc = attack_paths_doc(campaign_id, "all", False, finding_filter=finding_filter)
    if doc is None:
        return None
    vulns = [v for v in load_vulnerabilities(campaign_id) or [] if isinstance(v, dict)]
    if finding_filter is not None:
        vulns = [finding_filter(v) for v in vulns]
    tid = str((load_campaign(campaign_id) or {}).get("target_id") or "")
    ids = {a["action_id"] for a in A.build_actions(campaign_id, doc, vulns, tid)}
    legacy = A.legacy_action_ids(campaign_id, doc)       # exec_core <= 1.4 ids: migrated by their findings
    state, file_issues, file_status = load_declarations(campaign_id, ids | set(legacy))
    for aid, rec in (state.get("actions") or {}).items():
        if aid in legacy:
            rec["finding_ids"] = legacy[aid]
    from datetime import datetime, timezone
    plan = A.build_plan(campaign_id, doc, vulns, state, None, verification_available=False, target_id=tid,
                        today=datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    for i in plan["issues"]:
        i.setdefault("kind", "declaration-refused")
    plan["issues"] = file_issues + plan["issues"]
    plan["declarations"] = {"file": f"treatments/{campaign_id}.json", "status": file_status,
                            "schema_version": DECLARATIONS_VERSION,
                            "note": ("Statuses are declared by the owner in this file (edited by hand, never by an "
                                     "agent). They are not verified and never change the findings or the rating.")}
    plan["can_edit"] = False
    return plan
