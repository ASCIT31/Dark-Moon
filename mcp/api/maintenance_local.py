"""Maintenance windows, Darkmoon Community (advisory: a warning, never a block).

Same policy and evaluation as Pro (``exec_core.maintenance``). No MCP tool and no API writes it. The owner writes the
policy in a file they edit themselves, read and validated here on every read (the local agent has shell access in the
same container, so the file is not tamper-evident; Community only warns anyway):

    <data dir>/policies/<project_id>.json      (data dir = ~/.local/share/opencode unless DARKMOON_DATA_DIR)

    {
      "schema_version": "darkmoon-maintenance-policy/1",
      "project_id": "<project_id>",
      "timezone": "Europe/Paris",
      "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "22:00", "end": "06:00"}],
      "blackouts": [{"start": "2026-12-24", "end": "2027-01-02", "label": "Year-end freeze"}],
      "max_duration_minutes": 360
    }

When a campaign starts (``dashboard_init_campaign``), the policy of its project is evaluated: outside it, the MCP
server writes a WARNING line on its log (security event ``campaign.launch`` / ``warning``) and records the evaluation
on the campaign (``maintenance_check``); the campaign is NOT stopped and nothing is said to the model. A policy file
that cannot be read gives a warning too (never a silent pass). ``python3 -m api.maintenance_local check <project_id>``
prints the same evaluation for a script or a customer pipeline (exit code 0 allowed, 1 warn, 3 outside the policy).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from api import json_storage as _js
from api.exec_core import maintenance as M
from api.json_storage import is_safe_id, load_project

MAX_FILE = 64 * 1024
_LOG = logging.getLogger("darkmoon.maintenance")


def policy_path(project_id: str) -> Path:
    return Path(_js.DATA_DIR) / "policies" / f"{project_id}.json"


def load_policy(project_id: str) -> Tuple[Any, str, list]:
    """(policy for evaluate, file status absent | read | unreadable, issues). An unreadable or invalid file gives a
    policy that evaluates to « blocked » (shown as a warning here): a broken file never passes silently."""
    if not is_safe_id(project_id):
        return None, "absent", []
    p = policy_path(project_id)
    base = Path(_js.DATA_DIR) / "policies"
    try:
        if not p.is_file():
            return None, "absent", []
        if p.resolve().parent != base.resolve() or p.stat().st_size > MAX_FILE:
            return {"_unreadable": True}, "unreadable", [{"field": "file", "message": "refused (outside the store or too large)"}]
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"_unreadable": True}, "unreadable", [{"field": "file", "message": "not valid JSON"}]
    clean, issues = M.validate_policy(doc, project_id)
    if clean is None:      # evaluated as an unreadable policy (a foreign project_id must not pass as valid)
        return {"_unreadable": True}, "unreadable", issues
    return clean, "read", []


def evaluate(project_id: str, kind: str = "full", at: Optional[datetime] = None,
             planned_duration: Optional[int] = None) -> Dict[str, Any]:
    """The advisory evaluation of a launch on this project (``exec_core.maintenance.as_advisory``)."""
    policy, status, issues = load_policy(project_id)
    ev = M.as_advisory(M.evaluate(policy, at or datetime.now(timezone.utc), kind, planned_duration))
    ev.update({"project_id": project_id, "file": f"policies/{project_id}.json", "file_status": status,
               "summary": M.summary_line(ev)})
    if issues:
        ev["policy_issues"] = issues[:20]
    return ev


def policy_doc(project_id: str) -> Optional[Dict[str, Any]]:
    """The explorer's document: the policy in words, its file status and the evaluation now."""
    if not is_safe_id(project_id) or not load_project(project_id):
        return None
    policy, status, issues = load_policy(project_id)
    clean = policy if status == "read" else None
    return {"schema_version": M.POLICY_VERSION, "project_id": project_id, "policy": clean,
            "summary": M.describe(clean) if status != "unreadable" else
            ["The policy file could not be used: fix it (every launch gets a warning until then)."],
            "issues": issues, "evaluation_now": evaluate(project_id),
            "file": {"path": f"policies/{project_id}.json", "status": status,
                     "note": "Written by the owner, edited by hand (no MCP tool writes it; not tamper-evident). Community warns outside the "
                             "windows; it does not block a launch."},
            "enforced": False, "can_edit": False}


def check_at_start(campaign: Dict[str, Any], kind: Optional[str]) -> Optional[Dict[str, Any]]:
    """Called when a campaign is initialised: the evaluation to record on it (None without a policy), and a WARNING
    log line + security event outside the policy. Never raises."""
    try:
        pid = str(campaign.get("project_id") or "")
        ev = evaluate(pid, kind or "full")
        if not ev.get("policy_present") and ev.get("file_status") == "absent":
            return None
        from api import security_log as SL
        target = {"project_id": pid, "campaign_id": campaign.get("id")}
        if ev["decision"] != "allowed":
            _LOG.warning("Maintenance policy: %s (project %s, campaign %s)", ev["summary"], pid, campaign.get("id"))
            SL.emit("campaign.launch", "warning", via="mcp", target=target, reason="maintenance policy",
                    details={"codes": [r["code"] for r in ev["reasons"]], "advisory_of": ev.get("advisory_of")})
        else:
            SL.emit("campaign.launch", "success", via="mcp", target=target, details={"maintenance": "allowed"})
        return {k: ev.get(k) for k in ("decision", "advisory_of", "at_utc", "campaign_kind", "timezone", "local_time",
                                       "next_window_start_utc", "file_status", "summary")} | {
            "reasons": [r["code"] for r in ev.get("reasons") or []], "enforced": False}
    except Exception:  # noqa: BLE001 - a policy problem never breaks a campaign start
        _LOG.warning("Maintenance policy: evaluation failed", exc_info=True)
        return None


def main(argv: list) -> int:
    """``check <project_id> [--kind full] [--duration MINUTES] [--at ISO]``: the evaluation as JSON on stdout."""
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m api.maintenance_local")
    ap.add_argument("cmd", choices=["check"])
    ap.add_argument("project_id")
    ap.add_argument("--kind", default="full")
    ap.add_argument("--duration", type=int, default=None)
    ap.add_argument("--at", default=None)
    a = ap.parse_args(argv)
    at = M._utc(a.at) if a.at else None
    if a.at and at is None:
        print("--at: an ISO-8601 date-time", file=sys.stderr)
        return 2
    ev = evaluate(a.project_id, a.kind, at, a.duration)
    json.dump(ev, sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    if ev["decision"] != "allowed":
        print(ev["summary"], file=sys.stderr)
    return 0 if ev["decision"] == "allowed" else 3 if ev.get("advisory_of") == "blocked" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
