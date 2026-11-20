"""Application profile, Darkmoon Community (read-only).

Same document as in Pro (``exec_core.profile``). No MCP tool and no API writes it. The owner declares the profile in a
file they edit themselves, read and validated here on every read. The local agent has shell access in the same
container, so this file is not tamper-evident: the report says « Declared in the local profile file », never who.

    <data dir>/profiles/<project_id>.json      (data dir = ~/.local/share/opencode unless DARKMOON_DATA_DIR)

    {
      "schema_version": "darkmoon-application-profile-declarations/1",
      "project_id": "<project_id>",
      "fields": {
        "business_purpose": {"value": "Customer self-service portal", "at": "2026-11-20", "by_role": "product owner"},
        "personal_data": {"value": "yes", "provenance": "verified", "at": "2026-11-20", "by_role": "DPO"},
        "sector": "health",
        "rto": "4h"
      }
    }

Rules: every field is validated (``exec_core.profile.validate_declared``); an invalid field is reported in
``issues`` and ignored, never coerced. Provenance is ``declared_by_customer`` (default) or ``verified``; ``detected``
and ``inferred`` are Darkmoon's and refused in the file. The detected stack comes from the project's target and its
reference campaign's infrastructure and is always shown as detected, never confirmed. Owners are role labels.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from api import json_storage as _js
from api.exec_core import profile as P
from api.exec_core import project as XPR
from api.json_storage import (is_safe_id, load_campaigns, load_infrastructure, load_project, load_target)

MAX_FILE = 64 * 1024
_TOP = {"schema_version", "project_id", "fields"}


def profile_path(project_id: str) -> Path:
    return Path(_js.DATA_DIR) / "profiles" / f"{project_id}.json"


def load_declarations(project_id: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    """(validated declared fields, issues, file status: absent | read | unreadable). Never raises on a bad file."""
    p = profile_path(project_id)
    base = Path(_js.DATA_DIR) / "profiles"
    try:
        if not p.is_file():
            return {}, [], "absent"
        if p.resolve().parent != base.resolve() or p.stat().st_size > MAX_FILE:
            return {}, [{"kind": "profile-unreadable", "problems": ["file refused (outside the store or too large)"]}], "unreadable"
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, [{"kind": "profile-unreadable", "problems": ["the file is not valid JSON"]}], "unreadable"
    if not isinstance(doc, dict) or not isinstance(doc.get("fields"), dict):
        return {}, [{"kind": "profile-unreadable", "problems": ["expected an object with a fields object"]}], "unreadable"
    if doc.get("project_id") not in (None, project_id):
        return {}, [{"kind": "profile-unreadable", "problems": ["project_id does not match this project"]}], "unreadable"
    issues: List[Dict[str, Any]] = []
    if doc.get("schema_version") not in (None, P.FILE_VERSION):
        issues.append({"kind": "profile-schema", "problems": [f"schema_version should be {P.FILE_VERSION}"]})
    unknown = sorted(set(doc) - _TOP)
    if unknown:
        issues.append({"kind": "profile-invalid", "problems": [f"unknown top-level keys {unknown} ignored"]})
    clean, field_issues = P.validate_declared(doc["fields"])
    return clean, issues + field_issues, "read"


def detected_for_project(project: Dict[str, Any]) -> Dict[str, Any]:
    target = load_target(project.get("target_id") or "") if project.get("target_id") else None
    ref = XPR.reference_campaign([c for c in load_campaigns() if c.get("project_id") == project.get("id")])
    nodes = load_infrastructure(ref["id"]) if ref and ref.get("id") else []
    return P.detected_stack((target or {}).get("technologies") or [], nodes, ref.get("id") if ref else None)


def profile_view(project_id: str) -> Optional[Tuple[Dict[str, Any], List[Dict[str, Any]], str]]:
    """(profile view, issues, file status) or None (malformed id / unknown project)."""
    if not is_safe_id(project_id):
        return None
    project = load_project(project_id)
    if not project:
        return None
    declared, issues, status = load_declarations(project_id)
    return P.view(declared, detected_for_project(project), project_id), issues, status


def profile_doc(project_id: str) -> Optional[Dict[str, Any]]:
    got = profile_view(project_id)
    if got is None:
        return None
    view, issues, status = got
    return {"schema_version": P.PROFILE_VERSION, "project_id": project_id, "profile": view, "issues": issues,
            "declarations": {"file": f"profiles/{project_id}.json", "status": status,
                             "schema_version": P.FILE_VERSION,
                             "note": ("Declared by the owner in this file, edited by hand (no MCP tool writes it; the "
                                      "local agent has shell access, so the file is not tamper-evident). Only "
                                      "declared or verified fields decide framework applicability.")},
            "can_edit": False}
