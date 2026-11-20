"""Application profile: what the organisation declares about the tested application, with provenance per field.

Pure functions, standard library only, no I/O. The same document shape in both editions: Pro stores the declared
fields in the project's owner-input store (the EBIOS context file, revisioned and audited, admin-only writes);
Community reads a file the owner edits by hand (``profiles/<project_id>.json``). No MCP tool writes it in either edition;
in Community the local agent has shell access in the same container, so that file is not tamper-evident.

Provenance of every field: ``detected`` (seen by a campaign, never confirmed), ``inferred`` (derived by Darkmoon;
no field is inferred in v1), ``declared_by_customer``, ``verified`` (declared and checked by the organisation),
``unknown`` (nothing recorded). Business facts are never invented: a field nobody declared reads ``unknown``.
Only ``declared_by_customer`` and ``verified`` values feed framework applicability (``applicability_facts``).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

PROFILE_VERSION = "darkmoon-application-profile/1"
FILE_VERSION = "darkmoon-application-profile-declarations/1"
PROVENANCES = ("detected", "inferred", "declared_by_customer", "verified", "unknown")
DECLARABLE = ("declared_by_customer", "verified")
PROVENANCE_LABEL = {
    "detected": "Detected by a campaign, not confirmed",
    "inferred": "Inferred by Darkmoon, not confirmed",
    "declared_by_customer": "Declared by the organisation",
    "verified": "Declared and verified by the organisation",
    "unknown": "Not provided",
}
YES_NO = ("yes", "no", "unknown")
LEVELS = ("low", "medium", "high", "critical", "unknown")
NIS2_SECTORS = ("energy", "transport", "banking", "financial_market_infrastructure", "health", "drinking_water",
                "waste_water", "digital_infrastructure", "ict_service_management", "public_administration", "space",
                "postal_and_courier", "waste_management", "chemicals", "food", "manufacturing", "digital_providers",
                "research", "other", "unknown")

_TEXT_MAX = 1000
_ITEM_MAX = 120
_LIST_MAX = 30
_ROLE_MAX = 64

# name -> (kind, group, extra). kind: text | role | list | enum | duration | short | date
FIELDS: Dict[str, Tuple[str, str, Any]] = {
    "description": ("text", "application", None),
    "business_purpose": ("text", "application", None),
    "business_owner": ("role", "ownership", None),
    "technical_owner": ("role", "ownership", None),
    "business_processes": ("list", "application", None),
    "user_categories": ("list", "data", None),
    "data_categories": ("list", "data", None),
    "personal_data": ("enum", "data", YES_NO),
    "languages": ("list", "technology", None),
    "frameworks": ("list", "technology", None),
    "databases": ("list", "technology", None),
    "infrastructure": ("list", "technology", None),
    "external_dependencies": ("list", "technology", None),
    "criticality": ("enum", "resilience", LEVELS),
    "availability_requirement": ("enum", "resilience", LEVELS),
    "rto": ("duration", "resilience", None),
    "rpo": ("duration", "resilience", None),
    "sla": ("short", "resilience", None),
    "data_residency": ("short", "data", None),
    "sector": ("enum", "regulatory", NIS2_SECTORS),
    "nis2_entity_type": ("enum", "regulatory", ("essential", "important", "not_in_scope", "unknown")),
    "iso27001_isms_scope": ("enum", "regulatory", ("in_scope", "out_of_scope", "unknown")),
    "ai_system_declared": ("enum", "regulatory", YES_NO),
    "ai_risk_class": ("enum", "regulatory", ("high_risk", "limited_risk", "minimal_risk", "not_ai_system",
                                             "unknown")),
    "last_verification_date": ("date", "governance", None),
}
STACK_FIELDS = ("languages", "frameworks", "databases", "infrastructure")
NOTES = {
    "rto": "Declared, not assessed by Darkmoon.",
    "rpo": "Declared, not assessed by Darkmoon.",
    "sla": "Declared, not assessed by Darkmoon.",
    "availability_requirement": "Declared, not assessed by Darkmoon.",
    "business_owner": "A role or team, not a person's name.",
    "technical_owner": "A role or team, not a person's name.",
}

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_PHONE = re.compile(r"(?:\+|00)?\d(?:[\s.-]?\d){7,}")
_DURATION = re.compile(r"^(\d{1,4})\s*(min|m|h|d)$")
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_AT = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?Z?)?$")


def _clean_text(v: Any, limit: int) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(v, str):
        return None, "must be a string"
    s = _CTRL.sub("", v).strip()
    if not s:
        return None, "empty"
    if len(s) > limit:
        return None, f"longer than {limit} characters"
    return s, None


def _valid_date(s: Any) -> bool:
    m = _DATE.match(s) if isinstance(s, str) else None
    if not m:
        return False
    y, mo, d = (int(x) for x in m.groups())
    if not (1 <= mo <= 12 and 1 <= d <= 31 and 1970 <= y <= 2200):
        return False
    return d <= (29 if mo == 2 and (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28 if mo == 2
                 else 30 if mo in (4, 6, 9, 11) else 31)


def validate_value(name: str, value: Any) -> Tuple[Any, Optional[str]]:
    """(clean value, problem). The value is refused, never coerced, when it does not fit the field."""
    if name not in FIELDS:
        return None, "unknown field"
    kind, _, extra = FIELDS[name]
    if kind == "text":
        return _clean_text(value, _TEXT_MAX)
    if kind == "short":
        return _clean_text(value, _ITEM_MAX)
    if kind == "role":
        s, err = _clean_text(value, _ROLE_MAX)
        if err:
            return None, err
        if _EMAIL.search(s) or _PHONE.search(s):
            return None, "a role or team label, not an e-mail address or a phone number"
        return s, None
    if kind == "list":
        if not isinstance(value, list):
            return None, "must be a list of strings"
        if len(value) > _LIST_MAX:
            return None, f"more than {_LIST_MAX} items"
        out: List[str] = []
        for x in value:
            s, err = _clean_text(x, _ITEM_MAX)
            if err:
                return None, f"item {err}"
            if s not in out:
                out.append(s)
        return out, None
    if kind == "enum":
        v = value.strip().lower() if isinstance(value, str) else value
        if v not in extra:
            return None, f"one of {list(extra)}"
        return v, None
    if kind == "duration":
        m = _DURATION.match(value.strip().lower()) if isinstance(value, str) else None
        if not m:
            return None, "a duration such as 30min, 4h or 2d"
        return f"{int(m.group(1))}{'min' if m.group(2) in ('m', 'min') else m.group(2)}", None
    if kind == "date":
        return (value, None) if _valid_date(value) else (None, "a date YYYY-MM-DD")
    return None, "unknown field kind"


def validate_declared(fields: Any, allow_stamps: bool = True) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Validate declared fields ``{name: {"value", "provenance"?, "at"?, "by_role"?}}`` (a bare value is accepted as
    ``{"value": value}``). Returns (clean, issues); an invalid field is left out and reported, never coerced.
    ``allow_stamps=False`` (an API request) refuses ``at`` / ``by_role``: the server stamps them."""
    clean: Dict[str, Dict[str, Any]] = {}
    issues: List[Dict[str, Any]] = []
    if not isinstance(fields, dict):
        return {}, [{"kind": "profile-invalid", "problems": ["fields: must be an object"]}]
    for name in sorted(fields, key=str):
        raw = fields[name]
        entry = raw if isinstance(raw, dict) else {"value": raw}
        problems: List[str] = []
        if name not in FIELDS:
            issues.append({"kind": "profile-field-unknown", "field": str(name)[:64]})
            continue
        allowed = {"value", "provenance"} | ({"at", "by_role", "by"} if allow_stamps else set())
        extra = sorted(set(entry) - allowed)
        if extra:
            problems.append(f"unknown keys {extra}")
        prov = entry.get("provenance", "declared_by_customer")
        if prov not in DECLARABLE:
            problems.append(f"provenance: one of {list(DECLARABLE)} (detected and inferred are set by Darkmoon)")
        if entry.get("value") is None:
            problems.append("value: required (remove the field to make it unknown)")
            value = None
        else:
            value, err = validate_value(name, entry.get("value"))
            if err:
                problems.append(f"value: {err}")
        out: Dict[str, Any] = {"value": value, "provenance": prov}
        if allow_stamps:
            at = entry.get("at")
            if at is not None and not (isinstance(at, str) and _AT.match(at)):
                problems.append("at: a date YYYY-MM-DD or a UTC timestamp")
            elif at is not None:
                out["at"] = at
            role = entry.get("by_role")
            if role is not None:
                r, err = validate_value("business_owner", role)
                if err:
                    problems.append(f"by_role: {err}")
                else:
                    out["by_role"] = r
            by = entry.get("by")
            if by is not None:
                if isinstance(by, str) and by.strip() and len(by.strip()) <= _ROLE_MAX and not _CTRL.search(by):
                    out["by"] = by.strip()
                else:
                    problems.append(f"by: the declaring account, 1 to {_ROLE_MAX} printable characters")
        if problems:
            issues.append({"kind": "profile-field-invalid", "field": name, "problems": problems})
            continue
        clean[name] = out
    return clean, issues


def _tech_name(t: Any) -> Tuple[str, str, str]:
    if isinstance(t, str):
        return t.strip(), "", ""
    if not isinstance(t, dict):
        return "", "", ""
    name = str(t.get("name") or t.get("technology") or t.get("product") or "").strip()
    return name, str(t.get("version") or "").strip(), str(t.get("category") or t.get("type") or "").strip().lower()


def _bucket(category: str) -> str:
    if "lang" in category:
        return "languages"
    if "framework" in category or "cms" in category or "library" in category:
        return "frameworks"
    if "database" in category or category in ("db", "datastore", "cache"):
        return "databases"
    return "infrastructure"


def detected_stack(technologies: Iterable[Any] = (), nodes: Iterable[Any] = (),
                   campaign_id: Optional[str] = None) -> Dict[str, Any]:
    """Technologies seen by a campaign (target record + infrastructure nodes), grouped per stack field. Always
    ``detected``: an agent reported them, nobody confirmed them."""
    items: Dict[str, Dict[str, Any]] = {}
    for t in list(technologies or []) + [n for n in (nodes or []) if isinstance(n, dict) and
                                         (n.get("technology") or n.get("product"))]:
        name, version, cat = _tech_name(t)
        name = _CTRL.sub("", name)[:_ITEM_MAX]
        if not name:
            continue
        key = name.lower()
        if key in items:
            if version and not items[key]["version"]:
                items[key]["version"] = _CTRL.sub("", version)[:40]
            continue
        items[key] = {"name": name, "version": _CTRL.sub("", version)[:40], "field": _bucket(cat)}
    rows = sorted(items.values(), key=lambda r: (r["field"], r["name"].lower()))[:60]
    return {"provenance": "detected", "confirmed": False, "campaign_id": campaign_id, "items": rows,
            "note": "Detected by the campaign's agents; not confirmed by the organisation."}


def view(declared: Optional[Dict[str, Any]] = None, detected: Optional[Dict[str, Any]] = None,
         project_id: Optional[str] = None) -> Dict[str, Any]:
    """The profile document: every field with its value and provenance. ``declared`` = validated declared fields
    (``validate_declared``), ``detected`` = ``detected_stack(...)``. A stack field nobody declared shows the
    detected technologies with provenance ``detected``; a declared value always wins and the detection stays listed
    under ``detected``."""
    declared = declared or {}
    det = detected or {"provenance": "detected", "confirmed": False, "campaign_id": None, "items": []}
    fields: Dict[str, Dict[str, Any]] = {}
    counts = {p: 0 for p in PROVENANCES}
    for name, (kind, group, extra) in FIELDS.items():
        d = declared.get(name)
        if d is not None:
            f = {"value": d["value"], "provenance": d["provenance"], "at": d.get("at"), "by_role": d.get("by_role"),
                 "by": d.get("by")}
        elif name in STACK_FIELDS and any(i["field"] == name for i in det["items"]):
            f = {"value": [i["name"] + (f" {i['version']}" if i["version"] else "") for i in det["items"]
                           if i["field"] == name],
                 "provenance": "detected", "at": None, "by_role": None, "campaign_id": det.get("campaign_id")}
        else:
            f = {"value": None, "provenance": "unknown", "at": None, "by_role": None}
        f["group"] = group
        f["provenance_label"] = PROVENANCE_LABEL[f["provenance"]]
        if name in NOTES:
            f["note"] = NOTES[name]
        if kind == "enum":
            f["allowed"] = list(extra)
        fields[name] = f
        counts[f["provenance"]] += 1
    return {"schema_version": PROFILE_VERSION, "project_id": project_id, "fields": fields, "detected": det,
            "provenance_counts": counts,
            "reading": ("Business facts come only from the organisation. Detected technologies are what the agents "
                        "reported, not confirmed. Resilience figures (RTO, RPO, SLA) are declared, never assessed.")}


def declared_by_text(f: Dict[str, Any], local_file: bool = False) -> str:
    """Who declared a field and when, as the report shows it: « Declared by <account> on <date> », or for the
    Community local file « Declared in the local profile file on <date> » (the file has no account)."""
    prov = f.get("provenance") if f.get("provenance") in PROVENANCES else "unknown"
    if prov not in DECLARABLE:
        return PROVENANCE_LABEL[prov]
    date = str(f.get("at") or "")[:10]
    verb = "Declared and verified" if prov == "verified" else "Declared"
    if local_file:
        return f"{verb} in the local profile file" + (f" on {date}" if date else "")
    who = f.get("by") or f.get("by_role")
    return f"{verb} by {who}" + (f" on {date}" if date else "") if who else PROVENANCE_LABEL[prov] + (
        f" on {date}" if date else "")


def declared_value(profile_view: Optional[Dict[str, Any]], name: str) -> Tuple[Optional[Any], str]:
    """(value, provenance) of a field, the value only when declared or verified; else (None, provenance)."""
    f = ((profile_view or {}).get("fields") or {}).get(name)
    if not isinstance(f, dict):
        return None, "unknown"
    prov = f.get("provenance") if f.get("provenance") in PROVENANCES else "unknown"
    return (f.get("value") if prov in DECLARABLE else None), prov


def applicability_facts(profile_view: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """The facts framework applicability may use: declared or verified fields only."""
    out = {}
    for name in ("personal_data", "sector", "nis2_entity_type", "iso27001_isms_scope", "ai_system_declared",
                 "ai_risk_class"):
        value, prov = declared_value(profile_view, name)
        f = ((profile_view or {}).get("fields") or {}).get(name) or {}
        out[name] = {"value": value, "provenance": prov, "at": f.get("at") if value is not None else None}
    return out


def changed_fields(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, List[str]]:
    """Field names set, cleared or changed between two declared-field dicts (for the audit; no value)."""
    a, b = old or {}, new or {}
    return {"set": sorted(set(b) - set(a)), "cleared": sorted(set(a) - set(b)),
            "changed": sorted(k for k in set(a) & set(b)
                              if (a[k].get("value"), a[k].get("provenance")) != (b[k].get("value"), b[k].get("provenance")))}
