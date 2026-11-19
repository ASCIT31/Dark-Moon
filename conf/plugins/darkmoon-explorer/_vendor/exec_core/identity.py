"""Finding identity shared by stats, score, plan, report and explorer.

Pure functions, standard library only, no I/O. One finding has:

* a status class: counted, or excluded with one reason (``quarantined`` = the server flag, ``false_positive``);
* an open flag: counted and not closed (``remediated``, ``resolved``, ``closed``, ``fixed``);
* a displayed severity (the severity of the findings table, aliases normalised);
* a ``fingerprint``: the cross-campaign identity of one weakness (same algorithm as the historical
  ``campaign_view.fingerprint``: ``dedup_key`` when supplied, else target + category + endpoint path + CVE/CWE);
* a ``weakness_class``: a coarse family of the category (several agents naming the same flaw differently land in
  the same class);
* an ``asset``: the asset the weakness is on. v1 = the campaign target (one project = one target);
* a ``unit``: ``asset|weakness_class``, the penalty unit of the Cyber Score.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import ParseResult, urlparse

SEVERITIES = ("critical", "high", "medium", "low", "info")
PROOF_STATUSES = ("exploited", "confirmed", "unconfirmed")
CLOSED_STATUSES = frozenset({"remediated", "resolved", "closed", "fixed"})
EXCLUSION_REASONS = ("quarantined", "false_positive")

_FALSE_POSITIVE = re.compile(r"^false[\s_-]?positive$")
_SEVERITY_ALIAS = {
    "critical": "critical", "crit": "critical",
    "high": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "low": "low",
    "info": "info", "informational": "info", "information": "info", "none": "info",
}

# category -> weakness class. Unknown categories are their own class (normalised), so a new category is never
# silently merged with another one.
_CLASS_OF = {
    "sql_injection": "sql_injection", "sqli": "sql_injection", "blind_sql_injection": "sql_injection",
    "nosql_injection": "nosql_injection",
    "xss": "xss", "xss_stored": "xss", "xss_reflected": "xss", "xss_dom": "xss", "stored_xss": "xss",
    "reflected_xss": "xss", "dom_xss": "xss", "html_injection": "xss",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "ssti": "code_execution", "rce": "code_execution", "remote_code_execution": "code_execution",
    "command_injection": "code_execution", "os_command_injection": "code_execution",
    "code_injection": "code_execution", "deserialization": "code_execution",
    "insecure_deserialization": "code_execution",
    "lfi": "file_access", "rfi": "file_access", "path_traversal": "file_access",
    "directory_traversal": "file_access", "file_inclusion": "file_access",
    "unrestricted_file_upload": "file_upload", "file_upload": "file_upload",
    "idor": "access_control", "broken_access_control": "access_control", "privilege_escalation": "access_control",
    "mass_assignment": "access_control", "authorization_bypass": "access_control",
    "authentication_bypass": "authentication", "auth_bypass": "authentication",
    "broken_authentication": "authentication", "default_credentials": "authentication",
    "weak_credentials": "authentication", "weak_password": "authentication", "brute_force": "authentication",
    "user_enumeration": "authentication", "captcha_bypass": "authentication", "jwt": "authentication",
    "session_management": "session", "session_fixation": "session", "insecure_cookie": "session",
    "information_disclosure": "information_disclosure", "sensitive_data_exposure": "information_disclosure",
    "file_exposure": "information_disclosure", "file_disclosure": "information_disclosure",
    "credential_exposure": "information_disclosure",
    "security_misconfiguration": "configuration", "misconfiguration": "configuration",
    "insecure_configuration": "configuration", "missing_security_headers": "configuration",
    "clickjacking": "configuration", "exposed_admin_tool": "configuration", "cors": "configuration",
    "cors_misconfiguration": "configuration",
    "cryptographic_weakness": "cryptography", "crypto_weakness": "cryptography", "weak_tls": "cryptography",
    "outdated_software": "vulnerable_component", "vulnerable_component": "vulnerable_component",
    "outdated_component": "vulnerable_component", "known_vulnerability": "vulnerable_component",
    "cve": "vulnerable_component", "end_of_life": "vulnerable_component",
    "open_redirect": "open_redirect", "redirect_abuse": "open_redirect",
    "business_logic": "business_logic", "business_logic_flaw": "business_logic",
    "denial_of_service": "availability", "dos": "availability", "rate_limiting": "availability",
    "improper_input_validation": "input_validation", "input_validation": "input_validation",
}


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def status_of(v: Dict[str, Any]) -> str:
    """Stored status, lower-case; a missing status reads ``unconfirmed`` (the push default)."""
    return _text(v.get("status") or "unconfirmed").lower()


def is_quarantined(v: Dict[str, Any]) -> bool:
    """Held by the strict privacy policy: the server's ``quarantined`` flag, not reviewed by an operator. A status
    string « quarantined » sent by an agent is not a quarantine (it reads as an unconfirmed finding)."""
    return bool(v.get("quarantined")) and not v.get("quarantine_reviewed_by")


def exclusion_reason(v: Dict[str, Any]) -> Optional[str]:
    """Why a finding is counted nowhere, or None when it is counted."""
    if not isinstance(v, dict):
        return "malformed"
    if is_quarantined(v):
        return "quarantined"
    if _FALSE_POSITIVE.match(status_of(v)):
        return "false_positive"
    return None


AGENT_STATUS_WARNING = ("status {raw!r} cannot be set by an agent (allowed: exploited, confirmed, unconfirmed): "
                        "stored as unconfirmed. False positive, quarantine and closure are operator decisions.")


def agent_push_status(raw: Any) -> Tuple[str, Optional[str]]:
    """The status an agent may push (``dashboard_push_finding``): exploited, confirmed or unconfirmed. Anything else
    (false_positive, quarantined, remediated, fixed…) is stored as ``unconfirmed`` with a warning, so an agent can
    neither hide a finding from the counts nor close it; the finding stays visible."""
    s = re.sub(r"[\s-]+", "_", _text(raw).lower())
    if not s:
        return "unconfirmed", None
    if s in PROOF_STATUSES:
        return s, None
    return "unconfirmed", AGENT_STATUS_WARNING.format(raw=_text(raw)[:40])


def is_closed(v: Dict[str, Any]) -> bool:
    return status_of(v) in CLOSED_STATUSES


def is_open(v: Dict[str, Any]) -> bool:
    """Counted and not closed."""
    return exclusion_reason(v) is None and not is_closed(v)


def severity_of(v: Dict[str, Any]) -> str:
    """The displayed severity, aliases normalised; ``unknown`` when it is none of the five levels."""
    return _SEVERITY_ALIAS.get(_text(v.get("severity")).lower(), "unknown")


def proof_of(v: Dict[str, Any]) -> str:
    """Evidence level: exploited, confirmed, unconfirmed (any other status reads unconfirmed)."""
    s = status_of(v)
    return s if s in PROOF_STATUSES else "unconfirmed"


def _safe_urlparse(text: Any) -> ParseResult:
    s = str(text or "")
    try:
        return urlparse(s)
    except ValueError:
        try:
            return urlparse(s.replace("[", "%5B").replace("]", "%5D"))
        except ValueError:
            return urlparse("")


def norm_endpoint(ep: Any) -> str:
    """Endpoint path only: lower-case, no host, no query, duplicate slashes folded, numeric ids folded."""
    ep = str(ep or "").strip().lower()
    if not ep:
        return ""
    u = _safe_urlparse(ep if "://" in ep else "http://" + ep)
    path = re.sub(r"/+", "/", u.path or "/").rstrip("/") or "/"
    path = re.sub(r"/\d+(?=/|$)", "/{n}", path)
    return path


def fingerprint(v: Dict[str, Any]) -> str:
    """dedup_key when the agent supplied one, else target + category + endpoint path + CWE/CVE."""
    if v.get("dedup_key"):
        basis = f"dk|{v.get('target_id','')}|{v['dedup_key']}"
    else:
        ref = str(v.get("cve") or v.get("cwe") or "").strip().lower()
        cat = str(v.get("category") or v.get("type") or "").strip().lower()
        basis = f"fp|{v.get('target_id','')}|{cat}|{norm_endpoint(v.get('endpoint',''))}|{ref}"
        if not cat and not ref:
            basis += "|" + re.sub(r"\s+", " ", str(v.get("title", "")).strip().lower())
    return "fp_" + hashlib.sha256(basis.encode()).hexdigest()[:16]


def _category_key(v: Dict[str, Any]) -> str:
    cat = _text(v.get("category") or v.get("type")).lower()
    return re.sub(r"[^a-z0-9]+", "_", cat).strip("_")


def weakness_class(v: Dict[str, Any]) -> str:
    """Coarse family of the finding's category; ``unclassified`` without a category."""
    key = _category_key(v)
    if not key:
        return "unclassified"
    return _CLASS_OF.get(key, key)


def asset_key(v: Dict[str, Any]) -> str:
    """The asset the weakness is on. v1: the campaign target (one project = one target); no target -> ``scope``."""
    return _text(v.get("target_id")) or "scope"


def unit_key(v: Dict[str, Any]) -> str:
    return asset_key(v) + "|" + weakness_class(v)


def identity(v: Dict[str, Any]) -> Dict[str, Any]:
    """Every identity facet of one finding, in one dict."""
    return {
        "finding_id": v.get("id"),
        "fingerprint": fingerprint(v),
        "asset": asset_key(v),
        "weakness_class": weakness_class(v),
        "unit": unit_key(v),
        "severity": severity_of(v),
        "proof": proof_of(v),
        "excluded": exclusion_reason(v),
        "open": is_open(v),
    }
