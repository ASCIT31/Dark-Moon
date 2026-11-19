"""
Finding identity used by the attack-path triage (``api.fix_triage``).

The same fingerprint as Darkmoon Pro's campaign view: the agent's dedup_key when supplied, else target +
category + normalised endpoint path + CWE/CVE. Only this part of the Pro module is needed in Community.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict

from api.url_parts import safe_urlparse


def _norm_endpoint(ep: str) -> str:
    ep = str(ep or "").strip().lower()
    if not ep:
        return ""
    u = safe_urlparse(ep if "://" in ep else "http://" + ep)  # never raises
    path = re.sub(r"/+", "/", u.path or "/").rstrip("/") or "/"
    path = re.sub(r"/\d+(?=/|$)", "/{n}", path)   # /users/12 == /users/7
    return path


def fingerprint(v: Dict[str, Any]) -> str:
    """dedup_key when the agent supplied one, else target + category + endpoint path + CWE/CVE."""
    if v.get("dedup_key"):
        basis = f"dk|{v.get('target_id','')}|{v['dedup_key']}"
    else:
        ref = str(v.get("cve") or v.get("cwe") or "").strip().lower()
        cat = str(v.get("category") or v.get("type") or "").strip().lower()
        basis = f"fp|{v.get('target_id','')}|{cat}|{_norm_endpoint(v.get('endpoint',''))}|{ref}"
        if not cat and not ref:
            basis += "|" + re.sub(r"\s+", " ", str(v.get("title", "")).strip().lower())
    return "fp_" + hashlib.sha256(basis.encode()).hexdigest()[:16]
