"""
Finding identity used by the attack-path triage (``api.fix_triage``).

The same fingerprint as Darkmoon Pro's campaign view, from the shared core (``api.exec_core.identity``): the
agent's dedup_key when supplied, else target + category + normalised endpoint path + CWE/CVE.
"""
from __future__ import annotations

from typing import Any, Dict

from api.exec_core import identity as _identity


def _norm_endpoint(ep: str) -> str:
    return _identity.norm_endpoint(ep)


def fingerprint(v: Dict[str, Any]) -> str:
    """dedup_key when the agent supplied one, else target + category + endpoint path + CWE/CVE."""
    return _identity.fingerprint(v)
