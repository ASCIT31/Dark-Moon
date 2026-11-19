"""
Credential fingerprints of a finding, read by the attack-path rule R1 (``api.attack_paths_observed``).

Darkmoon Pro computes keyed fingerprints at push time and keeps them in a separate internal store. Community has
no such store, so findings never carry them and ``fingerprints_of`` returns an empty block: R1 then relies only on
values visible in the stored evidence, which is the honest result.
"""
from __future__ import annotations

from typing import Any, Dict

VERSION = 1
FIELD = "artifact_fingerprints"


def fingerprints_of(v: Dict[str, Any]) -> Dict[str, Any]:
    fp = v.get(FIELD)
    return fp if isinstance(fp, dict) and fp.get("v") == VERSION else {}
