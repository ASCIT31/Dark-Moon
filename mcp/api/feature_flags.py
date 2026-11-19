"""
Feature flags of the attack-path engine.

Every flag is OFF by default: with no environment variable set, the engine behaves as documented. A flag is read at
call time from the process environment, so a test can toggle it with ``monkeypatch.setenv``; in a deployment it is
set on the opencode container and takes effect after a restart.

Rollback of any flagged change = unset the variable (no migration, no stored data rewritten).
"""

from __future__ import annotations

import os
from typing import Dict

# name -> one-line description (also the registry checked by the tests: every flag is OFF by default)
FLAGS: Dict[str, str] = {
    "DM_DERIVE_KEEP_REACHED_OBJECTIVE": "derive_scenarios keeps an inlined producer's own chain when it reaches an "
                                        "objective no kept chain reaches",
    "DM_STABLE_PATH_IDS": "path ids hash the source chain id (stable across remediations) and the list document "
                          "carries a legacy-id alias table for one version",
    "DM_RANKING_COMBOS": "the ranking is completed by combinations of fixes when no single fix interrupts an open "
                         "scenario; the greedy prefix and its gap stay visible",
    "DM_R3_EXPLOIT_ORIGIN": "R3 starts at the node the exploit was sent to (endpoint), not at the node the finding "
                            "is attached to, when the finding is attached to the reached data store",
    "DM_MAX_RANKED_PATHS": "integer: proven paths above which the ranking is refused as too-large (default 200)",
}

# Never enabled in Community, whatever the environment says: they would count a path as proven on data the server
# did not record (a derived chain, a chain declared at finalisation) or need a fingerprint store Community lacks.
FORCED_OFF = frozenset({"DM_LEGACY_DERIVED_PROOF", "DM_FINALIZE_CHAINS_AS_PATHS", "DM_ARTIFACT_FINGERPRINTS",
                        "DM_TOOL_PROVENANCE"})

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
DEFAULT_ON: frozenset = frozenset()


def enabled(name: str) -> bool:
    """An explicit 1/true/yes/on or 0/false/no/off wins (case-insensitive); unset or malformed: OFF."""
    if name in FORCED_OFF:
        return False
    raw = str(os.environ.get(name, "")).strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return name in DEFAULT_ON


def int_value(name: str, default: int, lo: int, hi: int) -> int:
    """Integer flag, clamped to [lo, hi]; an unset or malformed value gives ``default``."""
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, v))
