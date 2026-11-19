"""Shared vocabulary of the executive views (dashboard, report, terminal), both editions.

Two families of tokens never mix:

* severity tokens (``critical`` .. ``info``) say how bad a weakness would be;
* evidence status tokens (``exploited``, ``confirmed``, ``unconfirmed``) say how much proof is on file.

Attack paths: a ``Possible Attack Path`` is a hypothesis (declared by an agent or inferred by the server); an
``Evidence-Backed Attack Path`` has every step backed by evidence the server observed. ``declared`` = stated by an
agent, not verified; ``corroborated`` = the server found evidence for it.
Pure data, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

LEGEND_VERSION = "darkmoon-legend/1"

SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}

EVIDENCE_STATUS = {
    "exploited": {"label": "Exploited", "meaning": "The weakness was used during the test; proof is on file."},
    "confirmed": {"label": "Confirmed", "meaning": "The weakness was observed; it was not used further."},
    "unconfirmed": {"label": "To confirm", "meaning": "Reported by an agent without enough proof yet."},
}

PATH_KIND = {
    "possible": {"label": "Possible Attack Path",
                 "meaning": "A chain of weaknesses that could be combined; a hypothesis, not observed."},
    "evidence_backed": {"label": "Evidence-Backed Attack Path",
                        "meaning": "Every step is backed by evidence the server observed during the campaign."},
}

DECLARATION = {
    "declared": {"label": "Declared", "meaning": "Stated by an agent or a person; not verified by the server."},
    "corroborated": {"label": "Corroborated", "meaning": "The server found evidence that supports it."},
}

TREATMENT = {
    "to_do": {"label": "To do", "meaning": "No treatment recorded yet."},
    "in_progress": {"label": "Treatment in Progress",
                    "meaning": "A fix is planned, under way or declared applied; not verified."},
    "not_reproduced": {"label": "Not reproduced at retest",
                       "meaning": "A completed retest did not reproduce it; this is not a proof of resolution."},
    "risk_accepted": {"label": "Risk accepted", "meaning": "Accepted by its owner until a stated date."},
}

SCORE_STATUS = {
    "rated": {"label": "Rated", "meaning": "The campaign met the coverage floor; the rating applies to its scope."},
    "limited": {"label": "Limited test",
                "meaning": "The campaign was below the coverage floor; the rating is capped and indicative."},
    "not_rated": {"label": "Not rated",
                  "meaning": "No rating: the campaign did not complete, was a retest, or its coverage is unknown."},
}

GRADE = {
    "A": "Low exposure found in the tested scope",
    "B": "Limited exposure found in the tested scope",
    "C": "Notable exposure found in the tested scope",
    "D": "High exposure found in the tested scope",
    "E": "Severe exposure found in the tested scope",
}

# provenance values of the attack-path engine -> path kind
_PATH_OF_PROVENANCE = {
    "observed": "evidence_backed",
    "declared": "possible",
    "derived": "possible",
    "inferred": "possible",
    "agent-declared": "possible",
}


def path_kind(provenance: Any) -> str:
    """Path kind of an engine provenance alone; anything unknown is a hypothesis. A ``derived`` path needs its
    corroboration record to be evidence-backed: use ``path_kind_of`` on the whole path."""
    return _PATH_OF_PROVENANCE.get(str(provenance or "").strip().lower(), "possible")


def path_kind_of(path: Any) -> str:
    """Path kind of one attack-path record of the engine.

    * a hypothesis (``hypothesis`` true) is always ``possible``;
    * ``observed``: every link was observed by the server -> ``evidence_backed``;
    * ``derived`` (built from the agents' claims): ``evidence_backed`` only when the engine CHECKED every claim against
      the evidence it recorded (``corroboration``: status ``corroborated``, nothing ``unverified``, ``checked`` true:
      matching server-computed credential fingerprints, an observed link on the same pair, or the proof excerpt found
      in the stored response). A derived path without that record, or corroborated without a check (legacy flag,
      labelled demo), stays ``possible``;
    * ``declared``, ``agent-declared``, ``inferred`` or anything unknown -> ``possible``: a declaration is never
      presented as a proven exploitation.
    """
    if not isinstance(path, dict) or path.get("hypothesis"):
        return "possible"
    prov = str(path.get("provenance") or "").strip().lower()
    if prov == "observed":
        return "evidence_backed"
    if prov == "derived":
        c = path.get("corroboration")
        if (isinstance(c, dict) and c.get("status") == "corroborated" and not c.get("unverified")
                and c.get("checked") is True):
            return "evidence_backed"
    return "possible"


def evidence_label(status: Any) -> str:
    s = str(status or "").strip().lower()
    return EVIDENCE_STATUS.get(s, EVIDENCE_STATUS["unconfirmed"])["label"]


def severity_label(severity: Any) -> Optional[str]:
    return SEVERITY.get(str(severity or "").strip().lower())


def legend() -> Dict[str, Any]:
    return {
        "version": LEGEND_VERSION,
        "severity": dict(SEVERITY),
        "evidence_status": {k: dict(v) for k, v in EVIDENCE_STATUS.items()},
        "path_kind": {k: dict(v) for k, v in PATH_KIND.items()},
        "declaration": {k: dict(v) for k, v in DECLARATION.items()},
        "treatment": {k: dict(v) for k, v in TREATMENT.items()},
        "score_status": {k: dict(v) for k, v in SCORE_STATUS.items()},
        "grade": dict(GRADE),
    }
