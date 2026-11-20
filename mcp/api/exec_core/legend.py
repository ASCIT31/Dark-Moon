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

import re
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
    "exploited": {"label": "Exploited",
                  "meaning": "Reported by the testing agent as used during the test, with evidence on file (the server "
                             "does not re-verify it)."},
    "confirmed": {"label": "Confirmed",
                  "meaning": "Reported by the testing agent as observed without being used further, with evidence on "
                             "file."},
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
                       "meaning": "A completed retest that met its coverage gate did not reproduce it; this is not a "
                                  "proof of resolution."},
    "risk_accepted": {"label": "Risk accepted",
                      "meaning": "Accepted by a named risk owner until a stated date (at most 12 months)."},
}

# weakness classes of exec_core.identity in plain words (a class without a label shows its key in words)
WEAKNESS_CLASS = {
    "sql_injection": "SQL injection", "nosql_injection": "NoSQL injection", "xss": "Cross-site scripting (XSS)",
    "csrf": "Cross-site request forgery (CSRF)", "ssrf": "Server-side request forgery (SSRF)",
    "xxe": "XML external entity (XXE)", "code_execution": "Code execution", "file_access": "File access",
    "file_upload": "Unrestricted file upload", "access_control": "Access control", "authentication": "Authentication",
    "session": "Session management", "information_disclosure": "Information disclosure",
    "configuration": "Security configuration", "cryptography": "Cryptography",
    "vulnerable_component": "Vulnerable component", "open_redirect": "Open redirect",
    "business_logic": "Business logic", "availability": "Availability", "input_validation": "Input validation",
    "unclassified": "Unclassified",
}

# target status keys of the stored record (API keys kept) -> words that never read as a breach
TARGET_STATUS = {
    "vulnerable": {"label": "Findings reported",
                   "meaning": "The testing agents reported weaknesses on this target; none was reported as exploited."},
    "compromised": {"label": "Exploitation reported",
                    "meaning": "A testing agent reported exploiting at least one weakness during the authorised test, "
                               "with evidence on file; this is a test result, not a statement that a breach occurred."},
    "unknown": {"label": "Not assessed", "meaning": "No campaign result recorded for this target yet."},
}

# test references Darkmoon may name for a campaign; ISO/IEC 27001 is a management-system standard, never a test method
TEST_REFERENCES = ("NIST SP 800-115", "MITRE ATT&CK", "OWASP WSTG", "PTES")
TEST_REFERENCES_DEFAULT = "Darkmoon automated security assessment"

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


def weakness_class_label(cls: Any) -> str:
    key = str(cls or "").strip().lower()
    return WEAKNESS_CLASS.get(key) or (key.replace("_", " ").capitalize() if key else WEAKNESS_CLASS["unclassified"])


def target_status_label(status: Any) -> str:
    s = str(status or "").strip().lower()
    return TARGET_STATUS.get(s, TARGET_STATUS["unknown"])["label"]


_ISO_27001 = re.compile(r"(?i)\bISO(?:\s*/\s*IEC)?\s*27001(?::\s*20\d\d)?\b")
_SEP = re.compile(r"\s*[/,;·|]\s*")


def _known_reference(part: str) -> Optional[str]:
    p = re.sub(r"\s+", " ", part).strip().lower()
    if "800-115" in p:
        return "NIST SP 800-115"
    if re.fullmatch(r"(mitre\s*)?att&(amp;)?ck|mitre", p):
        return "MITRE ATT&CK"
    if re.fullmatch(r"owasp( wstg| testing guide)?", p):
        return "OWASP WSTG"
    if p == "ptes":
        return "PTES"
    return None


def methodology_label(raw: Any) -> str:
    """How a campaign's declared methodology is shown everywhere (report, model, API). ISO/IEC 27001 is a
    management-system standard, never a test method: it is removed (old campaigns are rewritten on render). When what
    remains names only known test references -> « Test references: NIST SP 800-115, MITRE ATT&CK »; other declared
    text (a synthetic or partial run says so) is kept as declared; nothing left -> « Darkmoon automated security
    assessment »."""
    text = re.sub(r"\s+", " ", _ISO_27001.sub("", str(raw or ""))).strip()
    parts = [p for p in _SEP.split(text) if p.strip()]
    if not parts:
        return TEST_REFERENCES_DEFAULT
    known = [_known_reference(p) for p in parts]
    if all(known):
        return "Test references: " + ", ".join(r for r in TEST_REFERENCES if r in known)
    return " · ".join(p.strip() for p in parts)


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
        "target_status": {k: dict(v) for k, v in TARGET_STATUS.items()},
        "grade": dict(GRADE),
        "weakness_class": dict(WEAKNESS_CLASS),
    }
