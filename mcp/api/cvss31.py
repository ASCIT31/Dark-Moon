"""
CVSS v3.0 / v3.1 base score from a vector string (FIRST CVSS v3.1 specification, §7.1 and Appendix A
"Roundup"). Pure function, no dependency. Cross-checked in tests against values produced by the reference
``cvss`` package (Red Hat, 3.2) on the vectors of the real campaigns and on edge cases.

Parsing is strict, like the specification: metric names and values are case-sensitive, every base metric is
required, a metric may appear once, temporal and environmental metrics must carry a defined value (they are
validated but do not change the base score), unknown metrics and empty parts (a trailing ``/``) make the vector
invalid. Only surrounding whitespace is tolerated. ``CVSS:3.0`` vectors are scored with the 3.1 Roundup (same
result on every 3.0 vector tested). CVSS 4.0 and free text return ``None``.

Returns None for a missing or invalid vector: the caller never invents a score.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# temporal + environmental metrics: validated, ignored for the base score
_OTHER = {
    "E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
    "CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH", "MI": "XNLH", "MA": "XNLH",
}
_PREFIX = re.compile(r"^CVSS:3\.[01]/")


def _roundup(x: float) -> float:
    """Appendix A: smallest number, to one decimal, >= x, robust to floating point."""
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def parse(vector: Any) -> Optional[Dict[str, str]]:
    if not isinstance(vector, str):
        return None
    s = vector.strip()
    if not _PREFIX.match(s):
        return None
    m: Dict[str, str] = {}
    for part in s.split("/")[1:]:
        if part.count(":") != 1:
            return None
        k, v = part.split(":")
        if k in m:
            return None          # duplicated metric = invalid vector
        if k in _BASE:
            ok = v in (("U", "C") if k == "S" else _PR["U"] if k == "PR" else _W[k])
        else:
            ok = k in _OTHER and len(v) == 1 and v in _OTHER[k]
        if not ok:
            return None
        m[k] = v
    if any(k not in m for k in _BASE):
        return None
    return m


def base_score(vector: Any) -> Optional[float]:
    m = parse(vector)
    if m is None:
        return None
    changed = m["S"] == "C"
    iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))


def band(score: Optional[float]) -> Optional[str]:
    """CVSS v3.1 qualitative severity rating scale (§5)."""
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "none"


def assess(v: Dict[str, Any]) -> Dict[str, Any]:
    """Score used for ordering = the score computed from the vector. The agent's number is kept for display
    and flagged when it contradicts its own vector (difference > 0.1)."""
    reported = v.get("cvss_score")
    try:
        reported = float(reported)
        reported_ok = 0 <= reported <= 10     # NaN fails both comparisons
    except (TypeError, ValueError):
        reported, reported_ok = None, False
    computed = base_score(v.get("cvss_vector"))
    if computed is None:
        status = "no-valid-vector"
    elif not reported_ok:
        status = "reported-invalid"
    elif abs(computed - reported) > 0.1:
        status = "mismatch"
    else:
        status = "ok"
    return {"score": computed, "reported": reported if reported_ok else None, "status": status}
