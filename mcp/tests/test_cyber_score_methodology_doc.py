"""The customer-facing methodology (docs/cyber-score-methodology.md) states the values the code uses (R1 H-2).

Every row ``| `NAME` | value | … |`` of its reference table is compared with ``exec_core.score``; every constant the
rating uses must have a row. Same file in Community and Pro.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api.exec_core import report_model as RM  # noqa: E402
from api.exec_core import score as S  # noqa: E402

DOC = MCP.parent / "docs" / "cyber-score-methodology.md"


def _code_values():
    out = {}
    for k, v in S.SEVERITY_WEIGHT.items():
        out[f"SEVERITY_WEIGHT.{k}"] = v
    for k, v in S.PROOF_FACTOR.items():
        out[f"PROOF_FACTOR.{k}"] = v
    for name in ("UNIT_INCREMENT", "UNIT_INCREMENT_CAP", "CLASS_SPREAD", "CLASS_SPREAD_CAP", "LIMITED_CAP",
                 "MIN_DURATION_SECONDS", "MIN_AGENTS", "MIN_ASSETS", "MIN_COMMANDS"):
        out[name] = getattr(S, name)
    for rule, _sev, _proof, cap in S.CAPS:
        out[f"CAPS.{rule}"] = cap
    for g, floor in S.GRADES:
        out[f"GRADES.{g}"] = floor
    return out


@pytest.mark.skipif(not DOC.exists(), reason="docs not shipped next to the server")
def test_methodology_doc_matches_the_code():
    text = DOC.read_text(encoding="utf-8")
    rows = dict(re.findall(r"^\| `([A-Z_]+(?:\.[a-z_A-Z]+)?)` \| ([0-9.]+) \|", text, re.M))
    code = _code_values()
    assert set(rows) == set(code), (sorted(set(code) - set(rows)), sorted(set(rows) - set(code)))
    for name, value in code.items():
        assert float(rows[name]) == float(value), (name, rows[name], value)
    assert S.METHODOLOGY_VERSION in text
    for must in ("reported by the testing agent", "Run-to-run variance has not been measured", "Saturation at 0",
                 "not tamper-evident", "coverage gate"):
        assert must in text, must


def test_report_points_to_the_published_methodology():
    assert RM.METHODOLOGY_DOC == "docs/cyber-score-methodology.md"
    items = RM.method_summary()
    assert any(S.METHODOLOGY_VERSION in x and RM.METHODOLOGY_DOC in x for x in items)
    assert any(f"critical {S.SEVERITY_WEIGHT['critical']:g}" in x for x in items)
