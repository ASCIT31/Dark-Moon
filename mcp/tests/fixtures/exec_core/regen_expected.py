#!/usr/bin/env python3
"""Recompute the expected outputs of the exec_core golden fixtures (run from mcp/: python3
tests/fixtures/exec_core/regen_expected.py). Only after a deliberate methodology change: the parity test fails on
any drift, and the expected files are shipped byte-identically in both editions."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from api.exec_core import project, score, stats  # noqa: E402


def expected_for(doc):
    if "bundles" in doc["input"]:
        return {"project": project.reference_score(doc["input"]["bundles"])}
    findings = doc["input"]["findings"]
    return {"stats": stats.compute_stats(findings), "score": score.cyber_score(doc["input"])}


def dump(obj) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> None:
    out = {}
    for p in sorted(HERE.glob("*.json")):
        if p.name == "expected.json":
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        out[doc["name"]] = expected_for(doc)
    (HERE / "expected.json").write_text(dump(out), encoding="utf-8")
    print(f"{len(out)} expected outputs written")


if __name__ == "__main__":
    main()
