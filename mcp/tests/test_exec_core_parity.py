"""exec_core parity between Darkmoon Community and Pro (same file in both editions).

1. Every module of ``api/exec_core`` matches the SHA-256 listed in ``exec_core.MANIFEST``, and ``__init__.py`` itself
   matches ``INIT_SHA256`` below: the package is byte-identical in both editions.
2. The golden fixtures (anonymised real campaigns + synthetic edge cases) are byte-identical (``FIXTURES_SHA256``)
   and give exactly the committed expected outputs.
3. exec_core stays pure: standard library only, no file, network or process access.
4. Community: the copy vendored for the terminal explorer matches the manifest too.

After a deliberate change: ``python3 tests/test_exec_core_parity.py`` prints the new values (regenerate the expected
outputs first with ``tests/fixtures/exec_core/regen_expected.py``), then copy the package, fixtures and this file
verbatim to the other edition.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api import exec_core  # noqa: E402
from api.exec_core import project, score, stats  # noqa: E402

CORE = MCP / "api" / "exec_core"
FIXTURES = MCP / "tests" / "fixtures" / "exec_core"
VENDORED = MCP.parent / "conf" / "plugins" / "darkmoon-explorer" / "_vendor" / "exec_core"

INIT_SHA256 = "168d884592b46f99ec6d9c98fa044aa31c09e5e79cc90df3e2b539d15de9ba52"
FIXTURES_SHA256 = "ce78130382c532eecceb849f1b5dcd893ff369709f979fa43914fca27ddd946a"

STDLIB_ALLOWED = {"__future__", "hashlib", "json", "math", "re", "typing", "urllib.parse"}
FORBIDDEN_CALLS = {"open", "exec", "eval", "compile", "__import__", "input"}
FORBIDDEN_NAMES = {"os", "sys", "subprocess", "socket", "pathlib", "shutil", "sqlite3", "io", "tempfile"}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _modules(root: Path):
    return sorted(p for p in root.glob("*.py") if p.name != "__init__.py")


def _fixtures_digest() -> str:
    h = hashlib.sha256()
    for p in sorted(FIXTURES.iterdir()):
        if p.is_file() and p.suffix in (".json", ".py"):
            h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def test_modules_match_the_manifest():
    assert {p.name for p in _modules(CORE)} == set(exec_core.MANIFEST), "module added/removed without the manifest"
    for p in _modules(CORE):
        assert _sha(p) == exec_core.MANIFEST[p.name], f"{p.name} differs from the manifest (edition drift)"


def test_init_is_identical():
    assert _sha(CORE / "__init__.py") == INIT_SHA256


def test_vendored_explorer_copy_matches_when_present():
    if not VENDORED.is_dir():
        return  # Pro: the explorer imports api.exec_core from the MCP server
    assert {p.name for p in _modules(VENDORED)} == set(exec_core.MANIFEST)
    for p in _modules(VENDORED):
        assert _sha(p) == exec_core.MANIFEST[p.name], f"vendored {p.name} drifted"
    assert _sha(VENDORED / "__init__.py") == INIT_SHA256


def test_fixtures_are_identical():
    assert _fixtures_digest() == FIXTURES_SHA256


def _expected_for(doc):
    if "bundles" in doc["input"]:
        return {"project": project.reference_score(doc["input"]["bundles"])}
    return {"stats": stats.compute_stats(doc["input"]["findings"]), "score": score.cyber_score(doc["input"])}


def test_golden_fixtures_give_the_expected_outputs():
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    seen = set()
    for p in sorted(FIXTURES.glob("*.json")):
        if p.name == "expected.json":
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        got = json.loads(json.dumps(_expected_for(doc), sort_keys=True))
        assert got == expected[doc["name"]], f"golden drift: {doc['name']}"
        seen.add(doc["name"])
    assert seen == set(expected)


def test_golden_statuses_of_the_real_campaigns():
    """The decisions the plan requires on real data (07 §3.5.10)."""
    e = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    st = {k: v["score"]["score_status"] for k, v in e.items() if "score" in v}
    assert st["real_prevalidation_reconstructed"] == "limited"
    assert st["real_aborted_as_stored"] == st["real_aborted_reconstructed"] == "not_rated"
    for k in ("real_dvga_full_as_stored", "real_dvwa_e2e_as_stored", "real_prevalidation_as_stored"):
        assert st[k] == "not_rated"
    assert e["real_dvga_full_as_stored"]["stats"]["total_findings"] == 68
    assert e["real_dvwa_e2e_as_stored"]["stats"]["total_findings"] == 59


def test_exec_core_is_pure_stdlib_without_io():
    for p in _modules(CORE) + [CORE / "__init__.py"]:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name in STDLIB_ALLOWED, f"{p.name}: import {a.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    assert node.module in STDLIB_ALLOWED, f"{p.name}: from {node.module}"
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, f"{p.name}: {node.func.id}()"
            elif isinstance(node, ast.Name):
                assert node.id not in FORBIDDEN_NAMES, f"{p.name}: {node.id}"


if __name__ == "__main__":
    print("MANIFEST = {")
    for p in _modules(CORE):
        print(f'    "{p.name}": "{_sha(p)}",')
    print("}")
    print(f'INIT_SHA256 = "{_sha(CORE / "__init__.py")}"')
    print(f'FIXTURES_SHA256 = "{_fixtures_digest()}"')
