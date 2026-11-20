"""exec_core parity between Darkmoon Community and Pro (same file in both editions).

1. Every module of ``api/exec_core`` matches the SHA-256 listed in ``exec_core.MANIFEST``, and ``__init__.py`` itself
   matches ``INIT_SHA256`` below: the package is byte-identical in both editions.
2. The golden fixtures (anonymised real campaigns + synthetic edge cases) are byte-identical (``FIXTURES_SHA256``)
   and give exactly the committed expected outputs.
3. exec_core stays pure: standard library only, no file, network or process access.
4. Community: the copy vendored for the terminal explorer matches the manifest too.
5. The other modules both editions must ship identically (``SHARED_SHA256``: coverage recorder, score adapter,
   fix triage, security log, run binding of the MCP writes) match the hashes below, and so do the treatment-plan and framework-assessment parity fixtures and
   their tests. This file itself is shipped identically, so a change in one edition only
   fails the other edition's run once the file is copied (no cross-repository access from a test).

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

INIT_SHA256 = "4bd0955f4c00503ea21023ed6808c3002088824f5dae97a806f91fc00532eaa8"
SHARED_SHA256 = {
    "coverage_signals.py": "709bde05795a7b5f0ed83d0b700933542f14fa697c0dbba8755abf653e3bdb1f",
    "exec_score.py": "94e6bd24282becd2e382dc02556cd4ae90eea7ba5b898473516d112615b3bd94",
    "fix_triage.py": "97f3883ea3e754bbb92a72a1316ac22ff82aad96ff9195aefb0f4fcce74229f6",
    "run_binding.py": "5f42b3675eb1afaecf53e16547ad0b8c58ac48a34349ea9ad9c29810dcd84fae",
    "security_log.py": "f0c55e93aded8461847a55039e61d0d4f24f907bf30f28b6320ae740d6702a52",
}
SHARED_TESTS_SHA256 = {
    "test_exec_core_actions.py": "dddf9d25e8c1b1d88c1dc00e266e81438239ce894598ba57ae771131c7fd58ee",
    "test_exec_core_executive.py": "b6eb28e4b4f67684b0317162383fb5c3165fd6e4c3f27efaeaa7f3a191e14da6",
    "test_exec_core_maintenance.py": "b01da7cc688fe4e6f3efde0cb53c55ecc678c1885b201fdf21592b28262df1a7",
    "test_exec_core_taxonomy.py": "f55f8efaac308b2600c52c0bc8388bb0d89cf12ddc5565161a66cecdaf4eb35a",
    "test_exec_core_frameworks.py": "d4816a3bfa29a441309653a38687d5d40d13dd6d881988fa32a5002f198317b1",
    "test_exec_core_report_model.py": "df02fcf170f4533b5749ce2f70d8fd38d845097d1c1030e8158969c16afdf7d9",
    "test_run_binding.py": "d5f937f95b77269ae9f33f782b081b8a8968d7ddfd229f0759e48ebe67863187",
}
TREATMENT_FIXTURES_SHA256 = "c0dec06c1da681d658206603a6347dc055d089013c74c7733805752b0612e750"
FRAMEWORK_FIXTURES_SHA256 = "54797efc393278623b6cc26792e29ed354c0e2f5a71725564bbdef61bb0f41d6"
MAINTENANCE_FIXTURES_SHA256 = "0b2b564c884671b8bf75db474e4a6b88d853b448dab412ef9fdfb6a42cf31c1f"
REPORT_FIXTURES_SHA256 = "3ba50f62a1a44037b9adf513dfb92fc156eed3f14ef60abecf73ea15f0590972"
FIXTURES_SHA256 = "9a5944cce69bb4e86a4eae2f8bf4a452feb09a42b23d0de172ffe7c93b413597"

# zoneinfo (maintenance windows) reads the host's time-zone database: the only outside input exec_core accepts
STDLIB_ALLOWED = {"__future__", "datetime", "hashlib", "ipaddress", "json", "math", "re", "typing", "urllib.parse",
                  "zoneinfo"}
FORBIDDEN_CALLS = {"open", "exec", "eval", "compile", "__import__", "input"}
FORBIDDEN_NAMES = {"os", "sys", "subprocess", "socket", "pathlib", "shutil", "sqlite3", "io", "tempfile"}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _modules(root: Path):
    return sorted(p for p in root.glob("*.py") if p.name != "__init__.py")


def _fixtures_digest(root: Path = FIXTURES) -> str:
    h = hashlib.sha256()
    for p in sorted(root.iterdir()):
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


def test_shared_modules_are_identical():
    for name, sha in SHARED_SHA256.items():
        assert _sha(MCP / "api" / name) == sha, f"api/{name} differs from the other edition"


def test_fixtures_are_identical():
    assert _fixtures_digest() == FIXTURES_SHA256


def test_treatment_plan_fixtures_and_tests_are_identical():
    """The treatment plan parity fixture, its expected plan and its test run unchanged in both editions."""
    assert _fixtures_digest(FIXTURES / "treatment") == TREATMENT_FIXTURES_SHA256
    for name, sha in SHARED_TESTS_SHA256.items():
        assert _sha(MCP / "tests" / name) == sha, f"tests/{name} differs from the other edition"


def test_framework_assessment_fixtures_are_identical():
    """The framework-assessment / profile parity fixture and its expected output run unchanged in both editions."""
    assert _fixtures_digest(FIXTURES / "frameworks") == FRAMEWORK_FIXTURES_SHA256


def test_maintenance_fixtures_are_identical():
    """The maintenance-window golden cases and their expected evaluations run unchanged in both editions."""
    assert _fixtures_digest(FIXTURES / "maintenance") == MAINTENANCE_FIXTURES_SHA256


def test_report_model_fixtures_are_identical():
    """The report-model parity fixture and its expected models (core and store level) run unchanged in both editions."""
    assert _fixtures_digest(FIXTURES / "report") == REPORT_FIXTURES_SHA256


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
    print("SHARED_SHA256 = {")
    for name in SHARED_SHA256:
        print(f'    "{name}": "{_sha(MCP / "api" / name)}",')
    print("}")
    print("SHARED_TESTS_SHA256 = {")
    for name in SHARED_TESTS_SHA256:
        print(f'    "{name}": "{_sha(MCP / "tests" / name)}",')
    print("}")
    print(f'TREATMENT_FIXTURES_SHA256 = "{_fixtures_digest(FIXTURES / "treatment")}"')
    print(f'FRAMEWORK_FIXTURES_SHA256 = "{_fixtures_digest(FIXTURES / "frameworks")}"')
    print(f'MAINTENANCE_FIXTURES_SHA256 = "{_fixtures_digest(FIXTURES / "maintenance")}"')
    print(f'REPORT_FIXTURES_SHA256 = "{_fixtures_digest(FIXTURES / "report")}"')
    print(f'FIXTURES_SHA256 = "{_fixtures_digest()}"')
