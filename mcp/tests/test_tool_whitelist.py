"""Drift guard: every tool the toolbox exposes as an /out/bin wrapper (installed
by the setup scripts) MUST be present in the executor's allowed_tools whitelist,
otherwise the MCP rejects it at runtime with "Tool 'X' not in allowed list" and
the agents that call it silently lose that capability.

This test caught (and now prevents the recurrence of) grpcurl, kube-bench,
kubectl-who-can, rbac-police and zgrab2 drifting out of the whitelist while
staying installed in the toolbox. Runs standalone (python3 test_tool_whitelist.py)
or under pytest — it only reads files, no MCP import / heavy deps required.
"""
import re
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]  # mcp/tests -> mcp -> repo root
sys.path.insert(0, str(ROOT / "mcp"))
from src.tools.core.allowlist import EXECUTOR_ALLOWED_TOOLS  # noqa: E402

EXECUTOR = ROOT / "mcp" / "src" / "tools" / "core" / "executor.py"
WORKFLOW_BASE = ROOT / "mcp" / "src" / "tools" / "workflows" / "base.py"
SETUP_SCRIPTS = ["setup.sh", "setup_py.sh", "setup_ruby.sh"]
WORKFLOW_INTERNAL_TOOLS = {
    "mkdir", "echo", "cat", "rm", "chmod", "touch", "ls", "cp", "mv",
}


def allowed_tools():
    """Return executor allowed_tools without importing Docker dependencies."""
    s = EXECUTOR.read_text(encoding="utf-8")
    assert "from src.tools.core.allowlist import EXECUTOR_ALLOWED_TOOLS" in s
    assert "self.allowed_tools = set(EXECUTOR_ALLOWED_TOOLS)" in s
    return set(EXECUTOR_ALLOWED_TOOLS)


def workflow_allowed_tools():
    """Return workflow BaseWorkflow ALLOWED_TOOLS without importing docker deps."""
    s = WORKFLOW_BASE.read_text(encoding="utf-8")
    assert "from src.tools.core.allowlist import EXECUTOR_ALLOWED_TOOLS" in s
    assert "ALLOWED_TOOLS = set(EXECUTOR_ALLOWED_TOOLS) | WORKFLOW_INTERNAL_TOOLS" in s
    internal_block = re.findall(r'WORKFLOW_INTERNAL_TOOLS = \{([^}]+)\}', s, re.S)[0]
    internal = set(re.findall(r'"([^"]+)"', internal_block))
    return set(EXECUTOR_ALLOWED_TOOLS) | internal


def toolbox_wrappers():
    """Command names exposed as /out/bin wrappers by the setup scripts."""
    names = set()
    for fname in SETUP_SCRIPTS:
        p = ROOT / fname
        if not p.exists():
            continue
        t = p.read_text(encoding="utf-8", errors="ignore")
        for pat in (r'/out/bin/([a-zA-Z0-9_.\-]+)',
                    r'"\$BIN_OUT/([a-zA-Z0-9_.\-]+)',
                    r'\$\{?BIN_OUT\}?/([a-zA-Z0-9_.\-]+)'):
            names.update(re.findall(pat, t))
    names.discard("")
    return names


def test_all_toolbox_wrappers_are_whitelisted():
    allowed = allowed_tools()
    wrappers = toolbox_wrappers()
    assert wrappers, "no toolbox wrappers discovered — setup scripts moved or path wrong"
    missing = sorted(w for w in wrappers if w not in allowed)
    assert not missing, (
        "Toolbox tools installed but NOT in executor allowed_tools (agents that "
        "call them get 'not in allowed list'): " + ", ".join(missing)
    )


def test_workflow_allowlist_stays_synced_with_executor():
    expected = allowed_tools() | WORKFLOW_INTERNAL_TOOLS
    actual = workflow_allowed_tools()
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    assert not missing and not extra, (
        "Workflow ALLOWED_TOOLS drifted from executor allowed_tools plus "
        f"internal shell helpers; missing={missing}, extra={extra}"
    )


if __name__ == "__main__":
    a = allowed_tools()
    w = toolbox_wrappers()
    miss = sorted(x for x in w if x not in a)
    print(f"allowed_tools={len(a)} toolbox_wrappers={len(w)} missing={miss}")
    test_all_toolbox_wrappers_are_whitelisted()
    print("PASS: every toolbox wrapper is whitelisted")
