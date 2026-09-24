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

ROOT = pathlib.Path(__file__).resolve().parents[2]  # mcp/tests -> mcp -> repo root
EXECUTOR = ROOT / "mcp" / "src" / "tools" / "core" / "executor.py"
SETUP_SCRIPTS = ["setup.sh", "setup_py.sh", "setup_ruby.sh"]


def allowed_tools():
    """Parse the allowed_tools set literal from executor.py (no import needed)."""
    s = EXECUTOR.read_text(encoding="utf-8")
    i = s.index("allowed_tools")
    j = s.index("{", i)
    depth = 0
    k = j
    while k < len(s):
        if s[k] == "{":
            depth += 1
        elif s[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return set(re.findall(r'"([^"]+)"', s[j:k + 1]))


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


if __name__ == "__main__":
    a = allowed_tools()
    w = toolbox_wrappers()
    miss = sorted(x for x in w if x not in a)
    print(f"allowed_tools={len(a)} toolbox_wrappers={len(w)} missing={miss}")
    test_all_toolbox_wrappers_are_whitelisted()
    print("PASS: every toolbox wrapper is whitelisted")
