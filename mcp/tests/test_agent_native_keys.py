"""opencode receives its own agent keys only (fix at the source, replaces the darkmoon-agent-options.ts runtime filter).

A user report (Azure AI Foundry): every campaign failed at its first model call with 400
« Unrecognized request argument supplied: mcp », then « ...: id ». opencode keeps every agent key it does not know
(packages/core/src/v1/config/agent.ts, KNOWN_KEYS) as a call option, and the OpenAI-compatible adapters copy call
options into the request body. Darkmoon wrote its own keys into the agent blocks of opencode.json ("mcp", "primary",
"secondary", "prompt_file") and into the front matter of the agent files ("id").

They now map to opencode's native schema or to Darkmoon's own file:
  primary / secondary   -> "mode": "primary" / "subagent"       (opencode.json)
  prompt_file           -> darkmoon-agents.json, the Darkmoon agent registry read by the orchestrator; opencode loads
                           the same files natively from /root/.opencode/agents
  mcp: ["darkmoon"]     -> nothing per agent: the global "*": "allow" permission already gives every agent the
                           Darkmoon MCP tools (the key had no reader and no effect)
  front-matter id       -> nothing: equal to the native "name" in every file

These tests run the REAL apply-settings.sh and fail if a non-native key comes back. The key list is the one of
tools/agent-build/validate.py, checked against the opencode source at the pinned fork ref when that source is available
(DARKMOON_OPENCODE_SRC = a git checkout of the fork), and the generated config is loaded by the real opencode binary
when an image is given (DARKMOON_OPENCODE_IMAGE): every Darkmoon agent must then resolve with empty call options.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "conf" / "apply-settings.sh"
AGENTS = ROOT / "conf" / "agents"
spec = importlib.util.spec_from_file_location("_ab_validate_native_keys", ROOT / "tools" / "agent-build" / "validate.py")
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
OPENCODE_AGENT_KEYS = set(V.OPENCODE_AGENT_KEYS)


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("native-keys")
    # only the output directories move: the permission paths of the generated file stay the runtime ones
    script = SCRIPT.read_text().replace('OPENCODE_CONFIG_DIR="/root/.config/opencode"', f'OPENCODE_CONFIG_DIR="{tmp}/cfg"') \
                               .replace('OPENCODE_AUTH_DIR="/root/.local/share/opencode"', f'OPENCODE_AUTH_DIR="{tmp}/share"')
    assert str(tmp) in script
    s = tmp / "apply-settings.sh"
    s.write_text(script)
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp), "DARKMOON_MCP_TRANSPORT": "stdio",
           "OPENCODE_LOCAL_MODE": "true", "OPENCODE_LOCAL_PROVIDER_ID": "local",
           "OPENCODE_LOCAL_PROVIDER_NAME": "Local model",
           "OPENCODE_LOCAL_BASE_URL": "http://llm.internal:11434/v1", "OPENCODE_LOCAL_MODEL": "m"}
    p = subprocess.run(["bash", str(s)], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    cfg = json.loads((tmp / "cfg" / "opencode.json").read_text())
    registry = json.loads((tmp / "cfg" / "darkmoon-agents.json").read_text())
    return cfg, registry, tmp


def _front_matter_keys(text):
    return re.findall(r"^([A-Za-z_][\w-]*)\s*:", V.frontmatter(text), re.M)


def _agent_files():
    files = sorted(AGENTS.glob("*.md"))
    assert len(files) >= 51
    return files


def test_generated_agent_blocks_carry_opencode_keys_only(generated):
    cfg, _, _ = generated
    assert len(cfg["agent"]) >= 51
    for name, block in cfg["agent"].items():
        extra = set(block) - OPENCODE_AGENT_KEYS
        assert not extra, f"agent {name}: {sorted(extra)} would be sent to the model provider"
        assert not block.get("options"), f"agent {name}: explicit call options"


def test_agent_front_matter_carries_opencode_keys_only():
    for f in _agent_files():
        extra = set(_front_matter_keys(f.read_text())) - OPENCODE_AGENT_KEYS
        assert not extra, f"{f.name}: front-matter {sorted(extra)} would be sent to the model provider"


def test_front_matter_is_read_like_opencode():
    """gray-matter (opencode's parser) needs exactly « --- » to open the block: kubernetes.md's dash rule and its
    ID / NAME / DESCRIPTION lines are prompt text, not keys (opencode names that agent after the file)."""
    assert V.frontmatter("---\nname: a\ndescription: d\n---\nbody") == "name: a\ndescription: d"
    assert V.frontmatter("---\nname: a\n------------\nbody") == "name: a"          # ad.md closes on a dash rule
    assert V.frontmatter("------------\nID: k\nNAME: k\n------------\nbody") == ""
    assert V.frontmatter("---\r\nname: a\r\n---\r\nbody") == "name: a"
    assert _front_matter_keys((AGENTS / "kubernetes.md").read_text()) == []


def test_validate_rejects_a_non_native_front_matter_key(tmp_path):
    banner = V.canonical_banner()
    good = (AGENTS / "graphql.md").read_text()
    before = V.validate(str(AGENTS / "graphql.md"), banner)
    assert not [e for e in before if "front-matter" in e]
    bad = tmp_path / "graphql.md"
    bad.write_text(good.replace("---\nname: graphql\n", "---\nid: graphql\nname: graphql\n", 1))
    assert set(V.validate(str(bad), banner)) - set(before) == {"front-matter key 'id' is not an opencode agent key"}


def test_primary_and_subagents_use_the_native_mode(generated):
    cfg, _, _ = generated
    modes = {name: block.get("mode") for name, block in cfg["agent"].items()}
    assert modes.pop("pentest") == "primary"          # the only agent the API runs (opencode run --agent pentest)
    assert set(modes.values()) == {"subagent"}, modes  # every other agent is dispatched by the orchestrator (task)


def test_registry_maps_every_agent_to_the_file_opencode_loads_under_the_same_name(generated):
    cfg, registry, _ = generated
    agents = registry["agents"]
    assert set(agents) == set(cfg["agent"])
    for name, entry in agents.items():
        assert set(entry) == {"prompt_file"}
        path = entry["prompt_file"]
        assert path.startswith("/root/.opencode/agents/") and path.endswith(".md"), path
        f = AGENTS / Path(path).name
        assert f.is_file(), path
        # opencode's agent name for a file: its front-matter name, else the file name (config/agent.ts load)
        m = re.search(r"^name:\s*(\S+)\s*$", V.frontmatter(f.read_text()), re.M)
        assert (m.group(1) if m else f.stem) == name, f"{f.name} is loaded by opencode as another agent than {name}"
    assert agents["active-directory"]["prompt_file"].endswith("/ad.md")
    assert agents["nodejs"]["prompt_file"].endswith("/nodejs-express-angular.md")


def test_every_agent_keeps_the_darkmoon_mcp_tools(generated):
    """The removed per-agent « mcp »: the Darkmoon tools come from the global permission (Community: allow-all), for
    every agent; no agent block narrows it."""
    cfg, _, _ = generated
    assert cfg["mcp"]["darkmoon"]["enabled"] is True
    assert cfg["permission"] == {"*": "allow"}
    for name, block in cfg["agent"].items():
        assert "permission" not in block and "tools" not in block, name


def test_the_orchestrator_can_read_the_registry(generated):
    cfg, _, _ = generated
    assert cfg["permission"] == {"*": "allow"}                # read included
    script = SCRIPT.read_text()
    assert 'OPENCODE_CONFIG_DIR="/root/.config/opencode"' in script
    assert 'DARKMOON_AGENTS_FILE="$OPENCODE_CONFIG_DIR/darkmoon-agents.json"' in script   # the path pentest.md reads
    assert "/root/.config/opencode/darkmoon-agents.json" in (AGENTS / "pentest.md").read_text()
    text = (AGENTS / "pentest.md").read_text()
    assert "darkmoon-agents.json" in text and '"prompt_file" value of the sub-agent\'s entry in darkmoon-agents.json' in text
    assert "entry in opencode.json" not in text


def test_no_runtime_filter_plugin(generated):
    """The fix is at the source: no plugin rewrites the agent options at runtime."""
    cfg, _, _ = generated
    assert not [p for p in cfg["plugin"] if "agent-options" in p]
    assert not (ROOT / "conf" / "plugins" / "darkmoon-agent-options.ts").exists()


def test_key_list_matches_the_pinned_opencode_source():
    """OPENCODE_AGENT_KEYS is opencode's KNOWN_KEYS at the fork ref the image is built from."""
    src = os.environ.get("DARKMOON_OPENCODE_SRC")
    if not src or not Path(src, ".git").exists():
        pytest.skip("DARKMOON_OPENCODE_SRC (git checkout of the opencode fork) not set")
    ref = re.search(r"^ARG OPENCODE_REF=([0-9a-f]{40})$", (ROOT / "Dockerfile.opencode").read_text(), re.M).group(1)
    p = subprocess.run(["git", "-C", src, "show", f"{ref}:packages/core/src/v1/config/agent.ts"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        pytest.skip(f"fork ref {ref[:12]} not in {src}")
    known = re.search(r"const KNOWN_KEYS = new Set\(\[(.*?)\]\)", p.stdout, re.S).group(1)
    assert set(re.findall(r'"([^"]+)"', known)) == OPENCODE_AGENT_KEYS


def test_real_opencode_resolves_every_agent_without_call_options(generated):
    """The generated opencode.json and the agent files, loaded by the opencode binary of the image: no agent may end
    up with call options (they would be copied into the provider request)."""
    image, docker = os.environ.get("DARKMOON_OPENCODE_IMAGE"), shutil.which("docker")
    if not image or not docker:
        pytest.skip("DARKMOON_OPENCODE_IMAGE (an opencode image of this repo) not set")
    cfg, _, tmp = generated
    home = tmp / "home"
    (home / ".config").mkdir(parents=True, exist_ok=True)
    (home / ".tmp").mkdir(exist_ok=True)
    shutil.copytree(tmp / "cfg", home / ".config" / "opencode", dirs_exist_ok=True)
    shutil.copytree(AGENTS, home / ".opencode" / "agents", dirs_exist_ok=True)
    p = subprocess.run(
        [docker, "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
         "-v", f"{home}:/home/probe", "-e", "HOME=/home/probe", "-e", "XDG_CONFIG_HOME=/home/probe/.config",
         "-e", "XDG_DATA_HOME=/home/probe/.local/share", "-e", "XDG_CACHE_HOME=/home/probe/.cache",
         "-e", "XDG_STATE_HOME=/home/probe/.local/state", "-e", "TMPDIR=/home/probe/.tmp",
         "-e", "OPENCODE_CONFIG_DIR=/home/probe/.config/opencode", "-w", "/home/probe",
         # redirected to a file: a piped stdout is cut when the binary exits (≈64 KiB)
         "--entrypoint", "sh", image, "-c",
         "/usr/local/bin/opencode debug config --pure > /home/probe/debug-config.json"],
        capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, p.stderr[-2000:]
    resolved = json.loads((home / "debug-config.json").read_text())["agent"]
    for name in cfg["agent"]:
        assert name in resolved, f"opencode did not load agent {name}"
        assert resolved[name].get("options") in (None, {}), f"agent {name}: call options {resolved[name]['options']}"
        assert resolved[name].get("mode") == cfg["agent"][name]["mode"]


CAPTURE_SERVER = r'''
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with open(sys.argv[1], "a") as f:
            f.write(json.dumps({"path": self.path, "body": json.loads(body or b"{}")}) + "\n")
        msg = json.dumps({"error": {"message": "captured", "type": "invalid_request_error"}}).encode()
        self.send_response(400); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(msg))); self.end_headers(); self.wfile.write(msg)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 18999), H).serve_forever()
'''


def test_openai_compatible_request_body_has_no_darkmoon_key(generated):
    """The generic @ai-sdk/openai-compatible adapter (Ollama, vLLM, LiteLLM, any custom URL) copies agent call options
    into the body. The real opencode binary runs the orchestrator against a local capture server: before the fix the
    body carried mcp / primary / prompt_file / id next to model and messages."""
    image, docker = os.environ.get("DARKMOON_OPENCODE_IMAGE"), shutil.which("docker")
    if not image or not docker:
        pytest.skip("DARKMOON_OPENCODE_IMAGE (an opencode image of this repo) not set")
    cfg, _, tmp = generated
    assert cfg["provider"]["local"]["npm"] == "@ai-sdk/openai-compatible"
    home = tmp / "capture-home"
    (home / ".tmp").mkdir(parents=True, exist_ok=True)
    shutil.copytree(tmp / "cfg", home / ".config" / "opencode", dirs_exist_ok=True)
    shutil.copytree(AGENTS, home / ".opencode" / "agents", dirs_exist_ok=True)
    run_cfg = json.loads(json.dumps(cfg))
    run_cfg["provider"]["local"]["options"]["baseURL"] = "http://127.0.0.1:18999/v1"
    run_cfg["mcp"] = {}                                   # no MCP server in this container; agent blocks untouched
    (home / ".config" / "opencode" / "opencode.json").write_text(json.dumps(run_cfg))
    (home / "capture.py").write_text(CAPTURE_SERVER)
    subprocess.run(
        [docker, "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
         "-v", f"{home}:/home/probe", "-e", "HOME=/home/probe", "-e", "XDG_CONFIG_HOME=/home/probe/.config",
         "-e", "XDG_DATA_HOME=/home/probe/.local/share", "-e", "XDG_CACHE_HOME=/home/probe/.cache",
         "-e", "XDG_STATE_HOME=/home/probe/.local/state", "-e", "TMPDIR=/home/probe/.tmp",
         "-e", "OPENCODE_CONFIG_DIR=/home/probe/.config/opencode", "-w", "/home/probe",
         "--entrypoint", "sh", image, "-c",
         "python3 /home/probe/capture.py /home/probe/captured.jsonl & sleep 1; "
         "timeout 90 /usr/local/bin/opencode run --pure --agent pentest hello > /home/probe/run.out 2>&1; true"],
        capture_output=True, text=True, timeout=180)
    captured = home / "captured.jsonl"
    assert captured.exists(), (home / "run.out").read_text()[-2000:] if (home / "run.out").exists() else "no request"
    bodies = [json.loads(line)["body"] for line in captured.read_text().splitlines()]
    assert any("tool_choice" in b for b in bodies), "the orchestrator's own call was not captured"
    for b in bodies:
        leaked = {k for k in b if k.lower() in {"mcp", "primary", "secondary", "prompt_file", "id", "name"}}
        assert not leaked, f"Darkmoon agent keys in the provider request: {sorted(leaked)}"
