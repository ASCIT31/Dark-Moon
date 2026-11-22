"""The AI SDK adapter of the local / custom provider can be chosen (OPENCODE_LOCAL_NPM in .opencode.env).

A user report: an OpenAI reasoning model on Azure AI Foundry, declared as the custom OpenAI-compatible provider,
failed (« Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' ») until
the provider's "npm" was changed to "@ai-sdk/openai" by hand in opencode.json; apply-settings.sh rewrites that file
at every start with a hard-coded "@ai-sdk/openai-compatible", so the only way to keep the change was to bind-mount the
file over the generated one. Azure endpoints now get the native Azure mode (test_apply_settings_azure.py); the
setting remains for OpenAI's own API or an OpenAI-native proxy. These tests run the real script with its /root paths redirected to a temporary directory.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "conf" / "apply-settings.sh"


@pytest.fixture
def run_settings(tmp_path):
    script = SCRIPT.read_text().replace("/root/.config/opencode", str(tmp_path / "cfg")) \
                               .replace("/root/.local/share/opencode", str(tmp_path / "share"))
    s = tmp_path / "apply-settings.sh"
    s.write_text(script)

    def run(**env):
        full = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "DARKMOON_MCP_TRANSPORT": "stdio",
                "OPENCODE_LOCAL_MODE": "true", "OPENCODE_LOCAL_PROVIDER_ID": "local",
                "OPENCODE_LOCAL_PROVIDER_NAME": "Local model",
                "OPENCODE_LOCAL_BASE_URL": "https://llm.example.com/v1",
                "OPENCODE_LOCAL_MODEL": "gpt-test", "OPENCODE_LOCAL_API_KEY": "k-test", **env}
        p = subprocess.run(["bash", str(s)], env=full, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stdout + p.stderr
        cfg = json.loads((tmp_path / "cfg" / "opencode.json").read_text())
        return cfg, p.stdout + p.stderr

    yield run
    shutil.rmtree(tmp_path / "cfg", ignore_errors=True)


def test_default_stays_openai_compatible(run_settings):
    cfg, _ = run_settings()
    prov = cfg["provider"]["local"]
    assert prov["npm"] == "@ai-sdk/openai-compatible"
    assert prov["options"] == {"baseURL": "https://llm.example.com/v1", "apiKey": "k-test"}
    assert cfg["model"] == "local/gpt-test"


@pytest.mark.parametrize("npm", ["@ai-sdk/openai", "@ai-sdk/openai-compatible"])
def test_supported_adapter_is_written(run_settings, npm):
    cfg, _ = run_settings(OPENCODE_LOCAL_NPM=npm)
    assert cfg["provider"]["local"]["npm"] == npm


@pytest.mark.parametrize("npm", ["evil-package", "@ai-sdk/openai\",\"x\":\"y", "file:///tmp/x.js", "@ai-sdk/anthropic",
                                 "@ai-sdk/azure"])  # Azure has its native mode
def test_unsupported_adapter_falls_back_with_a_warning(run_settings, npm):
    """Only adapters bundled in the opencode binary: nothing is ever fetched from npm, nothing injected in the JSON."""
    cfg, out = run_settings(OPENCODE_LOCAL_NPM=npm)
    assert cfg["provider"]["local"]["npm"] == "@ai-sdk/openai-compatible"
    assert "is not supported" in out


def test_variable_is_ignored_outside_local_mode(run_settings):
    cfg, _ = run_settings(OPENCODE_LOCAL_MODE="false", OPENCODE_LOCAL_NPM="@ai-sdk/openai")
    assert "provider" not in cfg
