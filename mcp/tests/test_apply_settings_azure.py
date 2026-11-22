"""Native Azure mode of apply-settings.sh: opencode's built-in "azure" provider (@ai-sdk/azure).

A user report (Azure AI Foundry): a Foundry deployment declared as the local / custom-URL provider went through the
generic OpenAI-compatible adapter, which sends max_tokens; OpenAI reasoning deployments reject it (« Unsupported
parameter: 'max_tokens' ... Use 'max_completion_tokens' »). opencode's native azure provider uses the Responses API
(validated end to end on a real Foundry resource with GPT, Kimi and Grok deployments, same opencode build as this
image). These tests run the real script with its /root paths redirected to a temporary directory.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "conf" / "apply-settings.sh"
KEY = "k-secret-value-never-written"


@pytest.fixture
def run_settings(tmp_path):
    script = SCRIPT.read_text().replace("/root/.config/opencode", str(tmp_path / "cfg")) \
                               .replace("/root/.local/share/opencode", str(tmp_path / "share"))
    s = tmp_path / "apply-settings.sh"
    s.write_text(script)

    def run(**env):
        full = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "DARKMOON_MCP_TRANSPORT": "stdio", **env}
        p = subprocess.run(["bash", str(s)], env=full, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stdout + p.stderr
        raw = (tmp_path / "cfg" / "opencode.json").read_text()
        cfg = json.loads(raw)
        if "azure" in cfg.get("provider", {}):
            assert KEY not in raw                 # Azure mode: the key is referenced through {env:...}, never written
        return cfg, p.stdout + p.stderr

    yield run
    shutil.rmtree(tmp_path / "cfg", ignore_errors=True)


def local(url, model="gpt-5-mini", **extra):
    return {"OPENCODE_LOCAL_MODE": "true", "OPENCODE_LOCAL_PROVIDER_ID": "local",
            "OPENCODE_LOCAL_PROVIDER_NAME": "Local model", "OPENCODE_LOCAL_BASE_URL": url,
            "OPENCODE_LOCAL_MODEL": model, "OPENCODE_LOCAL_API_KEY": KEY, **extra}


def assert_azure(cfg, resource, model, key_env):
    assert set(cfg["provider"]) == {"azure"}
    prov = cfg["provider"]["azure"]
    assert "npm" not in prov                      # opencode's built-in provider, nothing to resolve
    assert prov["options"] == {"resourceName": resource, "apiKey": "{env:%s}" % key_env}
    assert list(prov["models"]) == [model]
    assert cfg["model"] == cfg["small_model"] == f"azure/{model}"
    for name, agent in cfg["agent"].items():
        if "model" in agent:
            assert agent["model"] == f"azure/{model}", name


def test_explicit_azure_mode(run_settings):
    cfg, out = run_settings(AZURE_RESOURCE_NAME="my-foundry", AZURE_API_KEY=KEY, AZURE_MODEL="gpt-5-mini")
    assert_azure(cfg, "my-foundry", "gpt-5-mini", "AZURE_API_KEY")
    assert "options" not in cfg["provider"]["azure"]["models"]["gpt-5-mini"]   # Responses API by default
    assert "native" in out


def test_completion_urls_option(run_settings):
    cfg, out = run_settings(AZURE_RESOURCE_NAME="my-foundry", AZURE_API_KEY=KEY, AZURE_MODEL="Kimi-K3.1-Pro",
                            AZURE_USE_COMPLETION_URLS="true")
    assert cfg["provider"]["azure"]["models"]["Kimi-K3.1-Pro"]["options"] == {"useCompletionUrls": True}
    assert "chat/completions" in out


@pytest.mark.parametrize("url", ["https://my-foundry.openai.azure.com/openai/v1",
                                 "https://my-foundry.services.ai.azure.com/openai/v1",
                                 "https://MY-FOUNDRY.cognitiveservices.azure.com/openai/v1/",
                                 "https://my-foundry.services.ai.azure.com/api/projects/p1"])
def test_local_azure_url_becomes_native_azure(run_settings, url):
    """An existing .opencode.env (custom URL on Azure) works after an update, with no edit."""
    cfg, out = run_settings(**local(url))
    assert_azure(cfg, "my-foundry", "gpt-5-mini", "OPENCODE_LOCAL_API_KEY")
    assert "Azure resource endpoint" in out


def test_explicit_key_wins_in_the_local_switch(run_settings):
    cfg, _ = run_settings(**local("https://my-foundry.openai.azure.com/openai/v1"), AZURE_API_KEY=KEY)
    assert cfg["provider"]["azure"]["options"]["apiKey"] == "{env:AZURE_API_KEY}"


def test_opt_out_keeps_the_generic_adapter(run_settings):
    cfg, _ = run_settings(**local("https://my-foundry.openai.azure.com/openai/v1"), OPENCODE_LOCAL_AZURE_NATIVE="false")
    assert cfg["provider"]["local"]["npm"] == "@ai-sdk/openai-compatible"
    assert cfg["model"] == "local/gpt-5-mini"


@pytest.mark.parametrize("url", ["https://my-foundry.openai.azure.com.attacker.example/v1",
                                 "https://openai.azure.com/v1", "http://127.0.0.1:11434/v1",
                                 "https://llm.example.com/v1", "https://x.azure-api.net/openai/v1"])
def test_other_urls_stay_local(run_settings, url):
    cfg, _ = run_settings(**local(url))
    assert "local" in cfg["provider"]
    assert cfg["model"] == "local/gpt-5-mini"


def test_explicit_azure_wins_over_local(run_settings):
    cfg, _ = run_settings(**local("http://10.0.0.5:8080/v1", model="qwen"),
                          AZURE_RESOURCE_NAME="my-foundry", AZURE_API_KEY=KEY, AZURE_MODEL="gpt-5-mini")
    assert_azure(cfg, "my-foundry", "gpt-5-mini", "AZURE_API_KEY")


@pytest.mark.parametrize("env", [{"AZURE_RESOURCE_NAME": 'my"x', "AZURE_MODEL": "gpt-5-mini"},
                                 {"AZURE_RESOURCE_NAME": "my-foundry", "AZURE_MODEL": 'm","x":"y'},
                                 {"AZURE_RESOURCE_NAME": "my foundry", "AZURE_MODEL": "gpt-5-mini"}])
def test_unsafe_names_are_refused(run_settings, env):
    cfg, out = run_settings(AZURE_API_KEY=KEY, **env)
    assert "azure" not in cfg.get("provider", {})
    assert "must be plain names" in out


def test_azure_model_with_dots_is_accepted(run_settings):
    cfg, _ = run_settings(AZURE_RESOURCE_NAME="my-foundry", AZURE_API_KEY=KEY, AZURE_MODEL="DeepSeek-V4.1-Flash")
    assert cfg["model"] == "azure/DeepSeek-V4.1-Flash"
