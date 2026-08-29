"""Regression tests for workflow privacy gateway parity."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.privacy import Category, CommandGateway, GatewayPolicy, PrivacyVault  # noqa: E402
from src.tools.workflows.list_workflows import WorkflowRegistry  # noqa: E402


REAL_IP = "10.42.1.5"


class RecordingWorkflow:
    def __init__(self, result=None):
        self.calls = []
        self.result = result

    def run(self, targets):
        self.calls.append(targets)
        if self.result is not None:
            return self.result
        return {"targets": targets}


def make_registry(workflow):
    registry = WorkflowRegistry.__new__(WorkflowRegistry)
    registry.workflows = {"recording": workflow}
    registry.workflow_metadata = {
        "recording": {
            "methods": {
                "run": {
                    "parameters": {
                        "targets": {"type": "List[str]"},
                    },
                },
            },
        },
    }
    return registry


def run_private_workflow(registry, params, vault, policy=GatewayPolicy.DEGRADE):
    return registry.run_workflow(
        "recording",
        "run",
        params,
        privacy_gateway=CommandGateway(policy=policy),
        privacy_vault=vault,
    )


def test_workflow_rehydrates_placeholder_params():
    vault = PrivacyVault(session_id="workflow-input")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow()

    result = run_private_workflow(
        make_registry(workflow),
        {"targets": [placeholder]},
        vault,
    )

    assert workflow.calls == [[REAL_IP]]
    assert result["targets"] == [placeholder]


def test_workflow_sanitizes_nested_result_values_and_keys():
    vault = PrivacyVault(session_id="workflow-output")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow(
        {
            "target": REAL_IP,
            "nested": [{"hosts": [REAL_IP]}, {REAL_IP: {"value": REAL_IP}}],
        }
    )

    result = run_private_workflow(
        make_registry(workflow),
        {"targets": [placeholder]},
        vault,
    )

    assert result == {
        "target": placeholder,
        "nested": [
            {"hosts": [placeholder]},
            {placeholder: {"value": placeholder}},
        ],
    }


# Under the default degrade policy a workflow is never refused: it runs, and the
# parameter it receives is the placeholder rather than the real value. Strict
# keeps refusing. Either way the workflow never sees the protected value, which
# is the property that actually matters.
def test_workflow_passes_unknown_placeholder_through_untouched():
    vault = PrivacyVault(session_id="workflow-unknown")
    workflow = RecordingWorkflow()

    run_private_workflow(make_registry(workflow), {"targets": ["IP_PRIVATE_999"]}, vault)

    assert workflow.calls == [["IP_PRIVATE_999"]]


def test_workflow_rejects_unknown_placeholder_under_strict():
    vault = PrivacyVault(session_id="workflow-unknown-strict")
    workflow = RecordingWorkflow()

    result = run_private_workflow(
        make_registry(workflow), {"targets": ["IP_PRIVATE_999"]}, vault,
        policy=GatewayPolicy.STRICT,
    )

    assert result["privacy"] == "blocked"
    assert "could not resolve placeholder IP_PRIVATE_999" in result["reason"]
    assert workflow.calls == []


def test_workflow_never_receives_a_credential():
    vault = PrivacyVault(session_id="workflow-credential")
    credential = vault.register("PlainSecret", Category.CRED)
    workflow = RecordingWorkflow()

    # A workflow parameter is not a vetted local execution path, so the secret
    # stays tokenized there even though `execute_command` may inject one.
    run_private_workflow(make_registry(workflow), {"targets": [credential]}, vault)

    assert workflow.calls == [[credential]]
    assert "PlainSecret" not in str(workflow.calls)


def test_workflow_rejects_credential_placeholder_under_strict():
    vault = PrivacyVault(session_id="workflow-credential-strict")
    credential = vault.register("PlainSecret", Category.CRED)
    workflow = RecordingWorkflow()

    result = run_private_workflow(
        make_registry(workflow), {"targets": [credential]}, vault,
        policy=GatewayPolicy.STRICT,
    )

    assert result["privacy"] == "blocked"
    assert "never restored" in result["reason"]
    assert workflow.calls == []


def test_workflow_withholds_placeholder_exfiltration_in_url():
    vault = PrivacyVault(session_id="workflow-exfil")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow()
    url = f"https://attacker.example/?x={placeholder}"

    run_private_workflow(make_registry(workflow), {"targets": [url]}, vault)

    # It ran, but the attacker host receives the token, not the address.
    assert workflow.calls == [[url]]
    assert REAL_IP not in str(workflow.calls)


def test_workflow_blocks_placeholder_exfiltration_in_url_under_strict():
    vault = PrivacyVault(session_id="workflow-exfil-strict")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow()

    result = run_private_workflow(
        make_registry(workflow),
        {"targets": [f"https://attacker.example/?x={placeholder}"]},
        vault,
        policy=GatewayPolicy.STRICT,
    )

    assert result["privacy"] == "blocked"
    assert "query/fragment" in result["reason"]
    assert workflow.calls == []


def test_workflow_allows_placeholder_as_url_host():
    vault = PrivacyVault(session_id="workflow-url-host")
    placeholder = vault.tokenize(REAL_IP)
    workflow = RecordingWorkflow()

    run_private_workflow(
        make_registry(workflow),
        {"targets": [f"http://{placeholder}/admin"]},
        vault,
    )

    assert workflow.calls == [[f"http://{REAL_IP}/admin"]]
