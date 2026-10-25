import subprocess
import sys
from pathlib import Path


def test_workflow_validator_on_template():
    """Verify that test_workflow.py correctly validates TEMPLATE.py structure and inheritance."""
    mcp_dir = Path(__file__).resolve().parent.parent
    script_path = mcp_dir / "test_workflow.py"
    template_path = mcp_dir / "src" / "tools" / "workflows" / "TEMPLATE.py"

    assert script_path.exists(), "test_workflow.py must exist in mcp directory"
    assert template_path.exists(), "TEMPLATE.py must exist in workflows directory"

    result = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--validate",
            str(template_path),
            "MyWorkflow",
        ],
        cwd=str(mcp_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode == 0, f"Validator failed with: {result.stderr}"
    assert "✓ Class 'MyWorkflow' loaded" in result.stdout
    assert "✓ MyWorkflow inherits from BaseWorkflow" in result.stdout
    assert "• my_scan()" in result.stdout
    assert "✅ Valid workflow file!" in result.stdout


def test_workflow_validator_fails_on_nonexistent_class():
    """Verify that test_workflow.py exits with non-zero code on invalid class."""
    mcp_dir = Path(__file__).resolve().parent.parent
    script_path = mcp_dir / "test_workflow.py"
    template_path = mcp_dir / "src" / "tools" / "workflows" / "TEMPLATE.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--validate",
            str(template_path),
            "NonExistentWorkflow",
        ],
        cwd=str(mcp_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode != 0
