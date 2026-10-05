#!/usr/bin/env python3
"""
Workflow validator and runner helper for Darkmoon MCP Workflows.
Validates workflow class structure and inheritance as documented in WORKFLOW_GUIDE.md.
"""

import argparse
import importlib.util
import inspect
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

# Ensure UTF-8 output encoding across cross-platform environments (e.g. Windows consoles)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Mock docker module if not installed in current environment for standalone validation
try:
    import docker  # noqa: F401
except ImportError:
    mock_docker = types.ModuleType("docker")
    mock_docker.models = types.ModuleType("docker.models")
    mock_docker.models.containers = types.ModuleType("docker.models.containers")
    mock_docker.models.containers.Container = MagicMock()
    mock_docker.errors = types.ModuleType("docker.errors")
    mock_docker.errors.DockerException = Exception
    mock_docker.errors.NotFound = Exception
    mock_docker.from_env = MagicMock()
    sys.modules["docker"] = mock_docker
    sys.modules["docker.models"] = mock_docker.models
    sys.modules["docker.models.containers"] = mock_docker.models.containers
    sys.modules["docker.errors"] = mock_docker.errors


def load_workflow_module(file_path: str):
    """Dynamically load workflow module from file path."""
    resolved_path = Path(file_path).resolve()
    if not resolved_path.exists():
        print(f"❌ File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    module_name = resolved_path.stem
    spec = importlib.util.spec_from_file_location(module_name, resolved_path)
    if spec is None or spec.loader is None:
        print(f"❌ Failed to load spec for: {file_path}", file=sys.stderr)
        sys.exit(1)

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        print(f"❌ Error importing {file_path}: {e}", file=sys.stderr)
        sys.exit(1)

    return module


def validate_workflow(file_path: str, class_name: str) -> bool:
    """
    Validate that class exists in file, inherits from BaseWorkflow,
    and list available workflow methods.
    """
    # Ensure mcp root is in sys.path
    script_dir = Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    try:
        from src.tools.workflows.base import BaseWorkflow
    except ImportError as e:
        print(f"❌ Error importing BaseWorkflow: {e}", file=sys.stderr)
        return False

    module = load_workflow_module(file_path)

    if not hasattr(module, class_name):
        print(f"❌ Class '{class_name}' not found in {file_path}", file=sys.stderr)
        return False

    cls = getattr(module, class_name)
    if not inspect.isclass(cls):
        print(f"❌ '{class_name}' is not a class in {file_path}", file=sys.stderr)
        return False

    print(f"✓ Class '{class_name}' loaded")

    if not issubclass(cls, BaseWorkflow):
        print(f"❌ '{class_name}' does not inherit from BaseWorkflow", file=sys.stderr)
        return False

    print(f"✓ {class_name} inherits from BaseWorkflow")

    # Discover public methods defined in the workflow class (excluding BaseWorkflow base methods)
    base_methods = {name for name, _ in inspect.getmembers(BaseWorkflow, predicate=inspect.isfunction)}
    cls_methods = [
        name for name, func in inspect.getmembers(cls, predicate=inspect.isfunction)
        if not name.startswith("_") and name not in base_methods
    ]

    print(f"✓ Workflow methods available: {len(cls_methods)}")
    for method in cls_methods:
        print(f"  • {method}()")

    print("✅ Valid workflow file!")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Helper to validate and test Darkmoon MCP workflows."
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate workflow file structure and inheritance",
    )
    parser.add_argument(
        "file_path",
        help="Path to workflow python file (e.g. src/tools/workflows/my_workflow.py)",
    )
    parser.add_argument(
        "class_name",
        help="Workflow class name (e.g. MyWorkflow)",
    )
    parser.add_argument(
        "method_name",
        nargs="?",
        help="Workflow method to execute",
    )
    parser.add_argument("--target", help="Target host/IP for workflow scan")
    parser.add_argument("--timeout", type=int, default=1200, help="Timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Simulate execution without actual commands")

    args, unknown = parser.parse_known_args()

    if args.validate:
        valid = validate_workflow(args.file_path, args.class_name)
        sys.exit(0 if valid else 1)
    else:
        valid = validate_workflow(args.file_path, args.class_name)
        if not valid:
            sys.exit(1)
        if args.method_name:
            print(f"\nExecution requested for method: {args.method_name}")
            print("Note: Live Docker container execution requires Darkmoon Docker container environment.")
        sys.exit(0)


if __name__ == "__main__":
    main()
