"""
Workflow Registry - Dynamic workflow discovery and execution.

Allows the LLM to discover and execute workflows dynamically without
requiring manual registration in server.py.
"""

import importlib
import inspect
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, get_type_hints

from src.docker_client import DarkmoonDockerClient
from src.privacy import CommandGateway, PrivacyVault
from src.tools.workflows.base import BaseWorkflow


# Configure logging for workflow registry
logger = logging.getLogger(__name__)

# Files to exclude from workflow discovery
EXCLUDED_FILES = {"__init__.py", "base.py", "TEMPLATE.py", "list_workflows.py"}

# Store import errors for reporting to MCP clients
_import_errors: List[Dict[str, str]] = []


class WorkflowRegistry:
    """
    Dynamic registry for workflow discovery and execution.

    Automatically discovers all workflows in the workflows/ directory
    that inherit from BaseWorkflow.
    """

    def __init__(self, docker_client: DarkmoonDockerClient):
        self.docker_client = docker_client
        self.workflows: Dict[str, BaseWorkflow] = {}
        self.workflow_metadata: Dict[str, Dict[str, Any]] = {}
        self._discover_workflows()

    def _discover_workflows(self) -> None:
        """
        Discover all workflows in the workflows/ directory.

        Scans for .py files, imports them, and registers classes
        that inherit from BaseWorkflow.
        """
        workflows_dir = Path(__file__).parent

        for file_path in workflows_dir.glob("*.py"):
            if file_path.name in EXCLUDED_FILES:
                continue

            module_name = file_path.stem

            try:
                # Import the module dynamically
                module = importlib.import_module(
                    f"src.tools.workflows.{module_name}"
                )

                # Find classes that inherit from BaseWorkflow
                for name, cls in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(cls, BaseWorkflow)
                        and cls is not BaseWorkflow
                        and not name.startswith("_")
                    ):
                        # Create instance with docker_client
                        instance = cls(self.docker_client)
                        workflow_key = module_name

                        self.workflows[workflow_key] = instance
                        self.workflow_metadata[workflow_key] = self._extract_metadata(
                            cls, instance, file_path.name
                        )

            except Exception as e:
                error_info = {
                    "workflow": module_name,
                    "error": str(e),
                    "file": file_path.name,
                }
                _import_errors.append(error_info)
                logger.error(f"Error loading workflow {module_name}: {e}")

    def _extract_metadata(
        self,
        cls: type,
        instance: BaseWorkflow,
        filename: str
    ) -> Dict[str, Any]:
        """
        Extract metadata from a workflow class.

        Args:
            cls: The workflow class
            instance: Instance of the workflow
            filename: Source filename

        Returns:
            Metadata dictionary with class info, methods, and parameters
        """
        methods = {}

        # Get all public methods (excluding inherited from BaseWorkflow)
        base_methods = set(dir(BaseWorkflow))

        for method_name in dir(instance):
            if method_name.startswith("_"):
                continue
            if method_name in base_methods:
                continue

            method = getattr(instance, method_name)
            if not callable(method):
                continue

            # Extract method metadata
            methods[method_name] = self._extract_method_metadata(method)

        return {
            "class": cls.__name__,
            "description": (cls.__doc__ or "").strip().split("\n")[0],
            "file": filename,
            "methods": methods,
        }

    def _extract_method_metadata(self, method) -> Dict[str, Any]:
        """
        Extract metadata from a method.

        Args:
            method: The method to analyze

        Returns:
            Method metadata with description and parameters
        """
        sig = inspect.signature(method)
        docstring = method.__doc__ or ""

        # Parse first line of docstring as description
        description = docstring.strip().split("\n")[0] if docstring else ""

        # Extract parameters
        parameters = {}
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue

            param_info = {
                "required": param.default is inspect.Parameter.empty,
            }

            # Get type annotation if available
            if param.annotation is not inspect.Parameter.empty:
                param_info["type"] = self._format_type(param.annotation)

            # Get default value if available
            if param.default is not inspect.Parameter.empty:
                param_info["default"] = param.default

            parameters[param_name] = param_info

        return {
            "description": description,
            "parameters": parameters,
        }

    def _format_type(self, annotation) -> str:
        """Format a type annotation as a string."""
        if hasattr(annotation, "__origin__"):
            # Handle generic types like List[str], Union[str, List[str]]
            origin = annotation.__origin__.__name__
            args = ", ".join(
                self._format_type(arg) for arg in annotation.__args__
            )
            return f"{origin}[{args}]"
        elif hasattr(annotation, "__name__"):
            return annotation.__name__
        else:
            return str(annotation)

    def list_workflows(self) -> Dict[str, Any]:
        """
        List all available workflows with their metadata.

        Returns:
            Dictionary containing all workflows with their descriptions,
            methods, and parameters. Also includes any import errors.
        """
        result = {
            "workflows": self.workflow_metadata,
            "count": len(self.workflows),
            "available_workflows": list(self.workflows.keys()),
        }

        # Include import errors if any
        if _import_errors:
            result["import_errors"] = _import_errors
            result["warning"] = f"{len(_import_errors)} workflow(s) failed to load"

        return result

    def _convert_param_type(
        self,
        value: Any,
        expected_type: str,
        param_name: str
    ) -> Any:
        """
        Convert a parameter value to its expected type.

        Args:
            value: The value to convert
            expected_type: String representation of expected type
            param_name: Name of the parameter (for error messages)

        Returns:
            Converted value

        Raises:
            ValueError: If conversion fails
        """
        if value is None:
            return value

        # Handle common type conversions
        type_converters = {
            "int": int,
            "float": float,
            "bool": lambda v: v if isinstance(v, bool) else str(v).lower() in ("true", "1", "yes"),
            "str": str,
        }

        # Check for simple types
        if expected_type in type_converters:
            try:
                return type_converters[expected_type](value)
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"Cannot convert parameter '{param_name}' value '{value}' to {expected_type}: {e}"
                )

        # Handle List types
        if expected_type.startswith("List[") or expected_type.startswith("list["):
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                # Try to split comma-separated values
                return [v.strip() for v in value.split(",") if v.strip()]
            return [value]

        # Handle Union types (e.g., Union[str, List[str]])
        if expected_type.startswith("Union["):
            # Just return as-is for Union types
            return value

        # Default: return as-is
        return value

    def _convert_params(
        self,
        params: Dict[str, Any],
        method_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert all parameters to their expected types.

        Args:
            params: Raw parameters from caller
            method_metadata: Method metadata with parameter info

        Returns:
            Converted parameters
        """
        if not params:
            return {}

        converted = {}
        param_specs = method_metadata.get("parameters", {})

        for param_name, value in params.items():
            if param_name in param_specs and "type" in param_specs[param_name]:
                expected_type = param_specs[param_name]["type"]
                converted[param_name] = self._convert_param_type(
                    value, expected_type, param_name
                )
            else:
                converted[param_name] = value

        return converted

    def run_workflow(
        self,
        workflow: str,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        privacy_gateway: Optional[CommandGateway] = None,
        privacy_vault: Optional[PrivacyVault] = None,
        sanitize_output: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a workflow method by name.

        Args:
            workflow: Name of the workflow (e.g., "port_scan")
            method: Name of the method to call (e.g., "scan_ports")
            params: Parameters to pass to the method
            privacy_gateway: Gateway for the workflow privacy boundary.
            privacy_vault: Session vault for local placeholder resolution.

        Returns:
            Result of the workflow execution

        Raises:
            ValueError: If workflow or method not found
        """
        def finish(result: Dict[str, Any]) -> Dict[str, Any]:
            # If sanitize_output flag is set, the result needs sanitization
            if privacy_gateway is None or privacy_vault is None or not sanitize_output:
                return result
            return privacy_gateway.sanitize_result(result, privacy_vault)

        if workflow not in self.workflows:
            available = list(self.workflows.keys())
            return finish({
                "error": f"Workflow '{workflow}' not found",
                "available_workflows": available,
            })

        instance = self.workflows[workflow]

        if not hasattr(instance, method):
            available_methods = list(
                self.workflow_metadata[workflow]["methods"].keys()
            )
            return finish({
                "error": f"Method '{method}' not found in workflow '{workflow}'",
                "available_methods": available_methods,
            })

        workflow_method = getattr(instance, method)
        method_metadata = self.workflow_metadata[workflow]["methods"].get(method, {})

        try:
            # Convert parameters to expected types
            converted_params = self._convert_params(params or {}, method_metadata)

            if privacy_gateway is not None and privacy_vault is not None:
                privacy_result = privacy_gateway.process_tool_call(
                    tool=f"{workflow}.{method}",
                    args=converted_params,
                    rehydrate_fields=tuple(converted_params),
                    vault=privacy_vault,
                    enforce_exfil_policy=sanitize_output
                )
                if privacy_result.blocked:
                    return finish({
                        "error": "Privacy gateway blocked workflow parameters",
                        "privacy": "blocked",
                        "reason": privacy_result.reason,
                    })
                converted_params = privacy_result.resolved or {}

            result = workflow_method(**converted_params)
            return finish(result)
        except ValueError as e:
            # Type conversion error
            return finish({
                "error": f"Parameter conversion error: {str(e)}",
                "expected_parameters": method_metadata.get("parameters", {}),
            })
        except TypeError as e:
            # Parameter mismatch
            return finish({
                "error": f"Parameter error: {str(e)}",
                "expected_parameters": method_metadata.get("parameters", {}),
            })
        except Exception as e:
            logger.exception(f"Workflow execution error: {workflow}.{method}")
            return finish({
                "error": f"Execution error: {str(e)}",
                "workflow": workflow,
                "method": method,
            })

    def get_workflow_info(self, workflow: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific workflow.

        Args:
            workflow: Name of the workflow

        Returns:
            Detailed workflow metadata or error
        """
        if workflow not in self.workflow_metadata:
            return {
                "error": f"Workflow '{workflow}' not found",
                "available_workflows": list(self.workflows.keys()),
            }

        return self.workflow_metadata[workflow]
