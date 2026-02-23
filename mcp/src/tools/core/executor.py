import shlex
from typing import Optional, Dict, List
from src.docker_client import DarkmoonDockerClient
from src.models.common import ToolOutput, ExecutionResult


class GenericExecutor:
    """
    Generic command executor for running any tool in the Darkmoon toolbox.
    Provides validation, sanitization, and safe execution of arbitrary commands.
    """

    def __init__(self, docker_client: DarkmoonDockerClient):
        self.docker_client = docker_client

        # Whitelist of allowed tools (for security)
        self.allowed_tools = {
            # Port scanners
            "naabu",
            "masscan",
            # Web tools
            "httpx",
            "nuclei",
            "ffuf",
            "dirb",
            "wafw00f",
            "sqlmap",
            "arjun",
            "finalrecon",
            "lightpanda",
            "bash",
            "cat",
            "chmod",
            "node",
            "npm",
            "npx",
            "vulnx",
            # Recon
            "subfinder",
            "waybackurls",
            "katana",
            # DNS
            "dig",
            "nslookup",
            # Network
            "curl",
            "wget",
            "ping",
            # AD/Windows
            "netexec",
            "crackmapexec",
            "bloodhound-python",
            "impacket-smbclient",
            "hashcat",
            # Kubernetes
            "kubectl",
            "kubeletctl",
            "kubescape",
            # Misc
            "jq",
            "grep",
            "awk",
            "sed",
        }

        # Dangerous commands to block
        self.blocked_patterns = [
            "rm -rf",
            "dd if=",
            "mkfs",
            ":(){ :|:& };:",  # Fork bomb
            "> /dev/sda",
            "wget http",  # Prevent exfiltration without explicit approval
        ]

    def validate_command(self, command: str) -> tuple[bool, Optional[str]]:
        """
        Validate a command for safety.

        Args:
            command: Command to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for blocked patterns
        for pattern in self.blocked_patterns:
            if pattern in command:
                return False, f"Blocked pattern detected: {pattern}"

        # Extract first word (tool name)
        try:
            parts = shlex.split(command)
            if not parts:
                return False, "Empty command"

            tool_name = parts[0].split("/")[-1]  # Handle paths

            # Check if tool is allowed
            if tool_name not in self.allowed_tools:
                return (
                    False,
                    f"Tool '{tool_name}' not in allowed list. Allowed tools: {', '.join(sorted(self.allowed_tools))}",
                )

        except ValueError as e:
            return False, f"Command parsing error: {e}"

        return True, None

    def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        workdir: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        skip_validation: bool = False,
    ) -> ToolOutput:
        """
        Execute a generic command in the toolbox.

        Args:
            command: Command to execute
            timeout: Timeout in seconds
            workdir: Working directory
            environment: Environment variables
            skip_validation: Skip command validation (use with caution!)

        Returns:
            ToolOutput with execution results
        """
        # Validate command (unless explicitly skipped)
        if not skip_validation:
            is_valid, error_msg = self.validate_command(command)
            if not is_valid:
                return ToolOutput(
                    tool_name="generic_executor",
                    raw_output="",
                    parsed_data={"error": error_msg},
                    execution_result=ExecutionResult(
                        status="failed",
                        stderr=error_msg or "",
                        exit_code=1,
                    ),
                )

        # Execute command
        result = self.docker_client.execute_command(
            command=command,
            timeout=timeout or 300,
            workdir=workdir,
            environment=environment,
        )

        # Extract tool name from command
        try:
            tool_name = shlex.split(command)[0].split("/")[-1]
        except:
            tool_name = "unknown"

        return ToolOutput(
            tool_name=tool_name,
            raw_output=result.stdout,
            parsed_data={"command": command, "exit_code": result.exit_code},
            execution_result=result,
        )

    def execute_script(
        self,
        script_content: str,
        script_name: str = "script.sh",
        timeout: Optional[int] = None,
    ) -> ToolOutput:
        """
        Execute a bash script in the toolbox.

        Args:
            script_content: Content of the script
            script_name: Name for the script file
            timeout: Timeout in seconds

        Returns:
            ToolOutput with execution results
        """
        # Write script to temp file
        script_path = f"/tmp/{script_name}"
        write_cmd = f"cat > {script_path} << 'EOF'\n{script_content}\nEOF"
        write_result = self.docker_client.execute_command(write_cmd, timeout=30)

        if not write_result.success:
            return ToolOutput(
                tool_name="script_executor",
                raw_output="",
                parsed_data={"error": "Failed to write script"},
                execution_result=write_result,
            )

        # Make executable
        chmod_cmd = f"chmod +x {script_path}"
        self.docker_client.execute_command(chmod_cmd, timeout=10)

        # Execute script
        exec_cmd = f"bash {script_path}"
        result = self.docker_client.execute_command(exec_cmd, timeout=timeout or 600)

        return ToolOutput(
            tool_name="script_executor",
            raw_output=result.stdout,
            parsed_data={"script_name": script_name, "script_path": script_path},
            execution_result=result,
        )

    def add_allowed_tool(self, tool_name: str):
        """Add a tool to the allowed list."""
        self.allowed_tools.add(tool_name)

    def remove_allowed_tool(self, tool_name: str):
        """Remove a tool from the allowed list."""
        self.allowed_tools.discard(tool_name)

    def list_allowed_tools(self) -> List[str]:
        """Get list of allowed tools."""
        return sorted(self.allowed_tools)
