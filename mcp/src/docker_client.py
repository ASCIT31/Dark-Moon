import os
import time
import socket
import docker
import sys
from typing import Optional, List, Dict, Any
from docker.models.containers import Container
from docker.errors import DockerException, NotFound

from src.models.common import ExecutionResult, ExecutionStatus

STREAM_BASE = "/tmp/darkmoon_mcp_stream"


class DarkmoonDockerClient:
    """
    Docker client to interact with the Darkmoon security toolbox container.
    Handles command execution, health checks, and resource management.

    + Live stream broadcast to UNIX socket for monitoring console.
    """

    def __init__(
        self,
        container_name: str = "darkmoon",
        timeout: int = 300,
    ):
        self.container_name = container_name
        self.default_timeout = timeout
        try:
            self.client = docker.from_env()
        except DockerException as e:
            raise RuntimeError(f"Failed to connect to Docker: {e}")

        # Ensure stream socket exists (server created by darkmoon-cli)
        # Client will just connect if available.
        self._stream_enabled = True

    def _broadcast(self, b: bytes, session_id: str | None = None):
        if not self._stream_enabled:
            return

        sock_path = f"{STREAM_BASE}_{session_id}.sock" if session_id else f"{STREAM_BASE}.sock"

        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect(sock_path)
            s.sendall(b)
            s.close()
        except Exception:
            pass

    def get_container(self) -> Optional[Container]:
        """Get the Darkmoon container if it exists and is running."""
        try:
            container = self.client.containers.get(self.container_name)
            container.reload()
            return container if container.status == "running" else None
        except NotFound:
            return None
        except DockerException as e:
            raise RuntimeError(f"Error accessing container: {e}")

    def execute_command(
        self,
        command: str | List[str],
        timeout: Optional[int] = None,
        workdir: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        session_id: Optional[str] = None,   # NEW
    ) -> ExecutionResult:
        """
        Execute a command inside the Darkmoon container.
        Streams stdout/stderr live to monitoring console via UNIX socket.
        """
        container = self.get_container()
        if not container:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                stderr=f"Container '{self.container_name}' not found or not running",
                exit_code=1,
            )

        timeout = timeout or self.default_timeout
        start_time = time.time()

        try:
            # Prepare command
            if isinstance(command, list):
                cmd = command
                cmd_str = " ".join(command)
            else:
                cmd = ["bash", "-c", command]
                cmd_str = command

            # OPTIONAL: ignore health checks in the live stream (no spam)
            is_noise = cmd_str.startswith("which ") or cmd_str.startswith("df -h ")

            # Inject cyan prompt with timestamp before streaming
            if not is_noise:
                ts = time.strftime("%H:%M:%S")
                prefix = f"\n\033[1;32m[{ts}] darkmoon>\033[0m {cmd_str}\n\n"
                self._broadcast(prefix.encode(), session_id)

            # Use docker low-level exec API for correct streaming + exit code
            exec_id = self.client.api.exec_create(
                container=container.id,
                cmd=cmd,
                workdir=workdir,
                environment=environment,
                tty=True,   # important: reduce buffering, keep ANSI
            )["Id"]

            stream = self.client.api.exec_start(
                exec_id,
                stream=True,
                tty=True,
            )

            stdout_acc = ""

            for chunk in stream:
                if not chunk:
                    continue
                # chunk is bytes
                stdout_acc += chunk.decode("utf-8", errors="ignore")

                # broadcast raw bytes (keeps ANSI + CRLF exactly)
                if not is_noise:
                    self._broadcast(chunk, session_id)

            duration = time.time() - start_time

            inspect = self.client.api.exec_inspect(exec_id)
            exit_code = inspect.get("ExitCode", 1)

            status = (
                ExecutionStatus.SUCCESS
                if exit_code == 0
                else ExecutionStatus.FAILED
            )

            return ExecutionResult(
                status=status,
                stdout=stdout_acc,
                stderr="",
                exit_code=exit_code,
                duration=duration,
                metadata={
                    "command": cmd_str,
                    "workdir": workdir,
                    "timeout": timeout,
                },
            )

        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                stderr=f"Execution error: {str(e)}",
                exit_code=1,
                duration=duration,
                metadata={"command": str(command), "error": str(e)},
            )

    def check_tool_available(self, tool_name: str) -> bool:
        result = self.execute_command(f"which {tool_name}", timeout=5)
        return result.success

    def get_disk_usage(self) -> Optional[Dict[str, Any]]:
        """Get disk usage information from the container."""
        result = self.execute_command("df -h /opt/darkmoon/out", timeout=5)
        if result.success:
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                return {
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4],
                    "mounted_on": parts[5] if len(parts) > 5 else "-",
                }
        return None

    def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check."""
        container = self.get_container()
        if not container:
            return {
                "healthy": False,
                "container_running": False,
                "message": f"Container '{self.container_name}' not found or not running",
            }

        tools_to_check = ["naabu", "nuclei", "httpx", "subfinder"]
        tools_status = {}
        for tool in tools_to_check:
            tools_status[tool] = self.check_tool_available(tool)

        disk_usage = self.get_disk_usage()
        all_tools_available = all(tools_status.values())

        return {
            "healthy": all_tools_available,
            "container_running": True,
            "tools_available": tools_status,
            "disk_usage": disk_usage,
            "message": "All systems operational"
            if all_tools_available
            else "Some tools are not available",
        }

    def cleanup(self):
        """Clean up Docker client resources."""
        if hasattr(self, "client"):
            self.client.close()