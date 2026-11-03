import os
import re
import time
import socket
import docker
import sys
from typing import Optional, List, Dict, Any
from docker.models.containers import Container
from docker.errors import DockerException, NotFound

from src.models.common import ExecutionResult, ExecutionStatus
from src.execution_guard import adapt_command, classify, effective_timeout, remediation
from src.rate_limiter import enforce_rate_limits
from src.scope_policy import is_prohibited_tool, resolve_policy

STREAM_BASE = "/tmp/darkmoon_mcp_stream"

# Long-running scanners that routinely outlive the `timeout` wrapper: coreutils
# signals its direct child (bash), and a grandchild started through a pipe can be
# reparented and keep hammering the target long after the campaign moved on. Two
# of these were still running 72 minutes after their campaign had frozen.
_REAPABLE = (
    "hydra", "medusa", "ncrack", "patator", "sqlmap", "ffuf", "dirb",
    "gobuster", "feroxbuster", "wfuzz", "naabu", "masscan", "nuclei",
)


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
        # Scope-driven rate policy per MCP session (2026-11-03, PornBox
        # directive). Keyed by session_id; a session without an entry runs the
        # engine default. Written by dashboard_init_campaign / a dedicated
        # setter, read by execute_command.
        self._session_policy: Dict[str, Dict[str, Any]] = {}
        try:
            self.client = docker.from_env()
        except DockerException as e:
            raise RuntimeError(f"Failed to connect to Docker: {e}")

        # Ensure stream socket exists (server created by darkmoon-cli)
        # Client will just connect if available.
        self._stream_enabled = True
        self._gpu_cache = None

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

    def set_session_policy(self, session_id: str, policy: Dict[str, Any]) -> None:
        """Register the scope-driven rate policy for one MCP session.

        Called by dashboard_init_campaign (and any future scope tool) when the
        programme states its rate/automation rule. Until a policy is set, the
        session runs the engine default.
        """
        if policy:
            self._session_policy[session_id or ""] = policy

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
            # Prepare command.
            #
            # Every command is wrapped in coreutils `timeout` INSIDE the container.
            # The `timeout` argument used to be recorded in metadata and never
            # enforced: the stream loop below blocks until the process exits, so a
            # command that never ends (an unbounded `hydra -P rockyou.txt`, a `cat`
            # on a socket that never sends EOF) froze the whole campaign — no more
            # findings, no finalize, no report. Enforcing the deadline in the
            # container means the process is killed even if the client goes away.
            hard_timeout = effective_timeout(timeout)

            # Route heavy offline cracking to the right component instead of
            # refusing it. hashcat gets pinned to the GPU when the entrypoint found
            # a usable one, and always gets `--runtime`, so a full dictionary run
            # returns what it found inside the budget rather than holding the
            # campaign for hours. Measured on an RTX 5060: 7.57 MH/s on GPU against
            # 33.5 kH/s on CPU threads for md5crypt, a factor of 225.
            # Scope-driven rate policy (2026-11-03, PornBox directive): the
            # rate budget is a property of the TARGET PROGRAMME, not a global
            # constant — ALSCO allowed 5 req/s, PornBox forbids automated tools
            # outright. The policy is resolved per session (set via
            # dashboard_init_campaign's rate_policy argument) and enforced here
            # where no prompt text can argue with it.
            # Fallback chain: session policy > campaign scope file (written by
            # the Web UI launch into the shared darkmoon-settings store) >
            # env override > engine default.
            policy = resolve_policy(self._session_policy.get(session_id or ""))

            if isinstance(command, str):
                adapted, note = adapt_command(command, self._gpu_state(container))
                if note:
                    command = adapted
                    self._broadcast(f"\n\033[1;33m[guard]\033[0m {note}\n".encode(), session_id)

                # Programmes that forbid automated tools: refuse their scanners
                # pre-flight, the same way execution_guard refuses unbounded ones.
                forbidden = is_prohibited_tool(command, policy)
                if forbidden:
                    self._broadcast(
                        f"\n\033[1;33m[scope-policy]\033[0m {forbidden} is refused: this programme "
                        "prohibits automated tools / significant traffic — test manually, one request at a time\n".encode(),
                        session_id,
                    )
                    return ExecutionResult(
                        status=ExecutionStatus.CANCELLED,
                        stdout="",
                        stderr=(
                            f"[scope-policy] {forbidden} is refused under this programme's rate policy "
                            f"(mode={policy.get('mode')}, source={policy.get('source')}). The programme prohibits "
                            "automated tools or significant traffic. Test manually, one request at a time "
                            "(browser or curl with realistic headers), and derive findings from observed responses."
                        ),
                        exit_code=126,
                        timeout=0,
                    )

                # Mechanical rate limiting (2026-11-03, ALSCO audit): the engine
                # floors the rate of every network tool the agent or a workflow
                # launches, because prompt text could not stop `naabu -rate 500`
                # from getting the source IP banned. Applied here so neither a
                # free-form command nor a composed workflow script can bypass it.
                limited = enforce_rate_limits(command, policy)
                if limited != command:
                    command = limited
                    self._broadcast(
                        f"\n\033[1;36m[rate-limit]\033[0m engine capped network tool rate flags (scope={policy.get('mode')}, {policy.get('rps')}/s): {command}\n".encode(),
                        session_id,
                    )

            if isinstance(command, list):
                cmd = ["timeout", "--kill-after=5", str(hard_timeout)] + command
                cmd_str = " ".join(command)
            else:
                cmd = ["timeout", "--kill-after=5", str(hard_timeout), "bash", "-c", command]
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

            # coreutils `timeout` reports 124 on expiry (137 when it had to SIGKILL).
            # Hand the agent an actionable explanation instead of silence: a bare
            # "timed out" makes a model retry the identical command, which is how a
            # campaign burns an hour on the same dead end.
            if exit_code in (124, 137):
                self._reap_survivors(container, cmd_str)
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    stdout=stdout_acc,
                    stderr=remediation(cmd_str, duration, hard_timeout),
                    exit_code=exit_code,
                    duration=duration,
                    metadata={
                        "command": cmd_str,
                        "workdir": workdir,
                        "timeout": hard_timeout,
                        "timed_out": True,
                        "guard": classify(cmd_str).label or "unclassified",
                    },
                )

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
                    "timeout": hard_timeout,
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

    def _gpu_state(self, container) -> Dict[str, str]:
        """Read the GPU profile the toolbox entrypoint wrote at container start.

        The file lives INSIDE the toolbox, not next to the MCP: reading it from the
        local filesystem silently returned "no GPU" on every host and hashcat was
        never pinned to the card. Cached for the process lifetime, since hardware
        does not change under a running container.
        """
        if getattr(self, "_gpu_cache", None) is not None:
            return self._gpu_cache

        state = {"DM_GPU": "0", "DM_GPU_VENDOR": "unknown", "DM_HASHCAT_OPTS": ""}
        try:
            exec_id = self.client.api.exec_create(
                container=container.id,
                cmd=["bash", "-c", "cat /run/darkmoon-gpu.env 2>/dev/null || true"],
            )["Id"]
            raw = self.client.api.exec_start(exec_id).decode("utf-8", errors="ignore")
            for line in raw.splitlines():
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    state[k.strip()] = v.strip()
        except Exception:
            pass  # absent or unreadable: fall back to CPU assumptions, never crash

        self._gpu_cache = state
        return state

    def _reap_survivors(self, container, cmd_str: str) -> None:
        """Kill scanner grandchildren that outlived the `timeout` wrapper.

        `timeout` signals the bash it started; a tool launched inside a pipeline
        can survive that and keep running against the target indefinitely. Only
        binaries from a fixed allow-list are reaped, and only when the command
        that just expired actually mentions them, so this can never kill an
        unrelated process.
        """
        targets = [t for t in _REAPABLE if re.search(rf"\b{t}\b", cmd_str or "")]
        if not targets:
            return
        try:
            for tool in targets:
                self.client.api.exec_start(
                    self.client.api.exec_create(
                        container=container.id,
                        cmd=["bash", "-c", f"pkill -9 -x {tool} 2>/dev/null || true"],
                    )["Id"]
                )
        except Exception:
            pass  # best effort: never let cleanup mask the timeout itself

    def check_tool_available(self, tool_name: str) -> bool:
        result = self.execute_command(f"which {tool_name}", timeout=5)
        return result.success

    def check_tools_bulk(self, tools: List[str]) -> Dict[str, bool]:
        """Probe many tools in ONE container round-trip.

        The old health check ran one `docker exec which <tool>` per tool. At a
        dozen tools that is a dozen round-trips of container-exec overhead on
        every campaign start; over the full toolbox it would be a hundred. A
        single `command -v` loop inside one exec returns the whole map at once,
        so reporting the complete toolbox costs no more than probing four tools
        did before. A tool name is validated to a safe charset so the joined
        loop can never inject.
        """
        safe = [t for t in tools if re.fullmatch(r"[A-Za-z0-9_.+-]+", t or "")]
        if not safe:
            return {}
        names = " ".join(safe)
        script = (
            'for t in ' + names + '; do '
            'if command -v "$t" >/dev/null 2>&1; then echo "$t=1"; '
            'else echo "$t=0"; fi; done'
        )
        result = self.execute_command(["bash", "-c", script], timeout=30)
        status = {t: False for t in safe}
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if "=" in line:
                name, _, val = line.partition("=")
                if name in status:
                    status[name] = val.strip() == "1"
        return status

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