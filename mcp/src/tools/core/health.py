from typing import Dict, Any, List
from src.docker_client import DarkmoonDockerClient
from src.models.common import HealthStatus

# Shell built-ins and generic utilities that are allow-listed for command
# composition but are not "security tools" worth surfacing to the model.
_NON_TOOLS = {
    "bash", "cat", "chmod", "grep", "awk", "sed", "jq", "echo", "printf",
    "node", "npm", "npx", "zip", "unzip", "pip", "python",
}


class HealthChecker:
    """
    Comprehensive health check system for Darkmoon toolbox.
    Monitors container status, tool availability, and resource usage.
    """

    def __init__(self, docker_client: DarkmoonDockerClient):
        self.docker_client = docker_client

        # Essential tools that must be present for the toolbox to be "healthy".
        # This gates the healthy/unhealthy verdict only, NOT what the model sees.
        self.essential_tools = [
            "naabu",
            "nuclei",
            "httpx",
            "subfinder",
        ]

    def _reportable_tools(self) -> List[str]:
        """The full security toolbox, taken from the executor allow-list.

        tools_available used to be a hard-coded list of 13 names. The model reads
        that map and concludes those are the only tools it has, so it never
        reaches for snmpwalk, dig, showmount, redis-cli, psql, the cloud CLIs,
        binwalk and the rest — even though execute_command can run all ~130. The
        health check must therefore advertise the WHOLE toolbox, derived from the
        one source of truth (the executor allow-list), so it can never drift from
        what actually runs.
        """
        try:
            from src.tools.core.executor import GenericExecutor
            allowed = GenericExecutor(self.docker_client).list_allowed_tools()
        except Exception:
            allowed = list(self.essential_tools)
        tools = sorted(t for t in allowed if t not in _NON_TOOLS)
        for t in self.essential_tools:
            if t not in tools:
                tools.append(t)
        return tools

    def check(self) -> HealthStatus:
        """
        Perform comprehensive health check.

        Returns:
            HealthStatus with detailed health information
        """
        # Get basic health from Docker client
        health_info = self.docker_client.health_check()

        # Check if container is running
        if not health_info["container_running"]:
            return HealthStatus(
                healthy=False,
                container_running=False,
                message=health_info["message"],
            )

        # Probe the WHOLE toolbox in a single container round-trip, so the model
        # sees every tool it actually has instead of a hard-coded subset.
        all_tools_status = self.docker_client.check_tools_bulk(self._reportable_tools())

        # The healthy/unhealthy verdict rests only on the essential tools.
        essential_status = {t: all_tools_status.get(t, False) for t in self.essential_tools}
        essential_healthy = all(essential_status.values())
        disk_usage = health_info.get("disk_usage")

        # Check disk space warning
        disk_warning = False
        if disk_usage and "use_percent" in disk_usage:
            use_percent = int(disk_usage["use_percent"].rstrip("%"))
            disk_warning = use_percent > 80

        # Overall health determination
        healthy = essential_healthy and not disk_warning

        # Build message
        if not essential_healthy:
            missing_tools = [tool for tool, status in essential_status.items() if not status]
            message = f"Essential tools missing: {', '.join(missing_tools)}"
        elif disk_warning:
            message = f"Disk usage warning: {disk_usage['use_percent']} used"
        else:
            message = "All systems operational"

        return HealthStatus(
            healthy=healthy,
            container_running=True,
            tools_available=all_tools_status,
            disk_usage=disk_usage,
            message=message,
        )

    def check_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Check if a specific tool is available and get its version.

        Args:
            tool_name: Name of the tool to check

        Returns:
            Dictionary with tool status and version info
        """
        available = self.docker_client.check_tool_available(tool_name)

        version_info = None
        if available:
            # Try to get version
            version_cmd = f"{tool_name} --version 2>&1 || {tool_name} -version 2>&1 || {tool_name} version 2>&1"
            result = self.docker_client.execute_command(version_cmd, timeout=10)
            if result.success:
                version_info = result.stdout.strip().split("\n")[0]

        return {
            "tool_name": tool_name,
            "available": available,
            "version": version_info,
        }

    def check_network_connectivity(self) -> Dict[str, Any]:
        """
        Check network connectivity from the container.

        Returns:
            Dictionary with connectivity status
        """
        results = {}

        # Check DNS resolution
        dns_result = self.docker_client.execute_command("dig google.com +short", timeout=10)
        results["dns"] = {
            "working": dns_result.success and bool(dns_result.stdout.strip()),
            "output": dns_result.stdout.strip(),
        }

        # Check internet connectivity
        ping_result = self.docker_client.execute_command("ping -c 1 8.8.8.8", timeout=10)
        results["internet"] = {
            "working": ping_result.success and "1 received" in ping_result.stdout,
            "output": ping_result.stdout.strip(),
        }

        # Check HTTPS connectivity
        curl_result = self.docker_client.execute_command(
            "curl -s -o /dev/null -w '%{http_code}' https://google.com", timeout=10
        )
        results["https"] = {
            "working": curl_result.success and curl_result.stdout.strip() in ["200", "301"],
            "status_code": curl_result.stdout.strip(),
        }

        return results

    def get_resource_usage(self) -> Dict[str, Any]:
        """
        Get detailed resource usage information.

        Returns:
            Dictionary with resource usage stats
        """
        resources = {}

        # Get disk usage
        disk_result = self.docker_client.execute_command("df -h", timeout=10)
        if disk_result.success:
            resources["disk"] = disk_result.stdout

        # Get memory usage
        mem_result = self.docker_client.execute_command("free -h", timeout=10)
        if mem_result.success:
            resources["memory"] = mem_result.stdout

        # Get running processes count
        ps_result = self.docker_client.execute_command("ps aux | wc -l", timeout=10)
        if ps_result.success:
            resources["process_count"] = int(ps_result.stdout.strip())

        return resources

    def diagnose(self) -> Dict[str, Any]:
        """
        Run comprehensive diagnostics.

        Returns:
            Dictionary with full diagnostic information
        """
        return {
            "health": self.check().model_dump(),
            "network": self.check_network_connectivity(),
            "resources": self.get_resource_usage(),
            "essential_tools": {
                tool: self.check_tool(tool) for tool in self.essential_tools
            },
        }
