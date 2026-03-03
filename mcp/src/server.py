#!/usr/bin/env python3
"""
Darkmoon MCP Server
A Model Context Protocol server for the Darkmoon security toolbox.

Architecture:
- Health & Diagnostics (3 tools)
- Generic Executor (2 tools)
- Workflow Discovery & Execution (2 tools)
"""

import os
import uuid
from typing import Optional, Dict, Any
from fastmcp import FastMCP

from src.docker_client import DarkmoonDockerClient
from src.tools.core.executor import GenericExecutor
from src.tools.core.health import HealthChecker
from src.tools.workflows.list_workflows import WorkflowRegistry


# Initialize FastMCP server
mcp = FastMCP("Darkmoon CyberSecurity")

# Initialize Docker client
docker_client = DarkmoonDockerClient(
    container_name=os.getenv("DOCKER_CONTAINER_NAME", "darkmoon"),
    timeout=int(os.getenv("DOCKER_TIMEOUT", "300")),
)

# Initialize core components
executor = GenericExecutor(docker_client)
health_checker = HealthChecker(docker_client)

# Initialize workflow registry for dynamic discovery
workflow_registry = WorkflowRegistry(docker_client)


# ============================================================================
# HEALTH & DIAGNOSTICS (3 tools)
# ============================================================================

# ============================================================
# SESSION MANAGEMENT
# ============================================================

# Generate a unique session ID when the MCP server starts
SESSION_ID = uuid.uuid4().hex[:8]


@mcp.tool()
def get_session() -> Dict[str, str]:
    """
    Return the current MCP session ID.

    This ID is generated automatically when the server starts.
    It stays the same for the entire lifetime of the server.
    """
    return {
        "session_id": SESSION_ID
    }

@mcp.tool()
def health_check() -> Dict[str, Any]:
    """
    Perform a comprehensive health check of the Darkmoon toolbox.

    Checks:
    - Container running status
    - Essential tools availability (naabu, nuclei, httpx, subfinder)
    - Disk usage
    - Overall system health

    Returns:
        Health status with detailed diagnostics.

    Example:
        {
          "healthy": true,
          "container_running": true,
          "tools_available": {"naabu": true, "nuclei": true, ...},
          "disk_usage": {...},
          "message": "All systems operational"
        }
    """
    health_status = health_checker.check()
    return health_status.model_dump()


@mcp.tool()
def check_tool(tool_name: str) -> Dict[str, Any]:
    """
    Check if a specific security tool is available and get its version.

    Args:
        tool_name: Name of the tool to check (e.g., "naabu", "nuclei", "httpx")

    Returns:
        Tool availability status and version information.

    Example:
        check_tool("naabu")
        → {"tool_name": "naabu", "available": true, "version": "v2.3.7"}
    """
    return health_checker.check_tool(tool_name)


@mcp.tool()
def diagnose() -> Dict[str, Any]:
    """
    Run comprehensive diagnostics on the Darkmoon toolbox.

    Performs:
    - Full health check
    - Network connectivity tests (DNS, internet, HTTPS)
    - Resource usage analysis (disk, memory, processes)
    - Essential tools verification

    Returns:
        Complete diagnostic report.

    Use this when troubleshooting issues or before starting a pentest campaign.
    """
    return health_checker.diagnose()


# ============================================================================
# GENERIC EXECUTOR (2 tools)
# ============================================================================

@mcp.tool()
def execute_command(
    command: str,
    timeout: Optional[int] = 300,
    workdir: Optional[str] = None,
    session_id: Optional[str] = None,  # NEW
) -> str:
    """
    Execute any whitelisted security tool command in the Darkmoon toolbox.

    This is the most flexible tool - use it to run any security tool that's not
    covered by the specialized workflows.

    Security:
    - Only whitelisted tools are allowed (30+ tools available)
    - Dangerous patterns are blocked (rm -rf, fork bombs, etc.)
    - All commands run in isolated Docker container
    - Configurable timeouts

    Args:
        command: Command to execute (e.g., "httpx -u https://example.com -json")
        timeout: Timeout in seconds (default: 300)
        workdir: Working directory for execution (optional)

    Returns:
        Execution results with stdout, stderr, exit code, and duration.

    Examples:
        # HTTP probing
        execute_command("httpx -u https://example.com -json")

        # Subdomain enumeration
        execute_command("subfinder -d example.com -silent")

        # Web fuzzing
        execute_command("ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt")

        # DNS enumeration
        execute_command("dig example.com ANY")

    Note: Use list_allowed_tools() to see all available tools.
    """

    result = executor.execute(
        command=command,
        timeout=timeout,
        workdir=workdir,
        session_id=session_id,   # pass through
    )

    exit_code = result.execution_result.exit_code
    duration = result.execution_result.duration
    stdout = result.raw_output or ""
    stderr = result.execution_result.stderr or ""

    output = []
    output.append("=" * 60)
    output.append(f"COMMAND  : {command}")
    output.append(f"EXIT CODE: {exit_code}")
    output.append(f"DURATION : {duration:.2f}s")
    output.append("=" * 60)
    output.append("")

    if stdout:
        output.append("STDOUT:")
        output.append(stdout.strip())
        output.append("")

    if stderr:
        output.append("STDERR:")
        output.append(stderr.strip())
        output.append("")

    if not stdout and not stderr:
        output.append("[NO OUTPUT]")

    return "\n".join(output)

@mcp.tool()
def list_allowed_tools() -> Dict[str, Any]:
    """
    List all security tools available via execute_command.

    Returns a complete list of whitelisted tools that can be executed safely.

    Categories:
    - Port scanners: naabu, masscan
    - Web tools: httpx, nuclei, ffuf, dirb, wafw00f, sqlmap, arjun, finalrecon, lightpanda
    - Recon: subfinder, waybackurls, katana
    - DNS: dig, nslookup
    - Network: curl, wget, ping
    - AD/Windows: netexec, bloodhound-python, impacket-smbclient
    - Kubernetes: kubectl, kubeletctl, kubescape
    - Misc: jq, grep, awk, sed

    Returns:
        List of allowed tools with count.
    """
    tools = executor.list_allowed_tools()
    return {
        "allowed_tools": tools,
        "count": len(tools),
        "categories": {
            "port_scanners": ["naabu", "masscan"],
            "web": ["httpx", "nuclei", "ffuf", "dirb", "wafw00f", "sqlmap", "arjun", "finalrecon", "lightpanda", "vulnx", "hydra","whatweb"],
            "recon": ["subfinder", "waybackurls", "katana"],
            "dns": ["dig", "nslookup"],
            "network": ["curl", "wget", "ping"],
            "ad_windows": ["netexec", "bloodhound-python", "smbclient.py", "hashcat", "Get-GPPPassword.py", "GetADComputer.py", "GetADUsers.py", "GetLAPSassword.py", "GetNPUsers.py", "GetUserSPNs.py", "ldapdomaindump.py", "smbclient.py", "smbexec.py", "smbserver.py", "findDelegation.py", "addcomputer.py", "exchanger.py", "raiseChild.py", "rdp-check.py", "registry-read.py", "regsecrets.py", "rpcdump.py", "rpcmap.py", "ticketConverter.py", "ticketer.py", "tstool.py", "owneredit.py", "ping.py", "psexec.py", "sambaPipe.py", "samedit.py", "samrdump.py", "sniff.py", "sniffer.py", "secretsdump.py", "snmpwalk", "dcomexec.py", "dpapi.py", "filetime.py", "getArch.py", "getPac.py", "getST.py", "getTGT.py", "goldenPac.py", "jp.py", "keylistattack.py", "lookupsid.py", "mimikatz.py", "minikerberos-asreproast", "minikerberos-ccache2kirbi", "minikerberos-ccacheedit", "minikerberos-ccacheroast", "minikerberos-cve202233647", "minikerberos-cve202233679", "minikerberos-getNTPKInit", "minikerberos-getS4U2proxy", "minikerberos-getS4U2self", "minikerberos-getTGS", "minikerberos-kerb23hashdecrypt", "minikerberos-kerberoast", "minikerberos-keylist", "minikerberos-kirbi2ccache", "minikerberos-pw", "mqtt_check.py", "mssqlclient.py", "mssqlinstance.py", "wmiexec.py", "wmipersist.py", "wmiquery.py", "changepasswd.py", "badsuccessor.py", "net.py", "netview.py", "ntfs-read.py", "ntmlrelayx.py",],
            "kubernetes": ["kubectl", "kubeletctl", "kubescape"],
            "misc": ["jq", "grep", "awk", "sed", "zip", "unzip",],
        },
    }


# ============================================================================
# WORKFLOW DISCOVERY & EXECUTION (2 tools)
# ============================================================================


@mcp.tool()
def list_workflows() -> Dict[str, Any]:
    """
    List all available security workflows with their methods and parameters.

    Use this tool to discover what workflows are available before executing them.
    Each workflow has one or more methods that can be called via run_workflow().

    Returns:
        Dictionary containing:
        - workflows: Detailed info about each workflow (description, methods, parameters)
        - count: Total number of available workflows
        - available_workflows: List of workflow names

    Example response:
        {
          "workflows": {
            "port_scan": {
              "class": "PortScanWorkflow",
              "description": "Fast port scanning with service detection.",
              "methods": {
                "scan_ports": {
                  "description": "Fast port scanning with naabu.",
                  "parameters": {"target": {"required": true}, "top_ports": {"default": 100}}
                }
              }
            }
          },
          "count": 6,
          "available_workflows": ["port_scan", "subdomain_discovery", ...]
        }
    """
    return workflow_registry.list_workflows()


@mcp.tool()
def run_workflow(
    workflow: str,
    method: str,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Execute a workflow method dynamically by name.

    Use list_workflows() first to see available workflows and their methods.

    Args:
        workflow: Name of the workflow (e.g., "port_scan", "subdomain_discovery")
        method: Name of the method to call (e.g., "scan_ports", "discover_subdomains")
        params: Dictionary of parameters to pass to the method

    Returns:
        Result of the workflow execution, or error details if failed.

    Examples:
        # Port scanning
        run_workflow("port_scan", "scan_ports", {"target": "example.com", "top_ports": 100})

        # Subdomain discovery
        run_workflow("subdomain_discovery", "discover_subdomains", {"domain": "example.com"})

        # Vulnerability scanning
        run_workflow("vulnerability_scan", "scan_vulnerabilities", {"target": "https://example.com"})

        # AD enumeration
        run_workflow("ad_enumeration", "enumerate_ad", {"dc_ip": "192.168.1.1", "domain": "CORP.LOCAL"})

        # Kubernetes audit
        run_workflow("kubernetes_audit", "audit_kubernetes", {"target": "https://k8s-api:6443"})

        # Web crawling
        run_workflow("web_crawler", "crawl_website", {"target": "https://example.com"})
    """
    return workflow_registry.run_workflow(workflow, method, params)

# ============================================================================
# SERVER STARTUP
# ============================================================================


def main():
    """Run the MCP server."""
    # Print startup info
    print("=" * 60)
    print("Darkmoon MCP Server")
    print("=" * 60)
    print(f"Container: {docker_client.container_name}")
    print(f"Default timeout: {docker_client.default_timeout}s")
    print()

    # Perform initial health check
    print("Performing initial health check...")
    health = health_checker.check()
    print(f"Status: {'[OK] Healthy' if health.healthy else '[!] Unhealthy'}")
    print(f"Message: {health.message}")
    print()

    if not health.healthy:
        print("[WARNING] Some tools are not available. Check health status.")
        print()

    print("Available MCP Tools (7 total):")
    print()
    print("  Health & Diagnostics (3):")
    print("    - health_check()      : Full system health check")
    print("    - check_tool()        : Check specific tool availability")
    print("    - diagnose()          : Comprehensive diagnostics")
    print()
    print("  Generic Executor (2):")
    print("    - execute_command()   : Run any whitelisted security tool")
    print("    - list_allowed_tools(): List all available tools (30+)")
    print()
    print("  Workflow Discovery (2):")
    print("    - list_workflows()    : List all available workflows")
    print("    - run_workflow()      : Execute a workflow by name")
    print()
    print(f"  Discovered Workflows ({len(workflow_registry.workflows)}):")
    for wf_name in sorted(workflow_registry.workflows.keys()):
        wf_meta = workflow_registry.workflow_metadata[wf_name]
        print(f"    - {wf_name}: {wf_meta['description']}")
    print()
    print("Architecture: Executor + Dynamic Workflow Registry")
    print("=" * 60)

    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()