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
import threading
import uuid
from typing import Optional, Dict, Any
from fastmcp import FastMCP

from src.docker_client import DarkmoonDockerClient
from src.tools.core.executor import GenericExecutor
from src.tools.core.health import HealthChecker
from src.tools.workflows.list_workflows import WorkflowRegistry
from src.privacy import (
    PrivacyVault,
    CommandGateway,
    GatewayDecision,
    resolve_categories,
    resolve_policy,
    PLACEHOLDER_ANY_RE,
)


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

# ============================================================
# PRIVACY GATEWAY (reversible local tokenization)
# ------------------------------------------------------------
# The model only ever sees deterministic placeholders. Real values are injected
# locally by the CommandGateway right before execution, and re-tokenized out of
# any tool output before it goes back to the model. Toggle with DARKMOON_PRIVACY.
#
# The gateway does not block. When a placeholder sits somewhere its real value
# must not go, the command still runs with the placeholder left in place, and
# the model is told which values were held back. Widening the default boundary
# to URL/DOMAIN/PATH (issue #40) meant nearly every pentest command carries a
# placeholder, so a blocking gateway refused ordinary work (PR #42). Set
# DARKMOON_PRIVACY_POLICY=strict to get the old refuse-outright behaviour.
# ============================================================
PRIVACY_ENABLED = os.getenv("DARKMOON_PRIVACY", "1").lower() not in ("0", "false", "no", "off")
_command_gateway = CommandGateway()
_vaults: Dict[str, PrivacyVault] = {}
# The pre-model tokenization endpoint (prompt_socket) runs in a daemon thread, so
# vault access it triggers is serialized against the stdio tool handlers with this
# lock. In practice they never overlap (the launch prompt is tokenized before the
# model can issue its first tool call), but the lock makes it correct regardless.
_vault_lock = threading.RLock()


def _privacy_policy():
    """Resolved per call so an operator can flip the policy without a restart."""
    return resolve_policy()

def _privacy_enabled_for(session_id: Optional[str]) -> bool:
    """Return whether the privacy vault is enabled for this session"""
    sid = session_id or SESSION_ID
    vault = _vaults.get(sid)
    if vault is not None and not vault.is_expired() and vault.privacy_enabled is not None:
        return vault.privacy_enabled
    return PRIVACY_ENABLED

# Which categories are tokenized. By default we cover the FULL documented
# boundary — IPs, internal hosts, domains, URLs, emails and internal paths — so
# the model never receives them inside a tool call or its output. The default set
# lives in privacy.DEFAULT_CATEGORIES (single source of truth, shared with the
# vault) so the server can no longer silently narrow it below what the docs
# promise. An operator may still override it with DARKMOON_PRIVACY_CATEGORIES
# (comma-separated, e.g. "IP_PRIVATE,HOST_INTERNAL,URL,PATH"); an unset or
# malformed value falls back to the full default. USER/CRED are register-only
# categories (never auto-detected from free text) and, once registered, are
# never restored into an executed command. See issue #40.
def _resolve_categories():
    return resolve_categories(os.getenv("DARKMOON_PRIVACY_CATEGORIES"))


def _get_vault(session_id: Optional[str]) -> PrivacyVault:
    """Return (creating if needed) the per-session privacy vault.

    Locked because the tokenization socket (a daemon thread) and the tool-call
    handlers (the asyncio loop) can call this concurrently for the same session
    on the persistent-http MCP; without it two vaults could be created for one
    session and one thread's mappings would be lost.
    """
    sid = session_id or SESSION_ID
    with _vault_lock:
        vault = _vaults.get(sid)
        if vault is None or vault.is_expired():
            ttl = int(os.getenv("DARKMOON_PRIVACY_TTL", str(6 * 3600)))
            vault = PrivacyVault(session_id=sid, ttl_seconds=ttl, enabled_categories=_resolve_categories())
            _vaults[sid] = vault
        return vault


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
def tokenize_prompt(text: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Tokenize a launch prompt BEFORE it reaches the model.

    The Darkmoon privacy boundary normally acts only on tool calls and their
    output. The initial campaign prompt (TARGET / CREDS / SCOPE / TOKEN / IP /
    port) is sent to the model first, so without this it would reach the model in
    clear (issue #40, section 3). This applies the SAME per-session vault the
    tool calls use, so every placeholder is identical to the ones the gateway
    rehydrates during the run and restores into the local report — no value is
    ever hard-coded.

    Intended caller: the Darkmoon OpenCode privacy plugin, which rewrites the
    outgoing user message with the returned `tokenized` text before the model
    sees it. Safe to call repeatedly (deterministic per session).

    Args:
        text: the raw prompt text to tokenize.
        session_id: privacy vault session id; defaults to the server session,
                    i.e. the exact vault execute_command / run_workflow use.

    Returns:
        {"tokenized": <text with placeholders>, "session_id": <sid>,
         "changed": <bool>, "stats": {<category>: <count>}}
    """
    original = text or ""
    if not PRIVACY_ENABLED or not _privacy_enabled_for(session_id):
        return {"tokenized": original, "session_id": session_id or SESSION_ID,
                "changed": False, "stats": {}}
    with _vault_lock:
        vault = _get_vault(session_id)
        tokenized = vault.tokenize_prompt(original)
        stats = vault.stats()
    return {
        "tokenized": tokenized,
        "session_id": vault.session_id,
        "changed": tokenized != original,
        "stats": stats,
    }


def _privacy_socket_tokenize(text: str, session_id: Optional[str]) -> str:
    """Callback for the local pre-model tokenization socket (prompt_socket).

    Shares the exact per-session vault used by execute_command / run_workflow and
    by the report renderer, so a placeholder minted for the launch prompt is the
    same one rehydrated during the run and restored into the local report.
    """
    original = text or ""
    if not PRIVACY_ENABLED or not _privacy_enabled_for(session_id):
        return original
    with _vault_lock:
        return _get_vault(session_id).tokenize_prompt(original)


# ---------------------------------------------------------------------------
# Global tool result/error sanitizer (issue #40 — output side, belt-and-braces)
# ---------------------------------------------------------------------------
# execute_command already re-tokenizes its own stdout/stderr, but a tool or
# workflow that runs a library in-process (e.g. impacket) and RAISES — or that
# returns text through any other path — would otherwise hand the model a real
# value, e.g. a rehydrated IP embedded in an exception message such as
# "target 192.168.56.10: invalid principal syntax". This middleware is the
# catch-all: EVERY ToolResult and EVERY tool exception leaving the MCP is passed
# through the session vault, so the model only ever sees placeholders regardless
# of which code path produced the text.
from fastmcp.server.middleware import Middleware  # noqa: E402
from fastmcp.exceptions import ToolError  # noqa: E402


def _sanitize_for_model(value: Any, session_id: Optional[str]) -> Any:
    """Re-tokenize any real value in a tool result/error via the session vault.

    Idempotent: values already turned into placeholders do not match any category
    pattern, so re-running it over already-sanitized execute_command output is a
    no-op. Never raises — sanitization must not turn a working tool into an error.
    """
    if not PRIVACY_ENABLED:
        return value
    try:
        with _vault_lock:
            vault = _get_vault(session_id)
            if vault is None or not (
                _privacy_enabled_for(session_id) or vault.known_placeholders()
            ):
                return value
            return _command_gateway.sanitize_result(value, vault)
    except Exception:  # noqa: BLE001 — sanitization must be fail-safe
        return value


class _PrivacySanitizerMiddleware(Middleware):
    """Scrub every tool result and every tool exception before it reaches the LLM."""

    async def on_call_tool(self, context, call_next):
        args = getattr(context.message, "arguments", None)
        session_id = args.get("session_id") if isinstance(args, dict) else None
        try:
            result = await call_next(context)
        except ToolError as exc:
            raise ToolError(_sanitize_for_model(str(exc), session_id)) from None
        except Exception as exc:  # noqa: BLE001 — any tool exception must be scrubbed
            raise ToolError(
                _sanitize_for_model(f"{type(exc).__name__}: {exc}", session_id)
            ) from None
        try:
            content = getattr(result, "content", None)
            if isinstance(content, list):
                for block in content:
                    if getattr(block, "type", None) == "text" and isinstance(
                        getattr(block, "text", None), str
                    ):
                        block.text = _sanitize_for_model(block.text, session_id)
            sc = getattr(result, "structured_content", None)
            if sc is not None:
                result.structured_content = _sanitize_for_model(sc, session_id)
        except Exception:  # noqa: BLE001 — never break a successful call
            pass
        return result


mcp.add_middleware(_PrivacySanitizerMiddleware())


def _rehydrate_report(text: Optional[str], session_id: Optional[str] = None) -> Optional[str]:
    """Restore real values into a finished report/summary before it is written to
    disk. The model only ever sees and emits placeholders, so a saved report would
    otherwise read "Target: IP_PRIVATE_001" instead of the real address, and every
    finding would reference tokens instead of the hosts/domains/credentials the
    pentester needs. The report is local and CONFIDENTIAL, so secrets are restored
    too. Uses the same per-session vault the launch prompt and tool calls shared.
    """
    if not text or not PRIVACY_ENABLED:
        return text
    try:
        with _vault_lock:
            vault = _get_vault(session_id)
        if vault is None:
            return text

        def _sub(m: "re.Match") -> str:
            ph = m.group("ph")
            real = vault.rehydrate(ph, allow_secret=True)
            return real if real is not None else ph

        return PLACEHOLDER_ANY_RE.sub(_sub, text)
    except Exception:  # noqa: BLE001 — never fail finalize over rehydration
        return text


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

    # Privacy gateway: the model sends a command that may reference placeholders
    # (IP_PRIVATE_001, ...). Rehydrate to real values locally, or block unsafe use.
    # `command` is what the model sent (placeholders) and is echoed back as-is;
    # `real_command` (real values) is what actually runs and is never shown back.
    vault = _get_vault(session_id)
    # enforce_exfil_policy depends on whether the privacy gateway is enabled for
    # this session. When it is off, structural checks still run and rehydration
    # still happens, but the positional exfiltration rules are not applied.
    gw = _command_gateway.process_command(
        command,
        vault,
        enforce_exfil_policy=_privacy_enabled_for(session_id),
        policy=_privacy_policy(),
    )
    if gw.decision == GatewayDecision.BLOCK:
        # Only reachable under DARKMOON_PRIVACY_POLICY=strict. The default policy
        # degrades instead, so a pentest command is never refused for privacy.
        return (
            "=" * 60 + "\n"
            f"COMMAND  : {command}\n"
            "PRIVACY  : BLOCKED (strict policy)\n"
            f"REASON   : {gw.reason}\n"
            + "=" * 60 + "\n\n"
            "[BLOCKED BY PRIVACY GATEWAY] This command was not executed. "
            "Protected values may only be used as scan/tool arguments against the "
            "in-scope target, never printed, echoed, or sent to another host."
        )
    real_command = gw.command or command

    result = executor.execute(
        command=real_command,
        timeout=timeout,
        workdir=workdir,
        session_id=session_id,   # pass through
    )

    exit_code = result.execution_result.exit_code
    duration = result.execution_result.duration
    stdout = result.raw_output or ""
    stderr = result.execution_result.stderr or ""

    # Re-tokenize any real value that appears in the output before the model sees
    # it. This runs whenever the vault holds a mapping, even for a session whose
    # exfiltration policy is relaxed: a session that turns the policy off must not
    # start leaking values the model was already given placeholders for. Output
    # sanitization is what makes the degrade policy safe, so it is not optional.
    if vault is not None and (_privacy_enabled_for(session_id) or vault.known_placeholders()):
        stdout = _command_gateway.sanitize_output(stdout, vault)
        stderr = _command_gateway.sanitize_output(stderr, vault)

    output = []
    output.append("=" * 60)
    output.append(f"COMMAND  : {command}")
    output.append(f"EXIT CODE: {exit_code}")
    output.append(f"DURATION : {duration:.2f}s")
    if gw.withheld:
        # Not an error: the command ran. Telling the model which values stayed
        # tokenized stops it from retrying the same shape forever.
        output.append(f"PRIVACY  : {len(gw.withheld)} value(s) kept tokenized")
        for note in gw.notes:
            output.append(f"           - {note}")
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
    - Web tools: httpx, nuclei, ffuf, dirb, wafw00f, sqlmap, arjun, finalrecon, lightpanda, cmseek, wpscan
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
            "web": ["httpx", "nuclei", "ffuf", "dirb", "wafw00f", "sqlmap", "arjun", "finalrecon", "lightpanda", "vulnx", "hydra","whatweb","cmseek","wpscan"],
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
    params: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a workflow method dynamically by name.

    Use list_workflows() first to see available workflows and their methods.

    Args:
        workflow: Name of the workflow (e.g., "port_scan", "subdomain_discovery")
        method: Name of the method to call (e.g., "scan_ports", "discover_subdomains")
        params: Dictionary of parameters to pass to the method
        session_id: Privacy vault session ID. Uses the server session by default.

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
    # privacy gateway and vault are always assigned now 
    # (and never None since get_vault creates if missing and gateway is defined above)
    # so structural checks and rehydration inside run_workflow always run,
    # and the exfiltration policy is passed below as a sanitize_output parameter
    privacy_gateway = _command_gateway
    privacy_vault = _get_vault(session_id)

    return workflow_registry.run_workflow(
        workflow,
        method,
        params,
        privacy_gateway=privacy_gateway,
        privacy_vault=privacy_vault,
        enforce_exfil_policy=_privacy_enabled_for(session_id),
    )

# ============================================================================
# DASHBOARD EXPORT TOOLS (4 tools)
# ============================================================================


@mcp.tool()
def dashboard_init_campaign(
    session_id: str,
    target_host: str,
    target_ip: str,
    project_name: str = "Darkmoon Assessment",
    methodology: str = "ISO 27001 / NIST SP 800-115 / MITRE ATT&CK",
) -> Dict[str, Any]:
    """
    Initialize a live campaign for the Darkmoon Dashboard.

    Call this ONCE at the beginning of a pentest campaign, right after get_session().
    It creates the project, target, and campaign skeleton in the dashboard data store.
    The returned campaign_id must be used in all subsequent push calls.

    Args:
        session_id: The MCP session ID (from get_session())
        target_host: Target hostname or IP
        target_ip: Target IP address
        project_name: Name for the assessment project
        methodology: Methodology string

    Returns:
        Dictionary with project_id, target_id, campaign_id.

    Example:
        dashboard_init_campaign(
            session_id="d7c20dbe",
            target_host="172.20.0.4",
            target_ip="172.20.0.4",
        )
        → {"project_id": "proj_...", "target_id": "tgt_...", "campaign_id": "camp_..."}
    """
    from api.live_push import init_live_campaign
    return init_live_campaign(
        session_id=session_id,
        target_host=target_host,
        target_ip=target_ip,
        project_name=project_name,
        methodology=methodology,
    )


@mcp.tool()
def dashboard_push_finding(
    campaign_id: str,
    title: str,
    severity: str,
    cvss_score: float,
    category: str,
    status: str,
    description: str,
    endpoint: str,
    discovered_by_agent: str,
    remediation: str = "",
    evidence_commands: Optional[str] = None,
    evidence_logs: Optional[str] = None,
    evidence_explanation: str = "",
    cve: Optional[str] = None,
    cvss_vector: Optional[str] = None,
    mitre_attack_id: Optional[str] = None,
    mitre_attack_name: Optional[str] = None,
    iso27001_control: Optional[str] = None,
    node_id: Optional[str] = None,
    plugin_or_component: Optional[str] = None,
    raw_request: Optional[str] = None,
    raw_response: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Push a single vulnerability finding to the Darkmoon Dashboard in real-time.

    Call this each time a vulnerability is discovered during the pentest.
    The finding is immediately written to disk and visible in the API.

    Args:
        campaign_id: Campaign ID returned by dashboard_init_campaign()
        title: Short title of the vulnerability
        severity: critical, high, medium, low, info
        cvss_score: CVSS 3.1 score (0.0 to 10.0)
        category: Vulnerability category (remote_code_execution, xss_stored, sql_injection, ssrf, etc.)
        status: exploited, confirmed, unconfirmed
        description: Technical description
        endpoint: Affected endpoint/URL
        discovered_by_agent: Agent ID that found this (wordpress, nodejs, php, etc.)
        remediation: Remediation recommendation
        evidence_commands: Commands used to reproduce (one per line, newline-separated)
        evidence_logs: Chronological exploit logs (one per line, newline-separated)
        evidence_explanation: Human-readable explanation of the vulnerability
        cve: CVE identifier if applicable
        cvss_vector: Full CVSS vector string
        mitre_attack_id: MITRE ATT&CK technique ID (e.g., T1190)
        mitre_attack_name: MITRE ATT&CK technique name
        iso27001_control: ISO 27001 Annex A control
        node_id: Infrastructure node ID this vuln is attached to
        plugin_or_component: Vulnerable component name
        raw_request: Raw HTTP request (evidence)
        raw_response: Raw HTTP response (evidence)

    Returns:
        Dictionary with vuln_id, total findings count.

    Example:
        dashboard_push_finding(
            campaign_id="camp_20260323_abcd1234",
            title="SQL Injection in login form",
            severity="critical",
            cvss_score=9.8,
            category="sql_injection",
            status="exploited",
            description="The login endpoint is vulnerable to SQL injection...",
            endpoint="/api/login",
            discovered_by_agent="php",
            evidence_commands="sqlmap -u http://target/api/login --data='user=test'",
            evidence_logs="[12:30:01] SQLi confirmed: extracted 3 tables",
            evidence_explanation="The login form passes unsanitized input to SQL query...",
        )
    """
    from api.live_push import push_finding

    finding = {
        "campaign_id": campaign_id,
        "node_id": node_id or "",
        "title": title,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cve": cve,
        "category": category,
        "mitre_attack_id": mitre_attack_id,
        "mitre_attack_name": mitre_attack_name,
        "iso27001_control": iso27001_control,
        "status": status,
        "description": description,
        "evidence": {
            "commands": evidence_commands.split("\n") if evidence_commands else [],
            "payloads": [],
            "raw_request": raw_request or "",
            "raw_response": raw_response or "",
            "extracted_data": None,
            "screenshots": [],
            "logs": evidence_logs.split("\n") if evidence_logs else [],
            "explanation": evidence_explanation,
        },
        "remediation": remediation,
        "plugin_or_component": plugin_or_component,
        "endpoint": endpoint,
        "discovered_by_agent": discovered_by_agent,
        "discovered_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    return push_finding(campaign_id=campaign_id, finding=finding)


@mcp.tool()
def dashboard_push_infra_node(
    campaign_id: str,
    node_type: str,
    label: str,
    host: str,
    technology: str,
    risk_level: str = "none",
    port: Optional[int] = None,
    version: Optional[str] = None,
    parent_node_id: Optional[str] = None,
    node_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Push an infrastructure node to the Darkmoon Dashboard in real-time.

    Call this as you discover infrastructure components during the pentest.
    Nodes form a tree via parent_node_id for the infrastructure graph.

    Args:
        campaign_id: Campaign ID returned by dashboard_init_campaign()
        node_type: host, service, application, plugin, theme, endpoint, tool_exposed, file_exposed, service_internal
        label: Display label for the graph (e.g., "Apache 2.4.38")
        host: Hostname or IP
        technology: Technology name (e.g., "Apache HTTP Server")
        risk_level: critical, high, medium, low, info, none
        port: Port number (null for hosts)
        version: Detected version
        parent_node_id: ID of the parent node (null for root)
        node_id: Custom node ID (auto-generated if not provided)

    Returns:
        Dictionary with node_id, total nodes count.

    Example:
        dashboard_push_infra_node(
            campaign_id="camp_20260323_abcd1234",
            node_type="host",
            label="172.20.0.4",
            host="172.20.0.4",
            technology="Linux (Docker)",
        )
    """
    from api.live_push import push_infra_node

    node = {
        "node_type": node_type,
        "label": label,
        "host": host,
        "port": port,
        "technology": technology,
        "version": version,
        "risk_level": risk_level,
        "parent_node_id": parent_node_id,
        "vulnerability_ids": [],
    }
    if node_id:
        node["id"] = node_id

    return push_infra_node(campaign_id=campaign_id, node=node)


@mcp.tool()
def dashboard_finalize_campaign(
    campaign_id: str,
    duration_seconds: int = 0,
    executive_summary: str = "",
    report_markdown: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Finalize a campaign on the Darkmoon Dashboard.

    Call this ONCE after the pentest is complete and the report has been generated.
    Sets the campaign status to "completed" and saves the markdown report.

    Args:
        campaign_id: Campaign ID returned by dashboard_init_campaign()
        duration_seconds: Total campaign duration in seconds
        executive_summary: 1-3 sentence executive summary
        report_markdown: Full markdown report content

    Returns:
        Dictionary with final status, findings count, risk level.

    Example:
        dashboard_finalize_campaign(
            campaign_id="camp_20260323_abcd1234",
            duration_seconds=900,
            executive_summary="Critical RCE achieved via SQL injection...",
            report_markdown="# Vulnerability Assessment Report\\n..."
        )
    """
    from api.live_push import finalize_campaign, _generate_report_from_db
    from api.json_storage import load_campaign, load_report_content

    def _is_reference(content) -> bool:
        if not content:
            return True
        s = str(content).strip()
        return (
            len(s) < 2000
            or s.startswith("See full report")
            or s.startswith("Report available")
            or s.startswith("/output/")
            or s.startswith("/tmp/")
            or s.startswith("pentest_report_")
            or (len(s) < 500 and ("report" in s.lower() or "path" in s.lower()))
        )

    # Check if a good report already exists — never overwrite with a worse one
    existing_camp = load_campaign(campaign_id)
    existing_path = existing_camp.get("report_path", "") if existing_camp else ""
    existing_content = load_report_content(existing_path) if existing_path else ""
    existing_is_good = (
        existing_content
        and len(existing_content) > 10000
        and not _is_reference(existing_content)
    )

    resolved_markdown = report_markdown

    if existing_is_good and (
        not report_markdown
        or len(str(report_markdown).strip()) < len(existing_content)
    ):
        # Keep the existing good report — agent passed a shorter/worse version
        resolved_markdown = existing_content

    elif _is_reference(report_markdown):
        # Agent passed a file path or reference — check disk first, then auto-generate
        from pathlib import Path
        reports_dir = Path("/root/.local/share/opencode/reports")
        if reports_dir.exists():
            suffix = campaign_id[-8:]
            disk_reports = sorted(
                [p for p in reports_dir.glob("pentest_report_*.md")
                 if suffix in p.name or p.stat().st_size > 10000],
                key=lambda p: p.stat().st_size,
                reverse=True,
            )
            if disk_reports and disk_reports[0].stat().st_size > 10000:
                resolved_markdown = disk_reports[0].read_text(encoding="utf-8")

        if not resolved_markdown or _is_reference(resolved_markdown):
            camp = load_campaign(campaign_id)
            if camp:
                resolved_markdown = _generate_report_from_db(
                    campaign_id, camp, executive_summary
                )

    # Restore real values before the report is written to disk. The model authored
    # everything from placeholders only; the local CONFIDENTIAL report must show the
    # real hosts, domains, IPs and credentials the pentester needs. finalize_campaign
    # regenerates the body from the (placeholder) DB findings, so the rehydration has
    # to run at its single write point — hence the callback — not just here.
    executive_summary = _rehydrate_report(executive_summary) or executive_summary

    return finalize_campaign(
        campaign_id=campaign_id,
        duration_seconds=duration_seconds,
        executive_summary=executive_summary,
        report_markdown=resolved_markdown,
        rehydrate=_rehydrate_report,
    )


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

    # Pre-model tokenization endpoint (issue #40, section 3): a local unix socket
    # the Darkmoon opencode plugin POSTs the launch prompt to, so TARGET/CREDS/
    # SCOPE reach the model already tokenized. Started FIRST, before the toolbox
    # health check, so it is up even if the toolbox is momentarily unreachable.
    # Best-effort; never blocks startup.
    if PRIVACY_ENABLED:
        try:
            from src.prompt_socket import start as _start_privacy_socket, DEFAULT_SOCKET_PATH
            if _start_privacy_socket(_privacy_socket_tokenize) is not None:
                print(f"Pre-model prompt tokenization socket: {DEFAULT_SOCKET_PATH}")
                print()
        except Exception as _exc:  # noqa: BLE001
            print(f"[WARNING] prompt tokenization socket unavailable: {_exc.__class__.__name__}")
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

    print("Available MCP Tools (11 total):")
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
    print("  Dashboard Export (4):")
    print("    - dashboard_init_campaign()    : Init live campaign")
    print("    - dashboard_push_finding()     : Push vuln in real-time")
    print("    - dashboard_push_infra_node()  : Push infra node in real-time")
    print("    - dashboard_finalize_campaign(): Finalize + write report")
    print()
    print(f"  Discovered Workflows ({len(workflow_registry.workflows)}):")
    for wf_name in sorted(workflow_registry.workflows.keys()):
        wf_meta = workflow_registry.workflow_metadata[wf_name]
        print(f"    - {wf_name}: {wf_meta['description']}")
    print()
    print("Architecture: Executor + Dynamic Workflow Registry")
    print("=" * 60)

    # Run the server. Default transport is stdio (opencode `type: local`, one MCP
    # process spawned per session). Set DARKMOON_MCP_TRANSPORT=http to run as a
    # PERSISTENT streamable-http server instead (opencode `type: remote`): started
    # once at boot, its per-process vault — and the pre-model tokenization socket
    # above — are up before any prompt, so the plugin can tokenize the launch
    # prompt (and the session-title call that precedes the main request) without
    # waiting for a per-session MCP to spawn. See issue #40, section 3.
    transport = os.getenv("DARKMOON_MCP_TRANSPORT", "stdio").strip().lower()
    if transport in ("http", "streamable-http", "sse"):
        host = os.getenv("DARKMOON_MCP_HOST", "127.0.0.1")
        port = int(os.getenv("DARKMOON_MCP_PORT", "8181"))
        path = os.getenv("DARKMOON_MCP_PATH", "/mcp")
        print(f"Transport: {transport} on http://{host}:{port}{path}")
        mcp.run(transport=transport, host=host, port=port, path=path)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
