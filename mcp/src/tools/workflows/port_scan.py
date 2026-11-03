"""
Port Scan Workflow

Fast port scanning with service detection.
Uses naabu for port scanning and httpx for HTTP service verification.
"""

from typing import Dict, Any, Union, List
from src.tools.workflows.base import BaseWorkflow


class PortScanWorkflow(BaseWorkflow):
    """
    Fast port scanning with service detection.

    Use cases:
    - Network reconnaissance
    - Service discovery
    - Attack surface enumeration
    """

    def scan_ports(
        self,
        target: Union[str, List[str]],
        top_ports: int = 100,
        rate_limit: int = 25,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """
        Fast port scanning with naabu.

        Workflow:
        1. Naabu port scan (240s)
        2. httpx HTTP service verification (60s)

        Args:
            target: Single host or list of hosts
            top_ports: 100 (fast), 1000 (thorough), or 0 for full scan
            rate_limit: Packets per second ceiling for naabu (default 25).
                        DO NOT raise this: during the 2026-11-02 ALSCO campaign
                        an uncapped run (-rate 500) got the source IP banned for
                        6 minutes by the target firewall and killed the run.
                        The engine also floors this mechanically (see
                        mcp/src/rate_limiter.py) — a higher value passed here is
                        capped again at the choke point.
            timeout: Total timeout in seconds (default: 300s)

        Returns:
            Port scan results with discovered services
        """
        steps = {}

        # Normalize target to list
        if isinstance(target, str):
            targets = [target]
            target_str = target
        else:
            targets = target
            target_str = ",".join(targets[:3]) + ("..." if len(targets) > 3 else "")

        workspace_dir = f"/opt/darkmoon/out/port_scan_{target_str.replace('.', '_')}"

        # ========================================
        # Calculate timeout distribution
        # Reserve 10s for setup, split remaining between steps
        # ========================================
        setup_timeout = 10
        remaining_timeout = max(timeout - setup_timeout, 60)  # At least 60s
        naabu_timeout = int(remaining_timeout * 0.75)  # 75% for port scan
        httpx_timeout = remaining_timeout - naabu_timeout  # 25% for HTTP verification

        # ========================================
        # STEP 0: Create workspace
        # ========================================
        self.execute_step(
            step_name="Create workspace",
            command=f"mkdir -p {workspace_dir}",
            timeout=setup_timeout,
            parse_json=False,
        )

        # Write targets to file (escape single quotes to prevent shell injection)
        targets_file = f"{workspace_dir}/targets.txt"
        escaped_targets = [t.replace("'", "'\\''") for t in targets]
        self.docker_client.execute_command(
            f"echo '{chr(10).join(escaped_targets)}' > {targets_file}",
            timeout=setup_timeout
        )

        # ========================================
        # STEP 1: Naabu port scan (rate-capped)
        # ========================================
        naabu_output = f"{workspace_dir}/naabu_output.json"
        top_ports_arg = self.normalize_top_ports(top_ports)
        # `-rate` is explicit here: the 2026-11-02 ALSCO campaign ran naabu
        # uncapped (-rate 500) and the target firewall banned the source IP
        # for 6 minutes. 25 pps stays inside the bug-bounty norms.
        rate_limit = max(1, min(int(rate_limit), 25))

        success, findings, output = self.execute_step(
            step_name=f"Port scanning ({len(targets)} targets, top {top_ports} ports, {rate_limit} pps)",
            command=f"naabu -list {targets_file} -top-ports {top_ports_arg} -rate {rate_limit} -json -silent -o {naabu_output} && cat {naabu_output}",
            timeout=naabu_timeout,
            parse_json=True,
        )

        # Extract ports and group by host
        ports_by_host = {}
        all_ports = []

        for finding in findings:
            host = finding.get("host", "unknown")
            port = finding.get("port")

            if port:
                all_ports.append(port)
                if host not in ports_by_host:
                    ports_by_host[host] = []
                ports_by_host[host].append(port)

        steps["port_scan"] = {
            "success": success,
            "ports_found": len(findings),
            "unique_ports": len(set(all_ports)),
            "ports": sorted(set(all_ports)),
            "by_host": ports_by_host,
            "findings": findings,
        }

        # ========================================
        # STEP 2: httpx HTTP service detection
        # ========================================
        # Build URLs from discovered ports
        http_urls = []
        for host, ports in ports_by_host.items():
            for port in ports:
                if port in [80, 443, 8000, 8080, 8443, 8888]:
                    protocol = "https" if port == 443 or port == 8443 else "http"
                    http_urls.append(f"{protocol}://{host}:{port}")

        if http_urls:
            httpx_input = f"{workspace_dir}/httpx_input.txt"
            # URLs are already formatted, no user input here
            self.docker_client.execute_command(
                f"echo '{chr(10).join(http_urls)}' > {httpx_input}",
                timeout=setup_timeout
            )

            httpx_output = f"{workspace_dir}/httpx_output.json"
            success, findings, output = self.execute_step(
                step_name=f"HTTP service verification ({len(http_urls)} URLs)",
                command=f"httpx -l {httpx_input} -json -silent -o {httpx_output} && cat {httpx_output}",
                timeout=httpx_timeout,
                parse_json=True,
            )

            web_services = [f.get("url") for f in findings if f.get("url")]

            steps["http_services"] = {
                "success": success,
                "web_services_found": len(web_services),
                "web_services": web_services,
            }
        else:
            steps["http_services"] = {
                "success": True,
                "web_services_found": 0,
                "web_services": [],
            }

        # ========================================
        # SUMMARY
        # ========================================
        summary = {
            "total_ports": len(findings),
            "unique_ports": len(set(all_ports)),
            "hosts_scanned": len(targets),
            "hosts_with_ports": len(ports_by_host),
            "common_ports": sorted(set(all_ports))[:20],  # Top 20
            "http_services": steps["http_services"]["web_services_found"],
        }

        return self.create_result_dict(
            workflow_name="scan_ports",
            target=target,
            steps=steps,
            summary=summary,
        )
