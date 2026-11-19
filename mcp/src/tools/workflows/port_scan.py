"""
Port Scan Workflow

Fast port scanning with service detection.
Uses naabu for port scanning and httpx for HTTP service verification.
"""

import re
from typing import Dict, Any, List, Optional, Union
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
        timeout: int = 300,
        ports: Optional[Union[str, List[Union[int, str]]]] = None,
    ) -> Dict[str, Any]:
        """
        Fast port scanning with naabu.

        Workflow:
        1. Naabu port scan (240s)
        2. httpx HTTP service verification (60s)

        Args:
            target: Single host or list of hosts
            top_ports: 100 (fast), 1000 (thorough), or 0 for full scan
            timeout: Total timeout in seconds (default: 300s)
            ports: Explicit ports / ranges instead of top_ports, e.g. "22,445,1883,5432-5433" or [22, 445]

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
        # STEP 1: Naabu port scan
        # ========================================
        naabu_output = f"{workspace_dir}/naabu_output.json"
        port_spec = None
        if ports:
            port_spec = ",".join(str(p).strip() for p in ports) if isinstance(ports, (list, tuple)) else str(ports).strip()
            if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", port_spec):
                return {"success": False, "error": f"invalid ports {port_spec!r}: use e.g. '22,445,1883' or '1-1024'",
                        "complete": False}
        port_arg = f"-p {port_spec}" if port_spec else f"-top-ports {self.normalize_top_ports(top_ports)}"

        success, findings, output = self.execute_step(
            step_name=f"Port scanning ({len(targets)} targets, {'ports ' + port_spec if port_spec else f'top {top_ports} ports'})",
            command=f"naabu -list {targets_file} {port_arg} -json -silent -o {naabu_output} && cat {naabu_output}",
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
            # a failed scan proves nothing: never read « 0 ports » as « no service » (live run 18/11)
            "complete": bool(success),
            **({} if success else {"note": "port scan did NOT complete (see output): the absence of open ports is "
                                           "NOT established; fix the error or scan by IP / explicit ports"}),
            "error_output": None if success else (output or "")[-600:],
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
            "total_ports": steps["port_scan"]["ports_found"],  # not the httpx step's findings
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
