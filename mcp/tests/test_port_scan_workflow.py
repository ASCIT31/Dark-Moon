"""Tests for PortScanWorkflow.scan_ports with a fake docker client (no Docker, no network)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.common import ExecutionResult, ExecutionStatus  # noqa: E402
from src.tools.workflows.port_scan import PortScanWorkflow  # noqa: E402


WEB_PORTS = [80, 443, 8000, 8080, 8443, 8888]


class RecordingDockerClient:
    """Records every command; answers naabu and httpx with canned JSON lines."""

    def __init__(self, naabu_findings=(), httpx_findings=()):
        self.commands = []
        self.naabu_output = "\n".join(json.dumps(f) for f in naabu_findings)
        self.httpx_output = "\n".join(json.dumps(f) for f in httpx_findings)

    def execute_command(self, command, timeout=None, **kwargs):
        self.commands.append(command)
        stdout = ""
        if command.startswith("naabu "):
            stdout = self.naabu_output
        elif command.startswith("httpx "):
            stdout = self.httpx_output
        return ExecutionResult(status=ExecutionStatus.SUCCESS, stdout=stdout)

    def commands_starting(self, prefix):
        return [c for c in self.commands if c.startswith(prefix)]


def run_scan(target, naabu_findings=(), httpx_findings=(), **kwargs):
    client = RecordingDockerClient(naabu_findings, httpx_findings)
    result = PortScanWorkflow(client).scan_ports(target, **kwargs)
    return client, result


def targets_written(client):
    """The host list the workflow echoes into targets.txt, unquoted again."""
    (echo,) = [c for c in client.commands_starting("echo ") if "targets.txt" in c]
    quoted = echo[len("echo "):echo.rindex(" > ")]
    assert quoted.startswith("'") and quoted.endswith("'")
    return quoted[1:-1].replace("'\\''", "'").split("\n")


def test_a_single_string_target_is_normalised_to_a_list():
    client, result = run_scan("scanme.example")

    assert targets_written(client) == ["scanme.example"]
    assert result["target"] == "scanme.example"
    assert result["summary"]["hosts_scanned"] == 1


def test_a_list_of_targets_is_scanned_as_given():
    hosts = ["a.example", "b.example", "c.example", "d.example"]
    client, result = run_scan(hosts)

    assert targets_written(client) == hosts
    assert result["summary"]["hosts_scanned"] == 4
    # naabu reads the same file the targets were written to
    (echo,) = [c for c in client.commands_starting("echo ") if "targets.txt" in c]
    (naabu,) = client.commands_starting("naabu ")
    assert naabu.startswith(f"naabu -list {echo.rpartition(' > ')[2]} ")


def test_a_single_quote_in_a_target_is_escaped_in_the_echo_command():
    client, _ = run_scan("evil'; touch /tmp/pwned; echo '")

    (echo,) = [c for c in client.commands_starting("echo ") if "targets.txt" in c]
    assert "'\\''" in echo
    # unquoting gives back exactly the target: the quote never ends the shell string
    assert targets_written(client) == ["evil'; touch /tmp/pwned; echo '"]


def test_naabu_gets_the_normalised_top_ports_value():
    for top_ports, expected in ((50, "100"), (100, "100"), (500, "1000"), (5000, "full")):
        client, _ = run_scan("scanme.example", top_ports=top_ports)
        (naabu,) = client.commands_starting("naabu ")
        assert f"-top-ports {expected} " in naabu
        assert PortScanWorkflow(client).normalize_top_ports(top_ports) == expected


def test_ports_are_grouped_by_host_from_naabu_json_lines():
    naabu = [
        {"host": "a.example", "port": 22},
        {"host": "a.example", "port": 3306},
        {"host": "b.example", "port": 22},
    ]
    _, result = run_scan(["a.example", "b.example"], naabu_findings=naabu)

    port_scan = result["steps"]["port_scan"]
    assert port_scan["by_host"] == {"a.example": [22, 3306], "b.example": [22]}
    assert port_scan["ports"] == [22, 3306]
    assert port_scan["unique_ports"] == 2
    assert port_scan["ports_found"] == 3
    assert port_scan["success"] is True
    assert result["summary"]["hosts_with_ports"] == 2


def test_httpx_is_not_called_without_a_web_port():
    client, result = run_scan("a.example", naabu_findings=[{"host": "a.example", "port": 22}])

    assert client.commands_starting("httpx ") == []
    assert not [c for c in client.commands_starting("echo ") if "httpx_input" in c]
    assert result["steps"]["http_services"] == {"success": True, "web_services_found": 0, "web_services": []}


def test_httpx_checks_every_web_port_that_was_found():
    naabu = [{"host": "a.example", "port": port} for port in [22, *WEB_PORTS]]
    httpx = [{"url": "https://a.example:443"}, {"url": "http://a.example:8080"}]
    client, result = run_scan("a.example", naabu_findings=naabu, httpx_findings=httpx)

    (echo,) = [c for c in client.commands_starting("echo ") if "httpx_input" in c]
    assert echo.split("'")[1].split("\n") == [
        "http://a.example:80", "https://a.example:443", "http://a.example:8000",
        "http://a.example:8080", "https://a.example:8443", "http://a.example:8888",
    ]
    assert len(client.commands_starting("httpx ")) == 1
    assert result["steps"]["http_services"]["web_services"] == [
        "https://a.example:443", "http://a.example:8080",
    ]
    assert result["summary"]["http_services"] == 2
