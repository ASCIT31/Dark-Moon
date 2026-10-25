import json
import logging
import shlex
from typing import List, Optional, Dict, Any, Tuple
from src.docker_client import DarkmoonDockerClient
from src.tools.core.allowlist import EXECUTOR_ALLOWED_TOOLS


# Configure logging for workflows
logger = logging.getLogger(__name__)


# Workflow steps share the GenericExecutor toolbox allowlist, with a small set of
# shell helpers needed for file setup/cleanup inside composed workflow commands.
# Keeping this derived from EXECUTOR_ALLOWED_TOOLS prevents workflows from
# drifting away from the tools the MCP executor actually permits.
WORKFLOW_INTERNAL_TOOLS = {
    "mkdir", "echo", "cat", "rm", "chmod", "touch", "ls", "cp", "mv",
}
ALLOWED_TOOLS = set(EXECUTOR_ALLOWED_TOOLS) | WORKFLOW_INTERNAL_TOOLS

# Dangerous patterns to block
BLOCKED_PATTERNS = [
    "rm -rf /",
    "rm -rf /*",
    "dd if=",
    "mkfs",
    ":(){ :|:& };:",
    "> /dev/sda",
]


class BaseWorkflow:
    """
    Template de base pour créer des workflows intelligents.
    Gère automatiquement : imports, parsing JSON, résultats, erreurs.

    Pour créer un nouveau workflow :
    1. Hériter de BaseWorkflow
    2. Implémenter votre méthode avec les commandes
    3. Utiliser self.execute_step() pour chaque étape
    """

    def __init__(self, docker_client: DarkmoonDockerClient):
        self.docker_client = docker_client
        self._step_errors: List[Dict[str, Any]] = []

    def _validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a command for safety before execution.

        Args:
            command: Command to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check for blocked patterns
        for pattern in BLOCKED_PATTERNS:
            if pattern in command:
                return False, f"Blocked dangerous pattern: {pattern}"

        # Extract first word (tool name) - handle shell operators
        try:
            # Split by common shell operators to get first command
            first_cmd = command.split("&&")[0].split("|")[0].split(";")[0].strip()
            parts = shlex.split(first_cmd)
            if not parts:
                return False, "Empty command"

            tool_name = parts[0].split("/")[-1]

            if tool_name not in ALLOWED_TOOLS:
                return False, f"Tool '{tool_name}' not allowed in workflows"

        except ValueError as e:
            return False, f"Command parsing error: {e}"

        return True, None

    def execute_step(
        self,
        step_name: str,
        command: str,
        timeout: int = 300,
        parse_json: bool = True,
        print_progress: bool = True,
        retry_count: int = 0,
        retry_delay: int = 5,
    ) -> Tuple[bool, List[Dict[str, Any]], str]:
        """
        Exécute une étape de workflow avec parsing automatique.

        Args:
            step_name: Nom de l'étape (ex: "Port scanning")
            command: Commande à exécuter
            timeout: Timeout en secondes
            parse_json: Parser le JSON automatiquement (default: True)
            print_progress: Afficher les messages de progression (default: True)
            retry_count: Nombre de tentatives en cas d'échec (default: 0)
            retry_delay: Délai entre les tentatives en secondes (default: 5)

        Returns:
            Tuple (success, findings, raw_output)
            - success: bool - True si la commande a réussi
            - findings: List[Dict] - Résultats parsés (vide si parse_json=False)
            - raw_output: str - Output brut de la commande
        """
        # Validate command first
        is_valid, error_msg = self._validate_command(command)
        if not is_valid:
            logger.error(f"Command validation failed for '{step_name}': {error_msg}")
            self._step_errors.append({
                "step": step_name,
                "error": error_msg,
                "type": "validation_error",
            })
            return False, [], ""

        if print_progress:
            logger.info(f"[*] {step_name}...")

        # Execute with retry logic
        attempts = 0
        max_attempts = retry_count + 1
        result = None
        last_error = None

        while attempts < max_attempts:
            attempts += 1
            result = self.docker_client.execute_command(command, timeout=timeout)

            if result.success:
                break

            last_error = result.stderr
            if attempts < max_attempts:
                logger.warning(
                    f"[!] {step_name} failed (attempt {attempts}/{max_attempts}), "
                    f"retrying in {retry_delay}s..."
                )
                import time
                time.sleep(retry_delay)

        # Parse JSON results if requested
        findings = []
        json_errors = []

        if parse_json and result.success and result.stdout:
            findings, json_errors = self._parse_json_lines_with_errors(result.stdout)

            # Log JSON parsing errors but don't fail the step
            if json_errors:
                logger.warning(
                    f"[!] {step_name}: {len(json_errors)} JSON parsing errors "
                    f"(got {len(findings)} valid findings)"
                )
                self._step_errors.append({
                    "step": step_name,
                    "json_errors": json_errors[:5],  # Limit to first 5 errors
                    "json_error_count": len(json_errors),
                    "type": "json_parse_warning",
                })

        if print_progress:
            if result.success:
                if parse_json:
                    logger.info(f"[+] {step_name} completed: {len(findings)} findings")
                else:
                    logger.info(f"[+] {step_name} completed")
            else:
                error_preview = (result.stderr or "Unknown error")[:100]
                logger.error(f"[!] {step_name} failed after {attempts} attempt(s): {error_preview}")
                self._step_errors.append({
                    "step": step_name,
                    "error": result.stderr,
                    "exit_code": result.exit_code,
                    "attempts": attempts,
                    "type": "execution_error",
                })

        return result.success, findings, result.stdout

    def _parse_json_lines_with_errors(
        self, output: str
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse JSON lines with error tracking.

        Args:
            output: Raw output containing JSON (one per line)

        Returns:
            Tuple of (findings, errors)
            - findings: Successfully parsed JSON objects
            - errors: Lines that failed to parse
        """
        findings = []
        errors = []

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Skip common log prefixes
            if line.startswith("[") and not line.startswith("[{"):
                continue  # Likely a log line like [INFO] or [*]

            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError as e:
                # Only track as error if it looks like it should be JSON
                if line.startswith("{") or line.startswith("["):
                    errors.append(f"Line: {line[:50]}... Error: {str(e)}")

        return findings, errors

    def _parse_json_lines(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse les lignes JSON (format utilisé par naabu, nuclei, etc.).

        Args:
            output: Output brut contenant des JSON (une ligne = un JSON)

        Returns:
            Liste de dictionnaires parsés
        """
        findings, _ = self._parse_json_lines_with_errors(output)
        return findings

    def get_step_errors(self) -> List[Dict[str, Any]]:
        """
        Get all errors that occurred during workflow execution.

        Returns:
            List of error dictionaries with step name, error type, and details
        """
        return self._step_errors.copy()

    def clear_step_errors(self) -> None:
        """Clear accumulated step errors."""
        self._step_errors.clear()

    def create_result_dict(
        self,
        workflow_name: str,
        target: str | List[str],
        steps: Dict[str, Any],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Crée la structure de résultat standardisée.

        Args:
            workflow_name: Nom du workflow
            target: Cible(s) du scan
            steps: Dictionnaire des étapes exécutées
            summary: Résumé des résultats

        Returns:
            Dictionnaire de résultats formaté
        """
        result = {
            "workflow": workflow_name,
            "target": target,
            "steps": steps,
            "summary": summary,
        }

        # Include any errors that occurred during execution
        if self._step_errors:
            result["errors"] = self._step_errors
            result["has_errors"] = True

            # Count error types
            error_summary = {}
            for err in self._step_errors:
                err_type = err.get("type", "unknown")
                error_summary[err_type] = error_summary.get(err_type, 0) + 1
            result["error_summary"] = error_summary

            # Clear errors after including them
            self.clear_step_errors()
        else:
            result["has_errors"] = False

        return result

    def extract_ports(self, findings: List[Dict[str, Any]]) -> List[int]:
        """
        Extrait les ports depuis les findings naabu.

        Args:
            findings: Résultats de naabu (format JSON)

        Returns:
            Liste de ports
        """
        ports = []
        for finding in findings:
            if "port" in finding:
                ports.append(finding["port"])
        return ports

    def count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Compte les findings par sévérité (pour nuclei).

        Args:
            findings: Résultats de nuclei (format JSON)

        Returns:
            Dictionnaire {severity: count}
        """
        severity_counts = {}
        for finding in findings:
            severity = finding.get("info", {}).get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts

    def write_temp_file(self, filename: str, content: str) -> str:
        """
        Écrit un fichier temporaire dans le container.

        Args:
            filename: Nom du fichier (ex: "targets.txt")
            content: Contenu à écrire

        Returns:
            Chemin complet du fichier
        """
        filepath = f"/tmp/{filename}"
        write_cmd = f'echo "{content}" > {filepath}'
        self.docker_client.execute_command(write_cmd, timeout=10)
        return filepath

    def normalize_top_ports(self, top_ports: int) -> str:
        """
        Normalise le paramètre top_ports pour naabu (100, 1000, ou full).

        Args:
            top_ports: Nombre de ports souhaité

        Returns:
            Valeur valide pour naabu ("100", "1000", ou "full")
        """
        if top_ports <= 100:
            return "100"
        elif top_ports <= 1000:
            return "1000"
        else:
            return "full"


# ============================================================================
# EXEMPLE DE WORKFLOW UTILISANT LE TEMPLATE
# ============================================================================


class ExampleWorkflow(BaseWorkflow):
    """
    Exemple de workflow utilisant BaseWorkflow.
    Démontre comment créer un workflow en quelques lignes.
    """

    def simple_scan(
        self,
        target: str,
        timeout: int = 600,
    ) -> Dict[str, Any]:
        """
        Exemple de workflow simple : port scan + vuln scan.

        Args:
            target: Cible à scanner
            timeout: Timeout total

        Returns:
            Résultats du workflow
        """
        steps = {}

        # Étape 1: Port scanning
        success, findings, output = self.execute_step(
            step_name="Port scanning with naabu",
            command=f"naabu -host {target} -top-ports 100 -json",
            timeout=timeout // 2,
        )
        steps["port_scan"] = {
            "success": success,
            "ports_found": len(findings),
            "ports": self.extract_ports(findings),
        }

        # Étape 2: Vulnerability scanning
        success, findings, output = self.execute_step(
            step_name="Vulnerability scanning with nuclei",
            command=f"nuclei -target {target} -severity critical,high -json -silent",
            timeout=timeout // 2,
        )
        steps["vuln_scan"] = {
            "success": success,
            "vulnerabilities_found": len(findings),
            "severity_breakdown": self.count_by_severity(findings),
            "vulnerabilities": findings,
        }

        # Résumé
        summary = {
            "total_ports": steps["port_scan"]["ports_found"],
            "total_vulnerabilities": steps["vuln_scan"]["vulnerabilities_found"],
        }

        return self.create_result_dict("simple_scan", target, steps, summary)
