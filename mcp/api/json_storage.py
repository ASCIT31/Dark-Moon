"""
Darkmoon Dashboard — JSON Storage Layer

Reads/writes all data from filesystem JSON files.
No database. Pure JSON file storage.

Directory layout:
    data/
    ├── projects.json
    ├── targets.json
    ├── campaigns/
    │   └── camp_XXXX.json
    ├── infrastructure/
    │   └── camp_XXXX.json
    ├── vulnerabilities/
    │   └── camp_XXXX.json
    └── reports/
        └── *.md
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# Resolve data directory relative to the MCP server root
_API_DIR = Path(__file__).resolve().parent          # .../server/api
_SERVER_DIR = _API_DIR.parent                        # .../server
DATA_DIR = _SERVER_DIR / "data"

PROJECTS_FILE = DATA_DIR / "projects.json"
TARGETS_FILE = DATA_DIR / "targets.json"
CAMPAIGNS_DIR = DATA_DIR / "campaigns"
INFRASTRUCTURE_DIR = DATA_DIR / "infrastructure"
VULNERABILITIES_DIR = DATA_DIR / "vulnerabilities"
REPORTS_DIR = DATA_DIR / "reports"


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    """Read and parse a JSON file. Returns [] if file not found."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    """Write data as pretty-printed JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

def load_projects() -> List[Dict[str, Any]]:
    """Load all projects from projects.json."""
    return _read_json(PROJECTS_FILE)


def load_project(project_id: str) -> Optional[Dict[str, Any]]:
    """Load a single project by ID."""
    for p in load_projects():
        if p.get("id") == project_id:
            return p
    return None


def save_project(project: Dict[str, Any]) -> None:
    """Upsert a project into projects.json."""
    projects = load_projects()
    for i, p in enumerate(projects):
        if p.get("id") == project.get("id"):
            projects[i] = project
            _write_json(PROJECTS_FILE, projects)
            return
    projects.append(project)
    _write_json(PROJECTS_FILE, projects)


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def load_targets() -> List[Dict[str, Any]]:
    """Load all targets from targets.json."""
    return _read_json(TARGETS_FILE)


def load_target(target_id: str) -> Optional[Dict[str, Any]]:
    """Load a single target by ID."""
    for t in load_targets():
        if t.get("id") == target_id:
            return t
    return None


def save_target(target: Dict[str, Any]) -> None:
    """Upsert a target into targets.json."""
    targets = load_targets()
    for i, t in enumerate(targets):
        if t.get("id") == target.get("id"):
            targets[i] = target
            _write_json(TARGETS_FILE, targets)
            return
    targets.append(target)
    _write_json(TARGETS_FILE, targets)


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

def load_campaigns() -> List[Dict[str, Any]]:
    """Load all campaigns from campaigns/ directory."""
    campaigns = []
    if CAMPAIGNS_DIR.exists():
        for f in sorted(CAMPAIGNS_DIR.glob("*.json")):
            data = _read_json(f)
            if isinstance(data, dict):
                campaigns.append(data)
            elif isinstance(data, list):
                campaigns.extend(data)
    return campaigns


def load_campaign(campaign_id: str) -> Optional[Dict[str, Any]]:
    """Load a single campaign by ID."""
    # Try direct file first
    direct = CAMPAIGNS_DIR / f"{campaign_id}.json"
    if direct.exists():
        data = _read_json(direct)
        if isinstance(data, dict):
            return data
    # Fallback: scan all campaign files
    for c in load_campaigns():
        if c.get("id") == campaign_id:
            return c
    return None


def save_campaign(campaign: Dict[str, Any]) -> None:
    """Save a campaign to campaigns/<campaign_id>.json."""
    campaign_id = campaign.get("id", "unknown")
    path = CAMPAIGNS_DIR / f"{campaign_id}.json"
    _write_json(path, campaign)


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

def load_infrastructure(campaign_id: str) -> List[Dict[str, Any]]:
    """Load infrastructure nodes for a campaign."""
    path = INFRASTRUCTURE_DIR / f"{campaign_id}.json"
    data = _read_json(path)
    if isinstance(data, list):
        return data
    return []


def save_infrastructure(campaign_id: str, nodes: List[Dict[str, Any]]) -> None:
    """Save infrastructure nodes for a campaign."""
    path = INFRASTRUCTURE_DIR / f"{campaign_id}.json"
    _write_json(path, nodes)


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

def load_vulnerabilities(campaign_id: str) -> List[Dict[str, Any]]:
    """Load vulnerabilities for a campaign."""
    path = VULNERABILITIES_DIR / f"{campaign_id}.json"
    data = _read_json(path)
    if isinstance(data, list):
        return data
    return []


def load_all_vulnerabilities() -> List[Dict[str, Any]]:
    """Load all vulnerabilities from all campaign files."""
    all_vulns = []
    if VULNERABILITIES_DIR.exists():
        for f in sorted(VULNERABILITIES_DIR.glob("*.json")):
            data = _read_json(f)
            if isinstance(data, list):
                all_vulns.extend(data)
    return all_vulns


def load_vulnerability(vuln_id: str) -> Optional[Dict[str, Any]]:
    """Load a single vulnerability by ID (scans all files)."""
    for v in load_all_vulnerabilities():
        if v.get("id") == vuln_id:
            return v
    return None


def save_vulnerabilities(campaign_id: str, vulns: List[Dict[str, Any]]) -> None:
    """Save vulnerabilities for a campaign."""
    path = VULNERABILITIES_DIR / f"{campaign_id}.json"
    _write_json(path, vulns)


# ---------------------------------------------------------------------------
# Vulnerability helpers
# ---------------------------------------------------------------------------

def _normalize_vulnerability_status(status: Any) -> str:
    return str(status or "unconfirmed").strip().lower()


def _is_open_vulnerability(vuln: Dict[str, Any]) -> bool:
    status = _normalize_vulnerability_status(vuln.get("status"))
    return status not in {"remediated", "resolved", "closed", "fixed"}


def count_open_vulnerabilities_for_campaign(campaign_id: str) -> int:
    return sum(1 for vuln in load_vulnerabilities(campaign_id) if _is_open_vulnerability(vuln))


def count_open_vulnerabilities_for_target(target_id: str) -> int:
    total = 0
    for campaign in load_campaigns():
        if campaign.get("target_id") == target_id:
            total += count_open_vulnerabilities_for_campaign(campaign.get("id", ""))
    return total


# ---------------------------------------------------------------------------
# Reports (Markdown)
# ---------------------------------------------------------------------------

def load_report_content(report_path: str) -> Optional[str]:
    """
    Load a markdown report file.

    report_path can be:
      - An absolute path
      - A relative path like /reports/filename.md (relative to data dir)
      - Just a filename
    """
    # Try as relative to data dir (strip leading /)
    clean = report_path.lstrip("/")
    candidate = DATA_DIR / clean
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")

    # Try in reports dir directly
    fname = Path(report_path).name
    candidate = REPORTS_DIR / fname
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")

    # Try as absolute
    abs_path = Path(report_path)
    if abs_path.exists():
        return abs_path.read_text(encoding="utf-8")

    return None


def list_reports() -> List[str]:
    """List all report filenames."""
    if REPORTS_DIR.exists():
        return [f.name for f in sorted(REPORTS_DIR.glob("*.md"))]
    return []

# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def find_target_by_host_or_ip(host: Optional[str] = None, ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Find a target by host or IP.
    Host match is case-insensitive, with subdomain fallback:
    - Exact match wins
    - Then: if queried host is a subdomain of a stored target host, return that target
      (e.g. wp.example.com -> example.com)
    """
    host_norm = (host or "").strip().lower()
    # Strip scheme/path if accidentally included (e.g. https://example.com)
    if "://" in host_norm:
        host_norm = host_norm.split("://", 1)[1].split("/")[0]
    ip_norm = (ip or "").strip()

    subdomain_match = None

    for t in load_targets():
        t_host = str(t.get("host", "")).strip().lower()
        t_ip = str(t.get("ip", "")).strip()

        # Exact match — highest priority
        if host_norm and t_host == host_norm:
            return t
        if ip_norm and t_ip == ip_norm:
            return t

        # Subdomain match — queried host ends with .{stored_host}
        if host_norm and t_host and host_norm.endswith("." + t_host):
            if subdomain_match is None:
                subdomain_match = t

    return subdomain_match


def find_project_by_target_id(target_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Find the unique project linked to a target_id."""
    if not target_id:
        return None

    for p in load_projects():
        if p.get("target_id") == target_id:
            return p

    return None