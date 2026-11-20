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

import fcntl
import json
import logging
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

# Resolve data directory — use opencode's standard data dir so it lands in the
# volume-mounted path (e.g. ./darkmoon-settings or ./reports on the host).
# DARKMOON_DATA_DIR lets tests and local tools point at a copy of the data.
_OPENDATA_DIR = Path.home() / ".local" / "share" / "opencode"
DATA_DIR = Path(os.environ.get("DARKMOON_DATA_DIR", "").strip() or _OPENDATA_DIR)

PROJECTS_FILE = DATA_DIR / "projects.json"
TARGETS_FILE = DATA_DIR / "targets.json"
CAMPAIGNS_DIR = DATA_DIR / "campaigns"
INFRASTRUCTURE_DIR = DATA_DIR / "infrastructure"
VULNERABILITIES_DIR = DATA_DIR / "vulnerabilities"
REPORTS_DIR = DATA_DIR / "reports"

# The Pro stack keeps DATA_DIR on a tmpfs (see the compose tmpfs list) and binds a
# separate persistent volume for reports, announced through DARKMOON_REPORTS_DIR.
# Nothing read that variable, so generated reports were written to the tmpfs and
# vanished on the next container restart, while the host-side ./reports directory
# the operator actually looks at stayed empty. Honour it when it is set; Community
# and prod do not set it and keep writing into their volume-mounted data dir
# exactly as before.
_REPORTS_OVERRIDE = os.environ.get("DARKMOON_REPORTS_DIR", "").strip()
if _REPORTS_OVERRIDE:
    REPORTS_DIR = Path(_REPORTS_OVERRIDE)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Identifier safety (path traversal guard)
# ---------------------------------------------------------------------------
# Every per-campaign file is named after an id that reaches us from request data
# (path/query/body params, MCP tool arguments, or ids stored inside records). An
# id is only ever a file NAME: ASCII letters, digits, "_" and "-", starting with
# a letter or digit, at most 128 chars. Real ids are camp_YYYYMMDD_<8 alnum>
# (the run fragment is hex or an opencode root-session fragment); tests and the
# demo use free-form ids such as camp_demo_chaindemo, which the grammar keeps.
# No dot, slash, backslash, NUL, whitespace or non-ASCII character can pass, so
# "..", absolute paths and encoded variants are rejected before any filesystem
# call. _resolve_inside() additionally refuses a resolved path (symlinks
# followed) that leaves its directory.
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", re.ASCII)


class InvalidIdError(ValueError):
    """An identifier that cannot name a file inside the data directory."""


def is_safe_id(value: Any) -> bool:
    return isinstance(value, str) and _SAFE_ID_RE.fullmatch(value) is not None


def safe_campaign_id(value: Any) -> str:
    """Return ``value`` if it is a well-formed id, else raise InvalidIdError."""
    if not is_safe_id(value):
        raise InvalidIdError("invalid identifier")
    return value


def _resolve_inside(base: Path, name: Any, suffix: str = ".json") -> Path:
    """``base / f"{name}{suffix}"`` after checking ``name`` against the id grammar
    and that the resolved path (symlinks followed) stays inside ``base``.
    Raises InvalidIdError otherwise; never touches a file outside ``base``."""
    safe_campaign_id(name)
    path = Path(base) / f"{name}{suffix}"
    if not is_inside(base, path):
        raise InvalidIdError("identifier resolves outside its directory")
    return path


def is_inside(base: Path, path: Path) -> bool:
    """True if ``path`` (symlinks followed) resolves inside ``base``."""
    try:
        return Path(path).resolve().is_relative_to(Path(base).resolve())
    except (OSError, RuntimeError, ValueError):
        return False


def store_files(base: Path, pattern: str = "*.json") -> List[Path]:
    """Sorted ``base.glob(pattern)`` without the entries (planted symlinks) that
    resolve outside ``base``: the "scan every campaign" loaders never follow a
    link out of the store."""
    base = Path(base)
    if not base.exists():
        return []
    return [f for f in sorted(base.glob(pattern)) if is_inside(base, f)]


def campaign_path(campaign_id: Any) -> Path:
    return _resolve_inside(CAMPAIGNS_DIR, campaign_id)


def infrastructure_path(campaign_id: Any) -> Path:
    return _resolve_inside(INFRASTRUCTURE_DIR, campaign_id)


def vulnerabilities_path(campaign_id: Any) -> Path:
    return _resolve_inside(VULNERABILITIES_DIR, campaign_id)


def _read_json(path: Path) -> Any:
    """Read and parse a JSON file. Returns [] if file not found."""
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    """Write data as pretty-printed JSON, atomically (temp file + os.replace), so a
    reader never sees a truncated file (B-12)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o666 & ~_UMASK)  # mkstemp creates 0600: keep the permissions a plain open() would give
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_UMASK = os.umask(0)
os.umask(_UMASK)


@contextmanager
def locked(name: str):
    """Cross-process exclusive lock (fcntl.flock) for a read-modify-write on the
    data dir, e.g. ``with locked(f"vulns-{campaign_id}")``. Not re-entrant: take
    it once around the whole update (B-12)."""
    lock_dir = _shared_lock_dir()
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:120]
    fd = _open_lock(lock_dir / f"{safe}.lock")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# The lock files live in DATA_DIR/.locks and carry no data. Only the process that owns the store (the MCP server)
# takes them, so they are private to its user; a lock file that cannot be opened for writing is locked through a
# read-only descriptor (flock does not need write access).
LOCK_DIR_MODE = 0o700
LOCK_FILE_MODE = 0o600


def _shared_lock_dir() -> Path:
    lock_dir = DATA_DIR / ".locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    try:
        st = lock_dir.stat()
        if st.st_uid == os.geteuid() and (st.st_mode & 0o7777) != LOCK_DIR_MODE:
            os.chmod(lock_dir, LOCK_DIR_MODE)
    except OSError:
        pass
    return lock_dir


def _open_lock(path: Path) -> int:
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, LOCK_FILE_MODE)
    except PermissionError:
        return os.open(str(path), os.O_RDONLY)
    try:
        st = os.fstat(fd)
        if st.st_uid == os.geteuid() and (st.st_mode & 0o777) != LOCK_FILE_MODE:
            os.fchmod(fd, LOCK_FILE_MODE)
    except OSError:
        pass
    return fd


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
        for f in store_files(CAMPAIGNS_DIR):
            try:
                data = _read_json(f)
            except (OSError, ValueError):
                # One unreadable file must not take the whole list down (B-12).
                logging.getLogger("darkmoon.storage").warning("unreadable campaign file %s", f.name)
                continue
            if isinstance(data, dict):
                campaigns.append(data)
            elif isinstance(data, list):
                campaigns.extend(data)
    return campaigns


def load_campaign(campaign_id: str) -> Optional[Dict[str, Any]]:
    """Load a single campaign by ID. A malformed id is simply "not found" (no
    filesystem access, so no existence oracle)."""
    try:
        direct = campaign_path(campaign_id)
    except InvalidIdError:
        return None
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
    path = campaign_path(campaign.get("id", "unknown"))
    _write_json(path, campaign)


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

def load_infrastructure(campaign_id: str) -> List[Dict[str, Any]]:
    """Load infrastructure nodes for a campaign ([] for a malformed id)."""
    try:
        path = infrastructure_path(campaign_id)
    except InvalidIdError:
        return []
    data = _read_json(path)
    if isinstance(data, list):
        return data
    return []


def save_infrastructure(campaign_id: str, nodes: List[Dict[str, Any]]) -> None:
    """Save infrastructure nodes for a campaign."""
    path = infrastructure_path(campaign_id)
    _write_json(path, nodes)


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

def load_vulnerabilities(campaign_id: str) -> List[Dict[str, Any]]:
    """Load vulnerabilities for a campaign ([] for a malformed id)."""
    try:
        path = vulnerabilities_path(campaign_id)
    except InvalidIdError:
        return []
    data = _read_json(path)
    if isinstance(data, list):
        return data
    return []


def load_all_vulnerabilities() -> List[Dict[str, Any]]:
    """Load all vulnerabilities from all campaign files."""
    all_vulns = []
    if VULNERABILITIES_DIR.exists():
        for f in store_files(VULNERABILITIES_DIR):
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
    path = vulnerabilities_path(campaign_id)
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
    """Open findings of one campaign (exec_core: quarantined / false-positive findings are counted nowhere)."""
    from api.exec_core import stats as _core_stats
    return len(_core_stats.open_findings(load_vulnerabilities(campaign_id)))


def count_open_vulnerabilities_for_target(target_id: str) -> int:
    """Distinct open weaknesses of the target's reference campaign (last complete, else latest), as in Pro.
    It used to sum every campaign of the target, counting a weakness found by three campaigns three times."""
    from api.exec_core import project as _core_project, stats as _core_stats
    ref = _core_project.reference_campaign([c for c in load_campaigns() if c.get("target_id") == target_id])
    if not ref:
        return 0
    return len(_core_stats.open_fingerprints(load_vulnerabilities(ref.get("id", "")), target_id))


# ---------------------------------------------------------------------------
# Reports (Markdown)
# ---------------------------------------------------------------------------

def _report_file(base: Path, fname: str) -> Optional[Path]:
    """``base/fname`` if it is a regular report file that resolves inside ``base``."""
    candidate = Path(base) / fname
    try:
        return candidate if is_inside(base, candidate) and candidate.is_file() else None
    except (OSError, ValueError):
        return None


def load_report_content(report_path: str) -> Optional[str]:
    """
    Load a markdown report file.

    report_path is what the store writes in campaign.report_path, i.e.
    ``/reports/<filename>.md`` (a bare filename is accepted too). Only the
    file NAME is used, and it is looked up in DATA_DIR/reports and REPORTS_DIR
    only: an absolute path or ``..`` never reaches another file (traversal
    guard; the store never wrote anything else).
    """
    if not isinstance(report_path, str) or "\x00" in report_path:
        return None
    fname = Path(report_path.replace("\\", "/")).name
    if not fname or fname.startswith(".") or not fname.endswith(".md"):
        return None
    for base in (DATA_DIR / "reports", REPORTS_DIR):
        found = _report_file(base, fname)
        if found is not None:
            return found.read_text(encoding="utf-8")
    return None


def list_reports() -> List[str]:
    """List all report filenames."""
    if REPORTS_DIR.exists():
        return [f.name for f in store_files(REPORTS_DIR, "*.md")]
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