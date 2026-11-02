"""
DarkMoon Web UI — backend.

Wraps the open-source DarkMoon engine (docker stack + MCP server + 50 specialist
agents) with an HTTP API and a browser dashboard. Nothing in the engine is
modified: the UI talks to the running containers over the Docker socket and reads
the same JSON/Markdown stores the MCP writes.

Endpoints
---------
GET  /api/overview              dashboard counters + severity breakdown
GET  /api/status                stack / container / MCP health
GET  /api/campaigns             campaigns from the dashboard JSON store
GET  /api/campaigns/{id}        one campaign (+ findings + infra nodes)
GET  /api/findings              findings, filterable by campaign/severity/status
GET  /api/infra/{campaign_id}   infrastructure nodes for a campaign
GET  /api/reports               markdown reports on disk
GET  /api/reports/{name}        one report (markdown)
GET  /api/sessions              opencode session logs on disk
GET  /api/sessions/{name}       one session log
GET  /api/agents                the 51 agent prompts shipped in the repo
GET  /api/agent/{name}          one agent prompt
GET  /api/tools                 MCP allowlist + workflows
GET  /api/env                   LLM provider configuration (secrets masked)
POST /api/env                   write .opencode.env
POST /api/launch                start a new assessment (returns job id)
GET  /api/jobs                  running / finished jobs
GET  /api/jobs/{id}             one job
GET  /api/jobs/{id}/stream      SSE live console of the job
POST /api/jobs/{id}/stop        stop a running job
POST /api/stack/{action}        up | down | restart | logs
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO = Path(os.environ.get("DARKMOON_REPO", "/repo")).resolve()
if not (REPO / "docker-compose.yml").exists():
    # Running straight on the host, from the repo checkout.
    REPO = Path(__file__).resolve().parent.parent

DATA_DIR = Path(os.environ.get("DARKMOON_DATA_DIR", REPO / "darkmoon-settings"))
REPORTS_DIR = Path(os.environ.get("DARKMOON_REPORTS_DIR", REPO / "reports"))
SESSIONS_DIR = Path(os.environ.get("DARKMOON_SESSIONS_DIR", REPO / "sessions"))
CONF_DIR = REPO / "conf"
MCP_DIR = REPO / "mcp"
ENV_FILE = REPO / ".opencode.env"
STATIC_DIR = Path(__file__).resolve().parent / "static"

OPENCODE_CONTAINER = os.environ.get("DARKMOON_OPENCODE_CONTAINER", "opencode")
TOOLBOX_CONTAINER = os.environ.get("DARKMOON_TOOLBOX_CONTAINER", "darkmoon")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _list_json_dir(path: Path) -> List[Any]:
    out: List[Any] = []
    if not path.exists():
        return out
    for f in sorted(path.glob("*.json")):
        data = _read_json(f, None)
        if isinstance(data, list):
            out.extend(data)
        elif isinstance(data, dict):
            out.append(data)
    return out


# ---------------------------------------------------------------------------
# Docker access
# ---------------------------------------------------------------------------

def _docker():
    import docker  # imported lazily so the API still boots without the socket

    return docker.from_env()


def _container(name: str):
    cli = _docker()
    return cli.containers.get(name)


def _docker_available() -> bool:
    try:
        _docker().ping()
        return True
    except Exception:
        return False


def _container_info(name: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "name": name,
        "present": False,
        "running": False,
        "status": "missing",
        "image": None,
        "started_at": None,
    }
    try:
        c = _container(name)
    except Exception as exc:  # pragma: no cover - depends on host state
        if type(exc).__name__ == "NotFound":
            return info
        info["status"] = f"unreachable: {type(exc).__name__}"
        return info
    if c is None:
        return info
    info["present"] = True
    info["running"] = bool(c.status == "running")
    info["status"] = c.status
    try:
        info["image"] = c.image.tags[0] if c.image.tags else None
    except Exception:
        pass
    try:
        c.reload()
        info["started_at"] = c.attrs.get("State", {}).get("StartedAt")
    except Exception:
        pass
    return info


def _exec_in_container(
    name: str, cmd: List[str], timeout: int = 30, environment: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    try:
        c = _container(name)
        if c is None:
            return {"ok": False, "stdout": "", "stderr": f"container {name} not found"}
        res = c.exec_run(cmd, stdout=True, stderr=True, demux=True, environment=environment)
        out = (res.output or (b"", b""))[0] or b""
        err = (res.output or (b"", b""))[1] or b""
        return {
            "ok": res.exit_code == 0,
            "exit_code": res.exit_code,
            "stdout": out.decode("utf-8", "replace"),
            "stderr": err.decode("utf-8", "replace"),
        }
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Data store readers (mirror of mcp/api/json_storage.py)
# ---------------------------------------------------------------------------

def load_projects() -> List[Dict[str, Any]]:
    data = _read_json(DATA_DIR / "projects.json", [])
    return data if isinstance(data, list) else []


def load_targets() -> List[Dict[str, Any]]:
    data = _read_json(DATA_DIR / "targets.json", [])
    return data if isinstance(data, list) else []


def load_campaigns() -> List[Dict[str, Any]]:
    return [c for c in _list_json_dir(DATA_DIR / "campaigns") if isinstance(c, dict)]


def load_vulns(campaign_id: Optional[str] = None) -> List[Dict[str, Any]]:
    if campaign_id:
        data = _read_json(DATA_DIR / "vulnerabilities" / f"{campaign_id}.json", [])
        return data if isinstance(data, list) else []
    return [v for v in _list_json_dir(DATA_DIR / "vulnerabilities") if isinstance(v, dict)]


def load_infra(campaign_id: str) -> List[Dict[str, Any]]:
    data = _read_json(DATA_DIR / "infrastructure" / f"{campaign_id}.json", [])
    return data if isinstance(data, list) else []


def _campaign_sort_key(c: Dict[str, Any]) -> str:
    return str(c.get("started_at") or c.get("created_at") or c.get("id") or "")


# ---------------------------------------------------------------------------
# Sessions (opencode sqlite db + markdown logs)
# ---------------------------------------------------------------------------

def _sqlite_sessions() -> List[Dict[str, Any]]:
    db = DATA_DIR / "opencode-dev.db"
    if not db.exists():
        return []
    tmp = Path(tempfile.gettempdir()) / f"dm_sessions_{uuid.uuid4().hex}.db"
    try:
        shutil.copy2(db, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=2)
        try:
            cur = conn.execute(
                "SELECT id, parent_id, title, time_created, time_updated FROM session "
                "ORDER BY time_created DESC LIMIT 200"
            )
            rows = cur.fetchall()
        finally:
            conn.close()
        return [
            {
                "id": r[0],
                "parent_id": r[1],
                "title": r[2] or "",
                "created_at": r[3],
                "updated_at": r[4],
                "root": r[1] is None,
            }
            for r in rows
        ]
    except Exception:
        return []
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _md_files(directory: Path) -> List[Dict[str, Any]]:
    if not directory.exists():
        return []
    out = []
    for f in sorted(directory.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            st = f.stat()
        except OSError:
            continue
        out.append(
            {
                "name": f.name,
                "size": st.st_size,
                "modified_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(
                    timespec="seconds"
                ),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

def _agent_meta(md_path: Path) -> Dict[str, Any]:
    text = md_path.read_text(encoding="utf-8", errors="replace")
    head = text[:4000]
    desc = ""
    m = re.search(r"^description:\s*(.+)$", head, re.MULTILINE)
    if m:
        desc = m.group(1).strip().strip('"').strip("'")
    if not desc:
        for line in head.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-", "|", ">", "`")) and len(line) > 30:
                desc = line
                break
    return {
        "file": md_path.name,
        "name": md_path.stem,
        "description": desc[:280],
        "bytes": len(text),
        "lines": text.count("\n") + 1,
        "primary": md_path.stem == "pentest",
    }


def load_agents() -> List[Dict[str, Any]]:
    agents_dir = CONF_DIR / "agents"
    if not agents_dir.exists():
        return []
    agents = [_agent_meta(p) for p in sorted(agents_dir.glob("*.md"))]
    agents.sort(key=lambda a: (not a["primary"], a["name"]))
    return agents


# ---------------------------------------------------------------------------
# MCP tools / workflows
# ---------------------------------------------------------------------------

def load_tools() -> Dict[str, Any]:
    allowlist_file = MCP_DIR / "src" / "tools" / "core" / "allowlist.py"
    tools: List[str] = []
    if allowlist_file.exists():
        text = allowlist_file.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"EXECUTOR_ALLOWED_TOOLS\s*[:=].*?[\[{(](.*?)[\]})]", text, re.S)
        if m:
            tools = re.findall(r"[\"']([^\"']+)[\"']", m.group(1))
    workflows: List[Dict[str, Any]] = []
    wf_dir = MCP_DIR / "src" / "tools" / "workflows"
    if wf_dir.exists():
        for p in sorted(wf_dir.glob("*.py")):
            if p.stem.startswith("_") or p.stem == "TEMPLATE":
                continue
            workflows.append({"name": p.stem, "file": p.name})
    return {"allowed_tools": sorted(set(tools)), "count": len(set(tools)), "workflows": workflows}


# ---------------------------------------------------------------------------
# Job runner (live assessments)
# ---------------------------------------------------------------------------

class Job:
    def __init__(self, job_id: str, target: str, prompt: str, cmd: List[str], kind: str = "assessment"):
        self.id = job_id
        self.target = target
        self.prompt = prompt
        self.cmd = cmd
        self.kind = kind
        self.status = "starting"
        self.started_at = _now()
        self.finished_at: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.lines: List[str] = []
        self.events: List[Dict[str, Any]] = []
        self.session_id: Optional[str] = None
        self.error: Optional[str] = None
        self._subscribers: List[asyncio.Queue] = []
        self._task: Optional[asyncio.Task] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "prompt": self.prompt,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "session_id": self.session_id,
            "error": self.error,
            "lines": len(self.lines),
            "events": self.events[-200:],
            "command": " ".join(self.cmd),
            "kind": self.kind,
        }


JOBS: "OrderedDict[str, Job]" = OrderedDict()

# Short-lived cache for GET /api/status (see status()).
_STATUS_CACHE: Optional[tuple] = None

_SESSION_RE = re.compile(r"darkmoon\.sh\s+--log\s+([A-Za-z0-9_\-]+)")
_CAMPAIGN_RE = re.compile(r"camp_[0-9]{8}_[A-Za-z0-9_\-]+")


def _classify(line: str) -> Optional[Dict[str, Any]]:
    """Heuristic event classification for the live feed."""
    low = line.lower()
    if "error" in low or "failed" in low or "exception" in low:
        return {"kind": "error", "text": line[:400]}
    if "vulnerab" in low or "finding" in low or "exploit" in low:
        return {"kind": "finding", "text": line[:400]}
    if re.search(r"\b(find|scan|enumerat|detect|fingerprint)\w*\b", low):
        return {"kind": "recon", "text": line[:400]}
    if "$ " in line or line.strip().startswith("> "):
        return {"kind": "command", "text": line[:400]}
    if "agent" in low:
        return {"kind": "agent", "text": line[:400]}
    return None


def _broadcast(job: Job, payload: Dict[str, Any]) -> None:
    for q in list(job._subscribers):
        try:
            q.put_nowait(payload)
        except Exception:
            pass


_SECRET_ENV_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:API_KEY|APIKEY|SECRET|PASSWORD|TOKEN|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*(\S+)"
)
# Bare credential shapes that show up in tool output regardless of the variable
# name (env dumps, config files, curl headers, .env echoes).
_SECRET_VALUE_RES = [
    re.compile(r"sk-or-v1-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-cp-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]


def _redact(text: str) -> str:
    """Mask credentials before they reach the browser or the job buffer.

    An agent that runs `env` or `cat .env` prints the engine's provider keys
    straight into the console. The live console is served over SSE without
    authentication, so those keys would otherwise be readable by anyone who can
    reach the Web UI — and stored in the job buffer, which the SSE endpoint
    replays.
    """
    if not text:
        return text

    def _mask_kv(m: "re.Match[str]") -> str:
        name, val = m.group(1), m.group(2)
        if len(val) <= 6:
            return f"{name}=***"
        return f"{name}={val[:4]}…{val[-2:]}***"

    out = _SECRET_ENV_RE.sub(_mask_kv, text)
    for rx in _SECRET_VALUE_RES:
        out = rx.sub(lambda m: m.group(0)[:6] + "…" + m.group(0)[-2:] + "***", out)
    return out


def _push_line(job: Job, line: str) -> None:
    line = _redact(line)
    job.lines.append(line)
    if len(job.lines) > 4000:
        del job.lines[:1000]
    ev = _classify(line)
    if ev:
        ev["ts"] = _now()
        job.events.append(ev)
        if len(job.events) > 1000:
            del job.events[:1000]
    _broadcast(job, {"type": "line", "line": line, "ts": _now()})
    if ev:
        _broadcast(job, {"type": "event", "event": ev})


def _pump_exec_stream(job: Job, stream: Any, loop: asyncio.AbstractEventLoop, q: "asyncio.Queue") -> None:
    """Drain the exec output into an asyncio queue from a DEDICATED thread.

    This must not run on the loop's default executor. The default executor is
    shared with every other blocking Docker call the API makes (the status
    poll, the overview, the stack actions). When those pile up, no worker is
    left to run `next(stream)`, the exec pipe fills up, and the assessment
    process blocks forever on write — the run looks "running" but produces
    nothing. A dedicated thread cannot be starved that way.
    """
    try:
        while True:
            chunk = next(stream, None)
            if chunk is None:
                break
            loop.call_soon_threadsafe(q.put_nowait, chunk)
    except Exception as exc:  # pragma: no cover - defensive
        loop.call_soon_threadsafe(q.put_nowait, ("__error__", exc))
    finally:
        loop.call_soon_threadsafe(q.put_nowait, None)


async def _run_job(job: Job) -> None:
    loop = asyncio.get_running_loop()
    try:
        cli = await loop.run_in_executor(None, _docker)
        container = await loop.run_in_executor(None, lambda: cli.containers.get(OPENCODE_CONTAINER))
    except Exception as exc:
        job.status = "failed"
        job.error = f"{type(exc).__name__}: {exc}"
        job.finished_at = _now()
        _broadcast(job, {"type": "end", "status": job.status, "error": job.error})
        return

    job.status = "running"
    _broadcast(job, {"type": "status", "status": job.status})

    try:
        raw = await loop.run_in_executor(
            None,
            lambda: container.exec_run(job.cmd, stdout=True, stderr=True, demux=True, stream=True),
        )
        # exec_run(stream=True) returns an ExecResult whose .output is a generator.
        stream = getattr(raw, "output", raw)
        if stream is None:
            raise RuntimeError(f"no output stream from exec: {raw!r}")

        q: asyncio.Queue = asyncio.Queue()
        reader = threading.Thread(
            target=_pump_exec_stream, args=(job, stream, loop, q), daemon=True
        )
        reader.start()

        while True:
            chunk = await q.get()
            if chunk is None:
                break
            if isinstance(chunk, tuple) and len(chunk) == 2 and chunk[0] == "__error__":
                raise chunk[1]
            out, err = chunk if isinstance(chunk, tuple) else (chunk, b"")
            for raw_bytes in (out or b"", err or b""):
                text = raw_bytes.decode("utf-8", "replace") if raw_bytes else ""
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    _push_line(job, line)
                    m = _SESSION_RE.search(line)
                    if m:
                        job.session_id = m.group(1)
                        _broadcast(job, {"type": "session", "session_id": job.session_id})
                    c = _CAMPAIGN_RE.search(line)
                    if c:
                        _broadcast(job, {"type": "campaign", "campaign_id": c.group(0)})
        job.status = "completed"
        job.exit_code = 0
    except Exception as exc:
        job.status = "failed"
        job.error = f"{type(exc).__name__}: {exc}"
    finally:
        job.finished_at = _now()
        _broadcast(job, {"type": "end", "status": job.status, "error": job.error})


def build_prompt(payload: Dict[str, Any]) -> str:
    target = (payload.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    parts = [f"TARGET: {target}"]
    for key, env in (
        ("program", "PROGRAM"),
        ("focus", "FOCUS"),
        ("noise", "NOISE"),
        ("format", "FORMAT"),
        ("scope", "SCOPE"),
        ("creds", "CREDS"),
        ("methodology", "METHODOLOGY"),
        ("note", "NOTE"),
    ):
        val = (payload.get(key) or "").strip()
        if val:
            parts.append(f'{env}="{val}"')
    return " ".join(parts)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="DarkMoon Web UI", version="1.0.0", docs_url="/api/docs")


@app.get("/", response_class=HTMLResponse)
def index() -> Any:
    f = STATIC_DIR / "index.html"
    if f.exists():
        return HTMLResponse(f.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>DarkMoon Web UI</h1><p>static/index.html missing</p>")


@app.get("/api/overview")
def overview() -> Dict[str, Any]:
    campaigns = load_campaigns()
    vulns = load_vulns()
    sev = Counter(str(v.get("severity", "info")).lower() for v in vulns)
    status = Counter(str(c.get("status", "unknown")).lower() for c in campaigns)
    agents = load_agents()
    reports = _md_files(REPORTS_DIR)
    return {
        "generated_at": _now(),
        "campaigns": {
            "total": len(campaigns),
            "running": status.get("running", 0),
            "completed": status.get("completed", 0) + status.get("finished", 0),
            "by_status": dict(status),
        },
        "findings": {
            "total": len(vulns),
            "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
            "open": sum(
                1
                for v in vulns
                if str(v.get("status", "unconfirmed")).lower()
                not in {"remediated", "resolved", "closed", "fixed"}
            ),
        },
        "targets": len(load_targets()),
        "projects": len(load_projects()),
        "agents": len(agents),
        "reports": len(reports),
        "sessions": len(_md_files(SESSIONS_DIR)),
        "tools": load_tools()["count"],
        "recent_campaigns": sorted(campaigns, key=_campaign_sort_key, reverse=True)[:8],
        "recent_reports": reports[:8],
        "stack": {
            "opencode": _container_info(OPENCODE_CONTAINER),
            "darkmoon": _container_info(TOOLBOX_CONTAINER),
        },
    }


@app.get("/api/status")
def status() -> Dict[str, Any]:
    # The dashboard polls this every 15s. It shells into the engine container
    # (to probe the MCP port), and every one of those is a Docker API call. Left
    # uncached they pile up on the same executor the job runner uses and can
    # starve it, so the result is cached briefly.
    global _STATUS_CACHE
    cached = _STATUS_CACHE
    if cached and (time.time() - cached[0]) < 10:
        return cached[1]
    out = _status_uncached()
    _STATUS_CACHE = (time.time(), out)
    return out


def _status_uncached() -> Dict[str, Any]:
    mcp = _exec_in_container(
        OPENCODE_CONTAINER,
        [
            "python3",
            "-c",
            "import socket,sys\n"
            "s=socket.socket();s.settimeout(3)\n"
            "r=s.connect_ex(('127.0.0.1',8181))\n"
            "sys.exit(0 if r==0 else 1)",
        ],
        timeout=10,
    )
    env = _read_env()
    return {
        "docker": _docker_available(),
        "containers": {
            "opencode": _container_info(OPENCODE_CONTAINER),
            "darkmoon": _container_info(TOOLBOX_CONTAINER),
        },
        "mcp_reachable": bool(mcp.get("ok")),
        "provider_configured": bool(
            env.get("OPENCODE_MODEL")
            or env.get("OPENCODE_LOCAL_MODEL")
            or env.get("ANTHROPIC_MODEL")
        ),
        "provider_mode": (
            "local"
            if env.get("OPENCODE_LOCAL_MODE")
            else "anthropic"
            if env.get("ANTHROPIC_BASE_URL")
            else "cloud"
            if env.get("OPENROUTER_PROVIDER")
            else "none"
        ),
        "paths": {
            "repo": str(REPO),
            "data": str(DATA_DIR),
            "reports": str(REPORTS_DIR),
            "sessions": str(SESSIONS_DIR),
        },
        "jobs": [j.to_dict() for j in JOBS.values()],
    }


# -- campaigns / findings / infra -------------------------------------------

@app.get("/api/campaigns")
def campaigns() -> Dict[str, Any]:
    out = sorted(load_campaigns(), key=_campaign_sort_key, reverse=True)
    for c in out:
        cid = str(c.get("id", ""))
        c["findings_count"] = len(load_vulns(cid))
        c["nodes_count"] = len(load_infra(cid))
    return {"campaigns": out, "targets": load_targets(), "projects": load_projects()}


@app.get("/api/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str) -> Dict[str, Any]:
    for c in load_campaigns():
        if str(c.get("id")) == campaign_id:
            return {
                "campaign": c,
                "findings": load_vulns(campaign_id),
                "infrastructure": load_infra(campaign_id),
            }
    raise HTTPException(404, "campaign not found")


@app.get("/api/findings")
def findings(
    campaign_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
) -> Dict[str, Any]:
    items = load_vulns(campaign_id)
    if severity and severity.lower() != "all":
        items = [v for v in items if str(v.get("severity", "")).lower() == severity.lower()]
    if status and status.lower() != "all":
        items = [v for v in items if str(v.get("status", "")).lower() == status.lower()]
    if q:
        needle = q.lower()
        items = [
            v
            for v in items
            if needle
            in json.dumps(v, ensure_ascii=False).lower()
        ]
    items.sort(
        key=lambda v: (
            SEV_RANK.get(str(v.get("severity", "info")).lower(), 9),
            -float(v.get("cvss_score") or 0),
        )
    )
    return {"findings": items, "count": len(items)}


@app.get("/api/infra/{campaign_id}")
def infra(campaign_id: str) -> Dict[str, Any]:
    return {"campaign_id": campaign_id, "nodes": load_infra(campaign_id)}


# -- reports / sessions ------------------------------------------------------

@app.get("/api/reports")
def reports() -> Dict[str, Any]:
    return {"reports": _md_files(REPORTS_DIR)}


@app.get("/api/reports/{name}")
def report(name: str) -> Any:
    safe = Path(name).name
    path = REPORTS_DIR / safe
    if not path.exists():
        raise HTTPException(404, "report not found")
    return PlainTextResponse(_redact(path.read_text(encoding="utf-8", errors="replace")))


@app.get("/api/sessions")
def sessions() -> Dict[str, Any]:
    return {"sessions": _md_files(SESSIONS_DIR), "db_sessions": _sqlite_sessions()}


@app.get("/api/sessions/{name}")
def session(name: str) -> Any:
    safe = Path(name).name
    path = SESSIONS_DIR / safe
    if not path.exists():
        raise HTTPException(404, "session not found")
    return PlainTextResponse(_redact(path.read_text(encoding="utf-8", errors="replace")))


# -- agents / tools ----------------------------------------------------------

@app.get("/api/agents")
def agents() -> Dict[str, Any]:
    items = load_agents()
    return {"agents": items, "count": len(items)}


@app.get("/api/agent/{name}")
def agent(name: str) -> Dict[str, Any]:
    path = CONF_DIR / "agents" / f"{Path(name).name}.md"
    if not path.exists():
        raise HTTPException(404, "agent not found")
    return {
        "name": path.stem,
        "meta": _agent_meta(path),
        "content": path.read_text(encoding="utf-8", errors="replace"),
    }


@app.get("/api/tools")
def tools() -> Dict[str, Any]:
    return load_tools()


# -- configuration -----------------------------------------------------------

SECRET_KEYS = {
    "OPENROUTER_API_KEY",
    "OPENCODE_LOCAL_API_KEY",
    "ANTHROPIC_API_KEY",
    "MINIMAX_API_KEY",
}


def _read_env() -> Dict[str, str]:
    env: Dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def _mask(v: str) -> str:
    if len(v) <= 8:
        return "•" * len(v)
    return v[:4] + "•" * 8 + v[-4:]


@app.get("/api/env")
def get_env() -> Dict[str, Any]:
    env = _read_env()
    masked = {k: (_mask(v) if k in SECRET_KEYS else v) for k, v in env.items()}
    return {"configured": masked, "keys": sorted(env.keys()), "file": str(ENV_FILE)}


@app.post("/api/env")
async def set_env(request: Request) -> Dict[str, Any]:
    body = await request.json()
    mode = (body.get("mode") or "cloud").lower()
    env: Dict[str, str] = {}

    if mode == "local":
        provider_id = (body.get("provider_id") or "ollama").strip()
        base_url = (body.get("base_url") or "http://host.docker.internal:11434/v1").strip()
        model = (body.get("model") or "").strip()
        if not model:
            raise HTTPException(400, "model is required for a local provider")
        env = {
            "OPENCODE_LOCAL_MODE": "true",
            "OPENCODE_LOCAL_PROVIDER_ID": provider_id,
            "OPENCODE_LOCAL_PROVIDER_NAME": body.get("provider_name") or provider_id,
            "OPENCODE_LOCAL_BASE_URL": base_url,
            "OPENCODE_LOCAL_MODEL": model,
        }
        if body.get("api_key"):
            env["OPENCODE_LOCAL_API_KEY"] = str(body["api_key"]).strip()
    elif mode == "anthropic":
        base_url = (body.get("base_url") or "").strip()
        model = (body.get("model") or "").strip()
        if not base_url or not model:
            raise HTTPException(400, "base_url and model are required")
        env = {
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_MODEL": model,
            "ANTHROPIC_API_KEY": str(body.get("api_key") or "darkmoon-local").strip(),
        }
    else:
        provider = (body.get("provider") or "anthropic").strip()
        model = (body.get("model") or "").strip()
        key = str(body.get("api_key") or "").strip()
        if not model or not key:
            raise HTTPException(400, "model and api_key are required")
        env = {
            "OPENROUTER_PROVIDER": provider,
            "OPENCODE_MODEL": model,
            "OPENROUTER_API_KEY": key,
        }

    # Optional: MiniMax M Plan MCP (web_search + understand_image). Kept out of
    # the provider blocks above because it is independent of the LLM provider —
    # it adds MCP tools, not a model.
    #
    # "minimax_api_key" present in the body -> explicit intent (empty string
    # disables the MCP). Absent -> preserve whatever is already stored, so that
    # saving the provider config never silently drops the MCP key (and so the
    # masked key read back from GET /api/env is never written to disk).
    if "minimax_api_key" in body:
        minimax_key = str(body.get("minimax_api_key") or "").strip()
        if minimax_key:
            env["MINIMAX_API_KEY"] = minimax_key
            env["MINIMAX_API_HOST"] = str(body.get("minimax_api_host") or "https://api.minimax.io").strip()
    else:
        existing = _read_env()
        if existing.get("MINIMAX_API_KEY"):
            env["MINIMAX_API_KEY"] = existing["MINIMAX_API_KEY"]
            env["MINIMAX_API_HOST"] = existing.get("MINIMAX_API_HOST") or "https://api.minimax.io"

    header = "# Darkmoon — LLM provider configuration\n# Written by the DarkMoon Web UI\n"
    body_text = "\n".join(f"{k}={v}" for k, v in env.items()) + "\n"
    ENV_FILE.write_text(header + body_text, encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        pass

    # Apply live: the engine regenerates its own opencode.json / auth.json from
    # these variables. opencode re-reads that config at the start of every run,
    # so the next assessment picks the new model up without a restart.
    applied = False
    apply_out = ""
    try:
        res = _exec_in_container(
            OPENCODE_CONTAINER,
            ["bash", "/root/conf/apply-settings.sh"],
            environment={k: str(v) for k, v in env.items()},
        )
        applied = bool(res.get("ok"))
        apply_out = (res.get("stdout") or "") + (res.get("stderr") or "")
    except Exception as exc:  # pragma: no cover
        apply_out = f"{type(exc).__name__}: {exc}"

    return {
        "ok": True,
        "keys": sorted(env.keys()),
        "applied": applied,
        "apply_output": apply_out.strip()[-800:],
        "restart_required": mode == "anthropic",
    }


# -- AI scope generator -------------------------------------------------------
#
# Paste a bug-bounty program brief (HackerOne / Bugcrowd / Intigriti / platform
# text) and the configured LLM extracts a structured scope JSON: in-scope assets,
# out-of-scope rules, reward table, rate limits, safe-harbour flags and exclusions.
# The JSON is then loadable straight into the launch form (SCOPE=...).

SCOPE_SYSTEM_PROMPT = """You are a bug-bounty scope analyst. The user pastes a raw program brief
(HackerOne, Bugcrowd, Intigriti, or any other platform text). You return ONLY a
single JSON object — no prose, no markdown fences, no trailing commentary.

JSON schema:
{
  "name": "<program or company name>",
  "in_scope": ["https://...", "api.example.com", "*.example.com"],
  "out_of_scope": ["third-party vendors", "social engineering"],
  "assets": [{"url": "...", "tags": ["website testing"], "notes": ""}],
  "rewards": {"critical": 5000, "high": 1500, "medium": 500, "low": 250, "info": 0},
  "rate_limit": "5 requests per second, 5 concurrent",
  "safe_harbor": true,
  "exclusions": ["self-XSS", "open redirect", "missing security headers"],
  "notes": "anything else worth knowing (campaign multipliers, testing period, ...)"
}

Rules:
- in_scope / out_of_scope are free-text lists, one entry per bullet or line.
- assets is the per-target table when the program lists named targets with tags;
  if it only gives a wildcard, use in_scope instead and leave assets empty.
- rewards maps severity -> USD; use the program's stated bounty, or 0 when it
  says "no bounty" / "informative only". Use null for a range like 1500-2500.
- rate_limit captures the request-rate / concurrency rule verbatim when present.
- safe_harbor is true when the program explicitly waives CFAA/DMCA liability.
- exclusions is the "out of scope vulnerability types" / "ineligible findings" list.
- Be exhaustive but precise; never invent assets or rewards not in the text.
- NEVER widen the scope. Only list hostnames that appear verbatim in the brief.
  If the brief lists "app.example.com", do NOT emit "*.example.com" or
  "example.com" — a wildcard would authorise testing assets the program never
  granted. If a hostname is not literally in the brief, leave it out.
- Never invent reward amounts: use only the numbers written in the brief.
"""


def _scope_job_cmd(payload: Dict[str, Any]) -> List[str]:
    """Build the opencode run command for an AI scope parse (legacy fallback)."""
    brief = (payload.get("brief") or "").strip()
    if not brief:
        raise HTTPException(400, "brief is required")
    message = (
        "Program brief to parse:\n\n" + brief + "\n\n"
        "Return ONLY the JSON object described in your system instructions."
    )
    return ["opencode", "run", message]


def _strip_json_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1] if "\n" in text else text[3:]
        text = text.strip()
        if text.endswith("```"):
            text = text[:-3].strip()
    return text


def _extract_json_object(text: str) -> str:
    """Pull the first balanced {...} out of a model response."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return text
    return text[start : end + 1]


_HOST_RE = re.compile(
    r"(?:\*\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})", re.IGNORECASE
)


def _brief_hosts(text: str) -> set:
    """Every hostname literally present in the source brief."""
    hosts = set()
    for m in _HOST_RE.finditer(text):
        h = m.group(1).lower().strip(".")
        if h and "." in h:
            hosts.add(h)
    return hosts


def _validate_scope(scope: Dict[str, Any], brief: str) -> Dict[str, Any]:
    """Cross-check the generated scope against the brief it came from.

    A language model asked to summarise a bug-bounty policy occasionally widens
    the scope (inventing "*.example.com" from "app.example.com") or narrows it.
    Widening is the dangerous direction: it would authorise scanning assets the
    program never granted. So every generated host must be traceable to a host
    that literally appears in the brief; invented entries are dropped and
    reported back so the reviewer sees what was removed.
    """
    known = _brief_hosts(brief)
    if not known:
        return scope

    dropped: List[str] = []
    kept: List[str] = []
    for entry in scope.get("in_scope") or []:
        if not isinstance(entry, str):
            continue
        raw = entry.strip().lower().rstrip("/")
        if not raw:
            continue
        host = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0]
        host = host.lstrip("*.").strip(".")
        if not host:
            dropped.append(entry)
            continue
        # A host is acceptable if it appears in the brief, or if it is a
        # subdomain of a host the brief lists (e.g. brief has "example.com"
        # and the model emitted "api.example.com").
        base_ok = host in known or any(
            host == k or host.endswith("." + k) for k in known
        )
        if base_ok:
            kept.append(entry)
        else:
            dropped.append(entry)

    scope["in_scope"] = kept
    assets = []
    for a in scope.get("assets") or []:
        if not isinstance(a, dict):
            continue
        url = str(a.get("url") or "")
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lstrip("*.").strip(".")
        if host and (host in known or any(host == k or host.endswith("." + k) for k in known)):
            assets.append(a)
        else:
            dropped.append(url or "(empty asset)")
    scope["assets"] = assets

    if dropped:
        scope["_dropped_out_of_brief"] = sorted(set(x for x in dropped if x))
    return scope


def _scope_provider() -> Optional[Dict[str, str]]:
    """Resolve the configured LLM provider (base URL + model + optional key).

    Reads .opencode.env exactly like apply-settings.sh does, so the Web UI uses
    whatever the user configured in Settings — cloud, local or on-prem.
    """
    env = _read_env()
    if env.get("OPENCODE_LOCAL_MODE") == "true" and env.get("OPENCODE_LOCAL_BASE_URL"):
        return {
            "base_url": env["OPENCODE_LOCAL_BASE_URL"].rstrip("/"),
            "model": env.get("OPENCODE_LOCAL_MODEL") or "model",
            "api_key": env.get("OPENCODE_LOCAL_API_KEY") or "darkmoon-local",
        }
    if env.get("ANTHROPIC_BASE_URL"):
        return {
            "base_url": env["ANTHROPIC_BASE_URL"].rstrip("/"),
            "model": env.get("ANTHROPIC_MODEL") or "model",
            "api_key": env.get("ANTHROPIC_API_KEY") or "darkmoon-local",
        }
    if env.get("OPENROUTER_PROVIDER") and env.get("OPENCODE_MODEL"):
        return {
            "base_url": "https://openrouter.ai/api/v1",
            "model": f"{env['OPENROUTER_PROVIDER']}/{env['OPENCODE_MODEL']}",
            "api_key": env.get("OPENROUTER_API_KEY") or "",
        }
    return None


def _scope_via_openai(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Call the configured OpenAI-compatible endpoint directly (fast, no opencode)."""
    import urllib.request
    import urllib.error

    prov = _scope_provider()
    if not prov:
        return {"ok": False, "error": "no LLM provider configured — set one in Settings"}
    brief = (payload.get("brief") or "").strip()
    if not brief:
        return {"ok": False, "error": "brief is required"}

    body = json.dumps(
        {
            "model": prov["model"],
            "messages": [
                {"role": "system", "content": SCOPE_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": "Program brief to parse:\n\n" + brief
                    + "\n\nReturn ONLY the JSON object described in your system instructions.",
                },
            ],
            "temperature": 0.0,
            "max_tokens": 4096,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        prov["base_url"] + "/chat/completions",
        data=body,
        headers={
            "content-type": "application/json",
            "authorization": "Bearer " + prov["api_key"],
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"provider HTTP {exc.code}: {exc.read().decode('utf-8','replace')[:300]}"}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    try:
        raw = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError):
        return {"ok": False, "error": "provider returned an unexpected response shape", "raw": json.dumps(data)[:400]}

    if not raw:
        return {"ok": False, "error": "the model returned no output — check that the configured "
                          "endpoint is reachable and not out of memory (see Settings → LLM provider)"}
    json_str = _extract_json_object(_strip_json_fence(raw))
    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"model did not return valid JSON: {exc}", "raw": raw[-800:]}
    if not isinstance(parsed, dict):
        return {"ok": False, "error": "model returned a non-object JSON value", "raw": raw[-800:]}
    validated = _validate_scope(parsed, brief)
    dropped = validated.pop("_dropped_out_of_brief", [])
    return {"ok": True, "scope": validated, "model": prov["model"], "dropped": dropped}


def _scope_run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous helper used by the async endpoint (runs in an executor).

    Prefers the OpenAI-compatible HTTP API (what apply-settings.sh configures);
    falls back to running opencode head-less inside the engine container.
    """
    direct = _scope_via_openai(payload)
    if direct.get("ok"):
        return direct
    # Fallback: drive opencode the same way a real assessment is driven.
    cmd = _scope_job_cmd(payload)
    res = _exec_in_container(OPENCODE_CONTAINER, cmd, timeout=300)
    raw = (res.get("stdout") or "").strip()
    if not res.get("ok"):
        return {
            "ok": False,
            "error": (res.get("stderr") or "model failed").strip()[-400:],
            "raw": raw[-800:],
            "fallback_error": direct.get("error"),
        }
    if not raw:
        return {"ok": False, "error": (direct.get("error") or "the model returned no output — "
                          "check that the configured endpoint is reachable and not out of memory "
                          "(see Settings → LLM provider)"), "raw": ""}
    json_str = _extract_json_object(_strip_json_fence(raw))
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"model did not return valid JSON: {exc}", "raw": raw[-800:]}
    if not isinstance(data, dict):
        return {"ok": False, "error": "model returned a non-object JSON value", "raw": raw[-800:]}
    validated = _validate_scope(data, (payload.get("brief") or ""))
    dropped = validated.pop("_dropped_out_of_brief", [])
    return {"ok": True, "scope": validated, "model": "opencode head-less", "dropped": dropped}


@app.post("/api/scope")
async def scope(request: Request) -> Dict[str, Any]:
    """Parse a pasted bug-bounty brief into structured scope JSON using the
    configured LLM. Returns {ok, scope?, model?, error?, raw?}."""
    payload = await request.json()
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, lambda: _scope_run(payload))
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@app.post("/api/launch")
async def launch(request: Request) -> Dict[str, Any]:
    payload = await request.json()
    kind = (payload.get("kind") or "assessment").lower()

    if kind == "mcp-stream":
        job_id = "job_" + uuid.uuid4().hex[:10]
        job = Job(job_id, "MCP raw stream", "", ["darkmoon-cli"], kind="mcp-stream")
        JOBS[job_id] = job
        job._task = asyncio.create_task(_run_job(job))
        return job.to_dict()

    prompt = build_prompt(payload)
    job_id = "job_" + uuid.uuid4().hex[:10]
    cmd = ["opencode", "run", prompt]
    job = Job(job_id, payload.get("target", ""), prompt, cmd)
    JOBS[job_id] = job
    job._task = asyncio.create_task(_run_job(job))
    return job.to_dict()


@app.get("/api/jobs")
def jobs() -> Dict[str, Any]:
    return {"jobs": [j.to_dict() for j in reversed(list(JOBS.values()))]}


@app.get("/api/jobs/{job_id}")
def job(job_id: str) -> Dict[str, Any]:
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "job not found")
    return j.to_dict()


@app.get("/api/jobs/{job_id}/stream")
async def job_stream(job_id: str, request: Request) -> Any:
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "job not found")

    queue: asyncio.Queue = asyncio.Queue()
    j._subscribers.append(queue)
    try:
        backlog = list(j.lines)
    finally:
        pass

    async def gen():
        try:
            if backlog:
                yield f"data: {json.dumps({'type': 'backlog', 'lines': backlog})}\n\n"
            yield f"data: {json.dumps({'type': 'status', 'status': j.status})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"data: {json.dumps(payload)}\n\n"
                if payload.get("type") == "end":
                    break
        finally:
            try:
                j._subscribers.remove(queue)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str) -> Dict[str, Any]:
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "job not found")
    if j.status == "running":
        _exec_in_container(OPENCODE_CONTAINER, ["pkill", "-f", "opencode run"], timeout=10)
        j.status = "stopped"
        j.finished_at = _now()
        _broadcast(j, {"type": "end", "status": "stopped"})
    return j.to_dict()


# -- stack control -----------------------------------------------------------

COMPOSE = ["docker", "compose"]
STACK_CONTAINERS = [OPENCODE_CONTAINER, TOOLBOX_CONTAINER]


def _stack_action(action: str) -> Dict[str, Any]:
    """Drive the stack through the Docker API (no compose CLI needed)."""
    if action not in {"up", "down", "restart", "logs"}:
        raise HTTPException(400, "unsupported action")
    try:
        cli = _docker()
    except Exception as exc:
        raise HTTPException(503, f"docker unavailable: {exc}")

    out: List[str] = []
    ok = True
    for name in STACK_CONTAINERS:
        try:
            c = cli.containers.get(name)
        except Exception as exc:
            ok = False
            out.append(f"{name}: {exc}")
            continue
        try:
            if action == "up":
                c.start()
            elif action == "down":
                c.stop(timeout=20)
            elif action == "restart":
                c.restart(timeout=30)
            out.append(f"{name}: {action} ok")
        except Exception as exc:
            ok = False
            out.append(f"{name}: {type(exc).__name__}: {exc}")

    if action == "logs":
        try:
            c = cli.containers.get(OPENCODE_CONTAINER)
            out.append(c.logs(tail=300).decode("utf-8", "replace"))
        except Exception as exc:
            out.append(f"logs: {exc}")
    return {"ok": ok, "output": "\n".join(out)}


@app.post("/api/stack/{action}")
def stack(action: str) -> Dict[str, Any]:
    return _stack_action(action)


# ---------------------------------------------------------------------------
# Static assets (mounted last so /api routes win)
# ---------------------------------------------------------------------------

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "ts": _now()}
