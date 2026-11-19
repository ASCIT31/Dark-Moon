"""Coverage signals recorded by the MCP server for every campaign (Cyber Score v1 gate, exec_core.score).

Recorded server-side, never reconstructed from the findings. Stored additively in the campaign record under
``coverage_signals`` (schema ``darkmoon-coverage-signals/1``); a campaign recorded before this module has no such
block and is never rated (exec_core.score.gate).

* ``campaign_kind`` full | retest | short, with its source: ``launcher`` (env ``DARKMOON_CAMPAIGN_KIND`` of a stdio
  MCP started by a launcher), ``retest_store`` (Pro: the run was launched as a retest), ``declared_at_init`` (optional
  ``campaign_kind`` argument of ``dashboard_init_campaign``), else ``default`` (full).
* ``started_at`` / ``finalized_at`` / ``measured_duration_seconds``: server clock, init -> finalize (or abort).
* ``agents_dispatched``: the sub-agent sessions opened under the run's root OpenCode session (``agents_source``
  ``opencode_sessions``), read from the OpenCode session store at finalize; an agent that ran and found nothing is
  listed. When that store cannot be read, the agents named in the MCP calls of the campaign (``discovered_by_agent``)
  are used instead (``agents_source`` ``tool_calls_only``) and the score says so in its limitations.
  ``agents_reporting``: the agent names carried by MCP calls (always recorded, never used for the gate when sessions
  are known).
* ``assets_registered``: infrastructure nodes of the campaign at finalize.
* ``commands_executed`` / ``workflows_executed``: ``execute_command`` / ``run_workflow`` calls served by the MCP
  server for the run (counted before init too). Commands run by the agent's own shell tool are not seen.

Every function here is advisory: a failure never fails the MCP call that triggered it.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from api import json_storage

SCHEMA = "darkmoon-coverage-signals/1"
KINDS = ("full", "retest", "short")
KIND_ENV = "DARKMOON_CAMPAIGN_KIND"
_LOG = logging.getLogger("darkmoon.coverage")
_SUBAGENT_TITLE = re.compile(r"\(@([A-Za-z0-9_.-]{1,64}) subagent\)")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: Any) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(ts or "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalise_kind(value: Any) -> Optional[str]:
    v = str(value or "").strip().lower()
    return v if v in KINDS else None


def _retest_kind(session_frag: str) -> bool:
    """Pro: the run of this campaign was launched as a retest (retests.json row whose run id ends with the key)."""
    if not session_frag:
        return False
    try:
        from api import retest_store  # Pro only
    except Exception:  # noqa: BLE001
        return False
    try:
        for rt in retest_store.list_retests():
            tail = str(rt.get("run_id") or "").rsplit("_", 1)[-1].lower()
            if tail and tail == str(session_frag).lower():
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


def resolve_kind(declared: Any, session_frag: str) -> Dict[str, str]:
    if _retest_kind(session_frag):
        return {"campaign_kind": "retest", "campaign_kind_source": "retest_store"}
    env = normalise_kind(os.environ.get(KIND_ENV))
    if env:
        return {"campaign_kind": env, "campaign_kind_source": "launcher"}
    d = normalise_kind(declared)
    if d:
        return {"campaign_kind": d, "campaign_kind_source": "declared_at_init"}
    return {"campaign_kind": "full", "campaign_kind_source": "default"}


def blank(campaign: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "campaign_kind": "full",
        "campaign_kind_source": "default",
        "started_at": campaign.get("date") or _iso(_now()),
        "finalized_at": None,
        "measured_duration_seconds": None,
        "agents_dispatched": [],
        "agents_source": "pending",
        "agents_reporting": [],
        "assets_registered": 0,
        "commands_executed": 0,
        "workflows_executed": 0,
    }


def on_init(campaign: Dict[str, Any], declared_kind: Any = None) -> None:
    """Called by init before the campaign record is saved (new or reused). Never moves ``started_at``."""
    try:
        sig = campaign.get("coverage_signals")
        if not isinstance(sig, dict) or sig.get("schema") != SCHEMA:
            sig = blank(campaign)
            campaign["coverage_signals"] = sig
        kind = resolve_kind(declared_kind, str(campaign.get("session_id") or ""))
        # a stronger source wins; a sub-agent's init never downgrades the orchestrator's declaration
        rank = {"default": 0, "declared_at_init": 1, "launcher": 2, "retest_store": 3}
        if rank.get(kind["campaign_kind_source"], 0) > rank.get(sig.get("campaign_kind_source"), 0):
            sig.update(kind)
    except Exception:  # noqa: BLE001
        _LOG.warning("coverage signals: init not recorded", exc_info=True)


def note_agent(campaign: Dict[str, Any], agent: Any, via: str) -> None:
    """An MCP call carrying an agent name for this campaign (push_finding, evidence annotations)."""
    try:
        name = str(agent or "").strip()[:64]
        sig = campaign.get("coverage_signals")
        if not name or not isinstance(sig, dict) or sig.get("schema") != SCHEMA:
            return
        rows = sig.setdefault("agents_reporting", [])
        for r in rows:
            if r.get("agent") == name:
                r["calls"] = int(r.get("calls") or 0) + 1
                return
        rows.append({"agent": name, "first_seen": _iso(_now()), "via": via, "calls": 1})
    except Exception:  # noqa: BLE001
        _LOG.warning("coverage signals: agent not recorded", exc_info=True)


# ---------------------------------------------------------------- command counter (per run key, before init too)

def _counter_dir() -> Path:
    return Path(json_storage.DATA_DIR) / "coverage_signals"


def _counter_path(run_frag: str) -> Path:
    return json_storage._resolve_inside(_counter_dir(), run_frag, suffix=".json")


def read_counters(run_frag: Any) -> Dict[str, int]:
    out = {"commands_executed": 0, "workflows_executed": 0}
    try:
        if not run_frag or not json_storage.is_safe_id(str(run_frag)):
            return out
        p = _counter_path(str(run_frag))
        if p.exists():
            data = json.loads(p.read_text("utf-8"))
            for k in out:
                out[k] = max(0, int(data.get(k) or 0))
    except Exception:  # noqa: BLE001
        pass
    return out


def count_call(run_frag: Any, kind: str = "command") -> None:
    """One ``execute_command`` (kind ``command``) or ``run_workflow`` (kind ``workflow``) served for this run."""
    try:
        frag = str(run_frag or "")
        if not frag or not json_storage.is_safe_id(frag):
            return
        key = "workflows_executed" if kind == "workflow" else "commands_executed"
        with json_storage.locked(f"coverage-{frag}"):
            cur = read_counters(frag)
            cur[key] += 1
            _counter_dir().mkdir(parents=True, exist_ok=True)
            p = _counter_path(frag)
            json_storage._write_json(p, cur)
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
    except Exception:  # noqa: BLE001
        _LOG.warning("coverage signals: command not counted", exc_info=True)


# ---------------------------------------------------------------- dispatched agents (OpenCode session store)

def _opencode_db() -> Optional[Path]:
    try:
        from api import live_push
    except Exception:  # noqa: BLE001
        return None
    finder = getattr(live_push, "_opencode_db", None)
    if callable(finder):
        try:
            return finder()
        except Exception:  # noqa: BLE001
            return None
    p = getattr(live_push, "_OPENCODE_DB", None)
    return Path(p) if p and Path(p).exists() else None


def _clean(sid: Any) -> str:
    return str(sid or "").replace("ses_", "").replace("-", "")


def sessions_agents(db: Optional[Path], session_frag: str, started_at: Any) -> Optional[List[Dict[str, Any]]]:
    """Agents of the sub-agent sessions under the campaign's root session, or None when the root is not found.
    Root = the root session whose id starts with the campaign key, else the only root session opened in the
    10 minutes before the campaign start."""
    if not db or not Path(db).exists():
        return None
    try:
        conn = sqlite3.connect(str(db), timeout=2)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(session)")}
            agent_col = "agent" if "agent" in cols else "NULL"
            roots = conn.execute(f"SELECT id, time_created FROM session WHERE parent_id IS NULL").fetchall()
            root = None
            frag = str(session_frag or "").lower()
            for sid, _t in roots:
                if frag and _clean(sid).lower().startswith(frag):
                    root = sid
                    break
            if root is None:
                start = _parse(started_at)
                if start is not None:
                    hi = start.timestamp() * 1000 + 60_000
                    lo = hi - 11 * 60_000
                    near = [sid for sid, t in roots if t is not None and lo <= float(t) <= hi]
                    if len(near) == 1:
                        root = near[0]
            if root is None:
                return None
            rows = conn.execute(
                f"SELECT id, title, {agent_col}, time_created, time_updated FROM session WHERE parent_id = ?",
                (root,)).fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return None
    out: Dict[str, Dict[str, Any]] = {}
    for _sid, title, agent, t0, t1 in rows:
        name = str(agent or "").strip()
        if not name:
            m = _SUBAGENT_TITLE.search(str(title or ""))
            name = m.group(1) if m else ""
        if not name:
            continue
        r = out.setdefault(name, {"agent": name, "sessions": 0, "active_seconds": 0})
        r["sessions"] += 1
        try:
            r["active_seconds"] += max(0, int((float(t1) - float(t0)) / 1000))
        except (TypeError, ValueError):
            pass
    return [out[k] for k in sorted(out)]


def on_close(campaign: Dict[str, Any]) -> None:
    """Called by finalize / abort before the campaign record is saved: server-measured duration, dispatched agents,
    registered assets and toolbox counters. Re-running it (a second finalize) refreshes the values."""
    try:
        sig = campaign.get("coverage_signals")
        if not isinstance(sig, dict) or sig.get("schema") != SCHEMA:
            return  # recorded before coverage signals existed: never invent them afterwards
        now = _now()
        start = _parse(sig.get("started_at")) or _parse(campaign.get("date"))
        sig["finalized_at"] = _iso(now)
        sig["measured_duration_seconds"] = max(0, int((now - start).total_seconds())) if start else None
        frag = str(campaign.get("session_id") or "")
        sig.update(read_counters(frag))
        try:
            sig["assets_registered"] = len([n for n in json_storage.load_infrastructure(str(campaign.get("id") or ""))
                                            if isinstance(n, dict)])
        except Exception:  # noqa: BLE001
            pass
        agents = sessions_agents(_opencode_db(), frag, sig.get("started_at"))
        if agents is not None:
            sig["agents_dispatched"] = agents
            sig["agents_source"] = "opencode_sessions"
        else:
            sig["agents_dispatched"] = [{"agent": r.get("agent"), "sessions": 0, "active_seconds": 0}
                                        for r in sig.get("agents_reporting") or [] if r.get("agent")]
            sig["agents_source"] = "tool_calls_only"
    except Exception:  # noqa: BLE001
        _LOG.warning("coverage signals: close not recorded", exc_info=True)
