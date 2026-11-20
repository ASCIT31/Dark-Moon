"""Coverage signals recorded by the MCP server for every campaign (Cyber Score v1 gate, exec_core.score).

Recorded server-side, never reconstructed from the findings. Stored additively in the campaign record under
``coverage_signals`` (schema ``darkmoon-coverage-signals/1``); a campaign recorded before this module has no such
block, is never given one afterwards, and is never rated (exec_core.score.gate).

* ``campaign_kind`` full | retest | short, with its source, strongest first: ``retest_store`` (Pro: the run was
  launched as a retest), ``launcher`` (Pro: the kind the API wrote in the run sidecar at launch — a retest, or a run
  restricted to a focus list = short; or env ``DARKMOON_CAMPAIGN_KIND`` of a stdio MCP started by a launcher),
  ``declared_at_init`` (optional ``campaign_kind`` argument of ``dashboard_init_campaign``), else ``default`` (full).
* ``started_at`` / ``finalized_at`` / ``measured_duration_seconds``: server clock, init -> finalize (or abort).
* ``root_session_id``: the run's root OpenCode session, resolved at init (session id prefixed by the campaign key,
  else the root the API recorded for the run key in its run sidecar, else — Community only, single-user TUI — the
  latest root session at init).
* ``agents_dispatched``: the sub-agent sessions under that root opened during the campaign (``agents_source``
  ``opencode_sessions``); an agent that ran and found nothing is listed. When the root is unknown, the agents named
  in the campaign's MCP calls are listed instead (``agents_source`` ``tool_calls_only``) and they cannot meet the
  score's agent floor. ``agents_reporting``: the agent names carried by MCP calls (always recorded).
* ``assets_registered``: infrastructure nodes of the campaign at finalize.
* ``commands_executed`` / ``workflows_executed``: ``execute_command`` / ``run_workflow`` calls served by the MCP
  server for the run key, minus what an earlier campaign of the same run key had already counted (commands run
  before init belong to the first campaign of the key). Commands run by the agent's own shell tool are not seen.

* ``launch_restrictions`` (Pro): the restrictions given at launch (severity filter, attack exclusions, noise level,
  out-of-scope assets, custom rules, focus list — counts, never their content), copied from the run sidecar written
  by the API; they gate the score (``exec_core.score.gate``).

Finalisation (``finalize_decision``, both editions): only ``completed``, ``aborted``, ``stopped``, ``failed`` and
``error`` (and their aliases) are accepted. Once a campaign is terminal, a later finalize never changes its status nor
its measured duration (``on_close(frozen=True)``): an aborted or stopped campaign never becomes completed. At the
first close the digest of the gate fields is written on the campaign (``exec_core.score.signals_digest``); a later
mismatch means the signals were edited after finalisation (detects naive edits only, not a security boundary).

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
COUNTERS = ("commands_executed", "workflows_executed")
CHILD_WINDOW_BEFORE_START_MS = 15 * 60 * 1000   # a sub-agent opened just before the orchestrator's init still counts
_LOG = logging.getLogger("darkmoon.coverage")
_SUBAGENT_TITLE = re.compile(r"\(@([A-Za-z0-9_.-]{1,64}) subagent\)")
_RANK = {"default": 0, "declared_at_init": 1, "launcher": 2, "retest_store": 3}
TERMINAL = frozenset({"completed", "aborted", "stopped", "failed", "error"})
_STATUS_ALIASES = {"cancelled": "aborted", "canceled": "aborted", "abort": "aborted", "done": "completed",
                   "finish": "completed", "finished": "completed", "complete": "completed"}


def finalize_decision(campaign: Dict[str, Any], requested: Any) -> Dict[str, Any]:
    """The status a finalize may set: ``{"status", "frozen", "error"}``. A requested status outside the terminal
    whitelist is refused (``error``); a campaign already terminal keeps its status and its measured duration
    (``frozen``), so a later or forged finalize cannot turn an aborted / stopped campaign into a completed one."""
    req = str(requested or "completed").strip().lower()
    req = _STATUS_ALIASES.get(req, req)
    current = str(campaign.get("status") or "").strip().lower()
    if req not in TERMINAL:
        return {"status": current or "running", "frozen": current in TERMINAL,
                "error": f"final_status must be one of {sorted(TERMINAL)}"}
    if current in TERMINAL:
        return {"status": current, "frozen": True, "error": None}
    return {"status": req, "frozen": False, "error": None}


def launch_restrictions_from(meta: Any) -> Optional[Dict[str, Any]]:
    """The launch restrictions a launcher recorded in its run sidecar, normalised (counts only), or None."""
    r = (meta or {}).get("launch_restrictions") if isinstance(meta, dict) else None
    if not isinstance(r, dict):
        return None
    out: Dict[str, Any] = {}
    for k in ("severity", "noise"):
        v = str(r.get(k) or "").strip().lower()[:16]
        if v:
            out[k] = v
    for k in ("exclude", "out_of_scope", "rules", "focus"):
        try:
            n = int(r.get(k) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            out[k] = n
    out["source"] = "launcher"
    return out


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


# ---------------------------------------------------------------- run sidecar (Pro API) and retest store

def run_meta(session_frag: Any) -> Dict[str, Any]:
    """Pro: the API's run sidecar ``campaign_logs/<run_id>.meta.json`` (B-17) of this run key, or {}."""
    frag = str(session_frag or "").lower()
    if not frag or not json_storage.is_safe_id(frag):
        return {}
    try:
        logs = Path(json_storage.DATA_DIR) / "campaign_logs"
        if not logs.is_dir():
            return {}
        for p in sorted(logs.glob(f"*_{frag}.meta.json")):
            meta = json.loads(p.read_text("utf-8"))
            if isinstance(meta, dict) and str(meta.get("campaign_frag") or "").lower() == frag:
                return meta
    except Exception:  # noqa: BLE001
        return {}
    return {}


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
    launched = normalise_kind(run_meta(session_frag).get("campaign_kind")) or normalise_kind(os.environ.get(KIND_ENV))
    if launched:
        return {"campaign_kind": launched, "campaign_kind_source": "launcher"}
    d = normalise_kind(declared)
    if d:
        return {"campaign_kind": d, "campaign_kind_source": "declared_at_init"}
    return {"campaign_kind": "full", "campaign_kind_source": "default"}


# ---------------------------------------------------------------- OpenCode session store

def opencode_db() -> Optional[Path]:
    """The OpenCode session store the edition's live_push uses; Community: its configured file, else the most
    recently modified ``opencode*.db`` next to it (the released binary writes ``opencode.db``)."""
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
    if not p:
        return None
    p = Path(p)
    if p.exists():
        return p
    try:
        dbs = sorted(p.parent.glob("opencode*.db"), key=lambda x: x.stat().st_mtime, reverse=True)
    except OSError:
        return None
    return dbs[0] if dbs else None


def _clean(sid: Any) -> str:
    return str(sid or "").replace("ses_", "").replace("-", "")


def _roots(db: Optional[Path]) -> List[tuple]:
    if not db or not Path(db).exists():
        return []
    try:
        conn = sqlite3.connect(str(db), timeout=2)
        try:
            return conn.execute("SELECT id, time_created FROM session WHERE parent_id IS NULL").fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return []


def resolve_root(db: Optional[Path], session_frag: Any, latest_root_fallback: bool = False) -> Optional[str]:
    """Root session of the run: id prefixed by the campaign key, else the run sidecar's, else (Community) the latest
    root. Never guessed from timestamps around the campaign start (another run's agents must never be attributed)."""
    roots = _roots(db)
    if not roots:
        return None
    frag = str(session_frag or "").lower()
    for sid, _t in roots:
        if frag and _clean(sid).lower().startswith(frag):
            return str(sid)
    meta_root = run_meta(frag).get("session_id")
    if meta_root and any(str(sid) == str(meta_root) for sid, _t in roots):
        return str(meta_root)
    if latest_root_fallback:
        latest = max(roots, key=lambda r: (r[1] or 0, str(r[0])))
        return str(latest[0])
    return None


def sessions_agents(db: Optional[Path], root: Optional[str], started_at: Any = None,
                    finalized_at: Any = None) -> Optional[List[Dict[str, Any]]]:
    """Agents of the sub-agent sessions under ``root`` opened during the campaign, or None when unknown."""
    if not root or not db or not Path(db).exists():
        return None
    try:
        conn = sqlite3.connect(str(db), timeout=2)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(session)")}
            agent_col = "agent" if "agent" in cols else "NULL"
            if not conn.execute("SELECT 1 FROM session WHERE id = ?", (root,)).fetchone():
                return None
            rows = conn.execute(
                f"SELECT id, title, {agent_col}, time_created, time_updated FROM session WHERE parent_id = ?",
                (root,)).fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return None
    start, end = _parse(started_at), _parse(finalized_at)
    lo = start.timestamp() * 1000 - CHILD_WINDOW_BEFORE_START_MS if start else None
    hi = end.timestamp() * 1000 + 60_000 if end else None
    out: Dict[str, Dict[str, Any]] = {}
    for _sid, title, agent, t0, t1 in rows:
        try:
            created = float(t0)
        except (TypeError, ValueError):
            created = None
        if created is not None and ((lo is not None and created < lo) or (hi is not None and created > hi)):
            continue   # a sub-agent of an earlier or later campaign of the same root session
        name = str(agent or "").strip()
        if not name:
            m = _SUBAGENT_TITLE.search(str(title or ""))
            name = m.group(1) if m else ""
        if not name:
            continue
        r = out.setdefault(name, {"agent": name[:64], "sessions": 0, "active_seconds": 0})
        r["sessions"] += 1
        try:
            r["active_seconds"] += max(0, int((float(t1) - float(t0)) / 1000))
        except (TypeError, ValueError):
            pass
    return [out[k] for k in sorted(out)]


# ---------------------------------------------------------------- command counter (per run key, before init too)

def _counter_dir() -> Path:
    return Path(json_storage.DATA_DIR) / "coverage_signals"


def _counter_path(run_frag: str) -> Path:
    return json_storage._resolve_inside(_counter_dir(), run_frag, suffix=".json")


def read_counters(run_frag: Any) -> Dict[str, int]:
    out = {k: 0 for k in COUNTERS}
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


def _baseline(campaign: Dict[str, Any]) -> Dict[str, int]:
    """What earlier campaigns of the same run key already counted (their counter totals at close)."""
    out = {k: 0 for k in COUNTERS}
    frag = str(campaign.get("session_id") or "")
    if not frag:
        return out
    try:
        for c in json_storage.load_campaigns():
            if c.get("id") == campaign.get("id") or str(c.get("session_id") or "") != frag:
                continue
            sig = c.get("coverage_signals")
            totals = sig.get("counter_totals") if isinstance(sig, dict) else None
            if isinstance(totals, dict):
                for k in out:
                    try:
                        out[k] = max(out[k], int(totals.get(k) or 0))
                    except (TypeError, ValueError):
                        pass
    except Exception:  # noqa: BLE001
        pass
    return out


# ---------------------------------------------------------------- hooks called by live_push

def blank(campaign: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "campaign_kind": "full",
        "campaign_kind_source": "default",
        "started_at": campaign.get("date") or _iso(_now()),
        "finalized_at": None,
        "measured_duration_seconds": None,
        "root_session_id": None,
        "agents_dispatched": [],
        "agents_source": "pending",
        "agents_reporting": [],
        "assets_registered": 0,
        "commands_executed": 0,
        "workflows_executed": 0,
        "counter_baseline": {k: 0 for k in COUNTERS},
        "counter_totals": {k: 0 for k in COUNTERS},
    }


def on_init(campaign: Dict[str, Any], declared_kind: Any = None, create: bool = True,
            latest_root_fallback: bool = False) -> None:
    """Called by init before the campaign record is saved. ``create``: the record is new (an existing record without
    signals predates them and never gets any). Never moves ``started_at``; a later init only strengthens the kind."""
    try:
        sig = campaign.get("coverage_signals")
        if not isinstance(sig, dict) or sig.get("schema") != SCHEMA:
            if not create:
                return
            sig = blank(campaign)
            sig["counter_baseline"] = _baseline(campaign)
            sig["root_session_id"] = resolve_root(opencode_db(), campaign.get("session_id"), latest_root_fallback)
            campaign["coverage_signals"] = sig
        elif not sig.get("root_session_id"):
            sig["root_session_id"] = resolve_root(opencode_db(), campaign.get("session_id"), latest_root_fallback)
        kind = resolve_kind(declared_kind, str(campaign.get("session_id") or ""))
        if _RANK.get(kind["campaign_kind_source"], 0) > _RANK.get(sig.get("campaign_kind_source"), 0):
            sig.update(kind)
        if not sig.get("finalized_at") and "launch_restrictions" not in sig:
            lr = launch_restrictions_from(run_meta(str(campaign.get("session_id") or "")))
            if lr is not None:
                sig["launch_restrictions"] = lr
    except Exception:  # noqa: BLE001
        _LOG.warning("coverage signals: init not recorded", exc_info=True)


def note_agent(campaign: Dict[str, Any], agent: Any, via: str) -> None:
    """An MCP call carrying an agent name for this campaign (push_finding)."""
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


def on_close(campaign: Dict[str, Any], frozen: bool = False) -> None:
    """Called by finalize / abort before the campaign record is saved: server-measured duration, dispatched agents,
    registered assets and toolbox counters, then the digest of the gate fields (first close only). ``frozen`` (the
    campaign was already terminal, ``finalize_decision``): nothing is recomputed, the first close stands."""
    try:
        sig = campaign.get("coverage_signals")
        if not isinstance(sig, dict) or sig.get("schema") != SCHEMA:
            return  # recorded before coverage signals existed: never invent them afterwards
        if frozen and sig.get("finalized_at"):
            return
        now = _now()
        start = _parse(sig.get("started_at")) or _parse(campaign.get("date"))
        sig["finalized_at"] = _iso(now)
        sig["measured_duration_seconds"] = max(0, int((now - start).total_seconds())) if start else None
        frag = str(campaign.get("session_id") or "")
        totals = read_counters(frag)
        base = sig.get("counter_baseline") if isinstance(sig.get("counter_baseline"), dict) else {}
        sig["counter_totals"] = totals
        for k in COUNTERS:
            try:
                sig[k] = max(0, totals[k] - int(base.get(k) or 0))
            except (TypeError, ValueError):
                sig[k] = totals[k]
        try:
            sig["assets_registered"] = len([n for n in json_storage.load_infrastructure(str(campaign.get("id") or ""))
                                            if isinstance(n, dict)])
        except Exception:  # noqa: BLE001
            pass
        db = opencode_db()
        if not sig.get("root_session_id"):
            sig["root_session_id"] = resolve_root(db, frag)
        agents = sessions_agents(db, sig.get("root_session_id"), sig.get("started_at"), sig["finalized_at"])
        if agents is not None:
            sig["agents_dispatched"] = agents
            sig["agents_source"] = "opencode_sessions"
        else:
            sig["agents_dispatched"] = [{"agent": r.get("agent"), "sessions": 0, "active_seconds": 0}
                                        for r in sig.get("agents_reporting") or [] if r.get("agent")]
            sig["agents_source"] = "tool_calls_only"
        from api.exec_core import score as _score
        campaign[_score.SIGNALS_DIGEST_KEY] = _score.signals_digest(sig)   # each real close (never a frozen one)
    except Exception:  # noqa: BLE001
        _LOG.warning("coverage signals: close not recorded", exc_info=True)
