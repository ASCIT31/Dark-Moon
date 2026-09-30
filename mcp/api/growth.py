# -*- coding: utf-8 -*-
"""
Darkmoon growth signals — local, privacy-first, opt-out.

This module is the single source of truth for the Community "first real value"
milestones and for the one-time GitHub star CTA shown by the CLI.

DESIGN / GUARANTEES
-------------------
* LOCAL ONLY. Nothing here ever performs a network call. Every function only
  reads/writes small JSON files under a growth directory on the user's own disk.
  There is no server, no upload, no identifier of any kind.
* PRIVACY BY CONSTRUCTION. The only things this module can persist are:
    - milestone/funnel event *types* (from a fixed allow-list),
    - ISO-8601 timestamps,
    - integer counts,
    - the CTA booleans (shown / dismissed / clicked).
  There is deliberately NO code path that accepts a target, host, IP, credential,
  finding, command output, campaign id, customer id or scan scope. Callers pass a
  single allow-listed string; anything else is dropped.
* OPT-OUT.
    - DARKMOON_NO_TELEMETRY=1 (or DARKMOON_GROWTH_DISABLE=1) disables ALL local
      recording. No files are written; the CTA can therefore never fire either.
    - DARKMOON_DISABLE_GROWTH_CTA=1 keeps local milestones but never shows the CTA.
* FAIL-SAFE. Every public function is wrapped so that any error is swallowed. A
  growth problem must NEVER break a pentest run or the CLI.
* SHOWN ONCE. The CTA appears only after the first real delivered value and, by
  default, exactly once. It is non-blocking and informational.

CLI
---
  python -m api.growth milestone <type>       # record a milestone
  python -m api.growth funnel <STAGE>         # record a funnel stage
  python -m api.growth maybe-cta [--dry-run]  # print the CTA if eligible
  python -m api.growth status [--json]        # print current state
  python -m api.growth dismiss                # user opted out of the CTA
  python -m api.growth click                  # user clicked through to GitHub
  python -m api.growth reset                  # clear all growth state (support/tests)
Every mutating command supports --dry-run (report intent, change nothing).
"""
from __future__ import annotations

import json
import os
import sys
import datetime
from typing import Any, Dict, List, Optional

REPO_URL = "https://github.com/ASCIT31/Dark-Moon"

# --- allow-lists -----------------------------------------------------------
# Value events prove real delivered value and can trigger the CTA.
VALUE_EVENTS = frozenset({
    "campaign_finalized",
    "validated_finding",
    "report_generated",
    "retest_completed",
    "ci_run_success",
})
# Non-value events are recorded for the funnel but never trigger the CTA.
NON_VALUE_EVENTS = frozenset({
    "first_run",
    "first_campaign",
})
MILESTONE_EVENTS = VALUE_EVENTS | NON_VALUE_EVENTS

FUNNEL_STAGES = frozenset({
    "INSTALL",
    "FIRST_RUN",
    "FIRST_CAMPAIGN",
    "SUCCESS",
    "FIRST_VALIDATED_FINDING",
    "STAR_CTA_SHOWN",
    "STAR_CTA_CLICKED",
})

_FALSY = frozenset({"", "0", "false", "no", "off", "none"})


# --- env helpers -----------------------------------------------------------
def _flag(name: str) -> bool:
    """True when an env flag is set to a truthy value."""
    return os.environ.get(name, "").strip().lower() not in _FALSY


def telemetry_disabled() -> bool:
    return _flag("DARKMOON_NO_TELEMETRY") or _flag("DARKMOON_GROWTH_DISABLE")


def cta_disabled() -> bool:
    return _flag("DARKMOON_DISABLE_GROWTH_CTA") or telemetry_disabled()


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def max_shows() -> int:
    return max(1, _int_env("DARKMOON_GROWTH_CTA_MAX_SHOWS", 1))


def min_days_between() -> int:
    return max(0, _int_env("DARKMOON_GROWTH_CTA_MIN_DAYS", 30))


# --- paths -----------------------------------------------------------------
def growth_dir() -> str:
    d = os.environ.get("DARKMOON_GROWTH_DIR", "").strip()
    if not d:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "share"
        )
        d = os.path.join(base, "darkmoon", "growth")
    return d


def _path(name: str) -> str:
    return os.path.join(growth_dir(), name)


MILESTONES = "milestones.json"
CTA_STATE = "cta_state.json"
FUNNEL = "funnel.jsonl"


# --- time ------------------------------------------------------------------
def _now(now: Optional[datetime.datetime] = None) -> datetime.datetime:
    return now or datetime.datetime.now()


def _iso(dt: datetime.datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(s: Any) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.fromisoformat(str(s))
    except (TypeError, ValueError):
        return None


# --- low-level io (never raises) ------------------------------------------
def _load(name: str) -> Dict[str, Any]:
    try:
        with open(_path(name), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(name: str, obj: Dict[str, Any]) -> bool:
    if telemetry_disabled():
        return False
    try:
        os.makedirs(growth_dir(), exist_ok=True)
        tmp = _path(name) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, sort_keys=True)
        os.replace(tmp, _path(name))
        return True
    except Exception:
        return False


def _append_funnel(stage: str, dt: datetime.datetime) -> bool:
    if telemetry_disabled():
        return False
    try:
        os.makedirs(growth_dir(), exist_ok=True)
        with open(_path(FUNNEL), "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": _iso(dt), "stage": stage}) + "\n")
        return True
    except Exception:
        return False


# --- recording -------------------------------------------------------------
def record_milestone(event_type: str, now: Optional[datetime.datetime] = None) -> bool:
    """
    Record a milestone. Only the fixed event *type* is stored (plus timestamps and
    a count). Unknown types are ignored. No other data is accepted or persisted.
    Returns True if state was written.
    """
    try:
        if event_type not in MILESTONE_EVENTS:
            return False
        if telemetry_disabled():
            return False
        dt = _now(now)
        m = _load(MILESTONES)
        m.setdefault("first_seen_at", _iso(dt))
        events = m.setdefault("events", {})
        rec = events.setdefault(event_type, {"first_at": _iso(dt), "count": 0})
        rec["count"] = int(rec.get("count", 0)) + 1
        rec.setdefault("first_at", _iso(dt))
        rec["last_at"] = _iso(dt)
        if event_type in VALUE_EVENTS and not m.get("first_value_at"):
            m["first_value_at"] = _iso(dt)
        ok = _save(MILESTONES, m)
        # Mirror the value milestone into the funnel timeline.
        if event_type == "campaign_finalized":
            _append_funnel("SUCCESS", dt)
        elif event_type == "validated_finding":
            _append_funnel("FIRST_VALIDATED_FINDING", dt)
        return ok
    except Exception:
        return False


def record_funnel(stage: str, now: Optional[datetime.datetime] = None) -> bool:
    try:
        if stage not in FUNNEL_STAGES:
            return False
        return _append_funnel(stage, _now(now))
    except Exception:
        return False


# --- CTA state -------------------------------------------------------------
def cta_state() -> Dict[str, Any]:
    return _load(CTA_STATE)


def first_value_reached() -> bool:
    try:
        return bool(_load(MILESTONES).get("first_value_at"))
    except Exception:
        return False


def should_show_cta(now: Optional[datetime.datetime] = None) -> bool:
    try:
        if cta_disabled():
            return False
        if not first_value_reached():
            return False
        st = cta_state()
        if st.get("dismissed"):
            return False
        shows = int(st.get("show_count", 0))
        if shows >= max_shows():
            return False
        last = _parse(st.get("last_shown_at"))
        if last is not None and min_days_between() > 0:
            if (_now(now) - last).days < min_days_between():
                return False
        return True
    except Exception:
        return False


def mark_cta_shown(now: Optional[datetime.datetime] = None) -> None:
    try:
        dt = _now(now)
        st = cta_state()
        st["star_cta_shown"] = True
        st["show_count"] = int(st.get("show_count", 0)) + 1
        st["last_shown_at"] = _iso(dt)
        st.setdefault("first_shown_at", _iso(dt))
        _save(CTA_STATE, st)
        _append_funnel("STAR_CTA_SHOWN", dt)
    except Exception:
        pass


def mark_cta_dismissed() -> None:
    try:
        st = cta_state()
        st["dismissed"] = True
        st["dismissed_at"] = _iso(_now())
        _save(CTA_STATE, st)
    except Exception:
        pass


def mark_cta_clicked(now: Optional[datetime.datetime] = None) -> None:
    try:
        dt = _now(now)
        st = cta_state()
        st["clicked"] = True
        st["clicked_at"] = _iso(dt)
        _save(CTA_STATE, st)
        _append_funnel("STAR_CTA_CLICKED", dt)
    except Exception:
        pass


# --- rendering / emit ------------------------------------------------------
def render_cta() -> str:
    line = "─" * 62
    return (
        "\n"
        + line + "\n"
        + " Darkmoon just delivered your first real result.\n"
        + " If it was useful, a GitHub star helps the open source project grow:\n"
        + "   " + REPO_URL + "\n"
        + " (Shown once. Turn it off anytime: export DARKMOON_DISABLE_GROWTH_CTA=1)\n"
        + line + "\n"
    )


def maybe_emit_cta(stream=None, now: Optional[datetime.datetime] = None) -> bool:
    """Emit the CTA to `stream` (default stderr) if eligible, then mark it shown.
    Returns True if the CTA was emitted. Fail-safe."""
    try:
        if not should_show_cta(now=now):
            return False
        out = stream if stream is not None else sys.stderr
        out.write(render_cta())
        try:
            out.flush()
        except Exception:
            pass
        mark_cta_shown(now=now)
        return True
    except Exception:
        return False


# --- status ----------------------------------------------------------------
def status() -> Dict[str, Any]:
    m = _load(MILESTONES)
    st = cta_state()
    return {
        "growth_dir": growth_dir(),
        "telemetry_disabled": telemetry_disabled(),
        "cta_disabled": cta_disabled(),
        "first_value_reached": bool(m.get("first_value_at")),
        "first_value_at": m.get("first_value_at"),
        "milestone_events": {k: v.get("count") for k, v in (m.get("events") or {}).items()},
        "cta_shown": bool(st.get("star_cta_shown")),
        "cta_show_count": int(st.get("show_count", 0)),
        "cta_dismissed": bool(st.get("dismissed")),
        "cta_clicked": bool(st.get("clicked")),
        "would_show_now": should_show_cta(),
    }


def reset() -> None:
    for name in (MILESTONES, CTA_STATE, FUNNEL):
        try:
            os.remove(_path(name))
        except OSError:
            pass


# --- CLI -------------------------------------------------------------------
def _main(argv: List[str]) -> int:
    if not argv:
        print(__doc__.strip())
        return 2
    cmd = argv[0]
    dry = "--dry-run" in argv[1:]
    rest = [a for a in argv[1:] if a != "--dry-run"]

    if cmd == "milestone":
        if not rest:
            print("usage: growth milestone <type>", file=sys.stderr)
            return 2
        et = rest[0]
        if et not in MILESTONE_EVENTS:
            print(f"unknown milestone type: {et} (allowed: {sorted(MILESTONE_EVENTS)})",
                  file=sys.stderr)
            return 2
        if dry:
            print(f"[dry-run] would record milestone: {et} in {growth_dir()}")
            return 0
        print("recorded" if record_milestone(et) else "not recorded (opt-out or error)")
        return 0

    if cmd == "funnel":
        if not rest or rest[0] not in FUNNEL_STAGES:
            print(f"usage: growth funnel <STAGE> (allowed: {sorted(FUNNEL_STAGES)})",
                  file=sys.stderr)
            return 2
        if dry:
            print(f"[dry-run] would record funnel stage: {rest[0]}")
            return 0
        print("recorded" if record_funnel(rest[0]) else "not recorded (opt-out or error)")
        return 0

    if cmd == "maybe-cta":
        if dry:
            eligible = should_show_cta()
            print(f"[dry-run] would_show={eligible}")
            if eligible:
                sys.stdout.write(render_cta())
            return 0
        return 0 if maybe_emit_cta(stream=sys.stdout) else 0

    if cmd == "status":
        s = status()
        if "--json" in rest:
            print(json.dumps(s, indent=2))
        else:
            for k, v in s.items():
                print(f"  {k}: {v}")
        return 0

    if cmd == "dismiss":
        if dry:
            print("[dry-run] would mark CTA dismissed")
            return 0
        mark_cta_dismissed()
        print("dismissed")
        return 0

    if cmd == "click":
        if dry:
            print("[dry-run] would mark CTA clicked")
            return 0
        mark_cta_clicked()
        print("clicked")
        return 0

    if cmd == "reset":
        if dry:
            print(f"[dry-run] would delete growth state in {growth_dir()}")
            return 0
        reset()
        print("reset")
        return 0

    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
