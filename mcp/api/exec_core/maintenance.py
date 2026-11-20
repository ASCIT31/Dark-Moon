"""Maintenance windows: the owner's launch policy of a project and its evaluation (both editions).

A policy says WHEN active testing may start on a project:

* ``windows``: weekly time ranges in the project's IANA ``timezone`` (wall-clock time, so a window keeps its local hours
  across daylight-saving changes). ``days`` are the days a window STARTS on; ``end`` before ``start`` means the window
  runs past midnight (« fri 22:00–06:00 » = Friday 22:00 to Saturday 06:00); ``end`` ``24:00`` = midnight. Start is
  inclusive, end exclusive. Overlapping or adjacent windows add up. No window at all = no weekly restriction (only the
  blackout dates apply);
* ``blackouts``: date ranges (local dates, both ends inclusive) when nothing may start, windows included;
* ``intrusive_only``: when true, only intrusive campaign kinds are restricted (every kind Darkmoon launches today —
  ``full``, ``retest``, ``short`` — is intrusive; ``passive`` is the only kind that is not, and nothing launches it
  yet). An unknown kind counts as intrusive;
* ``max_duration_minutes``: the longest planned run the owner accepts. Darkmoon does not stop a running campaign at a
  window end or at this duration: a planned duration over it blocks the launch, an undeclared one is a warning.

``evaluate`` is pure and deterministic: same policy, instant, kind and duration -> same answer, wherever it runs (the
only outside input is the host's time-zone database, read through ``zoneinfo``). The answer is ``allowed``, ``warn``
or ``blocked`` with the reasons in plain words, the matched window, the local time and the next window start.
Enforcement is the edition's: Pro blocks its launch paths, Community only warns (``as_advisory``).

Which projects a launch touches (``target_matches``): the launch target and the stored target are normalised the same
way — URL forms (scheme, user info, port, path, trailing dot, case), IP literals in any form ``inet_aton`` accepts
(decimal, hexadecimal, octal or short dotted forms) and IPv4-mapped IPv6 addresses; a CIDR range matches every stored
address it contains; a host name matches its subdomains and its parent domains in both directions.

Daylight-saving rules: a local wall time that does not exist (spring forward) starts at the first instant after the
gap; a wall time that happens twice (fall back) starts at its first occurrence; « inside a window » compares the local
wall-clock time of the instant, so both occurrences of a repeated hour are treated alike.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

POLICY_VERSION = "darkmoon-maintenance-policy/1"
EVALUATION_VERSION = "darkmoon-maintenance-evaluation/1"

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_WORDS = {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday", "fri": "Friday",
             "sat": "Saturday", "sun": "Sunday"}
INTRUSIVE_KINDS = frozenset({"full", "retest", "short"})
NON_INTRUSIVE_KINDS = frozenset({"passive"})

MAX_WINDOWS = 28
MAX_BLACKOUTS = 100
MAX_BLACKOUT_DAYS = 366
MAX_LABEL = 80
MAX_NOTE = 500
MAX_DURATION_MINUTES = 7 * 24 * 60
_SEARCH_DAYS = 400            # next-window search horizon (covers the longest blackout)

TOP_KEYS = frozenset({"schema_version", "project_id", "enabled", "timezone", "intrusive_only", "windows", "blackouts",
                      "max_duration_minutes", "note"})
_WINDOW_KEYS = frozenset({"days", "start", "end", "label"})
_BLACKOUT_KEYS = frozenset({"start", "end", "label"})

# « UTC » or Area/Location[/Sub] — no absolute path, no « .. », no single-word legacy alias
_TZ_RE = re.compile(r"^(?:UTC|[A-Za-z][A-Za-z0-9_+\-]{0,30}(?:/[A-Za-z0-9][A-Za-z0-9_+\-]{0,30}){1,2})$")
_START_RE = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
_END_RE = re.compile(r"^(?:(?:[01][0-9]|2[0-3]):[0-5][0-9]|24:00)$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CONTROLS = re.compile("[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")

BLOCKING = frozenset({"policy-invalid", "timezone-unavailable", "outside-window", "blackout", "run-enters-blackout",
                      "duration-over-maximum"})
WARNING = frozenset({"may-run-past-window", "duration-not-declared"})


# ── validation ────────────────────────────────────────────────────────────────────────────────────────────────────

def zone(name: Any):
    """The tzinfo of an IANA name, or None (malformed name, or unknown to this host's time-zone database)."""
    if not isinstance(name, str) or not _TZ_RE.match(name):
        return None
    if name == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _label(v: Any, where: str, issues: List[Dict[str, str]], limit: int = MAX_LABEL) -> Optional[str]:
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        issues.append({"field": where, "message": "must be text"})
        return None
    if _CONTROLS.search(v):
        issues.append({"field": where, "message": "control characters are not allowed"})
        return None
    v = v.strip()
    if len(v) > limit:
        issues.append({"field": where, "message": f"at most {limit} characters"})
        return None
    return v or None


def _date(v: Any) -> Optional[date]:
    if not isinstance(v, str) or not _DATE_RE.match(v):
        return None
    try:
        return datetime.strptime(v, "%Y-%m-%d").date()
    except ValueError:
        return None


def validate_policy(doc: Any, project_id: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, str]]]:
    """(clean policy, issues). Any issue -> (None, issues): nothing is coerced or partly accepted."""
    issues: List[Dict[str, str]] = []
    if not isinstance(doc, dict):
        return None, [{"field": "policy", "message": "must be an object"}]
    unknown = sorted(str(k) for k in doc if k not in TOP_KEYS)
    if unknown:
        issues.append({"field": "policy", "message": f"unknown fields {unknown}"})
    if doc.get("schema_version") not in (None, POLICY_VERSION):
        issues.append({"field": "schema_version", "message": f"must be {POLICY_VERSION}"})
    if project_id is not None and doc.get("project_id") not in (None, project_id):
        issues.append({"field": "project_id", "message": "does not match this project"})
    enabled = doc.get("enabled", True)
    if not isinstance(enabled, bool):
        issues.append({"field": "enabled", "message": "must be true or false"})
    intrusive_only = doc.get("intrusive_only", False)
    if not isinstance(intrusive_only, bool):
        issues.append({"field": "intrusive_only", "message": "must be true or false"})
    tz = doc.get("timezone")
    if not isinstance(tz, str) or not _TZ_RE.match(tz):
        issues.append({"field": "timezone", "message": "an IANA time zone such as Europe/Paris, or UTC"})
    elif zone(tz) is None:
        issues.append({"field": "timezone", "message": f"unknown time zone {tz!r} on this server"})

    windows: List[Dict[str, Any]] = []
    raw_w = doc.get("windows", [])
    if not isinstance(raw_w, list):
        issues.append({"field": "windows", "message": "must be a list"})
        raw_w = []
    if len(raw_w) > MAX_WINDOWS:
        issues.append({"field": "windows", "message": f"at most {MAX_WINDOWS} windows"})
        raw_w = []
    for i, w in enumerate(raw_w):
        where = f"windows[{i}]"
        if not isinstance(w, dict):
            issues.append({"field": where, "message": "must be an object"})
            continue
        bad = sorted(str(k) for k in w if k not in _WINDOW_KEYS)
        if bad:
            issues.append({"field": where, "message": f"unknown fields {bad}"})
        days = w.get("days")
        if not isinstance(days, list) or not days or not all(isinstance(d, str) and d in DAYS for d in days):
            issues.append({"field": f"{where}.days", "message": f"a non-empty list of {', '.join(DAYS)}"})
            days = []
        elif len(set(days)) != len(days):
            issues.append({"field": f"{where}.days", "message": "a day is listed twice"})
        start, end = w.get("start"), w.get("end")
        if not isinstance(start, str) or not _START_RE.match(start):
            issues.append({"field": f"{where}.start", "message": "a time HH:MM between 00:00 and 23:59"})
            start = None
        if not isinstance(end, str) or not _END_RE.match(end):
            issues.append({"field": f"{where}.end", "message": "a time HH:MM between 00:00 and 24:00"})
            end = None
        if start and end and _minutes(start) == _minutes(end) % 1440 and end != "24:00":
            issues.append({"field": where, "message": "start and end are the same time (use 00:00–24:00 for a whole day)"})
        label = _label(w.get("label"), f"{where}.label", issues)
        if days and start and end:
            out = {"days": [d for d in DAYS if d in set(days)], "start": start, "end": end}
            if label:
                out["label"] = label
            windows.append(out)

    blackouts: List[Dict[str, Any]] = []
    raw_b = doc.get("blackouts", [])
    if not isinstance(raw_b, list):
        issues.append({"field": "blackouts", "message": "must be a list"})
        raw_b = []
    if len(raw_b) > MAX_BLACKOUTS:
        issues.append({"field": "blackouts", "message": f"at most {MAX_BLACKOUTS} blackout periods"})
        raw_b = []
    for i, b in enumerate(raw_b):
        where = f"blackouts[{i}]"
        if not isinstance(b, dict):
            issues.append({"field": where, "message": "must be an object"})
            continue
        bad = sorted(str(k) for k in b if k not in _BLACKOUT_KEYS)
        if bad:
            issues.append({"field": where, "message": f"unknown fields {bad}"})
        s, e = _date(b.get("start")), _date(b.get("end", b.get("start")))
        if s is None:
            issues.append({"field": f"{where}.start", "message": "a date YYYY-MM-DD"})
        if e is None:
            issues.append({"field": f"{where}.end", "message": "a date YYYY-MM-DD"})
        if s and e and e < s:
            issues.append({"field": where, "message": "end is before start"})
        elif s and e and (e - s).days >= MAX_BLACKOUT_DAYS:
            issues.append({"field": where, "message": f"at most {MAX_BLACKOUT_DAYS} days"})
        label = _label(b.get("label"), f"{where}.label", issues)
        if s and e and e >= s:
            out = {"start": s.isoformat(), "end": e.isoformat()}
            if label:
                out["label"] = label
            blackouts.append(out)

    md = doc.get("max_duration_minutes")
    if md is not None and (not isinstance(md, int) or isinstance(md, bool) or not 1 <= md <= MAX_DURATION_MINUTES):
        issues.append({"field": "max_duration_minutes", "message": f"a whole number of minutes, 1 to {MAX_DURATION_MINUTES}"})
    note = _label(doc.get("note"), "note", issues, MAX_NOTE)

    if issues:
        return None, issues
    clean: Dict[str, Any] = {"schema_version": POLICY_VERSION, "enabled": enabled, "timezone": tz,
                             "intrusive_only": intrusive_only, "windows": windows,
                             "blackouts": sorted(blackouts, key=lambda b: (b["start"], b["end"])),
                             "max_duration_minutes": md}
    if note:
        clean["note"] = note
    return clean, []


# ── time helpers ──────────────────────────────────────────────────────────────────────────────────────────────────

def _utc(at: Any) -> Optional[datetime]:
    """An aware UTC instant from a datetime (naive = UTC) or an ISO-8601 string; None when unreadable."""
    if isinstance(at, str):
        try:
            at = datetime.fromisoformat(at.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(at, datetime):
        return None
    if at.tzinfo is None or at.utcoffset() is None:
        at = at.replace(tzinfo=timezone.utc)
    return at.astimezone(timezone.utc)


def _iso(u: Optional[datetime]) -> Optional[str]:
    return u.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if u else None


def _wall(u: datetime, tz) -> datetime:
    return u.astimezone(tz).replace(tzinfo=None)


def local_instant(d: date, minute: int, tz) -> datetime:
    """The UTC instant of local wall time ``minute`` (0–1440) on local date ``d``. A wall time inside a spring-forward
    gap -> the first instant after the gap; a repeated wall time (fall back) -> its first occurrence."""
    if minute >= 1440:
        d, minute = d + timedelta(days=1), minute - 1440
    naive = datetime.combine(d, time(minute // 60, minute % 60))
    u = naive.replace(tzinfo=tz, fold=0).astimezone(timezone.utc)
    if _wall(u, tz) == naive:
        return u
    # gap: walk back to the first instant whose wall time reaches the requested one (gaps last at most a few hours)
    step = timedelta(minutes=1)
    for _ in range(24 * 60):
        if _wall(u - step, tz) < naive:
            break
        u -= step
    return u


def _window_hit(w: Dict[str, Any], d: date, minute: int) -> Optional[date]:
    """The local start date of the occurrence of window ``w`` covering local (``d``, ``minute``), or None."""
    s, e = _minutes(w["start"]), _minutes(w["end"])
    today, yesterday = DAYS[d.weekday()], DAYS[(d.weekday() - 1) % 7]
    if e > s:                                     # same-day window (end 24:00 = 1440 included)
        return d if today in w["days"] and s <= minute < e else None
    if today in w["days"] and minute >= s:        # overnight window, first part
        return d
    if yesterday in w["days"] and minute < e:     # overnight window, part after midnight
        return d - timedelta(days=1)
    return None


def _occurrence_end(w: Dict[str, Any], start_day: date, tz) -> datetime:
    s, e = _minutes(w["start"]), _minutes(w["end"])
    return local_instant(start_day if e > s else start_day + timedelta(days=1), e, tz)


def _covering(windows: List[Dict[str, Any]], u: datetime, tz) -> List[Tuple[Dict[str, Any], datetime]]:
    """Every window occurrence covering instant ``u``, with its end instant."""
    wall = _wall(u, tz)
    minute = wall.hour * 60 + wall.minute
    out = []
    for w in windows:
        sd = _window_hit(w, wall.date(), minute)
        if sd is not None:
            end = _occurrence_end(w, sd, tz)
            if end > u:
                out.append((w, end))
    return out


def _blackout_of(blackouts: List[Dict[str, Any]], d: date) -> Optional[Dict[str, Any]]:
    iso = d.isoformat()
    for b in blackouts:
        if b["start"] <= iso <= b["end"]:
            return b
    return None


def _next_window_start(policy: Dict[str, Any], u: datetime, tz) -> Optional[datetime]:
    """First instant strictly after ``u`` when a launch would be inside a window and outside every blackout."""
    windows, blackouts = policy["windows"], policy["blackouts"]
    start_day = _wall(u, tz).date()
    if not windows:                    # no weekly restriction: the day after the blackout that covers today
        d = start_day
        for _ in range(_SEARCH_DAYS):
            d += timedelta(days=1)
            if not _blackout_of(blackouts, d):
                return local_instant(d, 0, tz)
        return None
    best: Optional[datetime] = None
    for k in range(-1, _SEARCH_DAYS):
        d = start_day + timedelta(days=k)
        for w in windows:
            if DAYS[d.weekday()] not in w["days"]:
                continue
            st = local_instant(d, _minutes(w["start"]), tz)
            end = _occurrence_end(w, d, tz)
            cands = [st]
            mid = local_instant(d + timedelta(days=1), 0, tz)
            if st < mid < end:          # the part of an overnight window after midnight starts on another date
                cands.append(mid)
            for c in cands:
                if c > u and not _blackout_of(blackouts, _wall(c, tz).date()) and (best is None or c < best):
                    best = c
        # every candidate of a later day starts on or after that day's midnight
        if best is not None and best <= local_instant(d + timedelta(days=1), 0, tz):
            break
    return best


def _hm(minutes: int) -> str:
    return "24:00" if minutes == 1440 else f"{minutes // 60:02d}:{minutes % 60:02d}"


def _days_words(days: List[str]) -> str:
    idx = [DAYS.index(d) for d in days]
    if len(idx) >= 3 and idx == list(range(idx[0], idx[0] + len(idx))):
        return f"{DAY_WORDS[DAYS[idx[0]]]} to {DAY_WORDS[DAYS[idx[-1]]]}"
    return ", ".join(DAY_WORDS[d] for d in days)


def window_text(w: Dict[str, Any]) -> str:
    s, e = _minutes(w["start"]), _minutes(w["end"])
    span = f"{w['start']}–{w['end']}" + (" (next day)" if e <= s else "")
    return f"{_days_words(w['days'])}, {span}" + (f" — {w['label']}" if w.get("label") else "")


def describe(policy: Optional[Dict[str, Any]]) -> List[str]:
    """The policy in plain sentences (UI, terminal, report): the same words in both editions."""
    if not policy:
        return ["No maintenance policy: launches are not restricted by time."]
    lines = []
    if not policy.get("enabled", True):
        lines.append("Policy switched off: launches are not restricted by time.")
    scope = ("Intrusive campaigns" if policy.get("intrusive_only") else "Every campaign")
    if policy["windows"]:
        lines.append(f"{scope} may start only inside these windows ({policy['timezone']} time):")
        lines.extend(f"• {window_text(w)}" for w in policy["windows"])
    else:
        lines.append(f"No weekly window: {scope.lower()} may start at any time outside the blackout dates.")
    for b in policy["blackouts"]:
        span = b["start"] if b["start"] == b["end"] else f"{b['start']} to {b['end']}"
        lines.append(f"Blackout {span}" + (f" — {b['label']}" if b.get("label") else "") + ": nothing may start.")
    if policy.get("max_duration_minutes"):
        lines.append(f"Longest accepted run: {policy['max_duration_minutes']} minutes (declared at launch; Darkmoon "
                     "does not stop a running campaign).")
    return lines


# ── evaluation ────────────────────────────────────────────────────────────────────────────────────────────────────

def _reason(code: str, message: str) -> Dict[str, str]:
    return {"code": code, "message": message, "effect": "block" if code in BLOCKING else "warn" if code in WARNING else "none"}


def evaluate(policy: Any, at_utc: Any, campaign_kind: Any = "full", planned_duration: Any = None) -> Dict[str, Any]:
    """Whether a campaign of ``campaign_kind`` may start at ``at_utc`` (aware datetime, naive = UTC, or ISO-8601) under
    ``policy`` (raw or clean; validated here). ``planned_duration``: minutes (int) or a timedelta, None = not declared.
    Returns the evaluation document; ``decision`` is ``allowed``, ``warn`` or ``blocked``."""
    kind = str(campaign_kind or "full").strip().lower()[:32]
    intrusive = kind not in NON_INTRUSIVE_KINDS
    u = _utc(at_utc)
    doc: Dict[str, Any] = {"schema_version": EVALUATION_VERSION, "decision": "allowed", "enforced": True,
                           "reasons": [], "at_utc": _iso(u), "campaign_kind": kind, "intrusive": intrusive,
                           "policy_present": policy is not None, "timezone": None, "local_time": None,
                           "window": None, "window_ends_at_utc": None, "next_window_start_utc": None,
                           "planned_duration_minutes": None}
    reasons: List[Dict[str, str]] = doc["reasons"]
    if u is None:
        reasons.append(_reason("policy-invalid", "The launch time could not be read."))
        doc["decision"] = "blocked"
        return doc
    if policy is None:
        reasons.append(_reason("no-policy", "No maintenance policy for this project: launches are not restricted by time."))
        return doc
    clean, issues = validate_policy(policy)
    if clean is None:
        tz_issue = [i for i in issues if i["field"] == "timezone" and "unknown time zone" in i["message"]]
        if tz_issue and len(issues) == 1:
            reasons.append(_reason("timezone-unavailable", f"The policy's time zone is not available on this server "
                                                           f"({tz_issue[0]['message']}): launches are blocked until it is fixed."))
        else:
            reasons.append(_reason("policy-invalid", "The stored maintenance policy is not valid: launches are blocked "
                                                     "until an administrator fixes it."))
        doc["decision"] = "blocked"
        doc["policy_issues"] = issues[:20]
        return doc
    tz = zone(clean["timezone"])
    doc["timezone"] = clean["timezone"]
    doc["local_time"] = u.astimezone(tz).isoformat(timespec="minutes")
    dur: Optional[timedelta] = None
    if isinstance(planned_duration, timedelta):
        dur = planned_duration
    elif isinstance(planned_duration, int) and not isinstance(planned_duration, bool):
        dur = timedelta(minutes=planned_duration)
    if dur is not None:
        if dur <= timedelta(0):
            dur = None
        else:
            doc["planned_duration_minutes"] = int(dur.total_seconds() // 60)
    if not clean["enabled"]:
        reasons.append(_reason("policy-disabled", "The maintenance policy is switched off: launches are not restricted by time."))
        return doc
    if clean["intrusive_only"] and not intrusive:
        reasons.append(_reason("not-restricted", f"Only intrusive campaigns are restricted; a « {kind} » campaign is not."))
        return doc

    wall = _wall(u, tz)
    bo = _blackout_of(clean["blackouts"], wall.date())
    if bo:
        reasons.append(_reason("blackout", f"{wall.date().isoformat()} is a blackout date"
                                           + (f" ({bo['label']})" if bo.get("label") else "") + ": nothing may start."))
    cover = _covering(clean["windows"], u, tz) if clean["windows"] else []
    union_end: Optional[datetime] = None
    if clean["windows"]:
        if cover:
            w, end = min(cover, key=lambda c: (c[1], c[0]["start"]))
            doc["window"] = dict(w)
            union_end = max(e for _, e in cover)
            for _ in range(64):                    # overlapping / adjacent windows add up
                nxt = _covering(clean["windows"], union_end, tz)
                later = max((e for _, e in nxt), default=union_end)
                if later <= union_end:
                    break
                union_end = later
            doc["window_ends_at_utc"] = _iso(union_end)
            reasons.append(_reason("inside-window", f"Inside the window {window_text(w)} ({clean['timezone']})."))
        else:
            reasons.append(_reason("outside-window", f"Outside every maintenance window: local time "
                                                     f"{wall.strftime('%a %H:%M')} ({clean['timezone']})."))
    else:
        reasons.append(_reason("no-weekly-window", "No weekly window: only the blackout dates restrict launches."))

    md = clean.get("max_duration_minutes")
    if dur is not None:
        last_day = _wall(u + dur, tz).date()
        d = wall.date() + timedelta(days=1)
        while d <= last_day and not bo:
            hit = _blackout_of(clean["blackouts"], d)
            if hit:
                reasons.append(_reason("run-enters-blackout", f"A run of {doc['planned_duration_minutes']} minutes would "
                                                              f"reach the blackout date {d.isoformat()}."))
                break
            d += timedelta(days=1)
        if md and dur > timedelta(minutes=md):
            reasons.append(_reason("duration-over-maximum", f"The planned run ({doc['planned_duration_minutes']} minutes) is "
                                                            f"longer than the accepted maximum ({md} minutes)."))
        if union_end is not None and u + dur > union_end:
            reasons.append(_reason("may-run-past-window", "The planned run would go on after the window ends; Darkmoon "
                                                          "does not stop a running campaign at the window end."))
    elif md:
        reasons.append(_reason("duration-not-declared", f"No planned duration was given; the policy accepts runs of at "
                                                        f"most {md} minutes and Darkmoon does not stop a running campaign."))

    if any(r["effect"] == "block" for r in reasons):
        doc["decision"] = "blocked"
        if any(r["code"] in ("outside-window", "blackout") for r in reasons):   # a later start would be allowed
            doc["next_window_start_utc"] = _iso(_next_window_start(clean, u, tz))
    elif any(r["effect"] == "warn" for r in reasons):
        doc["decision"] = "warn"
    return doc


def as_advisory(evaluation: Dict[str, Any]) -> Dict[str, Any]:
    """The same evaluation where nothing is enforced (Community): a block becomes a warning, the reasons stay."""
    out = dict(evaluation)
    out["enforced"] = False
    if out.get("decision") == "blocked":
        out["decision"] = "warn"
        out["advisory_of"] = "blocked"
    return out


def combine(evaluations: List[Dict[str, Any]]) -> str:
    """One decision for a launch that touches several projects: the strictest one."""
    order = {"allowed": 0, "warn": 1, "blocked": 2}
    worst = max((order.get(e.get("decision"), 2) for e in evaluations), default=0)
    return ("allowed", "warn", "blocked")[worst]


def summary_line(evaluation: Dict[str, Any]) -> str:
    """One sentence for a log line, a terminal or a block message."""
    dec = evaluation.get("decision")
    msgs = [r["message"] for r in evaluation.get("reasons") or [] if r.get("effect") != "none"]
    head = {"allowed": "Launch allowed by the maintenance policy.",
            "warn": "Launch allowed with a maintenance warning.",
            "blocked": "Launch blocked by the maintenance policy."}.get(str(dec), "Maintenance policy decision unknown.")
    if evaluation.get("advisory_of") == "blocked":
        head = "WARNING: outside the maintenance policy (Community does not block the launch)."
    tail = " ".join(msgs)
    nxt = evaluation.get("next_window_start_utc")
    return " ".join(x for x in (head, tail, f"Next allowed start: {nxt} (UTC)." if nxt else "") if x)


# ── which stored targets a launch target touches ─────────────────────────────────────────────────────────────────

IPAddr = Any


def launch_host(target: Any) -> str:
    """Bare host of a target that may be a URL / host:port / [IPv6]:port: lower-case, no trailing dot, no ``*.``."""
    v = str(target or "").strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0] if not re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", v) else v   # keep a CIDR suffix
    v = v.split("?", 1)[0].split("#", 1)[0]
    v = v.rsplit("@", 1)[-1]
    if v.startswith("["):
        v = v[1:].split("]", 1)[0]
    elif v.count(":") == 1:
        v = v.split(":", 1)[0]
    v = v.strip().lower().rstrip(".")
    return v[2:] if v.startswith("*.") else v


def _inet_aton(text: str) -> Optional[IPAddr]:
    """IPv4 forms ``inet_aton`` accepts: 1 to 4 parts, each decimal, 0x-hexadecimal or 0-octal (10.0.0.05, 0x0a000005,
    167772165, 10.5)."""
    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or any(p == "" for p in parts):
        return None
    nums = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                n = int(p[2:], 16)
            elif len(p) > 1 and p.startswith("0"):
                n = int(p, 8)
            else:
                n = int(p, 10)
        except ValueError:
            return None
        nums.append(n)
    limits = {1: [2 ** 32], 2: [256, 2 ** 24], 3: [256, 256, 2 ** 16], 4: [256, 256, 256, 256]}[len(nums)]
    if any(n < 0 or n >= lim for n, lim in zip(nums, limits)):
        return None
    value = 0
    for n, lim in zip(nums, limits):
        value = value * lim + n
    return ipaddress.ip_address(value)


def parse_ip(text: Any) -> Optional[IPAddr]:
    """An IP address in any accepted form (IPv4-mapped IPv6 -> its IPv4), else None."""
    t = str(text or "").strip().lower().strip("[]")
    if not t:
        return None
    try:
        ip = ipaddress.ip_address(t.split("%", 1)[0])
    except ValueError:
        ip = _inet_aton(t) if re.match(r"^[0-9a-fx.]+$", t) else None
    if ip is not None and ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_network(text: Any) -> Optional[Any]:
    t = str(text or "").strip().lower()
    if "/" not in t:
        return None
    base, _, bits = t.partition("/")
    ip = parse_ip(base)
    if ip is None or not bits.isdigit():
        return None
    try:
        return ipaddress.ip_network(f"{ip}/{bits}", strict=False)
    except ValueError:
        return None


def _is_host(h: str) -> bool:
    """A host name, dotted or not (``dvga``, ``localhost``, an intranet short name): not an address, not a range."""
    return bool(h) and parse_ip(h) is None and parse_network(h) is None


def _is_name(h: str) -> bool:
    """A dotted host name: only these may act as a parent domain (a bare label such as ``com`` never does)."""
    return _is_host(h) and "." in h


def target_matches(launch_target: Any, stored_host: Any, stored_ip: Any = None) -> bool:
    """True when a launch target touches a stored target (``host``, ``ip``): same address in any form, a CIDR range
    containing a stored address, the same host name, a subdomain of it or a parent domain of it."""
    lh = launch_host(launch_target)
    if not lh:
        return False
    sh, si = launch_host(stored_host), launch_host(stored_ip)
    stored_ips = {x for x in (parse_ip(sh), parse_ip(si)) if x is not None}
    net = parse_network(lh)
    if net is not None:
        return any(ip.version == net.version and ip in net for ip in stored_ips)
    ip = parse_ip(lh)
    if ip is not None:
        return ip in stored_ips
    for h in (sh, si):
        if not _is_host(h):
            continue
        if lh == h or lh.endswith("." + h) or (_is_name(lh) and h.endswith("." + lh)):
            return True
    return False
