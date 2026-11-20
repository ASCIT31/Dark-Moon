"""Security event taxonomy: the stable names and fields of Darkmoon's security log events (both editions).

One event = one dictionary with a stable shape (``SCHEMA``):

* ``event``: the stable name (``auth.login``, ``admin.maintenance_policy.replace``, ``campaign.launch`` …), never
  renamed once shipped (a new meaning gets a new name);
* ``category`` / ``action`` / ``outcome`` / ``severity``: from the catalogue below; ``outcome`` is one of
  ``success``, ``failure``, ``blocked``, ``override``, ``warning``; ``severity`` (``info``, ``low``, ``medium``,
  ``high``) is fixed per (event, outcome) so a SIEM rule can rely on it;
* ``at`` (UTC, ISO-8601, given by the caller: this module never reads the clock), ``actor`` (account name),
  ``actor_role``, ``via`` (bearer / session / service / scheduler / mcp), ``source_ip``, ``target`` (project,
  campaign, run, schedule … ids), ``reason`` and ``details`` (small scalars only).

The field names were chosen to map easily onto common SIEM schemas (category / action / outcome / user / source
address); this is not a claim of conformance to any of them (no OCSF or ECS validation is done).

Hygiene, applied to every value (``event``):
* no secret: a key that names a secret (password, token, secret, cookie, csrf, authorization, api key, credential,
  session, private key …) keeps its key and loses its value (``[redacted]``); a value shaped like a bearer token, a
  JWT or a provider API key is replaced the same way;
* no log injection: control characters (new lines, ANSI escape, C1, bidi overrides) are written as visible escapes
  (``\\n``, ``\\x1b``, ``\\u202e``), so one event is always one line and cannot drive a terminal;
* bounded: text values are cut (``MAX_TEXT``), at most ``MAX_DETAILS`` detail keys, lists of at most 20 items.

Pure, no I/O.
"""
from __future__ import annotations

import json
import hashlib
import re
from typing import Any, Dict, List, Optional

SCHEMA = "darkmoon-security-event/1"

OUTCOMES = ("success", "failure", "blocked", "override", "warning")
SEVERITIES = ("info", "low", "medium", "high")
MAX_TEXT = 200
MAX_DETAILS = 20
REDACTED = "[redacted]"

_ADMIN = {"success": "low", "failure": "medium"}

# name -> (category, action, {outcome: severity}, meaning)
EVENTS: Dict[str, tuple] = {
    "auth.login": ("authentication", "login", {"success": "info", "failure": "medium"},
                   "An account signed in, or a sign-in was refused."),
    "auth.logout": ("authentication", "logout", {"success": "info"},
                    "An account signed out (every session of the account is revoked)."),
    "auth.password_change": ("authentication", "password_change", {"success": "low", "failure": "medium"},
                             "An account changed its password, or the current password was wrong."),
    "auth.csrf_rejected": ("authentication", "csrf_check", {"failure": "medium"},
                           "A state-changing request on a cookie session came without a valid CSRF token."),
    "auth.service_token_issue": ("iam", "service_token_issue", {"success": "medium"},
                                 "A service token was issued (command line)."),
    "authz.admin_denied": ("iam", "authorization_check", {"failure": "medium"},
                           "A non-administrator tried an administrator-only change."),
    "admin.ebios_context.replace": ("configuration", "ebios_context_replace", _ADMIN,
                                    "The EBIOS RM context of a project was replaced."),
    "admin.application_profile.replace": ("configuration", "application_profile_replace", _ADMIN,
                                          "The declared application profile of a project was replaced."),
    "admin.treatment_action.update": ("configuration", "treatment_action_update", _ADMIN,
                                      "A treatment action's status or declarations were changed."),
    "admin.maintenance_policy.replace": ("configuration", "maintenance_policy_replace", _ADMIN,
                                         "The maintenance policy of a project was replaced."),
    "admin.credential.create": ("configuration", "credential_create", _ADMIN, "A stored credential was added."),
    "admin.credential.update": ("configuration", "credential_update", _ADMIN, "A stored credential was changed."),
    "admin.credential.delete": ("configuration", "credential_delete", _ADMIN, "A stored credential was deleted."),
    "admin.webhook.create": ("configuration", "webhook_create", _ADMIN, "A webhook was registered."),
    "admin.webhook.delete": ("configuration", "webhook_delete", _ADMIN, "A webhook was deleted."),
    "admin.schedule.create": ("configuration", "schedule_create", _ADMIN, "A scheduled campaign was created."),
    "admin.schedule.update": ("configuration", "schedule_update", _ADMIN, "A scheduled campaign was changed."),
    "admin.schedule.delete": ("configuration", "schedule_delete", _ADMIN, "A scheduled campaign was deleted."),
    "admin.operator_path.change": ("configuration", "operator_path_change", _ADMIN,
                                   "An operator-declared attack path was created, changed, deleted or restored."),
    "admin.finding.quarantine_review": ("configuration", "finding_quarantine_review", _ADMIN,
                                        "A quarantined finding was reviewed."),
    "admin.evidence_token.revoke": ("iam", "evidence_token_revoke", _ADMIN, "A run evidence token was revoked."),
    "campaign.launch": ("campaign", "launch",
                        {"success": "info", "warning": "low", "blocked": "medium", "override": "high",
                         "failure": "medium"},
                        "A campaign launch: started, started with a maintenance warning, blocked by the maintenance "
                        "policy, started by an administrator override, or refused (scope)."),
    "campaign.stop": ("campaign", "stop", {"success": "low", "failure": "medium"}, "A running campaign was stopped."),
}

_SECRET_KEY = re.compile(r"(pass(word|wd|phrase)?|pwd|secret|token|csrf|cookie|authori[sz]ation|api[_-]?key|"
                         r"credential|session|private|bearer|jwt|otp|signature)", re.I)
_SECRET_VALUE = re.compile(r"(\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*"   # JWT
                           r"|\b[Bb]earer\s+[A-Za-z0-9._~+/=-]{8,}"                       # bearer header value
                           r"|\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"                          # provider API keys
                           r"|\bgh[pousr]_[A-Za-z0-9]{20,}"                               # GitHub tokens
                           r"|\bAKIA[0-9A-Z]{16}\b)")                                     # AWS access key id
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f​-‏  ‪-‮⁦-⁩]")
_ESC = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
_KEY = re.compile(r"[^A-Za-z0-9_.-]")


def _escape(m: "re.Match[str]") -> str:
    ch = m.group(0)
    if ch in _ESC:
        return _ESC[ch]
    return f"\\x{ord(ch):02x}" if ord(ch) <= 0xff else f"\\u{ord(ch):04x}"


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    """One safe line: secrets replaced, control characters escaped, length bounded."""
    s = value if isinstance(value, str) else str(value)
    s = _SECRET_VALUE.sub(REDACTED, s)
    s = _CONTROL.sub(_escape, s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _clean_key(k: Any) -> str:
    return _KEY.sub("_", str(k))[:48] or "_"


def _clean_value(key: str, v: Any, depth: int = 0) -> Any:
    if _SECRET_KEY.search(key):
        return REDACTED
    if v is None or isinstance(v, bool) or (isinstance(v, (int, float)) and abs(v) < 1e15):
        return v
    if isinstance(v, (list, tuple)):
        return [_clean_value(key, x, depth + 1) for x in list(v)[:20]] if depth < 2 else clean_text(v)
    if isinstance(v, dict):
        if depth >= 2:
            return clean_text(v)
        return {ck: _clean_value(ck, x, depth + 1) for ck, x in
                ((_clean_key(k), x) for k, x in list(v.items())[:MAX_DETAILS])}
    return clean_text(v)


UNKNOWN_ACTOR = "unknown"


def login_failure_actor(submitted: Any, account_exists: bool, salt: bytes) -> Dict[str, Any]:
    """Who a failed login names in the log (data minimisation): the account name when it is an existing account,
    else ``unknown`` and a short salted digest of what was typed (``details.username_digest``), so repeated attempts
    can be correlated without ever logging a mistyped password. ``salt`` = a server secret (never logged)."""
    text = str(submitted or "")
    if account_exists:
        return {"actor": clean_text(text, 64), "details": {}}
    digest = hashlib.sha256(bytes(salt or b"") + b"|login|" + text.encode("utf-8", "replace")).hexdigest()[:12]
    return {"actor": UNKNOWN_ACTOR, "details": {"username_digest": digest}}


def severity_of(name: str, outcome: str) -> str:
    return EVENTS[name][2][outcome]


def event(name: str, outcome: str, *, at: Optional[str] = None, actor: Any = None, actor_role: Any = None,
          via: Any = None, source_ip: Any = None, target: Optional[Dict[str, Any]] = None, reason: Any = None,
          details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The event dictionary. Unknown name or an outcome the catalogue does not give this event -> ValueError (a
    programming error, caught by the tests, never silently renamed)."""
    if name not in EVENTS:
        raise ValueError(f"unknown security event {name!r}")
    category, action, sev, _ = EVENTS[name]
    if outcome not in sev:
        raise ValueError(f"outcome {outcome!r} is not defined for {name}")
    ev: Dict[str, Any] = {"schema": SCHEMA, "event": name, "category": category, "action": action,
                          "outcome": outcome, "severity": sev[outcome]}
    if at is not None:
        ev["at"] = clean_text(at, 40)
    for k, v, lim in (("actor", actor, 64), ("actor_role", actor_role, 32), ("via", via, 32),
                      ("source_ip", source_ip, 64), ("reason", reason, 300)):
        if v not in (None, ""):
            ev[k] = clean_text(v, lim)
    if target:
        ev["target"] = {_clean_key(k): clean_text(v, 128) for k, v in list(target.items())[:8] if v not in (None, "")}
    if details:
        ev["details"] = {ck: _clean_value(ck, v) for ck, v in
                         ((_clean_key(k), v) for k, v in list(details.items())[:MAX_DETAILS])}
    return ev


def to_json(ev: Dict[str, Any]) -> str:
    """One JSON line (keys sorted, no raw control character: json escapes them and the values are already clean)."""
    return json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


_ORDER = ("event", "outcome", "severity", "category", "action", "actor", "actor_role", "via", "source_ip", "target",
          "reason", "details", "at")


def _kv(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    if isinstance(v, str) and (not v or re.search(r'[\s"=]', v)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def to_text(ev: Dict[str, Any]) -> str:
    """The plain-text form: ``key=value`` pairs on one line, in a fixed order."""
    keys = [k for k in _ORDER if k in ev] + sorted(k for k in ev if k not in _ORDER and k != "schema")
    return "security-event " + " ".join(f"{k}={_kv(ev[k])}" for k in keys)


def catalogue() -> List[Dict[str, Any]]:
    """The catalogue as rows (documentation, tests, the SIEM mapping of a customer)."""
    return [{"event": n, "category": c, "action": a, "severities": dict(s), "meaning": m}
            for n, (c, a, s, m) in sorted(EVENTS.items())]
