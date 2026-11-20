"""Security events and the log format of the Darkmoon server (shipped identically in Community and Pro).

``emit(name, outcome, ...)`` writes one event of the shared taxonomy (``exec_core.taxonomy``: stable names, fields,
secret and control-character hygiene) on the ``darkmoon.audit`` logger. It never raises: a logging problem must never
break a sign-in or a launch.

Log format (``DARKMOON_LOG_FORMAT``):

* ``text`` (default): unchanged for every existing logger; the security events get a handler of their own on
  ``darkmoon.audit`` writing ``<time> <LEVEL> darkmoon.audit security-event event=… outcome=…`` lines on stderr;
* ``json``: every ``darkmoon.*`` record is written as one JSON object per line on stderr (security events with their
  taxonomy fields, other records as ``{"at", "level", "logger", "message"}`` with the message cleaned the same way).

Nothing is configured when the process already configured logging for these loggers (a handler present): the
deployment then decides. The field names are chosen to map easily onto common SIEM schemas; no conformance claimed.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from api.exec_core import taxonomy as T
except ImportError:  # pragma: no cover - imported as a top-level package (explorer vendor layout)
    from exec_core import taxonomy as T  # type: ignore

AUDIT_LOGGER = "darkmoon.audit"
_MARK = "_darkmoon_security_log"


def log_format() -> str:
    v = os.environ.get("DARKMOON_LOG_FORMAT", "").strip().lower()
    return "json" if v == "json" else "text"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class JsonFormatter(logging.Formatter):
    """One JSON object per line; a security event keeps its taxonomy fields."""

    def format(self, record: logging.LogRecord) -> str:
        ev = getattr(record, "dm_event", None)
        if isinstance(ev, dict):
            return T.to_json(ev)
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            msg = str(record.msg)
        out: Dict[str, Any] = {"at": datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                               "level": record.levelname.lower(), "logger": record.name,
                               "message": T.clean_text(msg, 2000)}
        if record.exc_info:
            out["exception"] = T.clean_text(self.formatException(record.exc_info).splitlines()[-1], 300)
        return json.dumps(out, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """``<time> <LEVEL> <logger> <message>`` with the message on one line (control characters escaped)."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        return T.clean_text(line, 4000)


def configure(fmt: Optional[str] = None, stream=None) -> str:
    """Install the handler for the chosen format once (idempotent). Returns the format in force."""
    fmt = fmt or log_format()
    name = "darkmoon" if fmt == "json" else AUDIT_LOGGER
    lg = logging.getLogger(name)
    audit = logging.getLogger(AUDIT_LOGGER)
    if audit.level == logging.NOTSET or audit.level > logging.INFO:
        audit.setLevel(logging.INFO)
    if any(getattr(h, _MARK, False) for h in lg.handlers):
        return fmt
    if lg.handlers:            # the deployment configured this logger itself
        return fmt
    h = logging.StreamHandler(stream or sys.stderr)
    h.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    setattr(h, _MARK, True)
    lg.addHandler(h)
    return fmt


def _level(ev: Dict[str, Any]) -> int:
    return logging.WARNING if ev.get("severity") in ("medium", "high") else logging.INFO


def emit(name: str, outcome: str, *, actor: Any = None, actor_role: Any = None, via: Any = None,
         source_ip: Any = None, target: Optional[Dict[str, Any]] = None, reason: Any = None,
         details: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Write one security event; returns it (tests) or None when it could not be built. Never raises."""
    try:
        ev = T.event(name, outcome, at=_now(), actor=actor, actor_role=actor_role, via=via, source_ip=source_ip,
                     target=target, reason=reason, details=details)
    except Exception:  # noqa: BLE001
        logging.getLogger(AUDIT_LOGGER).error("security event %s/%s could not be built", T.clean_text(name, 64),
                                              T.clean_text(outcome, 16))
        return None
    try:
        logging.getLogger(AUDIT_LOGGER).log(_level(ev), T.to_text(ev), extra={"dm_event": ev})
    except Exception:  # noqa: BLE001
        pass
    return ev


def principal(user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """actor / actor_role / via of an authenticated principal (the API's user dict); nothing secret is read."""
    u = user if isinstance(user, dict) else {}
    via = "service" if u.get("svc") else u.get("via") or ("bearer" if u else None)
    return {"actor": u.get("sub"), "actor_role": u.get("role"), "via": via}


def client_ip(request: Any) -> Optional[str]:
    """The socket peer address (a forwarded header is not trusted here)."""
    try:
        return request.client.host if request is not None and request.client else None
    except Exception:  # noqa: BLE001
        return None
