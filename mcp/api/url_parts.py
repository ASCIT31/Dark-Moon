"""Tolerant URL port access for agent-written endpoints.

``urllib.parse`` raises ``ValueError`` from ``.port`` when the authority has a malformed port. Agents write such
endpoints (P6 dmlab: ``http://<jenkins>:8080:50000`` for a Jenkins agent port), and one finding then turned every
campaign view, the vulnerability list and ``/attack-paths`` into HTTP 500 (07_results.md § PROV, 500). A finding's
endpoint is data, never a reason to fail a page: these helpers never raise.
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import ParseResult, urlparse


def safe_urlparse(text: Any) -> ParseResult:
    """``urlparse`` that never raises. ``urlparse`` raises ``ValueError("Invalid IPv6 URL")`` on an unbalanced ``[``
    or ``]`` in the authority (agent-written endpoints, PR 1A property test); the brackets are then percent-encoded
    and the text parsed again, so the host, path and query stay readable as data. Last resort: an empty result."""
    s = str(text or "")
    try:
        return urlparse(s)
    except ValueError:
        try:
            return urlparse(s.replace("[", "%5B").replace("]", "%5D"))
        except ValueError:
            return urlparse("")


def safe_port(u: Any) -> Optional[int]:
    """``u.port``, or None when the port is absent or malformed."""
    try:
        return u.port
    except ValueError:
        return None


def port_text(u: Any) -> Optional[str]:
    """The port as written: the valid port, else the raw text after the host (``8080:50000``), else None."""
    p = safe_port(u)
    if p is not None:
        return str(p)
    netloc = str(getattr(u, "netloc", "") or "").rsplit("@", 1)[-1]
    if netloc.startswith("["):
        tail = netloc.split("]", 1)[1] if "]" in netloc else ""
    else:
        tail = netloc.split(":", 1)[1] if ":" in netloc else ""
        tail = ":" + tail if tail else ""
    tail = tail[1:] if tail.startswith(":") else tail
    return tail or None
