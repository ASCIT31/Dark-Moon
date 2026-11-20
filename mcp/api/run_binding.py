"""Binding of the agent's campaign writes to the calling run (R4 S3; shipped identically in Community and Pro).

Every ``dashboard_*`` write tool of the MCP (and the remediation tools that write into a campaign) takes a
``campaign_id`` chosen by the model. Ids are ``camp_<date>_<8 hex>`` and appear in tool results, so an agent of run A
(or an agent steered by target content) could write findings, nodes, PR links or a finalisation into the campaign of
run B. The write is now bound to the caller's RUN KEY, taken from the transport, never from a tool argument:

* the run key is the 8-hex campaign key the launcher gives each run (B-13a): the ``X-Darkmoon-Campaign-Frag`` header
  that opencode sends on every call to the shared streamable-http MCP (``{env:DARKMOON_CAMPAIGN_FRAG}``, substituted
  per opencode process, so per run), else the ``DARKMOON_CAMPAIGN_FRAG`` env of a stdio MCP. Sub-agents (task tool
  children) run inside the same opencode process and send the same header: they keep writing into their run's
  campaign. A campaign opened with a run key stores it as its ``session_id`` and is marked ``run_key_bound``;
* a caller WITH a run key writes only into a campaign whose ``session_id`` equals that key (an unknown campaign is
  refused the same way, so the answer does not tell whether another run's campaign exists);
* a caller WITHOUT a run key (terminal UI, a manual MCP client, legacy stdio, tests) writes only into a campaign that
  was not opened with a run key. Community never hands a run key today (one local operator, one TUI that runs
  several sessions in one opencode process): its campaigns are unbound and the behaviour is unchanged there. In Pro
  every API-launched run (New Campaign, scheduler, retest) has a key, so a keyless caller can no longer touch them;
* ``dashboard_init_campaign`` derives the campaign id from the caller's own key, so it can only open or re-open the
  caller's campaign (idempotent re-init by the same run, or a sub-agent's init, reuses it). A keyless init that
  would re-open a bound campaign is refused;
* read tools are not changed here (``dashboard_list_findings`` was already restricted to the run's campaign).

The operator's API routes (stop, abort, reconciliation) do not go through this module: they act on behalf of an
authenticated user, not of an agent.

A refusal answers one fixed sentence (no campaign status, owner or existence), and writes one WARNING line
``run-binding refused tool=… campaign=… caller_key=… reason=…`` on the ``darkmoon.mcp.run_binding`` logger; the first
accepted write of each (tool, campaign, key) writes one INFO line ``run-binding ok …`` (proof the binding is active
during a monitored campaign). The run key is not a secret: it is the suffix of the campaign id.
"""
from __future__ import annotations

import logging
import re
import sys
import threading
from typing import Any, Dict, Optional

RUN_KEY_HEADER = "x-darkmoon-campaign-frag"
RUN_KEY_ENV = "DARKMOON_CAMPAIGN_FRAG"
BOUND_FIELD = "run_key_bound"
REFUSAL = ("campaign not writable by this run: use the campaign_id that dashboard_init_campaign returned in this "
           "run (writes into another run's campaign are refused)")
LOGGER = "darkmoon.mcp.run_binding"

_KEY_RE = re.compile(r"^[0-9a-f]{8}$")
_seen: "set[tuple]" = set()
_lock = threading.Lock()
_MARK = "_darkmoon_run_binding"


def run_key(value: Any) -> Optional[str]:
    """A well-formed run key (8 lowercase hex), else None (empty, unsubstituted ``{env:…}``, anything else)."""
    v = str(value or "").strip().lower()
    return v if _KEY_RE.match(v) else None


def caller_run_key(header_value: Any = None, env_value: Any = None) -> Optional[str]:
    """The caller's run key: the per-call header first (shared http MCP), then the process env (stdio MCP)."""
    return run_key(header_value) or run_key(env_value)


def mark_bound(campaign: Dict[str, Any], key: Optional[str]) -> None:
    """Record that ``campaign`` belongs to the run ``key`` (called by init, only when the key opened it)."""
    if key and str(campaign.get("session_id") or "") == key:
        campaign[BOUND_FIELD] = True


def write_decision(campaign: Optional[Dict[str, Any]], key: Optional[str]) -> Dict[str, Any]:
    """{"allowed": bool, "reason": code}. Codes: same_run, other_run, unknown_campaign, unbound_campaign,
    run_key_required. A keyless caller and an unknown campaign: allowed (the tool answers « not found » as before)."""
    if key:
        if not isinstance(campaign, dict):
            return {"allowed": False, "reason": "unknown_campaign"}
        if str(campaign.get("session_id") or "") == key:
            return {"allowed": True, "reason": "same_run"}
        return {"allowed": False, "reason": "other_run"}
    if not isinstance(campaign, dict):
        return {"allowed": True, "reason": "unknown_campaign"}
    if campaign.get(BOUND_FIELD):
        return {"allowed": False, "reason": "run_key_required"}
    return {"allowed": True, "reason": "unbound_campaign"}


def refusal(campaign_id: Any) -> Dict[str, Any]:
    """The answer to a refused write: one fixed sentence, the id echoed (bounded) so the agent sees which call."""
    return {"status": "error", "error": REFUSAL, "campaign_id": str(campaign_id)[:80]}


def _logger() -> logging.Logger:
    lg = logging.getLogger(LOGGER)
    if lg.level == logging.NOTSET:
        lg.setLevel(logging.INFO)
    if not lg.handlers:  # the deployment did not configure this logger: one stderr handler of our own
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        setattr(h, _MARK, True)
        lg.addHandler(h)
    return lg


def _clean(v: Any, n: int = 80) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "?", str(v if v is not None else "-"))[:n] or "-"


def guard(tool: str, campaign_id: Any, campaign: Optional[Dict[str, Any]], key: Optional[str]) -> Optional[Dict[str, Any]]:
    """None when the write may proceed, else the refusal to return to the agent. Logs both (see module doc)."""
    d = write_decision(campaign, key)
    line = "tool=%s campaign=%s caller_key=%s reason=%s" % (_clean(tool, 48), _clean(campaign_id), _clean(key or "none"),
                                                             d["reason"])
    try:
        if not d["allowed"]:
            _logger().warning("run-binding refused " + line)
        else:
            sig = (tool, str(campaign_id), key)
            with _lock:
                first = sig not in _seen
                if first:
                    if len(_seen) > 4096:
                        _seen.clear()
                    _seen.add(sig)
            if first:
                _logger().info("run-binding ok " + line)
    except Exception:  # noqa: BLE001 - logging never decides a write
        pass
    return None if d["allowed"] else refusal(campaign_id)
