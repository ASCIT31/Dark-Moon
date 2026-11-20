"""exec_core.taxonomy + api.security_log: stable names, one line per event, no secret, no log injection
(same file in both editions)."""
from __future__ import annotations

import io
import json
import logging
import sys
from pathlib import Path

MCP = Path(__file__).resolve().parents[1]
if str(MCP) not in sys.path:
    sys.path.insert(0, str(MCP))

from api import security_log as SL  # noqa: E402
from api.exec_core import taxonomy as T  # noqa: E402

# The shipped names: renaming one breaks a customer's SIEM rule. Adding is fine (update this list), renaming is not.
STABLE = {
    "auth.login", "auth.logout", "auth.password_change", "auth.csrf_rejected", "auth.service_token_issue",
    "authz.admin_denied", "admin.ebios_context.replace", "admin.application_profile.replace",
    "admin.treatment_action.update", "admin.maintenance_policy.replace", "admin.credential.create",
    "admin.credential.update", "admin.credential.delete", "admin.webhook.create", "admin.webhook.delete",
    "admin.schedule.create", "admin.schedule.update", "admin.schedule.delete", "admin.operator_path.change",
    "admin.finding.quarantine_review", "admin.evidence_token.revoke", "campaign.launch", "campaign.stop",
}

SECRETS = ["S3cr3t-P@ssw0rd!", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl",
           "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", "AKIAABCDEFGHIJKLMNOP"]


def test_catalogue_names_are_stable():
    assert STABLE <= set(T.EVENTS), sorted(STABLE - set(T.EVENTS))
    for row in T.catalogue():
        assert row["category"] and row["action"] and row["meaning"]
        assert set(row["severities"]) <= set(T.OUTCOMES)
        assert set(row["severities"].values()) <= set(T.SEVERITIES)


def test_unknown_event_or_outcome_is_a_programming_error():
    for name, outcome in (("auth.loginn", "success"), ("auth.logout", "failure"), ("campaign.launch", "maybe")):
        try:
            T.event(name, outcome)
        except ValueError:
            continue
        raise AssertionError(f"{name}/{outcome} accepted")


def test_severity_is_fixed_per_event_and_outcome():
    assert T.event("auth.login", "failure")["severity"] == "medium"
    assert T.event("auth.login", "success")["severity"] == "info"
    assert T.event("campaign.launch", "override")["severity"] == "high"
    assert T.event("campaign.launch", "blocked")["severity"] == "medium"


def test_log_injection_newlines_ansi_bidi_in_user_names():
    evil = "admin\nsecurity-event event=auth.login outcome=success actor=root\r\x1b[2J\x1b]0;pwn\x07‮evil\x00"
    ev = T.event("auth.login", "failure", actor=evil, reason=evil, details={"note": evil, "nested": {"x": evil}})
    for line in (T.to_text(ev), T.to_json(ev)):
        assert "\n" not in line and "\r" not in line and "\x1b" not in line and "‮" not in line and "\x00" not in line
        assert "\\n" in line or "\\\\n" in line                              # visible, not interpreted
    text = T.to_text(ev)
    assert len(text.splitlines()) == 1                                   # one event = one record
    assert text.startswith("security-event event=auth.login outcome=failure severity=medium")   # forged pairs stay quoted
    parsed = json.loads(T.to_json(ev))
    assert parsed["actor"].startswith("admin\\nsecurity-event")
    assert len(parsed["actor"]) <= 64


def test_no_secret_by_key_or_by_shape():
    ev = T.event("admin.credential.create", "success", actor="alice", reason=f"Bearer {SECRETS[1]}",
                 details={"password": SECRETS[0], "api_key": "x", "Authorization": "Basic YWxhZGRpbg==",
                          "csrf_token": "abc", "cookie": "dm_session=1", "provider": "github",
                          "text": f"token {SECRETS[2]} and {SECRETS[3]} and {SECRETS[4]}",
                          "nested": {"client_secret": "zzz", "fine": "ok"}})
    blob = T.to_json(ev) + T.to_text(ev)
    for s in SECRETS + ["YWxhZGRpbg==", "dm_session=1", "zzz"]:
        assert s not in blob, s
    assert ev["details"]["provider"] == "github" and ev["details"]["nested"]["fine"] == "ok"
    assert ev["details"]["password"] == T.REDACTED


def test_bounded_values():
    ev = T.event("campaign.launch", "success", reason="x" * 10000, details={f"k{i}": i for i in range(100)},
                 target={f"t{i}": "y" * 1000 for i in range(20)})
    assert len(ev["reason"]) <= 300 and len(ev["details"]) <= T.MAX_DETAILS and len(ev["target"]) <= 8
    assert all(len(v) <= 128 for v in ev["target"].values())


def _capture(fmt):
    lg = logging.getLogger(SL.AUDIT_LOGGER)
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(SL.JsonFormatter() if fmt == "json" else SL.TextFormatter())
    lg.addHandler(h)
    old = lg.level
    lg.setLevel(logging.INFO)
    return lg, h, buf, old


def test_emit_json_and_text_lines_carry_no_secret():
    for fmt in ("json", "text"):
        lg, h, buf, old = _capture(fmt)
        try:
            SL.emit("auth.login", "failure", actor="bob\n" + SECRETS[1], source_ip="203.0.113.9",
                    details={"password": SECRETS[0]})
            SL.emit("auth.password_change", "success", actor="bob", details={"new_password": SECRETS[0]})
        finally:
            lg.removeHandler(h)
            lg.setLevel(old)
        out = buf.getvalue()
        lines = [x for x in out.splitlines() if x]
        assert len(lines) == 2, out
        for s in SECRETS:
            assert s not in out
        if fmt == "json":
            first = json.loads(lines[0])
            assert first["event"] == "auth.login" and first["outcome"] == "failure" and first["schema"] == T.SCHEMA
            assert first["at"].endswith("Z") and first["source_ip"] == "203.0.113.9"


def test_emit_never_raises():
    assert SL.emit("no.such.event", "success") is None
    assert SL.emit("auth.login", "nope") is None
    assert SL.emit("auth.login", "success", actor=object(), details={"x": object()}) is not None


def test_json_formatter_cleans_ordinary_records():
    rec = logging.LogRecord("darkmoon.api", logging.WARNING, __file__, 1, "user %s said %s", ("x\ny", SECRETS[1]), None)
    line = SL.JsonFormatter().format(rec)
    assert "\n" not in line and SECRETS[1] not in line
    assert json.loads(line)["logger"] == "darkmoon.api"


def test_configure_is_idempotent_and_default_is_text(monkeypatch):
    monkeypatch.delenv("DARKMOON_LOG_FORMAT", raising=False)
    assert SL.log_format() == "text"
    monkeypatch.setenv("DARKMOON_LOG_FORMAT", "JSON")
    assert SL.log_format() == "json"
    monkeypatch.setenv("DARKMOON_LOG_FORMAT", "xml")
    assert SL.log_format() == "text"
    lg = logging.getLogger(SL.AUDIT_LOGGER)
    before = list(lg.handlers)
    try:
        SL.configure("text", stream=io.StringIO())
        n = len(lg.handlers)
        SL.configure("text", stream=io.StringIO())
        assert len(lg.handlers) == n
    finally:
        for h in list(lg.handlers):
            if h not in before:
                lg.removeHandler(h)


def test_principal_reads_no_secret():
    who = SL.principal({"sub": "alice", "role": "admin", "via": "session", "csrf": "digest", "pv": 3})
    assert who == {"actor": "alice", "actor_role": "admin", "via": "session"}
    assert SL.principal({"sub": "svc:n8n", "role": "service", "svc": True})["via"] == "service"
    assert SL.principal(None) == {"actor": None, "actor_role": None, "via": None}
