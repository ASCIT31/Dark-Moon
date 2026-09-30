"""
Tests for the Darkmoon growth signals + one-time star CTA (api/growth.py).

Proves the guardrails the growth engine must never violate:
  1. the CTA never fires before the first real delivered value
  2. it fires exactly once (once-only), after a value milestone
  3. an explicit dismiss suppresses it permanently
  4. DARKMOON_DISABLE_GROWTH_CTA suppresses the CTA (milestones still recorded)
  5. DARKMOON_NO_TELEMETRY disables ALL local recording (no files, no CTA)
  6. the frequency cap / min-interval is honoured
  7. persisted state is privacy-safe: only event types, timestamps, counts, booleans
     (never a target / host / ip / finding / campaign id)
  8. render/emit is non-empty, points at the Community repo, and is idempotent
"""

import io
import json
import os
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from api import growth  # noqa: E402

GROWTH_ENV = [
    "DARKMOON_GROWTH_DIR",
    "DARKMOON_NO_TELEMETRY",
    "DARKMOON_GROWTH_DISABLE",
    "DARKMOON_DISABLE_GROWTH_CTA",
    "DARKMOON_GROWTH_CTA_MAX_SHOWS",
    "DARKMOON_GROWTH_CTA_MIN_DAYS",
    "XDG_DATA_HOME",
]


@pytest.fixture
def gdir(tmp_path, monkeypatch):
    for k in GROWTH_ENV:
        monkeypatch.delenv(k, raising=False)
    d = str(tmp_path / "growth")
    monkeypatch.setenv("DARKMOON_GROWTH_DIR", d)
    return d


def _emit():
    buf = io.StringIO()
    shown = growth.maybe_emit_cta(stream=buf)
    return shown, buf.getvalue()


# 1. never before first value ------------------------------------------------
def test_no_cta_before_value(gdir):
    assert growth.first_value_reached() is False
    assert growth.should_show_cta() is False
    shown, out = _emit()
    assert shown is False and out == ""


def test_non_value_milestone_does_not_trigger(gdir):
    growth.record_milestone("first_run")
    growth.record_milestone("first_campaign")
    assert growth.first_value_reached() is False
    assert growth.should_show_cta() is False


# 2. once-only after value ---------------------------------------------------
def test_cta_shows_once_after_value(gdir):
    growth.record_milestone("campaign_finalized")
    assert growth.first_value_reached() is True
    assert growth.should_show_cta() is True
    shown, out = _emit()
    assert shown is True
    assert growth.REPO_URL in out
    # second time: suppressed
    assert growth.should_show_cta() is False
    shown2, out2 = _emit()
    assert shown2 is False and out2 == ""


@pytest.mark.parametrize("evt", sorted(growth.VALUE_EVENTS))
def test_each_value_event_triggers(gdir, evt):
    growth.record_milestone(evt)
    assert growth.first_value_reached() is True
    assert growth.should_show_cta() is True


# 3. dismiss -----------------------------------------------------------------
def test_dismiss_suppresses(gdir):
    growth.record_milestone("validated_finding")
    growth.mark_cta_dismissed()
    assert growth.should_show_cta() is False
    shown, out = _emit()
    assert shown is False and out == ""


# 4. DARKMOON_DISABLE_GROWTH_CTA ---------------------------------------------
def test_disable_cta_env(gdir, monkeypatch):
    growth.record_milestone("campaign_finalized")
    monkeypatch.setenv("DARKMOON_DISABLE_GROWTH_CTA", "1")
    assert growth.cta_disabled() is True
    assert growth.should_show_cta() is False
    # milestones are still recorded (telemetry not disabled)
    assert growth.first_value_reached() is True


def test_disable_cta_env_falsy_is_noop(gdir, monkeypatch):
    growth.record_milestone("campaign_finalized")
    monkeypatch.setenv("DARKMOON_DISABLE_GROWTH_CTA", "0")
    assert growth.cta_disabled() is False
    assert growth.should_show_cta() is True


# 5. DARKMOON_NO_TELEMETRY ---------------------------------------------------
def test_no_telemetry_writes_nothing(gdir, monkeypatch):
    monkeypatch.setenv("DARKMOON_NO_TELEMETRY", "1")
    assert growth.record_milestone("campaign_finalized") is False
    assert growth.record_funnel("SUCCESS") is False
    # no files created at all
    assert not os.path.isdir(gdir) or os.listdir(gdir) == []
    assert growth.first_value_reached() is False
    assert growth.should_show_cta() is False


def test_growth_disable_alias(gdir, monkeypatch):
    monkeypatch.setenv("DARKMOON_GROWTH_DISABLE", "yes")
    assert growth.telemetry_disabled() is True
    assert growth.record_milestone("report_generated") is False


# 6. frequency cap / interval ------------------------------------------------
def test_max_shows_respected(gdir, monkeypatch):
    monkeypatch.setenv("DARKMOON_GROWTH_CTA_MAX_SHOWS", "2")
    monkeypatch.setenv("DARKMOON_GROWTH_CTA_MIN_DAYS", "0")
    growth.record_milestone("campaign_finalized")
    assert _emit()[0] is True
    assert _emit()[0] is True
    assert _emit()[0] is False  # cap reached at 2


def test_min_days_interval(gdir, monkeypatch):
    monkeypatch.setenv("DARKMOON_GROWTH_CTA_MAX_SHOWS", "5")
    monkeypatch.setenv("DARKMOON_GROWTH_CTA_MIN_DAYS", "30")
    growth.record_milestone("campaign_finalized")
    t0 = datetime.datetime(2026, 1, 1, 12, 0, 0)
    assert growth.maybe_emit_cta(stream=io.StringIO(), now=t0) is True
    # 10 days later: still within the interval -> suppressed
    assert growth.should_show_cta(now=t0 + datetime.timedelta(days=10)) is False
    # 31 days later: interval elapsed (and cap is 5) -> allowed
    assert growth.should_show_cta(now=t0 + datetime.timedelta(days=31)) is True


# 7. privacy of persisted state ----------------------------------------------
FORBIDDEN_SUBSTRINGS = [
    "192.168", "10.0.", "http://", "https://darkmoon-target", "password",
    "cred", "campaign_id", "camp_", "vuln_", "target", "host", "@",
]


def test_persisted_state_is_privacy_safe(gdir):
    # record a value milestone + funnel; inspect every byte written
    growth.record_milestone("campaign_finalized")
    growth.record_milestone("validated_finding")
    growth.record_funnel("INSTALL")
    _emit()
    growth.mark_cta_clicked()

    blob = ""
    for name in os.listdir(gdir):
        with open(os.path.join(gdir, name), "r", encoding="utf-8") as f:
            blob += f.read()
    low = blob.lower()
    for bad in FORBIDDEN_SUBSTRINGS:
        assert bad.lower() not in low, f"forbidden token {bad!r} leaked into growth state"

    # milestones.json: only allow-listed event types under events
    m = json.load(open(os.path.join(gdir, growth.MILESTONES)))
    for k in m.get("events", {}):
        assert k in growth.MILESTONE_EVENTS
    # funnel lines only carry ts + an allow-listed stage
    for line in open(os.path.join(gdir, growth.FUNNEL)):
        rec = json.loads(line)
        assert set(rec.keys()) == {"ts", "stage"}
        assert rec["stage"] in growth.FUNNEL_STAGES


def test_unknown_milestone_rejected(gdir):
    assert growth.record_milestone("exfiltrate_creds_1.2.3.4") is False
    assert growth.record_milestone("target=10.0.0.1") is False
    assert growth.first_value_reached() is False


def test_unknown_funnel_rejected(gdir):
    assert growth.record_funnel("LEAK_HOSTNAME") is False


# 8. render / emit -----------------------------------------------------------
def test_render_points_to_community_repo(gdir):
    txt = growth.render_cta()
    assert "github.com/ASCIT31/Dark-Moon" in txt
    assert "DARKMOON_DISABLE_GROWTH_CTA" in txt  # opt-out is advertised
    assert len(txt.strip()) > 0


def test_status_shape(gdir):
    growth.record_milestone("campaign_finalized")
    s = growth.status()
    assert s["first_value_reached"] is True
    assert s["would_show_now"] is True
    assert s["growth_dir"] == gdir


def test_reset(gdir):
    growth.record_milestone("campaign_finalized")
    _emit()
    growth.reset()
    assert growth.first_value_reached() is False
    assert growth.should_show_cta() is False


# fail-safe: a broken growth dir never raises --------------------------------
def test_failsafe_on_unwritable_dir(monkeypatch, tmp_path):
    for k in GROWTH_ENV:
        monkeypatch.delenv(k, raising=False)
    # point at a path under a file (cannot mkdir) -> every call must swallow
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    monkeypatch.setenv("DARKMOON_GROWTH_DIR", str(blocker / "sub" / "growth"))
    assert growth.record_milestone("campaign_finalized") in (False, True)  # no raise
    assert growth.maybe_emit_cta(stream=io.StringIO()) is False  # no raise
    assert isinstance(growth.status(), dict)
