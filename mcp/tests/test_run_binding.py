"""api/run_binding.py: the decision that binds the agent's campaign writes to the calling run (R4 S3).

Shipped identically in Community and Pro (hash in tests/test_exec_core_parity.py SHARED_TESTS_SHA256). The tool
wiring of each edition is tested in test_run_binding_tools*.py.
"""
import logging

from api import run_binding as RB

KEY_A, KEY_B = "aaaa1111", "bbbb2222"


def _camp(key, bound=True):
    c = {"id": f"camp_20261120_{key}", "session_id": key, "status": "running"}
    if bound:
        c[RB.BOUND_FIELD] = True
    return c


def test_run_key_grammar():
    assert RB.run_key("AAAA1111") == "aaaa1111"
    assert RB.run_key(" aaaa1111 ") == "aaaa1111"
    for bad in (None, "", "{env:DARKMOON_CAMPAIGN_FRAG}", "aaaa111", "aaaa11112", "gggg1111", "aaaa-111"):
        assert RB.run_key(bad) is None


def test_header_wins_over_env_and_garbage_falls_back():
    assert RB.caller_run_key(KEY_A, KEY_B) == KEY_A
    assert RB.caller_run_key("{env:DARKMOON_CAMPAIGN_FRAG}", KEY_B) == KEY_B
    assert RB.caller_run_key(None, None) is None


def test_same_run_writes_other_run_is_refused():
    assert RB.write_decision(_camp(KEY_A), KEY_A) == {"allowed": True, "reason": "same_run"}
    assert RB.write_decision(_camp(KEY_B), KEY_A) == {"allowed": False, "reason": "other_run"}
    # an unbound (legacy / terminal) campaign is not writable by a keyed run either: the key must match
    assert RB.write_decision(_camp(KEY_B, bound=False), KEY_A)["allowed"] is False


def test_unknown_campaign_refused_for_a_keyed_caller_only():
    assert RB.write_decision(None, KEY_A) == {"allowed": False, "reason": "unknown_campaign"}
    assert RB.write_decision(None, None)["allowed"] is True


def test_keyless_caller_writes_only_unbound_campaigns():
    assert RB.write_decision(_camp(KEY_A, bound=False), None) == {"allowed": True, "reason": "unbound_campaign"}
    assert RB.write_decision(_camp(KEY_A), None) == {"allowed": False, "reason": "run_key_required"}


def test_mark_bound_only_for_the_key_that_named_the_campaign():
    c = _camp(KEY_A, bound=False)
    RB.mark_bound(c, None)
    assert RB.BOUND_FIELD not in c
    RB.mark_bound(c, KEY_B)
    assert RB.BOUND_FIELD not in c
    RB.mark_bound(c, KEY_A)
    assert c[RB.BOUND_FIELD] is True


def test_refusal_is_one_fixed_sentence(caplog):
    caplog.set_level(logging.INFO, logger=RB.LOGGER)
    other = RB.guard("dashboard_push_finding", "camp_20261120_bbbb2222", _camp(KEY_B), KEY_A)
    unknown = RB.guard("dashboard_push_finding", "camp_20261120_cccc3333", None, KEY_A)
    # no status, owner or existence in the answer: both refusals read the same
    assert other["error"] == unknown["error"] == RB.REFUSAL and other["status"] == "error"
    assert "bbbb2222" not in other["error"] and "running" not in str(other)
    lines = [r.getMessage() for r in caplog.records if r.name == RB.LOGGER]
    assert any(x.startswith("run-binding refused tool=dashboard_push_finding campaign=camp_20261120_bbbb2222 "
                            "caller_key=aaaa1111 reason=other_run") for x in lines)
    assert all(r.levelno == logging.WARNING for r in caplog.records if "refused" in r.getMessage())


def test_accepted_write_logged_once_per_tool_campaign_key(caplog):
    caplog.set_level(logging.INFO, logger=RB.LOGGER)
    camp = _camp("dddd4444")
    for _ in range(3):
        assert RB.guard("dashboard_push_infra_node", camp["id"], camp, "dddd4444") is None
    ok = [r.getMessage() for r in caplog.records if r.getMessage().startswith("run-binding ok tool=dashboard_push_infra_node "
                                                                              "campaign=camp_20261120_dddd4444")]
    assert ok == ["run-binding ok tool=dashboard_push_infra_node campaign=camp_20261120_dddd4444 caller_key=dddd4444 "
                  "reason=same_run"]


def test_log_line_cannot_be_injected():
    caplog_free = RB._clean("camp_x\nrun-binding ok tool=evil")
    assert "\n" not in caplog_free and " " not in caplog_free
