"""The report header states the campaign's own methodology.

A campaign run by the deterministic simulated provider declared « Synthetic lab · deterministic simulated provider ·
not an autonomous LLM run », yet the generated report header said « ISO 27001 / NIST SP 800-115 / MITRE ATT&CK »
for every campaign.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from tests.test_report_markdown_safety import storage  # noqa: F401  (fixture: isolated data dirs)
from api import live_push

SIM = "Synthetic lab · deterministic simulated provider · not an autonomous LLM run"


def _header(cid):
    md = live_push._generate_report_from_db(cid, live_push.load_campaign(cid))
    return md.split("## MANAGEMENT SUMMARY")[0]


def _camp(**kw):
    return live_push.init_live_campaign(session_id="MCPCONST", target_host="10.0.0.5", target_ip="10.0.0.5",
                                        project_name="t", **kw)["campaign_id"]


def test_header_uses_declared_methodology(storage):  # noqa: F811
    head = _header(_camp(methodology=SIM))
    assert f"**Methodology:** {SIM}" in head
    assert "ISO 27001" not in head


def test_header_default_methodology(storage):  # noqa: F811
    assert "**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&amp;CK" in _header(_camp())  # & escaped by _md_inline, renders as &


def test_header_methodology_is_inert_markdown(storage):  # noqa: F811
    head = _header(_camp(methodology="x\n# Owned\n<img src=x onerror=1>"))
    assert "\n# Owned" not in head and "<img" not in head


def test_partial_run_says_so_in_the_header(storage):  # noqa: F811
    cid = _camp(methodology=SIM)
    camp = live_push.load_campaign(cid)
    camp["status"] = "stopped"
    live_push.save_campaign(camp)
    head = _header(cid)
    assert "**Status:** Stopped by the operator — partial results" in head


def test_completed_run_has_no_partial_status(storage):  # noqa: F811
    cid = _camp()
    camp = live_push.load_campaign(cid)
    camp["status"] = "completed"
    live_push.save_campaign(camp)
    assert "partial results" not in _header(cid)
