"""Report model in Darkmoon Community (lot L6): the report file written at finalisation is the Markdown rendering of
the same exec_core model as Pro, masked by the redaction engine (fail closed: evidence withheld without an engine).

Covers: the store seeded from the shared fixture giving the same masked model as Pro's adapter
(``expected_model_store.json``, shared), no secret of the evidence in the model or the file, the fail-closed path,
schema keys never read as secrets by the engine, finalisation writing the model report (and falling back to the
previous generator on failure), section markers for the terminal explorer, numbers parity file <-> model.
"""
import json
import re

import pytest

from api import json_storage as js
from api import live_push
from api import report_model_local as RL
from api.exec_core import report_markdown as RMD
from api.exec_core import report_model as RM
from tests.exec_store import isolate
from tests.test_exec_core_report_model import FIX, strip_edition_specific

CID = "camp_fx_report"


def _fx():
    return json.loads((FIX / "report_parity.json").read_text(encoding="utf-8"))


@pytest.fixture
def store(monkeypatch, tmp_path):
    data = isolate(monkeypatch, tmp_path)
    fx = _fx()
    (data / "campaigns" / f"{CID}.json").write_text(json.dumps(fx["campaign"]), encoding="utf-8")
    (data / "vulnerabilities" / f"{CID}.json").write_text(json.dumps(fx["findings"]), encoding="utf-8")
    (data / "infrastructure" / f"{CID}.json").write_text(json.dumps(fx["nodes"]), encoding="utf-8")
    (data / "targets.json").write_text(json.dumps([{**fx["target"], "technologies": fx["technologies"]}]), encoding="utf-8")
    (data / "projects.json").write_text(json.dumps([{**fx["project"], "target_id": fx["campaign"]["target_id"]}]),
                                        encoding="utf-8")
    (data / "profiles").mkdir()
    (data / "profiles" / f"{fx['project']['id']}.json").write_text(json.dumps({
        "schema_version": "darkmoon-application-profile-declarations/1", "project_id": fx["project"]["id"],
        "fields": fx["declarations"]}), encoding="utf-8")
    red = RL.load_redaction()
    assert red is not None, "the vendored redaction engine must load in the repository layout"
    red.reset_known_cache()
    return fx


def no_annex(m):
    for s in m["sections"]:
        s["blocks"] = [b for b in s.get("blocks", []) if not (b.get("type") == "subsection" and
                                                              b.get("id") in ("assets-mapped", "technique-mappings"))]
        s["sources"] = [x for x in s.get("sources", []) if not x.startswith("report_annex.")]
    return m


def test_community_adapter_gives_the_store_parity_model(store):
    """Same masked model as Pro's adapter on the same store, except the documented edition-specific fields and the
    Markdown each edition's report annex renders."""
    got = no_annex(strip_edition_specific(RL.masked(RL.build(CID, generated_at="2026-11-20T11:05:00Z"))))
    want = json.loads((FIX / "expected_model_store.json").read_text(encoding="utf-8"))
    for a, b in zip(got["sections"], want["sections"]):
        assert a == b, a["id"]
    assert got == want


def test_no_secret_in_the_masked_model_or_the_file(store):
    m = RL.masked(RL.build(CID))
    text = json.dumps(m, ensure_ascii=False)
    md = RL.render(m)
    for s in store["secrets"]:
        assert s not in text and s not in md, s


def test_fail_closed_without_a_redaction_engine(store):
    m = RL.masked(RL.build(CID), red=None)
    det = next(s for s in m["sections"] if s["id"] == "detailed_findings")
    sheets = [b for b in det["blocks"] if b["type"] == "finding"]
    assert sheets and all(b["evidence"] in ({}, {"withheld": True}) for b in sheets)
    assert any(b["evidence"] == {"withheld": True} for b in sheets)
    md = RL.render(m)
    assert "Evidence withheld: the redaction engine was not available" in md
    for s in store["secrets"]:
        assert s not in md, s


def test_schema_keys_survive_the_engine(store):
    red = RL.load_redaction()

    def keys(o):
        if isinstance(o, dict):
            for k, v in o.items():
                yield k
                yield from keys(v)
        elif isinstance(o, list):
            for v in o:
                yield from keys(v)
    raw = RL.build(CID)
    assert not sorted({k for k in keys(raw) if red._secret_key(str(k))} - {"counts"})
    assert RM.numbers_of(RL.masked(raw)) == RM.numbers_of(raw)


def test_finalisation_writes_the_model_report(store):
    camp = js.load_campaign(CID)
    camp["status"] = "running"
    js.save_campaign(camp)
    live_push.finalize_campaign(CID, duration_seconds=3600, executive_summary="Agent summary.")
    camp = js.load_campaign(CID)
    assert camp["report_model_version"] == "darkmoon-report/v2"
    body = (js.REPORTS_DIR / camp["report_path"].split("/")[-1]).read_text(encoding="utf-8")
    assert re.findall(r"<!-- dm-section: ([a-z-]+) -->", body) == [x.replace("_", "-") for x in RM.SECTION_IDS]
    assert "Agent summary." in body and "(community)" in body
    for s in store["secrets"]:
        assert s not in body, s
    # numbers parity: the file states the model's counts
    m = RL.model_doc(CID)
    es = body.split("<!-- dm-section: executive-summary -->")[1].split("<!-- dm-section:")[0]
    assert re.search(rf"^\| Total \| {m['counts']['total_findings']} \| {m['counts']['exploited']} \|", es, re.M)
    tp = body.split("<!-- dm-section: treatment-plan -->")[1].split("<!-- dm-section:")[0]
    assert len(re.findall(r"^\| \d+ \| \[", tp, re.M)) == RM.numbers_of(m)["treatment_plan"]["actions"]
    assert set(RMD.internal_links(body)) <= set(RMD.anchors(body))


def test_finalisation_falls_back_to_the_previous_generator(store, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("model failure")
    monkeypatch.setattr(RL, "report_markdown_for_file", boom)
    live_push.finalize_campaign(CID, duration_seconds=3600, executive_summary="")
    camp = js.load_campaign(CID)
    assert "report_model_version" not in camp
    body = (js.REPORTS_DIR / camp["report_path"].split("/")[-1]).read_text(encoding="utf-8")
    assert "MANAGEMENT SUMMARY" in body


def test_old_campaign_has_no_model(store):
    assert RL.model_doc(CID) is None             # never re-rendered silently: no model version on the record
    assert RL.model_doc("../x") is None
