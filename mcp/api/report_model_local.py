"""Report model of a campaign (``darkmoon-report/v2``, exec_core.report_model) from the Community local store.

Storage adapter only, the counterpart of Pro's ``report_model_store``: it gathers what the local read models already
compute (score, Prioritized Treatment Plan, framework assessment, application profile declared in the owner's file,
attack paths, infrastructure map and technique mappings of the report annex, CVSS recomputed from each vector) and
hands them to the pure core. The report file written at finalisation is the Markdown rendering of this model
(``exec_core.report_markdown``), the same renderer as Pro.

Masking (fail closed): the model goes through the redaction engine (``evidence_redaction``: the MCP server's copy
when installed, else the copy vendored with the terminal explorer) before it is rendered. When no engine can be
loaded, the evidence bodies (requests, responses, commands, logs) are withheld from the report: only the sentence
saying so is written.
"""
from __future__ import annotations

import copy
import datetime as _dt
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from api.exec_core import report_markdown as _md
from api.exec_core import report_model as _rm

_log = logging.getLogger(__name__)

MODEL_VERSION = _rm.SCHEMA_VERSION
MASKING = ("Evidence is masked by the Darkmoon redaction engine before the report is written (secrets, tokens, "
           "personal data); if the engine cannot be loaded, evidence bodies are withheld from the report.")
_VENDOR_DIRS = (
    Path(__file__).resolve().parents[2] / "conf" / "plugins" / "darkmoon-explorer" / "_vendor",   # repository layout
    Path("/opt/darkmoon/plugins/darkmoon-explorer/_vendor"),                                       # opencode image
)


def load_redaction():
    """The redaction engine, or None (fail closed). The vendored directory is APPENDED to the import path: its
    ``src`` package never shadows the MCP server's own."""
    try:
        from api import evidence_redaction as mod  # type: ignore
        return mod
    except Exception:  # noqa: BLE001
        pass
    extra = os.environ.get("DARKMOON_EXPLORER_VENDOR", "").strip()
    for d in ([Path(extra)] if extra else []) + list(_VENDOR_DIRS):
        if d.is_dir() and (d / "evidence_redaction.py").is_file():
            if str(d) not in sys.path:
                sys.path.append(str(d))
            try:
                import evidence_redaction as mod  # type: ignore
                if callable(getattr(mod, "redact_obj", None)) and callable(getattr(mod, "redact_text", None)):
                    return mod
            except Exception:  # noqa: BLE001
                continue
    return None


def _strip_heading(md: str) -> str:
    lines = [ln for ln in str(md or "").split("\n") if not ln.lstrip().startswith("<!-- dm-section:")]
    while lines and (not lines[0].strip() or lines[0].strip() == "---"):
        lines.pop(0)
    if lines and lines[0].startswith("## "):
        lines.pop(0)
    return "\n".join(lines).strip()


def _annex(campaign_id: str, campaign: Dict[str, Any], vulns_in_push_order: List[Dict[str, Any]],
           ap: Optional[Dict[str, Any]]) -> Dict[str, str]:
    from api import report_annex
    from api import report_annex_local as L
    out: Dict[str, str] = {}
    infra = None
    try:
        infra = L.infrastructure_doc(campaign_id, campaign, ap)
        out["infrastructure"] = _strip_heading(report_annex.infrastructure_section(infra))
    except Exception:  # advisory: the section is left out, never invented
        _log.warning("report model: infrastructure section skipped", exc_info=True)
    try:
        from api import frameworks as F
        fw = L.frameworks_doc(campaign_id, campaign, ap, (infra or {}).get("nodes"))
        out["frameworks"] = _strip_heading(report_annex.frameworks_section(fw, F.framework_catalogue()))
    except Exception:
        _log.warning("report model: technique mappings skipped", exc_info=True)
    try:
        declared = L.declared_links_markdown(vulns_in_push_order)
        if declared:
            out["declared_links"] = declared.strip()
    except Exception:
        _log.warning("report model: declared links skipped", exc_info=True)
    return out


def inputs(campaign_id: str, campaign: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    from api import cvss31, exec_score
    from api.json_storage import is_safe_id, load_campaign, load_project, load_target, load_vulnerabilities
    if not is_safe_id(campaign_id):
        return None
    camp = campaign if campaign is not None else load_campaign(campaign_id)
    if not camp:
        return None
    findings = [v for v in (load_vulnerabilities(campaign_id) or []) if isinstance(v, dict)]
    target = load_target(camp.get("target_id") or "") if camp.get("target_id") else None
    project = load_project(camp.get("project_id") or "") if camp.get("project_id") else None
    from api.exec_core import score as S
    previous = None
    if camp.get("target_id"):
        date = str(camp.get("date") or "")
        for b in reversed([b for b in exec_score.target_bundles(camp["target_id"])
                           if b["campaign"].get("id") != campaign_id and str(b["campaign"].get("date") or "") < date]):
            d = S.cyber_score(b)
            if S.comparable(d):
                previous = d
                break
    doc: Dict[str, Any] = {"edition": "community", "campaign": camp, "target": target, "project": project,
                           "findings": findings,
                           "cvss": {str(v.get("id")): cvss31.assess(v) for v in findings if v.get("id")},
                           "score": S.cyber_score({"campaign": camp, "findings": findings}, previous=previous),
                           "masking": MASKING}
    ap = None
    try:
        from api.attack_paths_local import attack_paths_doc
        ap = attack_paths_doc(campaign_id, "all", True)
        doc["attack_paths"] = ap
    except Exception:
        _log.warning("report model: attack paths unavailable", exc_info=True)
    try:
        from api.treatment_local import plan_doc
        doc["plan"] = plan_doc(campaign_id)
    except Exception:
        _log.warning("report model: treatment plan unavailable", exc_info=True)
    try:
        from api.framework_local import assessment_doc
        from api.profile_local import profile_view
        doc["assessment"] = assessment_doc(campaign_id)
        pv = profile_view(camp.get("project_id") or "") if camp.get("project_id") else None
        doc["profile"] = pv[0] if pv else None
    except Exception:
        _log.warning("report model: framework assessment / profile unavailable", exc_info=True)
    doc["annex"] = _annex(campaign_id, camp, findings, ap)
    return doc


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(campaign_id: str, campaign: Optional[Dict[str, Any]] = None, generated_at: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The raw model (evidence as stored). Write or show it only through ``masked``."""
    doc = inputs(campaign_id, campaign)
    if doc is None:
        return None
    doc["generated_at"] = generated_at or str(doc["campaign"].get("report_generated_at") or "") or _now()
    return _rm.build(doc)


def _withhold_evidence(model: Dict[str, Any]) -> Dict[str, Any]:
    for s in model.get("sections") or []:
        for b in s.get("blocks") or []:
            if b.get("type") == "finding" and b.get("evidence"):
                b["evidence"] = {"withheld": True}
    return model


def masked(model: Dict[str, Any], red: Any = "auto") -> Dict[str, Any]:
    """The model through the redaction engine; without an engine, evidence bodies withheld (fail closed)."""
    m = copy.deepcopy(model)
    red = load_redaction() if red == "auto" else red
    if red is None:
        return _withhold_evidence(m)
    try:
        return red.redact_obj(m)
    except Exception:  # noqa: BLE001 — a failing engine is no engine
        _log.warning("report model: redaction failed, evidence withheld", exc_info=True)
        return _withhold_evidence(m)


def render(model: Dict[str, Any]) -> str:
    return _md.render(model)


def report_markdown_for_file(campaign_id: str, campaign: Dict[str, Any]) -> str:
    """The report file written at finalisation: the Markdown of the masked model. Marks the record (caller saves)."""
    now = _now()
    model = build(campaign_id, campaign, generated_at=now)
    if model is None:
        raise ValueError("unknown campaign")
    campaign["report_model_version"] = MODEL_VERSION
    campaign["report_generated_at"] = now
    return render(masked(model))


def model_doc(campaign_id: str, red: Any = "auto") -> Optional[Dict[str, Any]]:
    """The masked model of a campaign (terminal explorer ``report-model``); None for an unknown campaign."""
    from api.json_storage import is_safe_id, load_campaign
    camp = load_campaign(campaign_id) if is_safe_id(campaign_id) else None
    if not camp or camp.get("report_model_version") != MODEL_VERSION:
        return None          # an older campaign keeps its report file (never silently re-rendered)
    m = build(campaign_id, camp)
    return masked(m, red) if m is not None else None
