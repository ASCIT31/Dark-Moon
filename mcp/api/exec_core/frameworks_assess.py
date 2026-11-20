"""Framework technical assessment: what one campaign's evidence says about selected controls of ISO/IEC 27001:2022
Annex A, GDPR art. 32 (and 25), NIS2 art. 21(2) and AI Act art. 15.

Pure functions, standard library only, no I/O. Not a compliance or audit opinion: no percentage, no grade, no
« compliant ». Each control has exactly one of four states:

* ``weakness_observed``: at least one counted finding (not false positive, not held by quarantine) maps to it;
* ``none_observed_in_tested_scope``: no such finding AND the campaign's server-recorded coverage shows that every
  weakness class of the control was exercised (completed full campaign meeting the coverage floor, sub-agents
  observed in the session log, and a dispatched agent whose instructions cover each class);
* ``not_tested``: otherwise (coverage not recorded or below the floor, or no dispatched agent covering the classes);
* ``not_technically_assessable``: the control is organisational / legal / outside what a test can observe.

Finding -> control mapping, deterministic, from stored fields only (documented in 05-FRAMEWORK-ASSESSMENT):
weakness class (``identity.weakness_class`` + ``framework_catalogues.EXTRA_CLASS``), else the CWE, else the ATT&CK
technique; plus the ISO 27001 control the agent cited (2022 identifier, or a 2013 identifier through the ID
crosswalk). Applicability comes only from declared or verified profile fields (``profile.applicability_facts``).
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import framework_catalogues as K
from . import identity, profile as P, score

ASSESSMENT_VERSION = "darkmoon-framework-assessment/1"
STATES = ("weakness_observed", "none_observed_in_tested_scope", "not_tested", "not_technically_assessable")
STATE_LABEL = {
    "weakness_observed": "Weakness observed",
    "none_observed_in_tested_scope": "No weakness observed in the tested scope",
    "not_tested": "Not tested by this campaign",
    "not_technically_assessable": "Not assessable by a technical test",
}
APPLICABILITY = ("declared_by_customer", "to_confirm", "not_applicable_declared")
APPLICABILITY_LABEL = {
    "declared_by_customer": "Applicable, as declared by the organisation",
    "to_confirm": "Applicability to be confirmed by the organisation",
    "not_applicable_declared": "Declared not applicable by the organisation",
}
READING = ("Technical findings relevant to these frameworks, from one campaign in its tested scope. This is not an "
           "audit, a certification or a legal opinion: « No weakness observed in the tested scope » is not a proof "
           "of absence, and organisational measures are not assessed.")
COMMON_LIMITS = [
    "One campaign, its tested scope only; a control is never declared satisfied.",
    "A finding is linked to a control by its weakness class, CWE, ATT&CK technique or the ISO control the agent "
    "cited: a mislabelled category lands under another control.",
    "« No weakness observed » requires server-recorded coverage of the control's weakness classes by a dispatched "
    "agent; it does not prove that every test of that class was run.",
    "Applicability uses only facts declared or verified by the organisation; detection never decides it.",
]
FRAMEWORK_LIMITS = {
    "iso27001": ["Clauses 4-10 and the organisational, people and physical controls are not assessed.",
                 "Agents' ISO citations are indicative; 2013 identifiers are mapped to 2022 identifiers by number."],
    "gdpr": ["Only the technical side of art. 32 is covered; art. 33-34 and the other obligations are not.",
             "Personal data categories are never inferred from findings."],
    "nis2": ["Entity type and sector are declared by the organisation; national transposition is not covered.",
             "Measures (a)-(d), (f), (g) are organisational and not assessed."],
    "ai_act": ["Applies only to a system the organisation declares high-risk; an AI component detected by the "
               "campaign does not make it one.",
               "Accuracy, poisoning and the risk-management system are not assessed by a security test."],
}

_ISO_REF = re.compile(r"(?i)(?<![A-Za-z0-9.])(?:annex\s+a\s*|a\s*\.?\s*)?(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?(?![\d])")
_CWE = re.compile(r"(?i)\bcwe[-_\s]?(\d{1,5})\b")
_ATTACK = re.compile(r"\b(T\d{4})(?:\.\d{3})?\b")

_CATALOGUE = {f["framework"]: f for f in K.FRAMEWORKS}
_CONTROLS = {f"{f['framework']}:{c['id']}": (f, c) for f in K.FRAMEWORKS for c in f["controls"]}
_ISO_IDS = {c["id"] for c in _CATALOGUE["iso27001"]["controls"]}


def _norm_agent(name: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name or "").strip().lower()).strip("-")


def control_key(framework: str, control_id: str) -> str:
    return f"{framework}:{control_id}"


def finding_class(v: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """(weakness class mapped to at least one control, basis) or (None, "unmapped")."""
    mapped = _mapped_classes()
    key = re.sub(r"[^a-z0-9]+", "_", str(v.get("category") or v.get("type") or "").strip().lower()).strip("_")
    cls = identity.weakness_class(v)
    cls = K.EXTRA_CLASS.get(key) or K.EXTRA_CLASS.get(cls, cls)
    if cls in mapped:
        return cls, "weakness_class"
    for m in _CWE.finditer(str(v.get("cwe") or "") + " " + str(v.get("cwe_id") or "")):
        c = K.CWE_CLASS.get(str(int(m.group(1))))
        if c in mapped:
            return c, "cwe"
    for m in _ATTACK.finditer(str(v.get("mitre_attack_id") or "")):
        c = K.ATTACK_CLASS.get(m.group(1))
        if c in mapped:
            return c, "attack_technique"
    return None, "unmapped"


def _build_mapped() -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for key, (_, c) in _CONTROLS.items():
        for cls in c["classes"]:
            out.setdefault(cls, []).append(key)
    return out


_MAPPED = _build_mapped()


def _mapped_classes() -> Dict[str, List[str]]:
    """weakness class -> control keys (assessable controls only)."""
    return _MAPPED


def iso_citations(text: Any) -> List[Dict[str, str]]:
    """ISO 27001 controls cited by the agent, as 2022 identifiers: ``{"cited", "control_id", "via"}``. A 4-part
    identifier is the 2013 numbering (crosswalk by ID); a 2-part identifier is read as 2022 when it exists there."""
    out: List[Dict[str, str]] = []
    s = text if isinstance(text, str) else ""
    s = re.sub(r"(?i)2700[12]\s*[:/\-]?\s*(2013|2022)", " ", s)
    for m in _ISO_REF.finditer(s):
        a, b, c = m.group(1), m.group(2), m.group(3)
        if c is not None:
            cited = f"A.{int(a)}.{int(b)}.{int(c)}"
            for cid in K.ISO_2013_TO_2022.get(cited, []):
                out.append({"cited": cited, "control_id": cid, "via": "iso_2013_crosswalk"})
            if cited not in K.ISO_2013_TO_2022:
                out.append({"cited": cited, "control_id": "", "via": "iso_2013_unmapped"})
        else:
            cited = f"A.{int(a)}.{int(b)}"
            if int(a) in (5, 6, 7, 8):
                out.append({"cited": cited, "control_id": cited, "via": "iso_2022"})
    seen, uniq = set(), []
    for r in out:
        k = (r["cited"], r["control_id"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def controls_for_finding(v: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every control a finding is technical evidence for, with the basis of each link (sorted, deterministic).
    Agent citations of controls that are not assessable by a test are returned with ``assessable: False``."""
    links: Dict[str, Set[str]] = {}
    cls, basis = finding_class(v)
    if cls:
        for key in _mapped_classes().get(cls, []):
            links.setdefault(key, set()).add(basis)
    for cit in iso_citations(v.get("iso27001_control")):
        if cit["control_id"] in _ISO_IDS:
            links.setdefault(control_key("iso27001", cit["control_id"]), set()).add("agent_citation:" + cit["via"])
    return [{"control": k, "basis": sorted(b), "assessable": _CONTROLS[k][1]["assessable"]}
            for k, b in sorted(links.items())]


def related_controls(finding_ids: Iterable[str], findings: Iterable[Any]) -> List[str]:
    """Control keys (assessable) the given findings are technical evidence for; used for treatment actions."""
    ids = {str(i) for i in finding_ids or []}
    out: Set[str] = set()
    for v in findings or []:
        if isinstance(v, dict) and str(v.get("id")) in ids and identity.exclusion_reason(v) is None:
            out.update(r["control"] for r in controls_for_finding(v) if r["assessable"])
    return sorted(out)


# ── coverage ───────────────────────────────────────────────────────────────────────────────────────────────────────

def exercised(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Weakness classes the campaign's server-recorded coverage shows as exercised, with the reason when none can be
    claimed. The coverage floor of the rating applies, except the agent-count floor (replaced per class here)."""
    g = score.gate(campaign or {})
    cov = g["coverage"]
    reasons = [r["code"] for r in g["not_rated_reasons"]] + [r["code"] for r in g["limited_reasons"]
                                                              if r["code"] != "few_agents"]
    agents = list(cov.get("specialised_agents") or []) if cov.get("present") else []
    areas: Set[str] = set()
    unknown_agents = []
    for a in agents:
        got = K.AGENT_AREAS.get(_norm_agent(a))
        if got is None:
            unknown_agents.append(a)
        else:
            areas.update(got)
    ok = not reasons and cov.get("agents_source") == "opencode_sessions" and bool(areas)
    if not ok and not reasons:
        reasons = ["agents_not_observed" if cov.get("agents_source") != "opencode_sessions" else "no_known_agent"]
    return {"coverage_ok": ok, "reasons": reasons, "agents": agents, "unknown_agents": unknown_agents,
            "classes_exercised": sorted(areas) if ok else [],
            "sentence": (f"Coverage recorded: {len(agents)} test agent(s); classes exercised: {len(areas)}."
                         if ok else "The campaign's recorded coverage does not support « no weakness observed »: "
                                    + ", ".join(reasons) + ".")}


# ── applicability ──────────────────────────────────────────────────────────────────────────────────────────────────

def applicability(framework: str, facts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    def res(status: str, field: str, text: str) -> Dict[str, Any]:
        f = facts.get(field) or {}
        return {"status": status, "label": APPLICABILITY_LABEL[status], "basis_field": field,
                "basis_value": f.get("value"), "basis_provenance": f.get("provenance", "unknown"),
                "basis_at": f.get("at"), "text": text}
    if framework == "iso27001":
        v = (facts.get("iso27001_isms_scope") or {}).get("value")
        if v == "in_scope":
            return res("declared_by_customer", "iso27001_isms_scope",
                       "The organisation declares this application in the scope of its ISO/IEC 27001 ISMS.")
        if v == "out_of_scope":
            return res("not_applicable_declared", "iso27001_isms_scope",
                       "The organisation declares this application outside any ISO/IEC 27001 ISMS scope.")
        return res("to_confirm", "iso27001_isms_scope", "No declaration about an ISO/IEC 27001 ISMS scope.")
    if framework == "gdpr":
        v = (facts.get("personal_data") or {}).get("value")
        if v == "yes":
            return res("declared_by_customer", "personal_data",
                       "The organisation declares that the application processes personal data.")
        if v == "no":
            return res("not_applicable_declared", "personal_data",
                       "The organisation declares that the application processes no personal data.")
        return res("to_confirm", "personal_data", "Processing of personal data is not declared.")
    if framework == "nis2":
        v = (facts.get("nis2_entity_type") or {}).get("value")
        sector = (facts.get("sector") or {}).get("value")
        if v in ("essential", "important"):
            return res("declared_by_customer", "nis2_entity_type",
                       f"The organisation declares itself an {v} entity under NIS2"
                       + (f" (sector declared: {sector})." if sector and sector != "unknown" else "."))
        if v == "not_in_scope":
            return res("not_applicable_declared", "nis2_entity_type",
                       "The organisation declares that it is not in the scope of NIS2.")
        if sector and sector != "unknown":
            return res("to_confirm", "nis2_entity_type",
                       f"Sector declared ({sector}) but no NIS2 entity type: the size and national transposition "
                       "decide, the organisation must declare it.")
        return res("to_confirm", "nis2_entity_type", "Neither sector nor NIS2 entity type is declared.")
    if framework == "ai_act":
        ai = (facts.get("ai_system_declared") or {}).get("value")
        rc = (facts.get("ai_risk_class") or {}).get("value")
        if ai == "yes" and rc == "high_risk":
            return res("declared_by_customer", "ai_risk_class",
                       "The organisation declares a high-risk AI system: art. 15 applies.")
        if ai == "no" or rc in ("limited_risk", "minimal_risk", "not_ai_system"):
            field = "ai_system_declared" if ai == "no" else "ai_risk_class"
            return res("not_applicable_declared", field,
                       "The organisation declares no high-risk AI system: art. 15 does not apply.")
        return res("to_confirm", "ai_risk_class",
                   "No declaration of a high-risk AI system; art. 15 applies only to one.")
    return res("to_confirm", "", "")


# ── assessment ─────────────────────────────────────────────────────────────────────────────────────────────────────

_EVIDENCE_FIELDS = ("raw_request", "raw_response", "evidence_commands", "evidence_logs", "evidence_explanation",
                    "evidence", "produced_artifacts")


def _evidence_ref(v: Dict[str, Any]) -> Dict[str, Any]:
    kinds = sorted(k for k in _EVIDENCE_FIELDS if v.get(k))
    return {"finding_id": str(v.get("id")), "ref": f"finding:{v.get('id')}#evidence",
            "evidence_recorded": bool(kinds), "recorded_fields": kinds}


def _ai_hints(nodes: Iterable[Any]) -> List[str]:
    rx = re.compile(r"(?i)\b(ollama|vllm|llama\.cpp|text-generation-inference|openai-compatible|lm studio|localai|"
                    r"triton inference|open-webui|open webui|litellm)\b|/v1/(models|chat/completions)\b|"
                    r"/api/(generate|chat)\b")
    out = []
    for n in nodes or []:
        if not isinstance(n, dict):
            continue
        txt = " ".join(str(n.get(k) or "") for k in ("label", "technology", "title", "endpoint", "service",
                                                       "product", "details"))
        if rx.search(txt) or n.get("port") == 11434:
            out.append(str(n.get("id") or "?"))
    return sorted(out)


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:16]


def assess(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Framework assessment of one campaign. ``bundle`` = {"campaign", "findings", "nodes"?, "actions"? (plan
    actions: action_id, finding_ids, related_attack_paths), "profile"? (``profile.view`` document)}."""
    campaign = bundle.get("campaign") if isinstance(bundle.get("campaign"), dict) else {}
    findings = [v for v in bundle.get("findings") or [] if isinstance(v, dict) and v.get("id")]
    actions = [a for a in bundle.get("actions") or [] if isinstance(a, dict) and a.get("action_id")]
    nodes = bundle.get("nodes") or []
    cov = exercised(campaign)
    facts = P.applicability_facts(bundle.get("profile"))

    counted, excluded = {}, {}
    for v in findings:
        (excluded if identity.exclusion_reason(v) else counted)[str(v["id"])] = v
    links_of: Dict[str, List[Dict[str, Any]]] = {fid: controls_for_finding(v) for fid, v in
                                                 {**counted, **excluded}.items()}
    by_control: Dict[str, List[str]] = {}
    excl_by_control: Dict[str, List[str]] = {}
    citations_not_assessable: Dict[str, List[str]] = {}
    unmapped: List[str] = []
    for fid, links in links_of.items():
        if fid in counted and not any(r["assessable"] for r in links):
            unmapped.append(fid)
        for r in links:
            if not r["assessable"]:
                if fid in counted:
                    citations_not_assessable.setdefault(r["control"], []).append(fid)
                continue
            (by_control if fid in counted else excl_by_control).setdefault(r["control"], []).append(fid)

    actions_of_finding: Dict[str, List[str]] = {}
    paths_of_action: Dict[str, List[str]] = {}
    for a in actions:
        aid = str(a["action_id"])
        for fid in a.get("finding_ids") or []:
            actions_of_finding.setdefault(str(fid), []).append(aid)
        paths_of_action[aid] = sorted({str(p) for p in a.get("related_attack_paths") or []})

    exercised_set = set(cov["classes_exercised"])
    frameworks: List[Dict[str, Any]] = []
    nav_controls: Dict[str, Dict[str, Any]] = {}
    for fw in K.FRAMEWORKS:
        rows = []
        counts = {s: 0 for s in STATES}
        fw_findings: Set[str] = set()
        fw_actions: Set[str] = set()
        for c in fw["controls"]:
            key = control_key(fw["framework"], c["id"])
            fids = sorted(set(by_control.get(key, [])))
            row: Dict[str, Any] = {"key": key, "control_id": c["id"], "text": c["text"],
                                   "classes": list(c["classes"])}
            if not c["assessable"]:
                state = "not_technically_assessable"
                row["why"] = c["why"]
                cited = sorted(set(citations_not_assessable.get(key, [])))
                if cited:
                    row["cited_by_findings"] = cited
                    row["cited_note"] = ("Cited by the testing agent; a technical test cannot assess this control, the "
                                         "findings are listed under the controls of their weakness class.")
            elif fids:
                state = "weakness_observed"
                proofs = {p: 0 for p in identity.PROOF_STATUSES}
                for fid in fids:
                    proofs[identity.proof_of(counted[fid])] += 1
                row["proof"] = proofs
                row["open_findings"] = sum(1 for fid in fids if identity.is_open(counted[fid]))
                row["to_confirm"] = proofs["exploited"] + proofs["confirmed"] == 0
                if row["to_confirm"]:
                    row["to_confirm_note"] = "Only unconfirmed findings: reported by the agent, to be confirmed."
            elif cov["coverage_ok"] and set(c["classes"]) <= exercised_set:
                state = "none_observed_in_tested_scope"
            else:
                state = "not_tested"
                missing = sorted(set(c["classes"]) - exercised_set)
                row["why"] = (cov["sentence"] if not cov["coverage_ok"] else
                              "No dispatched agent covers: " + ", ".join(missing) + ".")
            ex = sorted(set(excl_by_control.get(key, [])))
            if ex:
                row["excluded_finding_ids"] = ex
                row["excluded_note"] = (f"{len(ex)} finding(s) mapped here are marked false positive or held for "
                                        "review: not counted.")
            aids = sorted({a for fid in fids for a in actions_of_finding.get(fid, [])})
            pids = sorted({p for a in aids for p in paths_of_action.get(a, [])})
            row.update({"state": state, "state_label": STATE_LABEL[state], "finding_ids": fids,
                        "action_ids": aids, "attack_path_ids": pids})
            counts[state] += 1
            fw_findings.update(fids)
            fw_actions.update(aids)
            nav_controls[key] = {"framework": fw["framework"], "state": state, "finding_ids": fids,
                                 "action_ids": aids, "attack_path_ids": pids}
            rows.append(row)
        app = applicability(fw["framework"], facts)
        out = {"framework": fw["framework"], "label": fw["label"], "kind": fw["kind"], "source": fw["source"],
               "scope_note": fw["scope_note"], "applicability": app, "counts": counts, "controls": rows,
               "finding_ids": sorted(fw_findings), "action_ids": sorted(fw_actions),
               "limitations": COMMON_LIMITS + FRAMEWORK_LIMITS.get(fw["framework"], [])}
        if fw["framework"] == "ai_act":
            hints = _ai_hints(nodes)
            ai_findings = sorted({fid for k, r in nav_controls.items() if k.startswith("ai_act:")
                                  for fid in r["finding_ids"]})
            out["detection"] = {"ai_component_detected": bool(hints or ai_findings), "node_ids": hints,
                                "ai_finding_ids": ai_findings,
                                "note": "Detection is shown for information: it never decides applicability."}
        frameworks.append(out)

    nav_findings = {}
    for fid in sorted(counted):
        keys = sorted(r["control"] for r in links_of[fid] if r["assessable"])
        nav_findings[fid] = {"control_keys": keys, "action_ids": sorted(set(actions_of_finding.get(fid, []))),
                             "evidence": _evidence_ref(counted[fid])}
    nav_actions = {}
    for a in actions:
        aid = str(a["action_id"])
        fids = [str(f) for f in a.get("finding_ids") or [] if str(f) in counted]
        nav_actions[aid] = {"finding_ids": sorted(fids),
                            "control_keys": sorted({k for f in fids for k in nav_findings[f]["control_keys"]}),
                            "attack_path_ids": paths_of_action.get(aid, [])}
    nav_paths: Dict[str, Dict[str, Any]] = {}
    for aid, r in nav_actions.items():
        for pid in r["attack_path_ids"]:
            p = nav_paths.setdefault(pid, {"action_ids": set(), "control_keys": set()})
            p["action_ids"].add(aid)
            p["control_keys"].update(r["control_keys"])
    nav_paths_out = {pid: {"action_ids": sorted(v["action_ids"]), "control_keys": sorted(v["control_keys"])}
                     for pid, v in sorted(nav_paths.items())}

    return {
        "schema_version": ASSESSMENT_VERSION,
        "catalogue_version": K.CATALOGUE_VERSION,
        "campaign_id": campaign.get("id"),
        "project_id": campaign.get("project_id"),
        "reading": READING,
        "states": [{"value": s, "label": STATE_LABEL[s]} for s in STATES],
        "coverage": cov,
        "frameworks": frameworks,
        "excluded_frameworks": K.EXCLUDED,
        "unchanged_views": K.UNCHANGED_VIEWS,
        "unmapped_finding_ids": sorted(unmapped),
        "excluded_finding_ids": sorted(excluded),
        "navigation": {"controls": nav_controls, "findings": nav_findings, "actions": nav_actions,
                       "attack_paths": nav_paths_out},
        "inputs_digest": _digest({"c": campaign.get("id"), "f": sorted(links_of), "a": sorted(nav_actions),
                                  "p": facts}),
    }


def shown_in_summary(fw: Dict[str, Any]) -> str:
    """How one framework may appear in the executive / regulatory line: ``counts`` (applicability declared by the
    organisation), ``to_confirm`` (named without counts: the organisation has not declared it), ``hidden`` (declared
    not applicable, or the AI Act without a declared high-risk AI system: never named)."""
    st = (fw.get("applicability") or {}).get("status")
    if st == "declared_by_customer":
        return "counts"
    if st == "not_applicable_declared" or fw.get("framework") == "ai_act":
        return "hidden"
    return "to_confirm"


def summary_line(doc: Dict[str, Any]) -> str:
    """One collapsed regulatory line for the executive block, e.g. « Technical findings relevant to: GDPR art. 32
    (2 controls with a weakness observed), … ». Only frameworks the organisation declared applicable carry counts; a
    framework whose applicability is to confirm is named without counts (« applicability to confirm »); a framework
    declared not applicable, and the AI Act unless a high-risk AI system is declared, are never named."""
    parts, pending = [], []
    for fw in doc.get("frameworks") or []:
        n = fw["counts"]["weakness_observed"]
        how = shown_in_summary(fw)
        if not n or how == "hidden":
            continue
        if how == "counts":
            parts.append(f"{fw['label']} ({n} control{'s' if n != 1 else ''} with a weakness observed)")
        else:
            pending.append(fw["label"])
    if not parts and not pending:
        if not (doc.get("coverage") or {}).get("coverage_ok"):
            return ("No finding relevant to the listed frameworks was reported; the recorded coverage does not allow "
                    "a conclusion.")
        return "No weakness relevant to the listed frameworks was observed in the tested scope of this campaign."
    out = []
    if parts:
        out.append("Technical findings relevant to: " + "; ".join(parts) + ".")
    if pending:
        out.append("Findings may also be relevant to: " + "; ".join(pending)
                   + " (applicability to confirm by the organisation).")
    return " ".join(out)
