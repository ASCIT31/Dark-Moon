"""Cyber Score v1: an exposure rating of what one campaign found in its tested scope.

Deterministic, explainable, standard library only, no I/O. Input = one bundle
``{"campaign": {...}, "findings": [...]}``; the campaign carries the server-recorded ``coverage_signals``.

Order of evaluation (methodology 04-CYBER-SCORE-METHODOLOGY.md):

1. Status gate, before any number:
   * ``not_rated``: campaign not completed, retest campaign, coverage signals absent (campaign recorded before they
     existed) or below the minimum (no measured duration, no agent and no command observed). No number.
   * ``limited``: completed but below the coverage floor (short campaign, measured duration, specialised agents
     observed in the session log, registered assets or executed commands under the floor). Capped at ``LIMITED_CAP``.
   * ``rated``: otherwise.
2. Penalty per unit (asset, weakness class): the highest ``severity weight x proof factor`` of the unit, plus a
   bounded increment per additional distinct weakness (fingerprint) in the unit. Units of one class on several
   assets: the largest counts fully, the others add a bounded share.
3. Score = 100 - sum of class penalties, rounded, floored at 0.
4. Caps by worst evidence (exploited critical, confirmed critical, exploited high), then the limited cap.

Not in the v1 number: attack paths (shown beside it), treatment states and closures declared during the campaign
(closed findings are still scored), retest verdicts, CVSS (the displayed severity is used; a valid vector only
replaces a severity that is none of the five levels), agent count (a coverage signal only).
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, List, Optional

from . import identity, stats as _stats

METHODOLOGY_VERSION = "darkmoon-cyber-score/1"
SIGNALS_SCHEMA = "darkmoon-coverage-signals/1"

SEVERITY_WEIGHT = {"critical": 30.0, "high": 15.0, "medium": 5.0, "low": 2.0, "info": 0.0}
UNKNOWN_SEVERITY_AS = "high"   # a severity that is none of the five levels, without a valid CVSS vector: conservative
PROOF_FACTOR = {"exploited": 1.0, "confirmed": 0.8, "unconfirmed": 0.5}
UNIT_INCREMENT = 0.10          # per additional distinct weakness in one unit
UNIT_INCREMENT_CAP = 0.30      # at most +30 % of the unit's highest penalty
CLASS_SPREAD = 0.25            # share of each further unit of one class (other assets)
CLASS_SPREAD_CAP = 0.50        # at most +50 % of the class's largest unit
CAPS = (
    ("exploited_critical", "critical", "exploited", 39),
    ("confirmed_critical", "critical", "confirmed", 49),
    ("exploited_high", "high", "exploited", 59),
)
LIMITED_CAP = 69

MIN_DURATION_SECONDS = 1800    # 30 min of measured wall clock
MIN_AGENTS = 2                 # specialised agents dispatched
MIN_ASSETS = 1                 # infrastructure nodes registered
MIN_COMMANDS = 10              # toolbox commands executed through the MCP server

COMPLETE = frozenset({"completed", "complete", "done", "finished"})
KINDS = ("full", "retest", "short")
# OpenCode's own generic agents: a session of theirs is not a specialised test agent
GENERIC_AGENTS = frozenset({"general", "build", "plan", "explore", "task", "compaction", "title", "summary"})

GRADES = (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("E", 0))

BASE_LIMITATIONS = (
    "Exposure rating of what this campaign found in its tested scope, not a measure of the overall security level.",
    "Weights and caps are expert-set (methodology v1) and have not been scientifically validated.",
    "Severity and proof level of each finding are reported by the testing agent, with evidence on file; the server "
    "does not re-verify them, and the caps by worst evidence follow the agent's report.",
    "Run-to-run variance has not been measured: two campaigns on the same target may find different weaknesses.",
    "Attack paths are not part of the v1 rating; they are shown beside it with their evidence status.",
    "Only commands run through the Darkmoon toolbox are counted; commands run by the agent's own shell are not seen.",
)
SATURATION_TEXT = ("The penalties exceed the scale (sum {total}, {ratio}x the scale): the rating is at 0 and does not "
                   "distinguish further exposure.")
# launch restrictions recorded by the server at launch (coverage_signals.launch_restrictions)
NO_SEVERITY_FILTER = frozenset({"", "none", "critical"})   # a cap at critical filters nothing
REDUCED_NOISE = frozenset({"stealth"})
SIGNALS_DIGEST_FIELDS = ("schema", "campaign_kind", "campaign_kind_source", "started_at", "finalized_at",
                         "measured_duration_seconds", "agents_dispatched", "agents_source", "assets_registered",
                         "commands_executed", "workflows_executed", "launch_restrictions")
SIGNALS_DIGEST_KEY = "coverage_signals_digest"   # on the campaign record, written at the first close
TOP_CLASSES = 3


def _r(x: float) -> float:
    return float(round(x + 0.0, 2))


def _half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


def grade_of(score: Optional[int]) -> Optional[str]:
    if score is None:
        return None
    for g, floor in GRADES:
        if score >= floor:
            return g
    return "E"


def _int(x: Any) -> Optional[int]:
    """A finite integer, else None (strings, NaN, infinities, booleans and containers are refused)."""
    if x is None or isinstance(x, bool):
        return None
    try:
        if isinstance(x, float) and not math.isfinite(x):
            return None
        v = int(x)
    except (TypeError, ValueError, OverflowError):
        return None
    return v if v >= 0 else None


def _cvss_band(vector: Any) -> Optional[str]:
    """Severity band of a valid CVSS 3.x base vector (FIRST CVSS v3.1 §7), else None."""
    text = str(vector or "").strip()
    if not text.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    m = dict(p.split(":", 1) for p in text.split("/")[1:] if p.count(":") == 1)
    W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
         "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}}
    try:
        scope = {"U": False, "C": True}[m["S"]]
        pr = {"N": 0.85, "L": 0.68 if scope else 0.62, "H": 0.5 if scope else 0.27}[m["PR"]]
        av, ac, ui = W["AV"][m["AV"]], W["AC"][m["AC"]], W["UI"][m["UI"]]
        c, i, a = W["C"][m["C"]], W["C"][m["I"]], W["C"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope else 6.42 * iss
    if impact <= 0:
        return "info"
    expl = 8.22 * av * ac * pr * ui
    raw = min(1.08 * (impact + expl), 10) if scope else min(impact + expl, 10)
    base = math.ceil(raw * 10 - 1e-9) / 10
    return "critical" if base >= 9 else "high" if base >= 7 else "medium" if base >= 4 else "low"


def scored_severity(v: Dict[str, Any]) -> str:
    """Severity the score uses: the displayed severity; when it is none of the five levels, the band of a valid
    CVSS vector, else ``UNKNOWN_SEVERITY_AS`` (an unreadable label must never read as reassuring)."""
    sev = identity.severity_of(v)
    if sev != "unknown":
        return sev
    return _cvss_band(v.get("cvss_vector")) or UNKNOWN_SEVERITY_AS


def scored_proof(v: Dict[str, Any]) -> str:
    """Proof the score uses: the stored proof status; a finding declared closed during the campaign (remediated,
    fixed...) was found and its closure is not verified, so it is scored as confirmed."""
    if identity.is_closed(v):
        return "confirmed"
    return identity.proof_of(v)


def _agent_names(value: Any) -> List[str]:
    out: List[str] = []
    if not isinstance(value, list):
        return out
    for a in value:
        name = a.get("agent") if isinstance(a, dict) else a
        if not isinstance(name, str):
            continue
        name = name.strip()[:64]
        if name and name not in out:
            out.append(name)
    return sorted(out)


def signals_digest(sig: Any) -> Optional[str]:
    """SHA-256 of the gate fields of the coverage signals (``SIGNALS_DIGEST_FIELDS``), or None without signals.
    Stored once at the first close; a later mismatch flags signals modified after finalisation (detects naive edits of
    the record, not a security boundary: whoever can rewrite the record can rewrite the digest)."""
    if not isinstance(sig, dict) or sig.get("schema") != SIGNALS_SCHEMA:
        return None
    basis = json.dumps({k: sig.get(k) for k in SIGNALS_DIGEST_FIELDS}, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(basis.encode()).hexdigest()


def launch_restrictions_of(value: Any) -> Dict[str, Any]:
    """Normalised launch restrictions: severity filter, attack exclusions, noise level, out-of-scope assets, custom
    rules and focus list as recorded by the server at launch (counts for lists, never their content)."""
    r = value if isinstance(value, dict) else {}
    sev = str(r.get("severity") or "").strip().lower()[:16]
    noise = str(r.get("noise") or "").strip().lower()[:16]
    return {"severity": sev or None, "noise": noise or None,
            "exclude": _int(r.get("exclude")) or 0, "out_of_scope": _int(r.get("out_of_scope")) or 0,
            "rules": _int(r.get("rules")) or 0, "focus": _int(r.get("focus")) or 0,
            "recorded": bool(r)}


def coverage_of(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Normalised coverage signals, or ``{"present": False}`` for a campaign recorded without them."""
    sig = campaign.get("coverage_signals")
    if not isinstance(sig, dict) or sig.get("schema") != SIGNALS_SCHEMA:
        return {"present": False}
    agents = _agent_names(sig.get("agents_dispatched"))
    kind = str(sig.get("campaign_kind") or "").strip().lower()
    return {
        "present": True,
        "campaign_kind": kind if kind in KINDS else "unknown",
        "campaign_kind_source": str(sig.get("campaign_kind_source") or "default"),
        "started_at": sig.get("started_at"),
        "finalized_at": sig.get("finalized_at"),
        "measured_duration_seconds": _int(sig.get("measured_duration_seconds")),
        "agents_dispatched": agents,
        "specialised_agents": [a for a in agents if a.lower() not in GENERIC_AGENTS],
        "agents_source": str(sig.get("agents_source") or "unknown"),
        "assets_registered": _int(sig.get("assets_registered")) or 0,
        "commands_executed": _int(sig.get("commands_executed")) or 0,
        "workflows_executed": _int(sig.get("workflows_executed")) or 0,
        "launch_restrictions": launch_restrictions_of(sig.get("launch_restrictions")),
        "signals_intact": _intact(campaign, sig),
    }


def _intact(campaign: Dict[str, Any], sig: Dict[str, Any]) -> Optional[bool]:
    """True/False when a digest was recorded at the first close, None when none was (older record)."""
    stored = campaign.get(SIGNALS_DIGEST_KEY)
    if not isinstance(stored, str) or not stored:
        return None
    return stored == signals_digest(sig)


def _coverage_sentence(cov: Dict[str, Any]) -> str:
    if not cov.get("present"):
        return "Coverage not recorded for this campaign."
    mins = cov.get("measured_duration_seconds")
    def n(k: int, word: str) -> str:
        return f"{k} {word}{'' if k == 1 else 's'}"
    parts = [
        f"{cov['campaign_kind']} campaign",
        n(len(cov['specialised_agents']), "test agent"),
        f"{round(mins / 60)} min of server-measured activity" if mins else "duration not measured",
        n(cov['assets_registered'], "asset") + " registered",
        n(cov['commands_executed'] + cov['workflows_executed'], "toolbox command") + " executed",
    ]
    return ", ".join(parts) + "."


def gate(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """Score status and the reasons for it. Reasons are stable tokens + plain sentences."""
    status = str(campaign.get("status") or "").strip().lower()
    cov = coverage_of(campaign)
    not_rated: List[Dict[str, str]] = []
    limited: List[Dict[str, str]] = []
    if status not in COMPLETE:
        not_rated.append({"code": "not_completed",
                          "text": f"The campaign did not complete (status: {status or 'unknown'})."})
    if not cov["present"]:
        not_rated.append({"code": "no_coverage_signals",
                          "text": "This campaign was recorded before coverage signals existed (no server-measured "
                                  "duration, dispatched agents or command count): it cannot be rated."})
    else:
        if cov["campaign_kind"] == "retest":
            not_rated.append({"code": "retest",
                              "text": "A retest checks selected findings again; it is not rated as an assessment."})
        if cov["campaign_kind"] == "unknown":
            not_rated.append({"code": "unknown_kind", "text": "The campaign kind recorded is not recognised."})
        dur = cov["measured_duration_seconds"]
        if not dur or dur <= 0:
            not_rated.append({"code": "no_measured_duration", "text": "No server-measured duration."})
        if not cov["agents_dispatched"] and cov["commands_executed"] + cov["workflows_executed"] == 0:
            not_rated.append({"code": "no_activity_observed",
                              "text": "No dispatched agent and no toolbox command were observed by the server."})
        if cov.get("signals_intact") is False:
            not_rated.append({"code": "signals_modified",
                              "text": "The coverage signals were modified after the campaign was finalised (their "
                                      "recorded digest no longer matches): no rating. This check detects naive edits "
                                      "of the record only; it is not a security boundary."})
        lr = cov.get("launch_restrictions") or {}
        if (lr.get("severity") or "") not in NO_SEVERITY_FILTER:
            not_rated.append({"code": "severity_filter",
                              "text": f"Severity filter applied at launch (SEVERITY={lr['severity']}): the agents "
                                      "were told to cap the severities they report, so no rating is given."})
        if lr.get("exclude"):
            limited.append({"code": "attack_exclusions",
                            "text": f"{lr['exclude']} attack exclusion(s) applied at launch: excluded attacks are not "
                                    "reported as findings."})
        if (lr.get("noise") or "") in REDUCED_NOISE:
            limited.append({"code": "reduced_mode",
                            "text": f"Reduced test mode applied at launch (NOISE={lr['noise']}): only passive tools "
                                    "were allowed."})
        if cov["campaign_kind"] == "short":
            limited.append({"code": "short_campaign", "text": "Declared as a short campaign."})
        if dur and 0 < dur < MIN_DURATION_SECONDS:
            limited.append({"code": "short_duration",
                            "text": f"Measured duration {round(dur / 60)} min, under {MIN_DURATION_SECONDS // 60} min."})
        if cov["agents_source"] != "opencode_sessions":
            limited.append({"code": "agents_not_observed",
                            "text": "Dispatched agents were not observed in the agent session log; the agent names "
                                    "given in the MCP calls cannot meet the coverage floor."})
        elif len(cov["specialised_agents"]) < MIN_AGENTS:
            limited.append({"code": "few_agents",
                            "text": f"{len(cov['specialised_agents'])} specialised agent(s) dispatched, "
                                    f"under {MIN_AGENTS}."})
        if cov["assets_registered"] < MIN_ASSETS:
            limited.append({"code": "no_assets", "text": "No asset registered in the infrastructure map."})
        if cov["commands_executed"] + cov["workflows_executed"] < MIN_COMMANDS:
            limited.append({"code": "few_commands",
                            "text": f"{cov['commands_executed'] + cov['workflows_executed']} toolbox command(s) "
                                    f"executed, under {MIN_COMMANDS}."})
    if not_rated:
        st = "not_rated"
    elif limited:
        st = "limited"
    else:
        st = "rated"
    return {"score_status": st, "not_rated_reasons": not_rated, "limited_reasons": limited, "coverage": cov}


def _units(open_findings: List[Dict[str, Any]], target_id: str) -> Dict[str, Dict[str, Any]]:
    units: Dict[str, Dict[str, Any]] = {}
    for v in open_findings:
        sev = scored_severity(v)
        if sev == "info":
            continue
        vv = {**v, "target_id": v.get("target_id") or target_id}
        key = identity.unit_key(vv)
        proof = scored_proof(vv)
        pen = SEVERITY_WEIGHT[sev] * PROOF_FACTOR[proof]
        u = units.setdefault(key, {"unit": key, "asset": identity.asset_key(vv),
                                   "weakness_class": identity.weakness_class(vv),
                                   "finding_ids": [], "fingerprints": set(), "head": None, "head_penalty": -1.0})
        u["finding_ids"].append(str(v.get("id")))
        u["fingerprints"].add(identity.fingerprint(vv))
        head_key = (pen, SEVERITY_WEIGHT[sev], PROOF_FACTOR[proof], str(v.get("id")))
        if u["head"] is None or head_key > u["head"]:
            u["head"] = head_key
            u["head_penalty"] = pen
            u["severity"] = sev
            u["proof"] = proof
            u["head_finding_id"] = str(v.get("id"))
    return units


def _components(units: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_class: Dict[str, List[Dict[str, Any]]] = {}
    for u in units.values():
        extra = max(0, len(u["fingerprints"]) - 1)
        inc_ratio = min(UNIT_INCREMENT_CAP, UNIT_INCREMENT * extra)
        base = u["head_penalty"]
        row = {
            "unit": u["unit"], "asset": u["asset"], "weakness_class": u["weakness_class"],
            "severity": u["severity"], "proof": u["proof"], "head_finding_id": u["head_finding_id"],
            "finding_ids": sorted(u["finding_ids"]), "distinct_weaknesses": len(u["fingerprints"]),
            "base_penalty": _r(base), "increment": _r(base * inc_ratio), "penalty": _r(base * (1 + inc_ratio)),
        }
        by_class.setdefault(u["weakness_class"], []).append(row)
    out = []
    for cls in sorted(by_class):
        rows = sorted(by_class[cls], key=lambda r: (-r["penalty"], r["unit"]))
        top = rows[0]["penalty"]
        spread = min(CLASS_SPREAD_CAP * top, CLASS_SPREAD * sum(r["penalty"] for r in rows[1:]))
        out.append({"weakness_class": cls, "units": rows, "top_unit_penalty": _r(top),
                    "spread": _r(spread), "class_penalty": _r(top + spread)})
    out.sort(key=lambda c: (-c["class_penalty"], c["weakness_class"]))
    return out


def _caps(open_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for rule, sev, proof, cap in CAPS:
        ids = sorted(str(v.get("id")) for v in open_findings
                     if scored_severity(v) == sev and scored_proof(v) == proof)
        if ids:
            out.append({"rule": rule, "cap": cap, "finding_ids": ids})
    return out


def _capped(open_findings: List[Dict[str, Any]], target_id: str, st: str) -> int:
    """The number the rules give for these findings (status not ``not_rated``): 100 - penalties, then the caps."""
    comps = _components(_units(open_findings, target_id))
    sc = max(0, min(100, _half_up(100 - sum(c["class_penalty"] for c in comps))))
    for c in _caps(open_findings):
        sc = min(sc, c["cap"])
    return min(sc, LIMITED_CAP) if st == "limited" else sc


_CAP_WORDS = {"exploited_critical": "exploited critical", "confirmed_critical": "confirmed critical",
              "exploited_high": "exploited high"}


def _cap_phrase(c: Dict[str, Any]) -> str:
    return (f"capped at {c['cap']} while {len(c['finding_ids'])} {_CAP_WORDS.get(c['rule'], c['rule'])} "
            f"finding(s) remain open")


def next_cap_level(open_findings: List[Dict[str, Any]], target_id: str, st: str, score: Optional[int],
                   caps: List[Dict[str, Any]], raw: int) -> Optional[Dict[str, Any]]:
    """What holds the rating where it is and what would move it: the cap that binds now, what removes it and the
    rating the same rules would give without those findings (indicative: if a new campaign no longer reported them
    and nothing else changed); or, when the penalty sum alone sets the number, that sum and the caps behind it.
    None when the campaign is not rated or nothing holds the rating below 100."""
    if st == "not_rated" or score is None:
        return None
    ordered = sorted(caps, key=lambda c: (c["cap"], c["rule"]))
    binding = [c for c in ordered if c["cap"] == score and c["cap"] < raw]
    if binding:
        gone = sorted({f for c in binding for f in c["finding_ids"]})
        rest = [v for v in open_findings if str(v.get("id")) not in set(gone)]
        after = _capped(rest, target_id, st)
        rest_caps = sorted(_caps(rest), key=lambda c: (c["cap"], c["rule"]))
        text = _cap_phrase(binding[0]).capitalize()
        if rest_caps:
            text += "; then " + _cap_phrase(rest_caps[0])
        text += (f". Without them (no longer reported by a new campaign, nothing else changed) the same rules would "
                 f"give {after}.")
        return {"rule": binding[0]["rule"], "cap": binding[0]["cap"], "finding_ids": gone, "text": text,
                "score_without": after}
    if st == "limited" and score == LIMITED_CAP and raw > LIMITED_CAP:
        return {"rule": "limited_coverage", "cap": LIMITED_CAP, "finding_ids": [], "score_without": None,
                "text": f"Capped at {LIMITED_CAP} because the test was limited: a completed full campaign that meets "
                        "the coverage floor removes this cap."}
    if score >= 100:
        return None
    penalty = 100 - raw if raw > 0 else None
    text = ("The penalty sum of the weakness classes sets the rating"
            + ("" if penalty is not None else " at 0 (the penalties exceed the scale)"))
    if ordered:
        text += "; the caps by worst evidence would also hold it: " + _cap_phrase(ordered[0])
    text += ". The weakness classes that weigh most are listed with their share of the penalty sum."
    return {"rule": "penalties", "cap": None, "finding_ids": [], "text": text, "score_without": None}


def class_shares(comps: List[Dict[str, Any]], penalty: float, top: int = TOP_CLASSES) -> List[Dict[str, Any]]:
    """The weakness classes that weigh most, with their share of the penalty sum (deterministic, from the
    components; the share is of the penalty sum, not of a risk)."""
    if penalty <= 0:
        return []
    out = []
    for c in comps[:top]:
        out.append({"weakness_class": c["weakness_class"], "class_penalty": c["class_penalty"],
                    "share_of_penalty": _r(c["class_penalty"] / penalty),
                    "share_text": f"{round(100 * c['class_penalty'] / penalty)} % of the penalty sum"})
    return out


def _digest(campaign: Dict[str, Any], findings: List[Any]) -> str:
    keys = ("id", "severity", "status", "category", "type", "endpoint", "target_id", "cve", "cwe", "dedup_key",
            "quarantined", "quarantine_reviewed_by", "title")
    rows = sorted(([str(v.get(k)) for k in keys] for v in findings if isinstance(v, dict)))
    basis = json.dumps({"c": [campaign.get("id"), campaign.get("status"), campaign.get("target_id"),
                              campaign.get("coverage_signals")], "f": rows}, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(basis.encode()).hexdigest()


def cyber_score(bundle: Dict[str, Any], previous: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score document of one campaign. ``previous`` = the score document of an earlier campaign of the same target
    (optional): a trend is given only between two rated full campaigns."""
    campaign = dict(bundle.get("campaign") or {})
    findings = [v for v in (bundle.get("findings") or []) if isinstance(v, dict)]
    target_id = str(campaign.get("target_id") or "")
    g = gate(campaign)
    cov = g["coverage"]
    st = g["score_status"]

    kept, excluded = _stats.split(findings)
    # every counted finding is scored: a closure (remediated, fixed...) declared during the campaign is not verified,
    # and treatment states never change the rating; closed ones are listed and scored as confirmed
    open_f = kept
    closed_ids = sorted(str(v.get("id")) for v in kept if identity.is_closed(v))
    info_n = sum(1 for v in open_f if scored_severity(v) == "info")
    unknown = sorted(str(v.get("id")) for v in open_f if identity.severity_of(v) == "unknown")
    units = _units(open_f, target_id)
    comps = _components(units)
    caps = _caps(open_f)
    penalty = sum(c["class_penalty"] for c in comps)
    raw = max(0, min(100, _half_up(100 - penalty)))
    applied = []
    score: Optional[int] = None
    if st != "not_rated":
        score = raw
        for c in caps:
            if score > c["cap"]:
                applied.append({"rule": c["rule"], "cap": c["cap"], "finding_ids": c["finding_ids"]})
            score = min(score, c["cap"])
        if st == "limited":
            if score > LIMITED_CAP:
                applied.append({"rule": "limited_coverage", "cap": LIMITED_CAP, "finding_ids": []})
            score = min(score, LIMITED_CAP)
    else:
        for c in comps:
            c.pop("spread", None)
            c.pop("top_unit_penalty", None)
            c.pop("class_penalty", None)
            for u in c["units"]:
                for k in ("base_penalty", "increment", "penalty"):
                    u.pop(k, None)

    by_proof = {p: 0 for p in identity.PROOF_STATUSES}
    by_sev = {s: 0 for s in identity.SEVERITIES}
    for v in open_f:
        by_proof[scored_proof(v)] += 1
        s = scored_severity(v)
        if s in by_sev:
            by_sev[s] += 1
    to_confirm = sorted(str(v.get("id")) for v in open_f
                        if scored_proof(v) == "unconfirmed" and scored_severity(v) in ("critical", "high"))

    limitations = list(BASE_LIMITATIONS)
    limitations += [r["text"] for r in g["not_rated_reasons"]]
    limitations += [r["text"] for r in g["limited_reasons"]]
    if cov.get("present") and cov.get("agents_source") == "tool_calls_only":
        limitations.append("Dispatched agents were taken from the MCP calls that carried an agent name (the agent "
                           "session log was not readable); an agent that ran without reporting is not seen.")
    if unknown:
        limitations.append(f"{len(unknown)} finding(s) without a recognised severity were weighted from their CVSS "
                           f"vector, else as {UNKNOWN_SEVERITY_AS} (conservative).")
    if excluded.get("quarantined"):
        limitations.append(f"{excluded['quarantined']} finding(s) held for privacy review are not counted.")
    if excluded.get("false_positive"):
        limitations.append(f"{excluded['false_positive']} finding(s) marked false positive by an agent or an "
                           f"operator are not counted.")
    if closed_ids:
        limitations.append(f"{len(closed_ids)} finding(s) declared closed during the campaign are still scored (as "
                           f"confirmed): a closure is not verified until a completed retest.")
    if to_confirm:
        limitations.append(f"{len(to_confirm)} unconfirmed critical/high finding(s) to confirm; they weigh less "
                           f"than proven ones and never set a cap.")
    if st != "not_rated" and score == 100:
        limitations.append("100 means no weakness was found in the tested scope; it is not a proof of absence.")
    if st != "not_rated" and penalty > 100:
        limitations.append(SATURATION_TEXT.format(total=_r(penalty), ratio=_r(penalty / 100)))
    lr = cov.get("launch_restrictions") or {} if cov.get("present") else {}
    if lr.get("out_of_scope") or lr.get("rules"):
        limitations.append(f"Launch restrictions recorded: {lr.get('out_of_scope', 0)} out-of-scope asset(s), "
                           f"{lr.get('rules', 0)} custom rule(s); the rating covers what was tested under them.")

    doc: Dict[str, Any] = {
        "methodology_version": METHODOLOGY_VERSION,
        "campaign_id": campaign.get("id"),
        "target_id": target_id or None,
        "score": score,
        "grade": grade_of(score),
        "score_status": st,
        "status_reasons": g["not_rated_reasons"] + g["limited_reasons"],
        "assessed_at": (cov.get("finalized_at") if cov.get("present") else None) or campaign.get("date"),
        "assessment_coverage": {**{k: v for k, v in cov.items()}, "sentence": _coverage_sentence(cov),
                                "floors": {"min_duration_seconds": MIN_DURATION_SECONDS, "min_agents": MIN_AGENTS,
                                           "min_assets": MIN_ASSETS, "min_commands": MIN_COMMANDS}},
        "evidence_summary": {
            "counted_findings": len(kept), "open_findings": len(open_f),
            "by_proof": by_proof, "by_severity": by_sev,
            "units": len(units), "weakness_classes": len({u["weakness_class"] for u in units.values()}),
            "to_confirm": to_confirm, "unknown_severity": unknown,
            "declared_closed": closed_ids,
            "excluded": {**excluded, "informational": info_n},
        },
        "components": comps,
        "caps": caps,
        "caps_applied": applied,
        "penalty_total": _r(penalty) if st != "not_rated" else None,
        "penalty_over_scale": _r(penalty / 100) if st != "not_rated" else None,
        "next_cap_level": next_cap_level(open_f, target_id, st, score, caps, raw),
        "top_classes": class_shares(comps, penalty) if st != "not_rated" else [],
        "limitations": limitations,
        "trend": None,
        "source_campaign_ids": [campaign.get("id")] if campaign.get("id") else [],
        "inputs_digest": _digest(campaign, findings),
    }
    if previous is not None:
        doc["trend"] = trend_between(doc, previous)
    return doc


def comparable(doc: Dict[str, Any]) -> bool:
    cov = doc.get("assessment_coverage") or {}
    return doc.get("score_status") == "rated" and cov.get("campaign_kind") == "full" and doc.get("score") is not None


def trend_between(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Trend between two score documents: only two rated full campaigns of the same target are compared."""
    if current.get("target_id") != previous.get("target_id"):
        return {"available": False, "reason": "different targets"}
    if not (comparable(current) and comparable(previous)):
        return {"available": False, "reason": "a trend needs two rated full campaigns of the same target",
                "previous_campaign_id": previous.get("campaign_id")}
    delta = int(current["score"]) - int(previous["score"])
    a, b = current["assessment_coverage"], previous["assessment_coverage"]
    diffs = []
    added = sorted(set(a.get("specialised_agents") or []) - set(b.get("specialised_agents") or []))
    removed = sorted(set(b.get("specialised_agents") or []) - set(a.get("specialised_agents") or []))
    if added:
        diffs.append("agents added: " + ", ".join(added))
    if removed:
        diffs.append("agents not run this time: " + ", ".join(removed))
    if (a.get("assets_registered") or 0) != (b.get("assets_registered") or 0):
        diffs.append(f"assets registered: {b.get('assets_registered')} -> {a.get('assets_registered')}")
    da, db = a.get("measured_duration_seconds") or 0, b.get("measured_duration_seconds") or 0
    if db and (da < db / 2 or da > db * 2):
        diffs.append(f"measured duration: {round(db / 60)} min -> {round(da / 60)} min")
    return {"available": True, "previous_campaign_id": previous.get("campaign_id"),
            "previous_score": previous.get("score"), "delta": delta,
            "direction": "improved" if delta > 0 else "degraded" if delta < 0 else "stable",
            "scope_differences": diffs}
