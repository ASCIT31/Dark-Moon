"""
Darkmoon — structured attack paths, schema ``darkmoon-attack-paths/v1``.

Implements docs/focus-dashboard/ATTACK-PATHS-BACKEND.md §2–§3. The server is the single source
of attack paths, their steps and the effect of fixes; the frontend only displays them.

Three provenances, never mixed in one ranking:

- ``declared``: chains declared by the agent at finalisation (``campaign["attack_chains"]``,
  validated by ``attack_chains.parse_attack_chains_block`` and re-checked by
  ``attack_chains.derive_scenarios``);
- ``derived``: JOIN of the structured finding fields (prerequisites <-> produced_artifacts,
  reached_assets, negative_control) by ``attack_chains.derive_scenarios``;
- ``observed``: proven transitions read in the evidence of older campaigns (rules R1–R3,
  ``attack_paths_observed``).

A fourth provenance, ``inferred``, lists POSSIBLE paths deduced by fixed rules from the real topology and the
confirmed findings (``attack_paths_inferred``, docs/ATTACK-PATHS-INFERRED.md). It is always ``hypothesis: true``,
never ranked, never counted in the proven paths, the critical paths, the coverage or the insights.

``declared`` and ``derived`` both come from structured server data and are ranked together (the
"server" source of the frontend); ``observed`` is ranked only when no server path exists, and is
otherwise listed as unranked proven pivots. Ranking = ``attack_paths_engine`` + display gate.

Pure functions: no I/O, nothing written, nothing invented. Only ``artifact_ref`` hashes and
evidence counters leave this module; free text goes through ``attack_chains.redact_text``.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from api import feature_flags, fix_triage
from api.attack_chains import derive_scenarios, redact_text
from api.attack_paths_engine import (
    OFF_PATH_REASON_LABELS,
    first_blocked_step,
    is_scenario_interrupted,
    prioritize_corrections,
    ranking_gate,
)
from api.attack_paths_inferred import derive_inferred
from api.attack_paths_observed import (
    ancestors_of,
    derive_observed_input,
    group_duplicate_findings,
    is_pseudo_node,
    severity_of,
)

SCHEMA_VERSION = "darkmoon-attack-paths/v1"
# additive revisions: 1.1 insights (critical assets, choke points, blast radius, toxic combinations, per-edge
# technique/proof); 1.2 the single « Fix first » (fix_first) and the secondary triage view (api/fix_triage.py);
# 1.3 provenance « inferred » (hypotheses from topology + findings, api/attack_paths_inferred.py); additive, same
# revision: observed_links (two columns « usage » / « necessity » per observed link, 
SCHEMA_REVISION = "1.3"
SIMULATION_LABEL = "SIMULATION · not applied"
PROVENANCES = ("declared", "derived", "observed", "inferred", "agent-declared")
# round 5 (honesty): « agent-declared » = a path with at least one step the agent DECLARED (enabled_by, plausibility
# filtered) and the server did not observe. Always hypothesis: True, so no proven counter, ranking, insight, simulation
# « proven_* » figure, report or framework ever counts it; it is shown with its own level everywhere.
AGENT_DECLARED = "agent-declared"
AGENT_DECLARED_LABEL = "Declared by the agent · not verified by the server"
DECLARED_CHAIN_LABEL = "Declared by the agent · every step exploited · links not verified by the server"
DECLARED_PROVENANCES = ("declared", AGENT_DECLARED)
# 40-paths-v2 (CONTRACT.md): levels of a link / of a path built from links, weakest first. R1-R3 server rules keep the
# level « observed »; « summary.proven_paths » counts paths whose every link is at least an observed flow.
DECLARED_UNVERIFIED, OBSERVED_FLOW, CAUSAL = "declared_unverified", "observed_flow", "causal_necessity_demonstrated"
# architecture D: a declared link the server did not qualify is « declared_by_agent » (the paths-v2 value
# declared_unverified is read the same, for documents and tests of that version)
DECLARED_BY_AGENT = "declared_by_agent"
_DECLARED_LEVELS = (DECLARED_BY_AGENT, DECLARED_UNVERIFIED)
# architecture D final review: an R2 link (open registration matched by
# endpoint) is a historical INFERENCE: a path resting on one is provenance « inferred », a hypothesis, never proven
INFERRED_LEVEL = "inferred"
R2_PATH_NOTE = ("Inferred · not proven: at least one step rests on the historical server rule R2 (an open registration "
                "matched by its endpoint), an inference the server did not observe. A hypothesis, not a proof.")


def path_level(steps: List[Dict[str, Any]]) -> str:
    """The WEAKEST link level of a chain: inferred (R2) < declared_by_agent < observed_flow < observed (R1, R3) < causal."""
    levels = {(st.get("impact") or {}).get("level") for st in steps} - {None}
    if INFERRED_LEVEL in levels:
        return INFERRED_LEVEL
    if levels & set(_DECLARED_LEVELS):
        return DECLARED_BY_AGENT
    for lv in (OBSERVED_FLOW, "observed", CAUSAL):
        if lv in levels:
            return lv
    return "observed"
MAX_RANKED_PATHS = 200
ANALYSIS_LIMITS = {"max_findings": 5000, "max_evidence_chars": 60_000_000}
LIVE_EXCLUDED = ("false_positive", "remediated", "quarantined")
_CERTAINTY = {"exploited": 0, "confirmed": 1, "unconfirmed": 2}
_CERTAINTY_NAMES = ("exploited", "confirmed", "unconfirmed")
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}
_PROV_ORDER = {p: i for i, p in enumerate(PROVENANCES)}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _red(text: Any, limit: int = 500) -> str:
    return redact_text(text, limit)[0]


def _node_labels(nodes: List[Dict[str, Any]]) -> Dict[str, str]:
    """Human labels; a label shared by several nodes gets its node type appended."""
    base = {n["id"]: str(n.get("label") or n.get("host") or n["id"]) for n in nodes}
    count: Dict[str, int] = {}
    for v in base.values():
        count[v] = count.get(v, 0) + 1
    out = {}
    for n in nodes:
        lab = base[n["id"]]
        out[n["id"]] = _red(f"{lab} ({str(n.get('node_type') or 'asset').replace('_', ' ')})" if count[lab] > 1 else lab, 200)
    return out


def _label(labels: Dict[str, str], node_id: str) -> str:
    if is_pseudo_node(node_id):
        return "Unlocated asset"
    return labels.get(node_id, "Unknown asset")


def _status(v: Dict[str, Any]) -> str:
    return str(v.get("status") or "unconfirmed").strip().lower()


def _cvss(v: Dict[str, Any]) -> float:
    try:
        x = float(v.get("cvss_score"))
    except (TypeError, ValueError):
        return 0.0
    return x if x == x and x not in (float("inf"), float("-inf")) else 0.0


def _evidence_meta(v: Dict[str, Any]) -> Dict[str, Any]:
    ev = v.get("evidence")
    items = ev if isinstance(ev, list) else [ev] if isinstance(ev, dict) else []

    def count(e: Dict[str, Any], *keys: str) -> int:
        for k in keys:
            val = e.get(k)
            if isinstance(val, list):
                return len(val)
            if val:
                return 1
        return 0

    meta = {"commands": 0, "requests": 0, "has_extracted_data": False}
    for e in items:
        if not isinstance(e, dict):
            continue
        meta["commands"] += count(e, "commands", "command")
        meta["requests"] += count(e, "requests", "request", "raw_request")
        meta["has_extracted_data"] = meta["has_extracted_data"] or bool(e.get("extracted_data") or e.get("extractedData"))
    return meta


def _lower_first(s: str) -> str:
    return s[:1].lower() + s[1:] if len(s) > 1 and s[1:2].islower() else s


_CATEGORY_LABELS = {"sql_injection": "SQL injection", "ssrf": "Server-side request forgery (SSRF)",
                    "xss": "Cross-site scripting (XSS)", "idor": "Insecure direct object reference (IDOR)",
                    "rce": "Remote code execution", "lfi": "Local file inclusion", "xxe": "XML external entity (XXE)",
                    "csrf": "Cross-site request forgery (CSRF)"}


def category_label(category: Any) -> Optional[str]:
    """Readable label for a finding category key (never show `sql_injection`)."""
    key = str(category or "").strip().lower()
    if not key:
        return None
    return _CATEGORY_LABELS.get(key) or key.replace("_", " ").replace("-", " ").capitalize()


def fix_label(title: str) -> str:
    """Short imperative label of a fix, from the finding title (never an id)."""
    t = _red(title, 160).strip().rstrip(".")
    if not t:
        return "Fix this weakness"
    if re.match(r"(?i)^open\s", t):
        return f"Close {_lower_first(t)}"
    if re.match(r"(?i)^missing\s", t):
        return f"Add the {t[len('missing '):]}"
    return f"Fix {_lower_first(t)}"


def _path_id(campaign_id: str, provenance: str, objective: str, node_seq: List[str], taken: Set[str], source_id: str) -> str:
    raw = "\0".join([campaign_id, provenance, objective, "\x1f".join(node_seq)])
    pid = "ap_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    if pid in taken:  # same node sequence for two distinct chains: disambiguate with the source chain id
        pid = "ap_" + hashlib.sha256((raw + "\0" + source_id).encode("utf-8")).hexdigest()[:12]
    taken.add(pid)
    return pid


def _stable_path_id(campaign_id: str, provenance: str, objective: str, node_seq: List[str], source_id: str,
                    taken: Set[str]) -> str:
    """P7 fix 7 (P5-B2, flag DM_STABLE_PATH_IDS): content hash that ALWAYS includes the source chain id, so a path
    keeps its id when another path with the same node sequence disappears (remediation, retest). Same format."""
    raw = "\0".join([campaign_id, provenance, objective, "\x1f".join(node_seq), source_id])
    pid = "ap_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    n = 1
    while pid in taken:  # only if two records share every component (never seen); deterministic suffix
        pid = "ap_" + hashlib.sha256(f"{raw}\0{n}".encode("utf-8")).hexdigest()[:12]
        n += 1
    taken.add(pid)
    return pid


_PROOF_PREFIX = re.compile(r"^\s*(?:raw_response|extracted_data|response)\s*[:=-]\s*", re.I)
MIN_PROOF_EXCERPT = 8


def _uncorroborated(claims: List[Dict[str, Any]], vmap: Dict[str, Dict[str, Any]], links: List[Dict[str, Any]]) -> List[str]:
    """RT-04: the claims of one derived path that the SERVER cannot corroborate (empty list = proven).
    reuse  producer -> consumer: equal server fingerprints (produced == presented, same campaign) or an observed
           R1 link on the pair (an R2 link is an inference: never corroboration); a declared ref or
           produced_by_finding_id alone is never enough.
    reach  finding -> node: an observed R3 link to that node, or a proof_ref excerpt (>= 8 chars) present verbatim
           in the finding's stored raw_response / extracted_data."""
    from api.artifact_fingerprints import fingerprints_of
    from api.attack_paths_observed import output_text
    pairs = {(p, l["consumer"]) for l in links if l.get("kind") == "R1" for p in l.get("producers") or []}
    reach = {(l["consumer"], l.get("to_node_id")) for l in links if l.get("kind") == "R3"}
    out: List[str] = []
    for c in claims:
        if c.get("kind") == "reuse":
            cons = vmap.get(c["consumer"], {})
            presented = {x.get("fp") for x in fingerprints_of(cons).get("presented") or []}
            ok = False
            for prod_id in c.get("producers") or []:
                prod = vmap.get(prod_id, {})
                same_campaign = str(prod.get("campaign_id") or "") == str(cons.get("campaign_id") or "")
                produced = {x.get("fp") for x in fingerprints_of(prod).get("produced") or []}
                if (prod_id, c["consumer"]) in pairs or (same_campaign and produced & presented):
                    ok = True
                    break
            if not ok:
                out.append(f"reuse {','.join(c.get('producers') or [])} -> {c['consumer']} is declared only")
        elif c.get("kind") == "reach":
            if (c["finding"], c["node_id"]) in reach:
                continue
            excerpt = _PROOF_PREFIX.sub("", str(c.get("proof_ref") or "")).strip()
            text = output_text(vmap.get(c["finding"], {}).get("evidence"))
            # the stored proof_ref went through redact_text (secret-looking runs -> [redacted]): compare like with like
            if len(excerpt.replace("[redacted]", "").strip()) >= MIN_PROOF_EXCERPT and (excerpt in text or excerpt in redact_text(text, len(text) + 1)[0]):
                continue
            out.append(f"reach {c['finding']} -> {c['node_id']} is declared only")
    return out


def _hitting_sets(steps: List[Dict[str, Any]], cap: int = 10) -> List[List[str]]:
    """Minimal finding sets whose fix blocks one step (one finding per alternative of that step)."""
    sets: Set[Tuple[str, ...]] = set()
    for st in steps:
        alts = st.get("satisfied_by") or []
        if not alts or any(not a for a in alts):
            continue  # unknown dependency or reachable without any finding: cannot be blocked
        for combo in itertools.islice(itertools.product(*[sorted(set(a)) for a in alts]), 256):
            sets.add(tuple(sorted(set(combo))))
    # RT-07 (P8): same result as « every set without a strict subset, sorted, first `cap` », without the O(n^2) scan.
    # A strict subset is shorter, and any non-minimal set contains a MINIMAL set met earlier in (len, ids) order, so
    # each candidate is only checked against the minimal sets already kept, and the scan stops at `cap`.
    minimal: List[Tuple[Tuple[str, ...], frozenset]] = []
    for s in sorted(sets, key=lambda s: (len(s), s)):
        fs = frozenset(s)
        if any(m <= fs for _, m in minimal):
            continue
        minimal.append((s, fs))
        if len(minimal) >= cap:
            break
    return [list(s) for s, _ in minimal]


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------

def _analyse(campaign: Dict[str, Any], nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]],
             vulns: List[Dict[str, Any]], retest_verdicts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    campaign = campaign or {}
    cid = str(campaign.get("id") or "")
    nodes = [n for n in (nodes or []) if isinstance(n, dict) and n.get("id")]
    vulns = [v for v in (vulns or []) if isinstance(v, dict) and v.get("id")]
    # P4: a quarantined finding (strict privacy, not reviewed by an operator) is
    # excluded like a false positive: it never drives a path or a Fix first item.
    vulns = [dict(v, status="quarantined") if v.get("quarantined") and not v.get("quarantine_reviewed_by") else v
             for v in vulns]
    node_map = {n["id"]: n for n in nodes}
    labels = _node_labels(nodes)
    vmap = {str(v["id"]): v for v in vulns}
    live = [v for v in vulns if _status(v) not in LIVE_EXCLUDED]
    excluded = {str(v["id"]) for v in vulns} - {str(v["id"]) for v in live}
    attached: Dict[str, str] = {}
    for n in nodes:
        for vid in n.get("vulnerability_ids") or []:
            attached.setdefault(vid, n["id"])
    issues: List[Dict[str, Any]] = []

    # declared + derived (structured server data)
    try:
        server = derive_scenarios(campaign, nodes, vulns)
    except Exception as exc:  # a derivation error never breaks the page
        server = {"scenarios": [], "remediation_groups": [], "scenario_issues": [{"kind": "derivation-error", "message": type(exc).__name__}]}
    issues += [dict(i) for i in server.get("scenario_issues") or []]
    for it in (campaign.get("attack_chains") or {}).get("issues") or []:
        issues.append({"kind": "chain-rejected", **({"chain_id": it["chain_id"]} if it.get("chain_id") else {}), "message": _red(it.get("message"), 300)})

    records: List[Dict[str, Any]] = []
    for s in server.get("scenarios") or []:
        prov = "declared" if s.get("source") == "attack_chains_block" else "derived"
        if prov == "declared" and not campaign.get("demo") and not feature_flags.enabled("DM_FINALIZE_CHAINS_AS_PATHS"):
            # architecture D: the end-of-campaign narrative (ATTACK_CHAINS block) is report text only;
            # paths are assembled from the per-finding declarations (enabled_by). The labelled DEMO keeps its chains;
            # DM_FINALIZE_CHAINS_AS_PATHS=1 restores the paths-v2 behaviour (rollback).
            continue
        steps = [{"node_id": st["node_id"], "satisfied_by": [list(a) for a in st["satisfied_by"]], "rationale": st.get("rationale") or ""} for st in s["steps"]]
        # a chain DECLARED at finalisation (ATTACK_CHAINS block) links its steps by the agent's word,
        # exactly like enabled_by — never proven, whatever its steps' status. When every step is exploited / confirmed
        # it gets the stronger label (DECLARED_CHAIN_LABEL); proven stays server-verified only (observed R1-R3 / verified D, derived
        # corroborated). The labelled synthetic DEMO keeps its documented paths.
        every_step_live = all(
            any(a and all(_status(vmap.get(x, {})) in ("exploited", "confirmed") for x in a) for a in st["satisfied_by"]) for st in steps)
        # a one-step declared « chain » declares no transition (no link, no reach to another node): it keeps its former
        # status; any chain of 2+ steps declares transitions the server did not verify
        linked = len(steps) >= 2
        hypothesis = prov == "declared" and (not every_step_live or (
            linked and not campaign.get("demo") and not feature_flags.enabled("DM_LEGACY_DERIVED_PROOF")))
        consumer = s["id"].split(":", 1)[1] if prov == "derived" else None
        records.append({
            "source_id": s["id"], "provenance": prov, "steps": steps,
            "entry_node_id": steps[0]["node_id"], "objective_node_id": steps[-1]["node_id"],
            "criticality": s.get("criticality") if s.get("criticality") in _SEV_ORDER else "info",
            "criticality_source": "agent" if prov == "declared" else "default",
            "chain_title": s.get("title") if prov == "declared" else None, "consumer": consumer,
            "hypothesis": hypothesis,
            **({"level": "declared", "declared_steps_live": every_step_live} if prov == "declared" and hypothesis else {}),
            "claims": (server.get("claims") or {}).get(s["id"], []) if prov == "derived" else [],
        })

    # observed (evidence of older campaigns), behind the analysis volume cap
    chars = 0
    for v in live:
        ev = v.get("evidence")
        if isinstance(ev, dict):
            chars += sum(len(x) if isinstance(x, str) else len(repr(x)) for x in ev.values() if x is not None)
        if chars > ANALYSIS_LIMITS["max_evidence_chars"]:
            break
    observed: Optional[Dict[str, Any]] = None
    if len(live) > ANALYSIS_LIMITS["max_findings"] or chars > ANALYSIS_LIMITS["max_evidence_chars"]:
        issues.append({"kind": "too-large", "message": f"{len(live)} findings / {chars} evidence characters exceed the derivation limit; observed paths not computed."})
    else:
        observed = derive_observed_input(nodes, vulns, cid or None)
        issues += observed["issues"]
    server_records = [r for r in records]
    if observed:
        server_sets = [(r["objective_node_id"], {x for st in r["steps"] for a in st["satisfied_by"] for x in a}) for r in server_records]
        superseded = []
        for o in observed["input"]["scenarios"]:
            ids = {x for st in o["steps"] for a in st["satisfied_by"] for x in a}
            if any(obj == o["objective_node_id"] and ids <= sids for obj, sids in server_sets):
                superseded.append(o["id"])
                continue
            level = path_level(o["steps"])
            declared_step = level in _DECLARED_LEVELS
            inferred_step = level == INFERRED_LEVEL      # R2 (historical inference): a hypothesis of its own provenance
            records.append({
                "source_id": o["id"],
                "provenance": "inferred" if inferred_step else AGENT_DECLARED if declared_step else "observed",
                "steps": [{"node_id": st["node_id"], "satisfied_by": [list(a) for a in st["satisfied_by"]], "rationale": st.get("rationale") or "", "impact": st.get("impact")} for st in o["steps"]],
                "entry_node_id": o["entry_node_id"], "objective_node_id": o["objective_node_id"],
                "criticality": o["criticality"], "criticality_source": "default", "chain_title": None,
                "consumer": o.get("consumer"), "hypothesis": declared_step or inferred_step,
                # a path's level is its WEAKEST step (one unverified declared step = declared by the agent)
                "level": level, "assembly": o.get("assembly"),
            })
        if superseded:
            issues.append({"kind": "superseded-observed", "message": f"{len(superseded)} observed chain(s) are already described by the server chain data and are listed once."})

    # RT-04 (P8): a derived path rests on agent CLAIMS (prerequisites / produced_by_finding_id / reached_assets).
    # It counts as PROVEN only when every claim is corroborated by the server (credential fingerprints computed at
    # push time, an observed R1/R3 link on the same pair, or a reach proof_ref found verbatim in the stored
    # response); otherwise it stays listed as a hypothesis (never ranked, never in proven counts).
    # The labelled DEMO campaign (api/demo.py, `demo: true`, never mixed with real results by the engine) is
    # synthetic by construction and keeps its documented paths.
    legacy_claims = feature_flags.enabled("DM_LEGACY_DERIVED_PROOF") or bool(campaign.get("demo"))
    obs_links = (observed or {}).get("links") or []
    for r in records:
        if r["provenance"] != "derived":
            continue
        unverified = [] if legacy_claims else _uncorroborated(r["claims"], vmap, obs_links)
        # « checked »: the claims were really matched against the recorded evidence (False under the legacy flag or for
        # the labelled demo, where nothing is checked): exec_core counts a derived path evidence-backed only when checked
        r["corroboration"] = {"status": "claimed" if unverified else "corroborated", "unverified": unverified,
                              "checked": not legacy_claims}
        if unverified:
            r["hypothesis"] = True

    # inferred (hypotheses deduced from the real topology + confirmed findings; never ranked, never "proven")
    try:
        inferred = derive_inferred(nodes, live, attached, records)
    except Exception as exc:  # an inference error never breaks the page
        inferred = {"records": [], "issues": [{"kind": "inference-error", "message": type(exc).__name__}]}
    records += inferred["records"]
    issues += inferred["issues"]

    # path ids, titles
    taken: Set[str] = set()
    stable_taken: Set[str] = set()
    stable = feature_flags.enabled("DM_STABLE_PATH_IDS")
    paths_may_have_vanished = bool(excluded) or any(
        i.get("kind") in ("chain-already-interrupted", "chain-node-missing") for i in issues)
    records.sort(key=lambda r: (_PROV_ORDER[r["provenance"]], r["source_id"]))
    for r in records:
        seq = [st["node_id"] for st in r["steps"]]
        legacy = _path_id(cid, r["provenance"], r["objective_node_id"], seq, taken, r["source_id"])
        if stable:  # P7 fix 7: stable id; the legacy id is kept as an alias for one version
            # P8 RT-06: a legacy BASE id (no source in its hash) is handed to the next path of the same node sequence
            # when its first holder disappears; once any path may have disappeared (a finding excluded, a declared
            # chain dropped) such an alias is ambiguous and is not resolved (404 rather than another path).
            base = "ap_" + hashlib.sha256("\0".join([cid, r["provenance"], r["objective_node_id"], "\x1f".join(seq)]).encode("utf-8")).hexdigest()[:12]
            r["legacy_ambiguous"] = legacy == base and paths_may_have_vanished
            r["id"] = _stable_path_id(cid, r["provenance"], r["objective_node_id"], seq, r["source_id"], stable_taken)
            r["legacy_id"] = legacy
        else:
            r["id"] = legacy
        obj_label = _label(labels, r["objective_node_id"])
        if r.get("inference"):
            t = r["inferred_title"]
            r["title"] = (f"{t} → {obj_label}" if r["steps"][-1].get("kind") == "objective" else t) + " (inferred)"
        elif r["chain_title"]:
            r["title"] = re.sub(r"\s*-+>\s*", " → ", _red(r["chain_title"], 200))
        elif r["consumer"] and r["consumer"] in vmap:
            ct = _red(vmap[r["consumer"]].get("title") or "Finding", 160)
            r["title"] = ct if attached.get(r["consumer"]) == r["objective_node_id"] else f"{ct} → {obj_label}"
        else:
            r["title"] = f"Path to {obj_label}"
        ids = sorted({x for st in r["steps"] for a in st["satisfied_by"] for x in a})
        r["finding_ids"] = ids
        cert = 0
        for st in r["steps"]:
            alt_c = [max(_CERTAINTY.get(_status(vmap.get(x, {})), 2) for x in a) for a in st["satisfied_by"] if a]
            cert = max(cert, min(alt_c) if alt_c else 2)
        # an inferred chain is never confirmed as a chain: its findings' own proof is in inference.findings_certainty
        # (an R2-inferred chain likewise: its findings may be exploited, the chain is an inference)
        r["certainty"] = "unconfirmed" if r.get("inference") or r["provenance"] == "inferred" else _CERTAINTY_NAMES[cert]
        status = "open"
        if retest_verdicts:
            fixed = {f for f, verdict in retest_verdicts.items() if str(verdict).lower() == "fixed"}
            if fixed and is_scenario_interrupted({"steps": r["steps"]}, fixed):
                status = "interrupted_by_retest"
        r["status"] = status

    # engine candidates (all live findings, server attachment + ancestors)
    candidates = [{
        "id": str(v["id"]), "title": v.get("title") or str(v["id"]), "severity": severity_of(v.get("severity")),
        "cvss_score": _cvss(v), "node_id": attached.get(str(v["id"])),
        "node_ancestors": ancestors_of(attached.get(str(v["id"])), node_map),
        "category": v.get("category"),   # audit P1: lets the ranking prefer an actionable weakness over a consequence
    } for v in live]
    known = {c["id"] for c in candidates}
    server_groups = []
    for g in server.get("remediation_groups") or []:
        ids = sorted(x for x in g.get("finding_ids") or [] if x in known and x not in excluded)
        if len(ids) >= 2:
            server_groups.append({"id": g["id"], "finding_ids": ids, "reason": g.get("reason") or "same weakness"})
    in_server = {x for g in server_groups for x in g["finding_ids"]}
    groups = server_groups + [g for g in group_duplicate_findings(live) if not any(x in in_server for x in g["finding_ids"])]

    return {"campaign_id": cid, "records": records, "labels": labels, "vmap": vmap, "live": live, "attached": attached,
            "issues": issues, "candidates": candidates, "groups": groups, "node_map": node_map,
            "observed_links": obs_links}


def _ranking(a: Dict[str, Any]) -> Dict[str, Any]:
    records = a["records"]
    rankable = [r for r in records if not r["hypothesis"] and r["status"] == "open"]
    server = [r for r in rankable if r["provenance"] in ("declared", "derived")]
    source = server or [r for r in rankable if r["provenance"] == "observed"]
    kind = "server" if server else "observed"
    provs = sorted({r["provenance"] for r in source}, key=lambda p: _PROV_ORDER[p])
    label = "+".join(provs) if provs else None
    empty = {"allowed": False, "provenance": label, "note": None, "fixes": [], "pivots": [], "off_path": [], "gate_reason": None,
             "multi_fix_path_ids": [], "merged_paths": []}
    if not source:
        return {**empty, "note": "No proven attack path: nothing to rank.", "gate_reason": "status-not-ok"}
    # P7 fix 8: the cap is raisable by DM_MAX_RANKED_PATHS (default 200, engine limit 10 000; 05b §4: ~0.2 s at 1 000)
    if len(source) > feature_flags.int_value("DM_MAX_RANKED_PATHS", MAX_RANKED_PATHS, 1, 10000):
        return {**empty, "note": "too-large", "gate_reason": "too-large"}

    by_source = {r["source_id"]: r for r in source}
    scenarios = [{"id": r["source_id"], "entry_node_id": r["entry_node_id"], "objective_node_id": r["objective_node_id"],
                  "criticality": r["criticality"], "provenance": kind, "steps": r["steps"]} for r in source]
    combos = feature_flags.enabled("DM_RANKING_COMBOS")  # P7 fix 8 (graphbench C1), OFF = unchanged ranking
    result = prioritize_corrections(scenarios, a["candidates"], a["groups"], completion=combos)
    gate = ranking_gate(result)
    group_by_id = {g["id"]: g for g in a["groups"]}
    pid = lambda sid: by_source[sid]["id"]  # noqa: E731
    total = len(result.get("eligible_scenario_ids") or [])

    def label_of(fix_id: str, ids: List[str]) -> str:
        canon = [x for x in ids if not a["vmap"].get(x, {}).get("duplicate_of")] or ids
        title = a["vmap"].get(sorted(canon)[0], {}).get("title") or ""
        return fix_label(title)

    fixes = []
    for c in result.get("ranking") or []:
        objs_closed = [o for o in c["objectives_closed"] if not is_pseudo_node(o)]
        fixes.append({
            "rank": c["rank"], "fix_id": c["finding_id"], "label": label_of(c["finding_id"], c["finding_ids"]),
            "kind": "group" if c["finding_id"] in group_by_id else "finding",
            "finding_ids": c["finding_ids"],
            # P8 RT-08: a combination row interrupts what the COMBINATION interrupts (a unit alone interrupts nothing
            # by construction); interrupts_basis says which one is shown
            "interrupts": sorted(pid(s) for s in (c["combination"]["interrupts"] if c.get("combination") else c["standalone_interrupted"])),
            "interrupts_count": len(c["combination"]["interrupts"] if c.get("combination") else c["standalone_interrupted"]),
            "of_total": total,
            **({"interrupts_basis": "combination"} if c.get("combination") else {}),
            "marginal_interrupts": sorted(pid(s) for s in c["marginal_interrupted"]),
            "objectives_closed": objs_closed, "objectives_still_reachable": c["objectives_still_reachable"],
            "equivalent_alternatives": c["equivalent_alternatives"],
            "tie_break": c["tie_break"] and _tie_break_name(c["tie_break"]),
            "explanation": c["explanation"],
            **({"source": c["source"]} if c.get("source") else {}),
            **({"combination": {**c["combination"], "interrupts": sorted(pid(x) for x in c["combination"]["interrupts"])}}
               if c.get("combination") else {}),
        })
    off_path = [{"finding_id": o["id"], "reason": o["reason"], "reason_label": OFF_PATH_REASON_LABELS[o["reason"]]} for o in result.get("off_path") or []]
    common = {"provenance": label, "gate_reason": gate["reason"], "off_path": off_path,
              "multi_fix_path_ids": sorted(pid(s) for s in result.get("multi_fix_scenario_ids") or []),
              # RELEASE GATE: routes with no admissible (certified) correction, and findings whose actionability
              # is indeterminate (leads to investigate, never certified coverage) — surfaced so the UI/report can show
              # « no established actionable remediation » instead of recommending a consequence.
              "paths_without_established_fix": sorted(pid(s) for s in result.get("paths_without_established_fix") or []),
              "unverified_remediations": [{"finding_id": u["id"], "reason": u["reason"],
                                           "reason_label": OFF_PATH_REASON_LABELS.get(u["reason"], u["reason"])}
                                          for u in result.get("unverified_remediations") or []],
              "merged_paths": [{"path_id": pid(m["id"]), "into": pid(m["into"])} for m in result.get("merged_scenarios") or []],
              "non_admissible_finding_ids": sorted(result.get("non_admissible_finding_ids") or []),
              "engine_status": result.get("status"),
              **({"completion": result["completion"]} if result.get("completion") else {})}
    if gate["meaningful"]:
        return {**common, "allowed": True, "note": None, "fixes": fixes, "pivots": []}
    pivots = sorted(({k: v for k, v in f.items() if k not in ("rank", "tie_break", "explanation", "marginal_interrupts", "equivalent_alternatives")} for f in fixes),
                    key=lambda f: f["fix_id"])
    return {**common, "allowed": False, "note": f"Proven pivots: {gate['reason']}", "fixes": [], "pivots": pivots}


def _tie_break_name(rule: str) -> str:
    return {
        "criticality weight of newly interrupted scenarios": "criticality",
        "highest scenario criticality": "max-criticality",
        "standalone coverage": "standalone-coverage",
        "CVSS score": "cvss",
        "finding id (stable order)": "id",
    }.get(rule, rule)


_ARTEFACT_LABELS = {"jwt": "JWT", "basic-auth": "Basic credentials", "vendor-key": "API key",
                    "private-key": "Private key", "hex-secret": "Secret", "labeled-secret": "Secret",
                    "credential": "Credential"}
_STATUS_WORD = {"exploited": "exploited", "confirmed": "confirmed"}
# the two columns of an observed link; never stronger than what the server saw
USAGE_LABELS = {"observed": "Usage observed by the server", "evidence": "Shown in the finding evidence (server rule)"}
R2_USAGE_LABEL = "Inferred by a historical server rule (open registration matched by endpoint) · not proven"
NECESSITY_LABELS = {"demonstrated": "Necessity demonstrated (refused without it, accepted with it)",
                    "not_demonstrated": "Necessity not demonstrated",
                    "intrinsic": "Intrinsic reach", "not_assessed": "Necessity not assessed (evidence rule)"}


def _observed_links_doc(a: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Additive (schema 1.4): every observed link with its two columns. Ids and enums only; the proof is redacted."""
    out = []
    for l in a.get("observed_links") or []:
        out.append({
            "kind": l["kind"], "producers": list(l.get("producers") or []), "consumer": l["consumer"],
            "alternative_producers": list(l.get("alternative_producers") or []),
            "unattributed_sources": int(l.get("unattributed_sources") or 0),
            "from_node_id": l.get("from_node_id"), "to_node_id": l.get("to_node_id"),
            "capability": l.get("capability"),
            "usage": l.get("usage", "evidence"),
            "usage_label": R2_USAGE_LABEL if l.get("level") == INFERRED_LEVEL else USAGE_LABELS.get(l.get("usage", "evidence")),
            "necessity": l.get("necessity", "not_assessed"),
            "necessity_label": NECESSITY_LABELS.get(l.get("necessity", "not_assessed")),
            "necessity_reason": l.get("necessity_reason"),
            **({"authentication_required": bool(l["authentication_required"])} if "authentication_required" in l else {}),
            "necessity_note": _red(l.get("necessity_note") or "", 300) or None,
            "ranked": bool(l.get("ranked", True)), "auxiliary": bool(l.get("auxiliary")),
            "level": l.get("level", "observed"),
            **({"flags": list(l.get("flags") or []), "warnings": list(l.get("warnings") or []),
                "verification": l.get("verification"), "attack_context": l.get("attack_context")} if l.get("kind") == "D" else {}),
            **({"provenance": l["provenance"], "inference_note": l.get("inference_note")} if l.get("provenance") else {}),
            **({"consumer_attribution": l["consumer_attribution"]} if l.get("consumer_attribution") else {}),
            **({"producer_attribution": l["producer_attribution"]} if l.get("producer_attribution") else {}),
            "proof": _why(l.get("proof") or "", a["vmap"]),
        })
    return out


def step_impact(imp: Optional[Dict[str, Any]], node_label: str) -> Optional[Dict[str, Any]]:
    """P2 v2: short impact phrase, closed set, never stronger than the rule's proof (D-03, D-11).
    Hypotheses (declared) and derived steps without a rule get None."""
    if not isinstance(imp, dict):
        return None
    rule = imp.get("rule")
    cap = str(imp.get("capability") or "")
    if rule == "R1":
        kinds = cap[len("reused "):].split("/") if cap.startswith("reused ") else []
        creds = sorted({_ARTEFACT_LABELS[k] for k in kinds if k in _ARTEFACT_LABELS})
        if creds:
            label = "Reused " + " + ".join(creds) + " from an earlier step"
        elif kinds == ["internal-endpoint"]:
            label = "Internal URL disclosed, then used"
        else:
            return None
    elif rule == "R2":   # historical inference (endpoint match): never worded or sourced as an observation
        return {"label": _red("Account self-created (open registration) · inferred, not proven", 90), "rule": rule,
                "source": "inferred-rule", "level": INFERRED_LEVEL}
    elif rule == "D":  # enabled_by; its level is decided by the server's execution records (api/edge_verifier)
        from api.edge_verifier import D_STATE_LABELS
        level = imp.get("level") if imp.get("level") in (OBSERVED_FLOW, CAUSAL) else DECLARED_BY_AGENT
        out = {"label": ("Result of an earlier finding used (declared by the agent, not verified by the server)"
                         if level == DECLARED_BY_AGENT else "Result of an earlier finding used (flow recorded by the server)"),
               "rule": rule, "source": "declared-by-agent" if level == DECLARED_BY_AGENT else "server-verified",
               "level": level, "level_label": D_STATE_LABELS[level]}
        if imp.get("reason"):
            out["reason"] = imp["reason"]
        return out
    elif rule == "R3":
        if cap == "command execution on the host":
            label = f"Command execution on {node_label} (command output in response)"
        elif cap == "system account file read on the host":
            label = f"System account file read on {node_label}"
        elif cap.endswith(" database read"):
            label = f"{cap[:-len(' database read')].capitalize()} database rows read on {node_label}"
        else:
            return None
    elif rule in ("entry", "sink"):
        cls = category_label(imp.get("category")) or "Finding"
        status = _STATUS_WORD.get(str(imp.get("status")), "unconfirmed")
        label = ("Entry point: " if rule == "entry" else "Objective: ") + f"{cls}, {status}"
    else:
        return None
    return {"label": _red(label, 90), "rule": rule, "source": "observed-rule"}


def _why(text: str, vmap: Dict[str, Dict[str, Any]]) -> str:
    """Rationale shown to a human: finding ids replaced by their titles, secrets redacted."""
    out = str(text or "")
    for fid in sorted(vmap, key=len, reverse=True):
        if fid and fid in out:
            title = str(vmap[fid].get("title") or "a finding")[:60]
            out = re.sub(r"(?<![\w-])" + re.escape(fid) + r"(?![\w-])", f"“{title}”", out)
    return _red(out, 500)


def _steps_detail(r: Dict[str, Any], a: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    vmap, labels = a["vmap"], a["labels"]
    steps = []
    for n, st in enumerate(r["steps"], 1):
        ids = sorted({x for alt in st["satisfied_by"] for x in alt})
        node_label = _label(labels, st["node_id"])
        first_alt = next((alt for alt in st["satisfied_by"] if alt), [])
        titles = " + ".join(_red(vmap.get(x, {}).get("title") or "Unknown finding", 120) for x in first_alt) or "Reachable without any finding"
        others = len(st["satisfied_by"]) - 1
        plain = f"{titles} ({node_label})" + (f", or {others} other way{'s' if others > 1 else ''}" if others > 0 else "") + "."
        produces, requires, seen_at = [], [], []
        for x in ids:
            v = vmap.get(x, {})
            for p in v.get("produced_artifacts") or []:
                if isinstance(p, dict) and p.get("ref"):
                    e = {"artifact_ref": p["ref"], "type": p.get("type")}
                    if e not in produces:
                        produces.append(e)
            for p in v.get("prerequisites") or []:
                if isinstance(p, dict):
                    e = {k: p[k] for k in ("artifact_ref", "kind") if p.get(k)}
                    if e and e not in requires:
                        requires.append(e)
            if v.get("discovered_at"):
                seen_at.append(str(v["discovered_at"]))
        steps.append({
            "n": n, "node_id": st["node_id"], "node_label": node_label, "plain": plain,
            "satisfied_by": st["satisfied_by"],
            "findings": [{
                "id": x, "title": _red(vmap.get(x, {}).get("title") or "Unknown finding", 200),
                "severity": severity_of(vmap.get(x, {}).get("severity")), "status": _status(vmap.get(x, {})),
                "cvss_score": _cvss(vmap.get(x, {})), "evidence_meta": _evidence_meta(vmap.get(x, {})),
                "category_label": category_label(vmap.get(x, {}).get("category")),
            } for x in ids],
            "produces": produces, "requires": requires, "why": _why(st.get("rationale") or "", vmap),
            "impact": step_impact(st.get("impact"), node_label),
            "first_seen_at": min(seen_at) if seen_at else None,
            **_edge_insight(next(iter(first_alt), None), vmap),
        })
        if r.get("inference"):
            steps[-1].update(_inferred_step_extra(st, first_alt, vmap))
    inferred = bool(r.get("inference")) or r.get("provenance") == "inferred"   # R2-inferred paths too
    edges = []
    for prev, cur in zip(r["steps"], r["steps"][1:]):
        if prev["node_id"] != cur["node_id"]:
            fid = next((x for alt in cur["satisfied_by"] for x in alt), None)
            edge = {"from": prev["node_id"], "to": cur["node_id"], "type": "reaches", "finding_id": fid, "observed": not inferred,
                    **_edge_insight(fid, vmap)}
            if inferred:  # a deduced link is never shown as observed or proven
                edge.update(proof="hypothesis", inferred=True, kind=cur.get("kind"))
            edges.append(edge)
    return steps, edges


def _inferred_step_extra(st: Dict[str, Any], first_alt: List[str], vmap: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Additive fields of an INFERRED step (attack_paths_inferred): its kind, rule, the ATT&CK tactics of the
    technique tagged on its lead finding, and the fix of that finding. Exposure and hop steps carry no finding:
    their proof is « none »; an objective step is a deduction: its proof is « hypothesis »."""
    out: Dict[str, Any] = {"kind": st.get("kind"), "rule": st.get("rule"), "inferred": True, "tactics": [], "fix": None,
                           "finding_id": first_alt[0] if first_alt else None}
    if st.get("kind") == "objective":
        out["proof"] = "hypothesis"
    v = vmap.get(first_alt[0]) if first_alt else None
    if v:
        try:
            from api.attack_tactics import attack_block
            out["tactics"] = [{"id": t["id"], "name": t["name"]} for t in attack_block(v).get("possible_tactics") or []]
        except Exception:  # noqa: BLE001 — the ATT&CK extract is optional for this view
            out["tactics"] = []
        out["fix"] = {"finding_id": str(v["id"]), "label": fix_label(v.get("title") or ""),
                      "remediation": _red(v.get("remediation") or "", 400) or None}
    return out


def _path_summary(r: Dict[str, Any], a: Dict[str, Any], include_steps: bool) -> Dict[str, Any]:
    labels = a["labels"]
    out = {
        "id": r["id"], "title": r["title"],
        "objective": {"node_id": r["objective_node_id"], "label": _label(labels, r["objective_node_id"]),
                      "criticality": r["criticality"], "criticality_source": r["criticality_source"]},
        "entry": {"node_id": r["entry_node_id"], "label": _label(labels, r["entry_node_id"])},
        "criticality": r["criticality"], "certainty": r["certainty"], "provenance": r["provenance"],
        "hypothesis": r["hypothesis"], "steps_count": len(r["steps"]), "finding_ids": r["finding_ids"],
        "breaks_if_fixed": _hitting_sets(r["steps"]), "status": r["status"],
        "node_ids": _node_seq(r),
    }
    if r.get("level"):  # additive: weakest step of a path built from links (observed / declared by the agent)
        from api.declared_links import LEVEL_LABELS
        out["level"] = r["level"]
        out["level_label"] = LEVEL_LABELS[r["level"]]
    if r["provenance"] == "declared" and r["hypothesis"]:
        out["level_label"] = DECLARED_CHAIN_LABEL if r.get("declared_steps_live") else AGENT_DECLARED_LABEL
        out["note"] = (f"{out['level_label']}: the chain was declared by the agent at finalisation; the server did not "
                       f"observe the links between its steps. A hypothesis, not a proof.")
    if r["provenance"] == "inferred" and not r.get("inference"):   # R2: the historical inference, said as such
        out["note"] = R2_PATH_NOTE
    if r["provenance"] == AGENT_DECLARED:
        out["note"] = (f"{AGENT_DECLARED_LABEL}: at least one step rests on a link the agent declared (enabled_by) that "
                       f"the server could not observe. A hypothesis, not a proof.")
    if r.get("assembly"):  # 40-paths-v2, additive: why the chain set may be incomplete (bounded DFS stop reason)
        out["assembly"] = r["assembly"]
    if r.get("corroboration"):  # RT-04, additive: claimed (hypothesis) vs corroborated by the server
        out["corroboration"] = r["corroboration"]
    if r.get("inference"):  # additive: why this path is only a hypothesis (attack_paths_inferred)
        out["note"] = r["inference"]["note"]
        out["inference"] = {k: v for k, v in r["inference"].items() if k != "note"}
    if include_steps:
        out["steps"], out["edges"] = _steps_detail(r, a)
    return out


def _filter(records: List[Dict[str, Any]], provenance: str) -> List[Dict[str, Any]]:
    if provenance in (None, "", "all"):
        return records
    return [r for r in records if r["provenance"] == provenance]


def _sorted_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(records, key=lambda r: (r["hypothesis"], _SEV_ORDER.get(r["criticality"], 9), _PROV_ORDER[r["provenance"]], r["id"]))


# ---------------------------------------------------------------------------
# v1.1 insights (ATTACK-PATH-BENCHMARK.md): every value is derived from the campaign's own records — no invented proof
# ---------------------------------------------------------------------------

_PROOF = {"exploited": "exploited", "confirmed": "confirmed", "unconfirmed": "hypothesis"}


def _node_seq(r: Dict[str, Any]) -> List[str]:
    seq = [r["entry_node_id"]] + [st["node_id"] for st in r["steps"]]
    return [x for i, x in enumerate(seq) if x and (i == 0 or seq[i - 1] != x)]


def _technique(v: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    tid = str(v.get("mitre_attack_id") or "").strip()
    if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
        return None
    return {"id": tid, "name": _red(v.get("mitre_attack_name") or "", 80) or None}


def _edge_insight(fid: Optional[str], vmap: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    v = vmap.get(fid or "", {})
    return {
        "technique": _technique(v) if v else None,
        "proof": _PROOF.get(_status(v), "hypothesis") if v else "none",
        "evidence": {"finding_id": fid, **_evidence_meta(v)} if v else None,
    }


def _insights(a: Dict[str, Any], records: List[Dict[str, Any]], non_admissible: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Critical assets, choke points, blast radius per entry and toxic combinations, from the open proven paths only.

    ``non_admissible`` is the engine's authoritative set of on-path findings that are NOT certified corrections (a
    terminal consequence or an indeterminate lead). They are excluded from the choke-point FIX units so a realised
    breach is never presented as a « fix » (reviewer calcul F2)."""
    non_admissible = non_admissible or set()
    vmap, labels, node_map = a["vmap"], a["labels"], a["node_map"]
    live = [r for r in records if r["status"] == "open" and not r["hypothesis"]]
    total = len(live)

    # critical assets: objectives of proven open paths (criticality of the most critical path reaching them)
    assets: Dict[str, Dict[str, Any]] = {}
    for r in live:
        o = r["objective_node_id"]
        if is_pseudo_node(o):
            continue
        cur = assets.setdefault(o, {"node_id": o, "label": _label(labels, o), "node_type": str((node_map.get(o) or {}).get("node_type") or ""),
                                    "criticality": "info", "paths": 0, "path_ids": []})
        cur["paths"] += 1
        cur["path_ids"].append(r["id"])
        if _SEV_ORDER.get(r["criticality"], 9) < _SEV_ORDER.get(cur["criticality"], 9):
            cur["criticality"] = r["criticality"]
    critical_assets = sorted(({**x, "critical_asset": x["criticality"] in ("critical", "high"), "path_ids": sorted(x["path_ids"])} for x in assets.values()),
                             key=lambda x: (_SEV_ORDER.get(x["criticality"], 9), -x["paths"], x["node_id"]))

    # choke points — findings: paths eliminated if that finding alone is fixed (same engine as the simulation)
    chokes: List[Dict[str, Any]] = []
    # certified-fix candidates only: a terminal consequence / indeterminate lead is never presented as a choke-point
    # « fix » (reviewer calcul F2). A group keeps only its admissible members, mirroring the engine's mixed-group split.
    on_paths = {x for r in live for x in r["finding_ids"]} - non_admissible
    units: List[Tuple[str, List[str], str]] = []          # (fix id, finding ids fixed together, kind)
    grouped: Set[str] = set()
    for g in a["groups"]:
        ids = [x for x in g["finding_ids"] if x in vmap and x not in non_admissible]
        if any(x in on_paths for x in ids):
            units.append((g["id"], sorted(ids), "group"))
            grouped.update(ids)
    units += [(fid, [fid], "finding") for fid in sorted(on_paths - grouped)]
    for fix_id, ids, kind in units:
        cut = [r["id"] for r in live if first_blocked_step({"steps": r["steps"]}, set(ids)) is not None]
        if cut:
            lead = sorted(ids, key=lambda x: (_SEV_ORDER.get(severity_of(vmap.get(x, {}).get("severity")), 9), x))[0]
            v = vmap.get(lead, {})
            chokes.append({"kind": kind, "fix_id": fix_id, "finding_id": lead, "finding_ids": ids, "title": _red(v.get("title") or "Finding", 160),
                           "label": fix_label(v.get("title") or ""), "node_id": a["attached"].get(lead),
                           "severity": severity_of(v.get("severity")), "status": _status(v),
                           "paths_eliminated": len(cut), "of_total": total, "path_ids": sorted(cut)})
    chokes.sort(key=lambda c: (-c["paths_eliminated"], _SEV_ORDER.get(c["severity"], 9), c["finding_id"]))
    # choke points — assets: nodes crossed by several proven paths (entry excluded: it is where every path starts)
    through: Dict[str, List[str]] = {}
    for r in live:
        for nid in set(_node_seq(r)[1:]):
            through.setdefault(nid, []).append(r["id"])
    node_chokes = sorted(({"kind": "node", "node_id": n, "label": _label(labels, n), "paths_through": len(ids), "of_total": total, "path_ids": sorted(ids)}
                          for n, ids in through.items() if len(ids) >= 2 and not is_pseudo_node(n)),
                         key=lambda c: (-c["paths_through"], c["node_id"]))

    # blast radius per entry: what an attacker who holds this entry can reach, by proven paths
    blast: Dict[str, Dict[str, Any]] = {}
    for r in live:
        e = r["entry_node_id"]
        b = blast.setdefault(e, {"entry_node_id": e, "label": _label(labels, e), "paths": 0, "objectives": set(), "assets": set(), "critical_objectives": set()})
        b["paths"] += 1
        b["assets"].update(_node_seq(r)[1:])
        if not is_pseudo_node(r["objective_node_id"]):
            b["objectives"].add(r["objective_node_id"])
            if r["criticality"] in ("critical", "high"):
                b["critical_objectives"].add(r["objective_node_id"])
    blast_radius = sorted(({"entry_node_id": b["entry_node_id"], "label": b["label"], "paths": b["paths"], "assets_reached": len(b["assets"]),
                            "objectives": sorted(b["objectives"]), "critical_objectives": sorted(b["critical_objectives"])} for b in blast.values()),
                          key=lambda b: (-len(b["critical_objectives"]), -b["assets_reached"], b["entry_node_id"]))

    # toxic combinations: (1) findings needed TOGETHER at one step (AND-set); (2) a chain of individually minor findings
    # (each ≤ medium) whose path reaches a critical or high asset
    toxic: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for r in live:
        for st in r["steps"]:
            for alt in st["satisfied_by"]:
                if len(alt) >= 2:
                    key = tuple(sorted(alt))
                    t = toxic.setdefault(key, {"kind": "together", "finding_ids": list(key), "path_ids": set(), "path_criticality": "info"})
                    t["path_ids"].add(r["id"])
                    if _SEV_ORDER.get(r["criticality"], 9) < _SEV_ORDER.get(t["path_criticality"], 9):
                        t["path_criticality"] = r["criticality"]
        ids = r["finding_ids"]
        if len(ids) >= 2 and r["criticality"] in ("critical", "high") and all(_SEV_ORDER.get(severity_of(vmap.get(x, {}).get("severity")), 9) >= 2 for x in ids):
            key = tuple(sorted(ids))
            t = toxic.setdefault(key, {"kind": "chain", "finding_ids": list(key), "path_ids": set(), "path_criticality": r["criticality"]})
            t["path_ids"].add(r["id"])
    toxic_list = []
    for t in toxic.values():
        sev = [severity_of(vmap.get(x, {}).get("severity")) for x in t["finding_ids"]]
        toxic_list.append({**t, "path_ids": sorted(t["path_ids"]), "max_individual_severity": min(sev, key=lambda s: _SEV_ORDER.get(s, 9)),
                           "titles": [_red(vmap.get(x, {}).get("title") or "Finding", 120) for x in t["finding_ids"]]})
    toxic_list.sort(key=lambda t: (_SEV_ORDER.get(t["path_criticality"], 9), -len(t["path_ids"]), t["finding_ids"]))

    return {"paths_considered": total, "critical_assets": critical_assets, "choke_points": chokes[:12], "asset_choke_points": node_chokes[:12],
            "blast_radius": blast_radius, "toxic_combinations": toxic_list[:12]}


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def build_paths(campaign: Dict[str, Any], nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], vulns: List[Dict[str, Any]],
                *, provenance: str = "all", include_steps: bool = False, retest_verdicts: Optional[Dict[str, str]] = None,
                now: Optional[str] = None) -> Dict[str, Any]:
    """List document (§2.1). ``nodes`` must carry the server attachment (``vulnerability_ids``)."""
    if provenance not in ("all", "", None) + PROVENANCES:
        raise ValueError(f"provenance must be one of all, {', '.join(PROVENANCES)}")
    a = _analyse(campaign, nodes, edges, vulns, retest_verdicts)
    records = _sorted_records(_filter(a["records"], provenance))
    vulns_ok = [v for v in (vulns or []) if isinstance(v, dict) and v.get("id")]
    # inferred hypotheses never count as paths a finding is "on" nor as critical paths (they are listed apart)
    real = [r for r in records if r["provenance"] not in ("inferred",) + DECLARED_PROVENANCES or
            (r["provenance"] == "declared" and not r["hypothesis"])]          # (labelled demo only)
    inferred = [r for r in records if r["provenance"] == "inferred"]
    agent_declared = [r for r in records if r["provenance"] in DECLARED_PROVENANCES and r["hypothesis"]]
    on_paths = {x for r in real for x in r["finding_ids"]}
    coverage = {"findings_total": len(vulns_ok), "findings_on_paths": len(on_paths),
                "findings_without_node": sum(1 for v in vulns_ok if str(v["id"]) not in a["attached"])}
    open_real = [r for r in records if r["status"] == "open" and not r["hypothesis"]]
    _ranking_doc = _ranking(a)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": a["campaign_id"],
        "generated_at": now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "demo": bool((campaign or {}).get("demo")),
        "summary": {
            "paths_total": len(records),
            "critical_paths": sum(1 for r in real if r["criticality"] == "critical"),
            "proven_paths": sum(1 for r in records if not r["hypothesis"]),
            # round 5: paths resting on a link declared by the agent, counted apart (never proven)
            "declared_paths": len(agent_declared),
            "declared_critical_paths": sum(1 for r in agent_declared if r["criticality"] == "critical"),
            "inferred_paths": len(inferred),
            "inferred_critical_paths": sum(1 for r in inferred if r["criticality"] == "critical"),
            "findings_on_inferred_paths": len({x for r in inferred for x in r["finding_ids"]}),
            "objectives_reachable": sorted({r["objective_node_id"] for r in open_real if not is_pseudo_node(r["objective_node_id"])}),
            "provenances": sorted({r["provenance"] for r in records}, key=lambda p: _PROV_ORDER[p]),
            "coverage": coverage,
        },
        "paths": [_path_summary(r, a, include_steps) for r in records],
        "ranking": _ranking_doc,
        "issues": a["issues"],
        "note": None,
        "schema_revision": SCHEMA_REVISION,
        "insights": _insights(a, records, non_admissible=set(_ranking_doc.get("non_admissible_finding_ids") or [])),
        "observed_links": _observed_links_doc(a),
    }
    if feature_flags.enabled("DM_STABLE_PATH_IDS"):
        # P7 fix 7, additive, one version only: legacy id -> stable id (deep links, cached simulations, retest notes)
        doc["path_id_scheme"] = "stable-source-v1"
        doc["path_id_aliases"] = {r["legacy_id"]: r["id"] for r in sorted(a["records"], key=lambda x: x["id"])
                                  if r.get("legacy_id") and r["legacy_id"] != r["id"] and not r.get("legacy_ambiguous")}
    if provenance in ("all", "", None):
        # the single « Fix first » of the campaign (fix_triage.py); the ranking gate above is unchanged
        def _lbl(fix_id: str, ids: List[str]) -> str:
            canon = [x for x in ids if not a["vmap"].get(x, {}).get("duplicate_of")] or ids
            return fix_label(a["vmap"].get(sorted(canon)[0], {}).get("title") or "")
        info = {}
        for r in records:
            _, r_edges = _steps_detail(r, a)
            tech = next((e.get("technique") for e in reversed(r_edges) if e.get("technique")), None)
            info[r["id"]] = {"provenance": r["provenance"], "objective": _label(a["labels"], r["objective_node_id"]),
                             "access": tech and f"{tech['id']} {tech['name']}"}
        doc["triage"] = fix_triage.triage(a, _lbl, info, retest_verdicts)
        doc["fix_first"] = fix_triage.fix_first(doc["ranking"], doc["triage"], a["vmap"], _lbl,
                                                {g["id"]: g["finding_ids"] for g in a["groups"]})
    else:  # a filtered list would point at paths it does not contain: read the « all » document (review m-6)
        doc["triage"] = None
        doc["fix_first"] = None
    if not real:
        n = len(vulns_ok)
        doc["note"] = (f"No attack path could be proven for this campaign: it holds no chain data and the evidence of its "
                       f"{n} finding{'s' if n != 1 else ''} shows no proven link between them. This does not mean that no path exists.")
        if agent_declared:
            k = len(agent_declared)
            doc["note"] += (f" {k} path{'s' if k != 1 else ''} rest{'' if k != 1 else 's'} on links declared by the agent "
                            f"(enabled_by or the chains declared at finalisation): not verified by the server.")
        if inferred:
            k = len(inferred)
            doc["note"] += (f" {k} possible path{'s are' if k != 1 else ' is'} inferred from the infrastructure topology and the "
                            f"confirmed findings: hypotheses, not proofs (provenance \"inferred\").")
    return doc


def path_detail(campaign: Dict[str, Any], nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], vulns: List[Dict[str, Any]],
                path_id: str, *, retest_verdicts: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """Detail document (§2.2), or None when the path does not exist."""
    a = _analyse(campaign, nodes, edges, vulns, retest_verdicts)
    r = next((x for x in a["records"] if x["id"] == path_id), None)
    if r is None and feature_flags.enabled("DM_STABLE_PATH_IDS"):  # P7 fix 7: a legacy id still resolves (one version)
        r = next((x for x in a["records"] if x.get("legacy_id") == path_id and not x.get("legacy_ambiguous")), None)
    if r is None:
        return None
    return {"schema_version": SCHEMA_VERSION, "schema_revision": SCHEMA_REVISION, "campaign_id": a["campaign_id"],
            "demo": bool((campaign or {}).get("demo")), "path": _path_summary(r, a, True)}


def simulate(campaign: Dict[str, Any], nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], vulns: List[Dict[str, Any]],
             fix_finding_ids: List[str]) -> Dict[str, Any]:
    """Simulated effect of a set of fixes (§2.3). Nothing is written; never presented as a fix."""
    a = _analyse(campaign, nodes, edges, vulns)
    groups = {g["id"]: g["finding_ids"] for g in a["groups"]}
    known = set(a["vmap"])
    removed: List[str] = []
    unknown: List[str] = []
    for x in fix_finding_ids or []:
        x = str(x)
        if x in groups:
            removed += groups[x]
        elif x in known:
            removed.append(x)
        else:
            unknown.append(x)
    fixed = set(removed)
    interrupted, still_open, cut_at = [], [], {}
    for r in _sorted_records(a["records"]):
        step = first_blocked_step({"steps": r["steps"]}, fixed)
        if step is not None:
            interrupted.append(r["id"])
            cut_at[r["id"]] = step
        else:
            still_open.append(r["id"])
    by_id = {r["id"]: r for r in a["records"]}
    reachable = sorted({by_id[p]["objective_node_id"] for p in still_open
                        if not by_id[p]["hypothesis"] and not is_pseudo_node(by_id[p]["objective_node_id"])})
    return {
        "schema_version": SCHEMA_VERSION, "campaign_id": a["campaign_id"], "demo": bool((campaign or {}).get("demo")),
        "simulation": True, "label": SIMULATION_LABEL,
        "removed": sorted(set(removed)), "unknown": sorted(set(unknown)),
        "interrupted": interrupted, "still_open": still_open,
        "objectives_reachable": reachable, "cut_at": cut_at,
        "schema_revision": SCHEMA_REVISION,
        "paths_before": len(a["records"]), "paths_after": len(still_open),
        "hypothesis_path_ids": sorted(r["id"] for r in a["records"] if r["hypothesis"]),
        # round 5, additive: paths declared by the agent (hypotheses: never in proven_*), and those this fix would cut
        "declared_path_ids": sorted(r["id"] for r in a["records"] if r["provenance"] in DECLARED_PROVENANCES and r["hypothesis"]),
        "declared_interrupted": [p for p in interrupted if by_id[p]["provenance"] in DECLARED_PROVENANCES and by_id[p]["hypothesis"]],
        # P7 fix 6 (P2-D2), additive: `interrupted` / `paths_before` above mix proven paths and inferred hypotheses
        # (kept unchanged for v1 clients); these four count PROVEN paths only, for a « N of M proven paths » label.
        "proven_interrupted": [p for p in interrupted if not by_id[p]["hypothesis"]],
        "proven_still_open": [p for p in still_open if not by_id[p]["hypothesis"]],
        "proven_paths_before": sum(1 for r in a["records"] if not r["hypothesis"]),
        "proven_paths_after": sum(1 for p in still_open if not by_id[p]["hypothesis"]),
    }
