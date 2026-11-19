"""
Darkmoon — deterministic fix prioritisation over causal attack scenarios.

Python port of ``attack-path.engine.ts`` and ``observed/ranking-gate.ts`` (branch
``fe/base-secu-attackpaths``), adversarial fixes F1, F2, F8, F12, F13 included.

Semantics:
- a fix set F breaks an AND-set when it contains at least one of its findings;
- a step is blocked when every alternative AND-set is broken; an empty AND-set means "reachable
  without any finding" and is never broken;
- a scenario is interrupted when at least one step is blocked;
- a step whose ``satisfied_by`` is empty has an unknown dependency: the whole scenario is
  incomplete and excluded from every coverage figure.

Ranking is greedy on residual coverage (no double count). Ties: criticality weight of the newly
interrupted scenarios, highest criticality, standalone coverage, CVSS, id. The TypeScript version
uses a lazy max-heap; so does this port (only candidates sharing a scenario with the applied fix
are rescored, the others keep a score that cannot have changed).

Scenario dict: {id, entry_node_id, objective_node_id, criticality, provenance, steps:[{node_id,
satisfied_by}]}. Finding dict: {id, title, severity, cvss_score, node_id, node_ancestors?}.
Group dict: {id, finding_ids, reason}. Pure; inputs are never mutated.
"""

from __future__ import annotations

import heapq
import itertools
import time
import json
import math
from typing import Any, Dict, List, Optional, Set

from api.attack_paths_observed import is_pseudo_node, lc_key

CRITICALITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
ENGINE_LIMITS = {"max_scenarios": 10000, "max_findings": 20000, "max_occurrences": 5_000_000}
# Aligned 1:1 with the score-key positions (see ``score``): rule[i] explains a tie first broken at key index i; the
# last rule is the all-equal fallback (stable finding id). Actionability is the PRIMARY key so a consequence/impact
# finding never outranks or evicts a root correction, whatever its path coverage (phase-9b reviewer B).
TIE_BREAK_RULES = (
    "at least one attack path interrupted",                                  # key[0] = has gain
    "actionable technical fix preferred over a consequence/impact finding",  # key[1] = actionable
    "number of attack paths interrupted",                                    # key[2] = coverage
    "criticality weight of newly interrupted scenarios",                     # key[3] = sum of weights
    "highest scenario criticality",                                          # key[4] = max weight
    "standalone coverage",                                                   # key[5] = standalone
    "CVSS score",                                                            # key[6] = CVSS
    "finding id (stable order)",                                             # fallback (all equal)
)
OFF_PATH_REASON_LABELS = {
    "outside-chain": "outside any known chain",
    "needs-combined-fixes": "needs combined fixes",
    "covered-by-higher-rank": "on a chain already interrupted by a higher-ranked fix",
    "never-decisive": "on a chain but never decisive alone",
    "terminal-impact-no-remediation": "terminal impact — kept as impact, not a certified correction",
    "actionability-indeterminate": "actionability indeterminate — a remediation lead to investigate, not certified",
    "not-analysed": "not analysed (campaign too large)",
}


def criticality_weight(level: Any) -> int:
    return CRITICALITY_WEIGHT.get(level, 0) if isinstance(level, str) else 0


# A fix must be an actionable technical control, not the IMPACT it enables. These finding categories describe a
# CONSEQUENCE/outcome (data read, data exfiltrated, host owned) rather than a remediable weakness; the data is derived
# only from the existing ``category`` metadata — no new classification is introduced. When several candidate fixes
# interrupt the SAME paths, the engine prefers an actionable weakness over a terminal consequence (e.g. fix the
# hardcoded admin credentials / the arbitrary-SQL console, not « CRM data breach »). A consequence finding stays a
# finding and a graph objective; it is just not offered as THE remediation when an actionable one covers the same paths.
# This set holds the UNAMBIGUOUS impact outcomes. Exposure/disclosure are NOT here — they are handled by the generic
# position-aware classifier (``_finding_is_consequence``): an exposure that ENABLES a later step or is a SOLE-STEP
# control stays remediable; an exposure/disclosure reached only as the TERMINAL step after prior exploitation is the
# data-read OUTCOME and is a consequence. So « exposure stays eligible » holds exactly where it should (intermediate /
# standalone), not at a terminal objective — the earlier blanket exclusion of these categories is superseded.
_CONSEQUENCE_CATEGORIES = frozenset({
    "data_breach", "data_exfiltration", "data_leak", "account_takeover", "host_compromise", "full_compromise",
})
# Recognised fixable WEAKNESS / exploitation-technique categories (phase-9b closure). At a TERMINAL-after-prerequisite
# position the engine defaults to CONSEQUENCE and flips to remediable ONLY for one of these — a POSITIVE allow-list
# whose failure mode is safe (a missed weakness → treated as an outcome → the upstream root is preferred, the route is
# still fixed; never a consequence recommended). Matched by TOKEN so vendor spellings and suffixes are covered. This
# replaces the earlier outcome word-list, which every review defeated with one more synonym.
_WEAKNESS_TOKENS = (
    "rce", "remote_code", "code_exec", "code_execution", "command_inj", "command_exec", "os_command", "cmd_inj",
    "sql_inj", "sqli", "nosql", "ldap_inj", "xpath_inj", "injection", "xss", "cross_site", "ssrf", "csrf", "xxe",
    "idor", "bola", "bfla", "broken_access", "broken_object", "broken_function", "broken_auth", "auth_bypass",
    "authentication_bypass", "authorization", "missing_auth", "hardcoded", "default_cred", "weak_cred", "weak_password",
    "cleartext_cred", "plaintext_cred", "exposed_cred", "misconfig", "security_misconfiguration", "path_traversal",
    "directory_traversal", "lfi", "rfi",
    "file_inclusion", "deserial", "insecure_deserial", "prototype_pollution", "template_inj", "ssti", "file_upload",
    "open_redirect", "cors", "clickjack", "smuggling", "race_condition", "buffer_overflow", "format_string",
    "privilege_escalation", "priv_esc", "weak_tls", "weak_crypto", "insecure_crypto", "mass_assignment", "cve",
)


def _is_weakness_category(category: Any) -> bool:
    c = category.strip().lower() if isinstance(category, str) else ""
    return bool(c) and any(tok in c for tok in _WEAKNESS_TOKENS)


# OUTCOME / impact tokens (confidentiality, integrity, availability, misuse). Matched by token so vendor spellings and
# abbreviations are covered. A terminal-after-prerequisite finding with one of these is a consequence. Checked AFTER the
# weakness allow-list, so an injection/RCE at the objective is never swept in by a loose substring.
_OUTCOME_TOKENS = (
    "breach", "exfiltrat", "exfil", "leak", "spillage", "disclosure", "exposure", "pii", "sensitive_data",
    "sensitive_info", "data_dump", "database_dump", "dataexposure", "data_access", "unauthorized_read",
    "theft", "stolen", "harvest", "espionage", "eavesdrop", "privacy", "confidential", "intellectual_property",
    "tamper", "manipulat", "modif", "corrupt", "poison", "integrity", "defac", "fraud", "forgery", "falsif",
    "destruction", "destroy", "wipe", "ransom", "encrypt_impact", "denial_of_service", "outage", "disruption",
    "takeover", "account_compromise", "impersonat", "hijack_session", "surveillance",
)


def _is_outcome_category(category: Any) -> bool:
    c = category.strip().lower() if isinstance(category, str) else ""
    return bool(c) and any(tok in c for tok in _OUTCOME_TOKENS)


def is_consequence_category(category: Any) -> bool:
    return isinstance(category, str) and category.strip().lower() in _CONSEQUENCE_CATEGORIES


# A candidate is a recommendable remediation only when a distinct, identifiable TECHNICAL ACTION exists. A finding whose
# remediation is absent or a bare placeholder (« n/a », « monitor », « investigate ») carries no established control, so
# it cannot be used as a certain correction (owner: « si une correction technique ne peut pas être identifiée … conserve
# l'impact … ne l'utilise pas comme une correction certaine »). Several field names are accepted (scanners differ).
_WEAK_REMEDIATION = frozenset({"", "n/a", "na", "none", "null", "tbd", "todo", "unknown", "-", "—", "investigate",
                               "monitor", "review", "see above", "as needed"})


def has_actionable_remediation(finding: Any) -> bool:
    """True when the finding records a concrete technical remediation action (a distinct fixable control), not a bare
    placeholder. This is a STRUCTURAL signal (does a fix exist?), independent of any category name."""
    if not isinstance(finding, dict):
        return False
    for key in ("remediation", "fix", "recommendation", "remediation_action", "solution", "mitigation"):
        v = finding.get(key)
        if isinstance(v, str) and len(v.strip()) >= 8 and v.strip().lower() not in _WEAK_REMEDIATION:
            return True
    return False


def _finite(n: Any) -> float:
    if isinstance(n, bool) or not isinstance(n, (int, float)):
        return 0.0
    return float(n) if math.isfinite(n) else 0.0


def is_scenario_interrupted(scenario: Dict[str, Any], fixed: Set[str]) -> bool:
    return any(
        len(step.get("satisfied_by") or []) > 0
        and all(any(i in fixed for i in alt) for alt in step["satisfied_by"])
        for step in scenario.get("steps") or []
    )


def first_blocked_step(scenario: Dict[str, Any], fixed: Set[str]) -> Optional[int]:
    """1-based index of the first blocked step, None when the scenario stays open."""
    for i, step in enumerate(scenario.get("steps") or [], 1):
        alts = step.get("satisfied_by") or []
        if alts and all(any(x in fixed for x in alt) for alt in alts):
            return i
    return None


def _is_valid_step(step: Any) -> bool:
    if not isinstance(step, dict):
        return False
    by = step.get("satisfied_by")
    return isinstance(by, list) and all(isinstance(alt, list) and all(isinstance(i, str) for i in alt) for alt in by)


def _high_or_critical(findings: Dict[str, Dict[str, Any]]) -> List[str]:
    rows = [f for f in findings.values() if f.get("severity") in ("critical", "high")]
    rows.sort(key=lambda f: (-_finite(f.get("cvss_score")), lc_key(f["id"])))
    return [f["id"] for f in rows]


def _explain(rank: int, marginal: int, alone: int, total: int, still: int, alternatives: int) -> str:
    if rank == 1:
        parts = [f"Interrupts {marginal} of {total} known attack scenarios."]
    else:
        parts = [f"After the {rank - 1} higher-ranked fix{'es' if rank > 2 else ''}, interrupts {marginal} more of {total} known scenarios ({alone} on its own)."]
    if still:
        parts.append(f"{still} targeted asset{'s remain' if still > 1 else ' remains'} reachable through other scenarios.")
    if alternatives:
        parts.append(f"{alternatives} other fix{'es' if alternatives > 1 else ''} not ranked above would interrupt exactly the same scenarios at this point.")
    parts.append("Estimate based on known scenarios only; other attacks may exist.")
    return " ".join(parts)


def _too_large(base: Dict[str, Any], provenance: Any, findings: Dict[str, Dict[str, Any]], reason: str) -> Dict[str, Any]:
    off = [{"id": i, "reason": "not-analysed"} for i in _high_or_critical(findings)]
    return {**base, "status": "too-large", "provenance": provenance, "ranking": [], "off_path_findings": [o["id"] for o in off],
            "off_path": off, "multi_fix_scenario_ids": [], "reason": reason}


def _canonical_key(sc: Dict[str, Any]) -> str:
    steps = {json.dumps(sorted({json.dumps(sorted(set(alt))) for alt in st["satisfied_by"]})) for st in sc["steps"]}
    return json.dumps(sorted(steps))


COMBO_LIMITS = {"max_units": 4, "product_cap": 200, "max_evaluated": 5000}
# RT-07 (P8): the completion is BOUNDED per request. The operation budget is deterministic (same input -> same
# output); the time budget is a safety net. When either is reached, the whole completion is abandoned and the pure
# greedy ranking is returned, announced as not optimised (completion.truncated / optimised=false).
COMBO_BUDGET = {"max_enumerated": 20_000, "max_evaluated": 4_000, "max_rounds": 100, "time_s": 0.5}
NOT_OPTIMISED_NOTE = ("not optimised: the combination budget was reached, so the plain greedy ranking is shown "
                      "(scenarios needing combined fixes stay listed apart)")


class _ComboBudgetExceeded(Exception):
    pass


def prioritize_corrections(scenarios: List[Any], findings_in: List[Any], groups: Optional[List[Any]] = None,
                           completion: bool = False, budget: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    if not completion:
        return _prioritize(scenarios, findings_in, groups, False, None)
    b = {**COMBO_BUDGET, **(budget or {})}
    try:
        return _prioritize(scenarios, findings_in, groups, True, b)
    except _ComboBudgetExceeded as exc:
        out = _prioritize(scenarios, findings_in, groups, False, None)
        out["completion"] = {"enabled": True, "truncated": True, "optimised": False, "reason": str(exc),
                             "note": NOT_OPTIMISED_NOTE, "budget": {k: b[k] for k in sorted(b)}}
        return out


def _prioritize(scenarios: List[Any], findings_in: List[Any], groups: Optional[List[Any]],
                completion: bool, budget: Optional[Dict[str, float]]) -> Dict[str, Any]:
    """``completion`` (P7 fix 8, API flag DM_RANKING_COMBOS, default False = unchanged output): when no single fix
    interrupts an open scenario any more (OR steps), the greedy ranking is COMPLETED by the combination of fixes
    with the best interrupted-scenarios-per-fix ratio that blocks one step (one fix per alternative; graphbench C1),
    then the greedy resumes. Greedy entries are a prefix tagged ``source: greedy``; combination entries carry
    ``source: combination`` and ``combination``; ``completion`` reports the greedy gap."""
    issues: List[Dict[str, Any]] = []
    findings: Dict[str, Dict[str, Any]] = {}
    for f in findings_in if isinstance(findings_in, list) else []:
        if isinstance(f, dict) and isinstance(f.get("id"), str) and f["id"] and f["id"] not in findings:
            findings[f["id"]] = f

    seen: Set[str] = set()
    eligible: List[Dict[str, Any]] = []
    incomplete: List[Dict[str, Any]] = []
    provenances: Set[str] = set()
    for s in scenarios if isinstance(scenarios, list) else []:
        if not isinstance(s, dict) or not isinstance(s.get("id"), str) or not s["id"]:
            continue
        sid = s["id"]
        if sid in seen:
            issues.append({"kind": "duplicate-scenario", "scenario_id": sid, "message": f"Scenario {sid} appears more than once; first occurrence kept."})
            continue
        seen.add(sid)
        steps = s.get("steps")
        if steps is not None and not isinstance(steps, list):
            issues.append({"kind": "invalid-scenario", "scenario_id": sid, "message": f"Scenario {sid} has malformed steps and is ignored."})
            continue
        if not steps:
            issues.append({"kind": "empty-scenario", "scenario_id": sid, "message": f"Scenario {sid} has no steps and is ignored."})
            continue
        if not all(_is_valid_step(st) for st in steps):
            issues.append({"kind": "invalid-scenario", "scenario_id": sid, "message": f"Scenario {sid} has a step that is not a list of AND-sets of finding ids; it is ignored."})
            continue
        provenances.add(s.get("provenance"))
        for st in steps:
            for alt in st["satisfied_by"]:
                for i in alt:
                    if i not in findings:
                        issues.append({"kind": "unknown-finding", "scenario_id": sid, "finding_id": i,
                                       "message": f"Finding {i} referenced by scenario {sid} is not in the finding list; it cannot be proposed as a fix."})
        if any(not st["satisfied_by"] for st in steps):
            issues.append({"kind": "unknown-dependency", "scenario_id": sid, "message": f"Scenario {sid} has a step with unknown dependencies; it is excluded from coverage."})
            incomplete.append(s)
        else:
            eligible.append(s)

    # F2: identical dependency structures are counted once (merged into the smallest id).
    merged_scenarios: List[Dict[str, str]] = []
    merged_into: Dict[str, List[Dict[str, Any]]] = {}
    reps: Dict[str, Dict[str, Any]] = {}
    for sc in sorted(eligible, key=lambda x: x["id"]):
        key = _canonical_key(sc)
        rep = reps.get(key)
        if rep is None:
            reps[key] = sc
            continue
        merged_scenarios.append({"id": sc["id"], "into": rep["id"]})
        merged_into.setdefault(rep["id"], []).append(sc)
        issues.append({"kind": "merged-scenario", "scenario_id": sc["id"], "message": f"Scenario {sc['id']} depends on exactly the same findings as {rep['id']}; counted once."})
    if merged_scenarios:
        gone = {m["id"] for m in merged_scenarios}
        eligible = [sc for sc in eligible if sc["id"] not in gone]

    base = {"eligible_scenario_ids": [s["id"] for s in eligible], "incomplete_scenario_ids": [s["id"] for s in incomplete],
            "merged_scenarios": merged_scenarios, "issues": issues}

    if len(provenances) > 1 and "demo" in provenances:
        issues.append({"kind": "mixed-provenance", "message": "Demo scenarios cannot be mixed with real results."})
        off = [{"id": i, "reason": "not-analysed"} for i in _high_or_critical(findings)]
        return {**base, "status": "insufficient", "provenance": "mixed", "ranking": [], "off_path_findings": [o["id"] for o in off],
                "off_path": off, "multi_fix_scenario_ids": [], "reason": "Demo and real scenarios were mixed; nothing is computed."}
    provenance = None if not provenances else next(iter(provenances)) if len(provenances) == 1 else "mixed"

    if len(eligible) > ENGINE_LIMITS["max_scenarios"] or len(findings) > ENGINE_LIMITS["max_findings"]:
        return _too_large(base, provenance, findings, f"{len(eligible)} scenarios / {len(findings)} findings exceed the engine limit ({ENGINE_LIMITS['max_scenarios']} / {ENGINE_LIMITS['max_findings']}).")

    # flat indexes
    scenario_of_step: List[int] = []
    step_of_alt: List[int] = []
    steps_of_scenario: List[List[int]] = []
    alt_count: List[int] = []
    alts_of_step: List[List[int]] = []
    alt_members: List[List[str]] = []
    occurrences: Dict[str, List[int]] = {}
    occurrence_count = 0
    for si, s in enumerate(eligible):
        own = []
        for step in s["steps"]:
            st = len(alt_count)
            own.append(st)
            scenario_of_step.append(si)
            alt_count.append(len(step["satisfied_by"]))
            alts_of_step.append([])
            for alt in step["satisfied_by"]:
                a = len(step_of_alt)
                step_of_alt.append(st)
                alts_of_step[st].append(a)
                alt_members.append([i for i in dict.fromkeys(alt) if i in findings])
                for i in dict.fromkeys(alt):
                    if i not in findings:
                        continue
                    occurrences.setdefault(i, []).append(a)
                    occurrence_count += 1
        steps_of_scenario.append(own)
    alt_total = list(alt_count)
    if occurrence_count > ENGINE_LIMITS["max_occurrences"]:
        return _too_large(base, provenance, findings, f"{occurrence_count} finding references exceed the engine limit ({ENGINE_LIMITS['max_occurrences']}).")

    by_finding: Dict[str, List[int]] = {i: sorted({scenario_of_step[step_of_alt[a]] for a in alts}) for i, alts in occurrences.items()}

    if not eligible:
        off = [{"id": i, "reason": "outside-chain"} for i in _high_or_critical(findings)]
        return {**base, "status": "insufficient" if incomplete else "empty", "provenance": provenance, "ranking": [],
                "off_path_findings": [o["id"] for o in off], "off_path": off, "multi_fix_scenario_ids": [],
                "reason": ("No scenario has fully known dependencies; coverage cannot be demonstrated." if incomplete
                           else "No attack scenario is available for this scope.")}

    # candidates
    members: Dict[str, List[str]] = {}
    grouped: Set[str] = set()
    for g in groups if isinstance(groups, list) else []:
        gid = g.get("id") if isinstance(g, dict) else None
        raw_ids = g.get("finding_ids") if isinstance(g, dict) else None
        ids = list(dict.fromkeys(i for i in (raw_ids if isinstance(raw_ids, list) else []) if i in findings and i not in grouped))
        if not gid or len(ids) < 2 or gid in findings or gid in members:
            issues.append({"kind": "invalid-group", "message": f"Remediation group {gid or '?'} needs a unique id and at least two known, ungrouped findings; ignored."})
            continue
        members[gid] = sorted(ids)
        grouped.update(ids)
    for i in by_finding:
        if i not in grouped:
            members[i] = [i]
    for cid in list(members):
        if not any(f in by_finding for f in members[cid]):
            del members[cid]

    candidate_scenarios: Dict[str, List[int]] = {}
    scenario_candidates: List[List[str]] = [[] for _ in eligible]
    for cid, ids in members.items():
        lst = list(dict.fromkeys(si for f in ids for si in by_finding.get(f, [])))
        candidate_scenarios[cid] = lst
        for si in lst:
            scenario_candidates[si].append(cid)

    # Audit P1 (owner « ne confonds plus une vulnérabilité à corriger avec les conséquences qu'elle provoque »): decide
    # GENERICALLY — NOT from a closed category list — whether a finding is a remediable WEAKNESS or a pure CONSEQUENCE
    # (an impact/outcome you cannot patch directly). The primary signal is the finding's ROLE/POSITION in the graph,
    # corroborated by the remediation evidence and, only as a last reinforcement, the category:
    #   • a finding that ENABLES a later step (produces a capability a downstream operation consumes) is a
    #     prerequisite/pivot → a remediable weakness, never a consequence;
    #   • a finding that is a SOLE-STEP scenario (a standalone exposed control, e.g. a public .env, a weak admin
    #     console reachable directly) → a remediable weakness;
    #   • otherwise the finding is only ever reached as the TERMINAL step of a multi-step chain, after prior
    #     exploitation (an outcome). It is a consequence UNLESS a distinct technical control is established for it
    #     (an actionable remediation action). An explicit impact/outcome category (data_breach, exfiltration, …)
    #     marks it a consequence even then (you fix the access, not the breach). A terminal weakness WITH a concrete
    #     fix (e.g. unauthorised OS command execution at the objective host) stays remediable — a terminal node is
    #     NOT automatically a consequence.
    # The per-finding verdict is cached; ``_actionable`` (the score tie-break) reuses it, so the whole engine shares
    # one coherent notion of « remediable weakness vs consequence ».
    _last_step_of = {si: steps_of_scenario[si][-1] for si in range(len(eligible)) if steps_of_scenario[si]}

    def _finding_steps(f: str) -> Set[int]:
        return {step_of_alt[a] for a in occurrences.get(f, [])}

    def _remediation_class(f: str) -> str:
        """Tri-state remediation class of a finding: « weakness » (a fixable technical control → admissible as a
        certified correction), « consequence » (a terminal impact/outcome → visible but never a correction), or
        « indeterminate » (unknown/untyped, no established control → not counted as guaranteed coverage)."""
        fd = findings.get(f, {})
        cat = (fd.get("category") or "").strip().lower() if isinstance(fd.get("category"), str) else ""
        steps = _finding_steps(f)
        if not steps:
            if is_consequence_category(cat):
                return "consequence"
            if _is_weakness_category(cat) or not cat:
                return "weakness"
            return "indeterminate"
        enables_downstream = any(st != _last_step_of.get(scenario_of_step[st]) for st in steps)
        sole_step = any(len(steps_of_scenario[scenario_of_step[st]]) == 1 for st in steps)
        if enables_downstream:
            return "weakness"  # a prerequisite/pivot that produces a capability consumed downstream — fixable even if
            #                    the scanner mis-tagged it as an impact (position wins)
        if sole_step:
            # a standalone single-step finding: an EXPLICIT impact (account_takeover, data_breach …) is a consequence,
            # not a fixable control; anything else (a public .env, a misconfiguration, an exposure) is a remediable
            # standalone control.
            return "consequence" if is_consequence_category(cat) else "weakness"
        # TERMINAL-after-prerequisite (release gate, owner phase 1/2): tri-state. A recognised fixable WEAKNESS/technique
        # (e.g. OS command execution AS the objective) stays a « weakness ». An explicit impact or OUTCOME category
        # (read/leak/tamper/exfiltrate/destroy …) is a « consequence » (impact, NOT a correction). A category that is
        # PRESENT but UNRECOGNISED is « indeterminate » — the scanner tagged it with something we cannot certify, so
        # actionability is left uncertain (not counted as coverage, shown as a lead). An ABSENT category is merely
        # missing metadata, not a signal of impact → it defaults to « weakness » (remediable, never hidden).
        if _is_weakness_category(cat):
            return "weakness"
        if is_consequence_category(cat) or _is_outcome_category(cat):
            return "consequence"
        # A category that is PRESENT but UNRECOGNISED is « indeterminate » (unknown control, surfaced as a lead, not
        # counted as coverage). An ABSENT category is merely missing metadata, NOT a signal of impact: many real
        # weaknesses (a credential read exposed through an API, a .env disclosure) carry no category, so defaulting
        # them to « weakness » keeps them visible and certifiable — never hidden. (Reviewer FAILLE B was only PLAUSIBLE;
        # flipping absent→indeterminate here regresses real detections, which the engine's twin/producer tests encode.)
        return "indeterminate" if cat else "weakness"

    _class_f: Dict[str, str] = {f: _remediation_class(f) for f in findings}

    # RELEASE GATE phase 1 (reviewer FAILLE A/C): a remediation GROUP may certify coverage ONLY through its WEAKNESS
    # members. A group that bundles a fixable weakness with a terminal CONSEQUENCE (or an indeterminate finding) must not
    # let that non-weakness member close a route under the group's admissible label — the group's graph-cut would then
    # count a realised breach (or an unverified lead) as certified coverage. So we SPLIT every mixed group: the group
    # keeps its weakness members (its real coverage), and each non-weakness member becomes its own candidate (then
    # classified consequence/indeterminate and removed by the exclusion filter below). A route interruptible ONLY by the
    # former group's consequence/indeterminate member therefore stays OPEN (paths_without_established_fix).
    _split_groups = False
    for cid in list(members):
        ids = members[cid]
        if len(ids) < 2:
            continue
        weak = [f for f in ids if _class_f.get(f) == "weakness"]
        nonweak = [f for f in ids if _class_f.get(f) != "weakness"]
        if weak and nonweak:
            members[cid] = weak
            for f in nonweak:
                members.setdefault(f, [f])  # promote the non-weakness member to a standalone candidate (unique finding id)
            _split_groups = True
    if _split_groups:
        candidate_scenarios = {}
        scenario_candidates = [[] for _ in eligible]
        for cid, ids in members.items():
            lst = list(dict.fromkeys(si for f in ids for si in by_finding.get(f, [])))
            candidate_scenarios[cid] = lst
            for si in lst:
                scenario_candidates[si].append(cid)

    def _candidate_class(cid: str) -> str:
        cls = [_class_f.get(f, "indeterminate") for f in members.get(cid, [])]
        if not cls:
            return "indeterminate"
        if any(c == "weakness" for c in cls):
            return "weakness"       # a group with a fixable member is remediable via that member
        return "consequence" if all(c == "consequence" for c in cls) else "indeterminate"

    _consequence_f: Dict[str, bool] = {f: _class_f.get(f) == "consequence" for f in findings}

    def _is_pure_consequence(cid: str) -> bool:
        return _candidate_class(cid) == "consequence"

    # Owner RELEASE GATE phase 1/2: ONLY ADMISSIBLE candidates (a fixable weakness) are certified corrections and count
    # toward coverage. A pure CONSEQUENCE (terminal impact — a data read/exfiltration/compromise) is NEVER a correction,
    # even when it is the only finding that « interrupts » the path in the graph abstraction: a realised breach is not a
    # remediation. An INDETERMINATE candidate (unknown/untyped, no established control) does not produce guaranteed
    # coverage either. Both are removed from the ranking and kept VISIBLE elsewhere (impact / unverified lead). A route
    # that no admissible candidate interrupts stays OPEN and is reported « no established actionable remediation » — the
    # engine never attributes artificial coverage nor a positive marginal gain to a consequence.
    consequence_cids = {cid for cid in members if _candidate_class(cid) == "consequence"}
    indeterminate_cids = {cid for cid in members if _candidate_class(cid) == "indeterminate"}
    _excluded = consequence_cids | indeterminate_cids
    if _excluded:
        for cid in _excluded:
            del members[cid]
            candidate_scenarios.pop(cid, None)
        scenario_candidates = [[c for c in lst if c not in _excluded] for lst in scenario_candidates]

    def cvss_of(cid: str) -> float:
        return max([0.0] + [_finite(findings[f].get("cvss_score")) for f in members[cid]])

    alt_broken = [False] * len(step_of_alt)
    open_ = [True] * len(eligible)
    open_count = len(eligible)

    def gain(ids: List[str]) -> Set[int]:
        hits: Dict[int, int] = {}
        stamped: Set[int] = set()
        interrupted: Set[int] = set()
        for f in ids:
            for a in occurrences.get(f, []):
                if alt_broken[a] or a in stamped:
                    continue
                stamped.add(a)
                st = step_of_alt[a]
                si = scenario_of_step[st]
                if not open_[si]:
                    continue
                hits[st] = hits.get(st, 0) + 1
                if hits[st] == alt_count[st]:
                    interrupted.add(si)
        return interrupted

    standalone: Dict[str, List[str]] = {}

    def _actionable(cid: str) -> int:
        # 1 when the candidate fixes at least one remediable weakness; 0 when EVERY member finding is a CONSEQUENCE —
        # decided by the shared generic verdict (position/role + remediation + category), not a category name alone.
        # Coverage stays first in the key, so a lone consequence is still chosen when nothing actionable covers the
        # same paths; an equal-coverage actionable weakness is always preferred (audit P1).
        return 0 if _is_pure_consequence(cid) else 1

    def score(cid: str) -> Dict[str, Any]:
        g = gain(members[cid])
        gained = [si for si in candidate_scenarios[cid] if si in g]
        w = [criticality_weight(eligible[si].get("criticality")) for si in gained]
        # coverage first, THEN actionability (prefer a real fix over an impact), then criticality / standalone / CVSS.
        # key order (phase-9b closure): (0) HAS-GAIN first — a candidate that interrupts at least one open path always
        # beats an impotent one, so an actionable finding with zero gain never preempts a consequence that actually cuts
        # the route (mechanism 2b); (1) ACTIONABILITY — among USEFUL candidates a real fix outranks a consequence by any
        # coverage (reviewer B Faille 1); (2) coverage magnitude, then criticality / standalone / CVSS.
        key = [1 if gained else 0, _actionable(cid), len(gained), sum(w), max(w) if w else 0,
               len(standalone[cid]) if cid in standalone else len(gained), cvss_of(cid)]
        return {"id": cid, "gained": gained, "key": key}

    def order(sc: Dict[str, Any]) -> tuple:
        return tuple(-k for k in sc["key"]) + (lc_key(sc["id"]),)

    current: Dict[str, Dict[str, Any]] = {}
    # Max-heap (min-heap on the negated key) with lazy invalidation: an entry is stale once its
    # candidate was rescored or ranked (same behaviour as the TypeScript lazy greedy).
    heap: List[tuple] = []

    def pop_live() -> Optional[Dict[str, Any]]:
        while heap:
            sc = heapq.heappop(heap)[2]
            if current.get(sc["id"]) is sc:
                return sc
        return None

    def peek_live() -> Optional[Dict[str, Any]]:
        while heap and current.get(heap[0][2]["id"]) is not heap[0][2]:
            heapq.heappop(heap)
        return heap[0][2] if heap else None

    for cid in members:
        sc = score(cid)
        standalone[cid] = sorted(eligible[si]["id"] for si in sc["gained"])
        current[cid] = sc
        heapq.heappush(heap, (order(sc), id(sc), sc))

    pending: Dict[str, int] = {}

    def objectives_of(sc: Dict[str, Any]) -> List[str]:
        # a scenario without a string objective tracks no objective (it used to crash the sort below: P5-B1)
        objs = [sc.get("objective_node_id")] + [m.get("objective_node_id") for m in merged_into.get(sc["id"], [])]
        return [o for o in objs if isinstance(o, str)]

    for sc in eligible:
        for o in objectives_of(sc):
            pending[o] = pending.get(o, 0) + 1
    never_closed = {s.get("objective_node_id") for s in incomplete} | {o for o in pending if is_pseudo_node(o)}
    active_on: Dict[str, List[str]] = {}
    for f in findings.values():
        anc = f.get("node_ancestors")
        nodes = {n for n in [f.get("node_id"), *(anc if isinstance(anc, list) else [])] if isinstance(n, str) and n}
        for n in nodes:
            active_on.setdefault(n, []).append(f["id"])
    fixed_findings: Set[str] = set()
    waiting: Set[str] = set()
    closed: Set[str] = set()

    def try_close(objective: str) -> None:
        if objective in never_closed or objective in closed:
            return
        if any(f not in fixed_findings for f in active_on.get(objective, [])):
            waiting.add(objective)
            return
        waiting.discard(objective)
        closed.add(objective)

    index_of = {s["id"]: si for si, s in enumerate(eligible)}
    sorted_eligible = sorted(((s["id"], si) for si, s in enumerate(eligible)), key=lambda x: x[0])

    ranking: List[Dict[str, Any]] = []

    def apply_unit(cid: str, gained: List[int]) -> None:
        """Mark candidate ``cid`` fixed; ``gained`` = the open scenarios it interrupts now (rescoring included)."""
        nonlocal open_count
        del current[cid]
        for f in members[cid]:
            fixed_findings.add(f)
            for a in occurrences.get(f, []):
                if alt_broken[a]:
                    continue
                alt_broken[a] = True
                alt_count[step_of_alt[a]] -= 1
        for si in gained:
            open_[si] = False
            open_count -= 1
            for o in objectives_of(eligible[si]):
                pending[o] = pending.get(o, 1) - 1
                if pending[o] == 0:
                    try_close(o)
        for o in list(waiting):
            try_close(o)
        affected = {c for si in candidate_scenarios[cid] for c in scenario_candidates[si]}
        for c in affected:
            if c in current:
                sc = score(c)
                current[c] = sc
                heapq.heappush(heap, (order(sc), id(sc), sc))

    def entry(cid: str, gained: List[int], equivalent: List[str], tie_break: Optional[str]) -> Dict[str, Any]:
        own = standalone[cid]
        touched = {o for sid in own for o in objectives_of(eligible[index_of[sid]]) if not is_pseudo_node(o)}
        fix_ids = set(members[cid])
        pivot = [sid for sid in own if not any(any(f in fix_ids for f in alt) for alt in eligible[index_of[sid]]["steps"][-1]["satisfied_by"])]
        still = sorted(o for o in touched if o not in closed)
        rank = len(ranking) + 1
        return {
            "rank": rank,
            "finding_id": cid,
            "finding_ids": members[cid],
            "standalone_interrupted": own,
            "pivot_interrupted": pivot,
            "marginal_interrupted": [eligible[si]["id"] for si in gained],
            "remaining_open": [sid for sid, si in sorted_eligible if open_[si]],
            "objectives_closed": sorted(closed),
            "objectives_still_reachable": still,
            "equivalent_alternatives": equivalent,
            "tie_break": tie_break,
            "explanation": _explain(rank, len(gained), len(own), len(eligible), len(still), len(equivalent)),
        }

    unit_of: Dict[str, str] = {f: cid for cid, ids in members.items() for f in ids}
    spent = {"enumerated": 0, "evaluated": 0, "rounds": 0}
    t0 = time.perf_counter()

    def charge(kind: str, n: int = 1) -> None:
        spent[kind] += n
        if spent[kind] > budget[f"max_{kind}"]:
            raise _ComboBudgetExceeded(f"{kind} budget ({int(budget[f'max_{kind}'])}) reached")
        if (spent["enumerated"] + spent["evaluated"]) % 256 == 0 and time.perf_counter() - t0 > budget["time_s"]:
            raise _ComboBudgetExceeded(f"time budget ({budget['time_s']} s) reached")

    def best_combination() -> Optional[tuple]:
        """C1 completion: combinations (one live candidate per unbroken alternative) that block one step of an open
        scenario; the best interrupted-scenarios / fixes ratio wins, ties to the smallest then lexicographic."""
        combos: Set[tuple] = set()
        for si in range(len(eligible)):
            if not open_[si]:
                continue
            for st in steps_of_scenario[si]:
                choices = []
                blockable = True
                for a in alts_of_step[st]:
                    if alt_broken[a]:
                        continue
                    opts = sorted({unit_of[f] for f in alt_members[a] if f in unit_of and unit_of[f] in current}, key=lc_key)
                    if not opts:
                        blockable = False
                        break
                    choices.append(opts)
                if not blockable or not choices:
                    continue
                n = 0
                for combo in itertools.product(*choices):
                    n += 1
                    if n > COMBO_LIMITS["product_cap"]:
                        break
                    charge("enumerated")
                    c = tuple(sorted(set(combo), key=lc_key))
                    if len(c) <= COMBO_LIMITS["max_units"]:
                        combos.add(c)
        best, best_ratio = None, 0.0
        for k, c in enumerate(sorted(combos, key=lambda c: (len(c), [lc_key(x) for x in c]))):
            if k >= COMBO_LIMITS["max_evaluated"]:
                break
            charge("evaluated")
            g = gain([f for cid in c for f in members[cid]])
            if g and len(g) / len(c) > best_ratio:
                best, best_ratio = c, len(g) / len(c)
        return best

    greedy_ranks: Optional[int] = None
    greedy_interrupted = 0
    combo_count = 0
    while open_count:
        best = pop_live()
        if best is None or not best["gained"]:
            if not completion:
                break
            if best is not None:  # still a candidate: back into the heap for later rounds
                heapq.heappush(heap, (order(best), id(best), best))
            charge("rounds")
            combo = best_combination()
            if not combo:
                break
            if greedy_ranks is None:
                greedy_ranks = len(ranking)
                greedy_interrupted = len(eligible) - open_count
            combo_count += 1
            total = sorted(gain([f for cid in combo for f in members[cid]]))
            combo_id = f"combo-{combo_count}"
            for k, cid in enumerate(combo):
                gained = sorted(gain(members[cid]))
                apply_unit(cid, gained)
                e = entry(cid, gained, [], None)
                others = [x for x in combo if x != cid]
                e["source"] = "combination"
                e["combination"] = {"id": combo_id, "units": list(combo), "position": k + 1,
                                    "interrupts": [eligible[si]["id"] for si in total]}
                e["explanation"] = (f"Fix {k + 1} of a combination of {len(combo)} ({', '.join(others)} with it): together "
                                    f"they interrupt {len(total)} more of {len(eligible)} known scenarios that no single "
                                    f"fix interrupts. Estimate based on known scenarios only; other attacks may exist.")
                ranking.append(e)
            continue
        runner = peek_live()
        gained_set = set(best["gained"])
        equivalent = sorted(
            {c for c in scenario_candidates[best["gained"][0]]
             if c != best["id"] and c in current and len(current[c]["gained"]) == len(best["gained"])
             and all(si in gained_set for si in current[c]["gained"])
             and _actionable(c)}       # audit P1: don't present a consequence/impact finding as an equivalent FIX
        )
        tie_break = None
        if runner and len(runner["gained"]) == len(best["gained"]):
            # first key index where best and runner differ → the criterion that broke the tie (rules aligned 1:1 with
            # key positions; all-equal falls back to the stable finding id).
            i = next((k for k, v in enumerate(best["key"]) if v != runner["key"][k]), -1)
            tie_break = TIE_BREAK_RULES[i if i >= 0 else len(TIE_BREAK_RULES) - 1]

        apply_unit(best["id"], best["gained"])
        e = entry(best["id"], best["gained"], equivalent, tie_break)
        if completion:
            e["source"] = "greedy"
        ranking.append(e)

    # F1: every high/critical finding not removed by a ranked correction, with a reason.
    ranked = {f for c in ranking for f in c["finding_ids"]}
    candidate_of = {f: cid for cid, ids in members.items() for f in ids}
    breakable = [False] * len(step_of_alt)
    for alts in occurrences.values():
        for a in alts:
            breakable[a] = True
    breakable_in_step = [0] * len(alt_total)
    for a, ok in enumerate(breakable):
        if ok:
            breakable_in_step[step_of_alt[a]] += 1
    interruptible = [any(alt_total[st] > 0 and breakable_in_step[st] == alt_total[st] for st in steps) for steps in steps_of_scenario]

    off_path = []
    for fid in _high_or_critical(findings):
        if fid in ranked:
            continue
        cls = _class_f.get(fid)
        scs = by_finding.get(fid)
        if cls == "consequence":
            reason = "terminal-impact-no-remediation"   # an impact/outcome, visible but never a certified correction
        elif cls == "indeterminate":
            reason = "actionability-indeterminate"       # uncertain: a remediation lead to investigate, not certified
        elif not scs:
            reason = "outside-chain"
        elif any(open_[si] and interruptible[si] for si in scs):
            reason = "needs-combined-fixes"
        elif candidate_of.get(fid) and standalone.get(candidate_of[fid]):
            reason = "covered-by-higher-rank"
        else:
            reason = "never-decisive"
        off_path.append({"id": fid, "reason": reason})

    # Owner RELEASE GATE: an OPEN route that NO admissible (certified) correction interrupts is reported honestly — it
    # is never counted as closed and no artificial coverage is attributed. « unverified_remediations » surfaces the
    # indeterminate findings as leads to investigate (separate from the certified Top corrections).
    open_scenarios = [si for sid, si in sorted_eligible if open_[si]]
    paths_without_established_fix = [eligible[si]["id"] for si in open_scenarios]
    unverified_remediations = [{"id": f, "reason": "actionability-indeterminate"}
                               for f in findings if _class_f.get(f) == "indeterminate" and f in by_finding]
    # Authoritative set of on-path findings that are NOT admissible certified corrections (a terminal CONSEQUENCE or an
    # INDETERMINATE lead). Consumers (e.g. the insights choke-points surface) must never present any of these as a « fix »
    # — single source of truth for the engine's tri-state classification (reviewer calcul F2).
    non_admissible_finding_ids = sorted(f for f in findings
                                        if _class_f.get(f) in ("consequence", "indeterminate") and f in by_finding)
    out = {**base, "status": "ok", "provenance": provenance, "ranking": ranking,
           "off_path_findings": [o["id"] for o in off_path], "off_path": off_path,
           "multi_fix_scenario_ids": [sid for sid, si in sorted_eligible if open_[si]],
           "paths_without_established_fix": paths_without_established_fix,
           "unverified_remediations": unverified_remediations,
           "non_admissible_finding_ids": non_admissible_finding_ids, "reason": None}
    if completion:
        interrupted = len(eligible) - open_count
        out["completion"] = {
            "enabled": True, "truncated": False, "optimised": True,
            "greedy_ranks": len(ranking) if greedy_ranks is None else greedy_ranks,
            "combination_ranks": sum(1 for e in ranking if e.get("source") == "combination"),
            "combinations": combo_count,
            "greedy_interrupted": interrupted if greedy_ranks is None else greedy_interrupted,
            "interrupted": interrupted,
            "gap": interrupted - (interrupted if greedy_ranks is None else greedy_interrupted),
        }
    return out


def ranking_gate(result: Optional[Dict[str, Any]], real_provenances: tuple = ("observed", "server")) -> Dict[str, Any]:
    """Display gate for "fix X interrupts N of M" (ranking-gate.ts)."""
    result = result or {}
    scenario_count = len(result.get("eligible_scenario_ids") or [])
    ranking = result.get("ranking") or []
    top = ranking[0] if ranking else None
    top_n = len((top or {}).get("standalone_interrupted") or [])
    if top and top.get("combination"):  # P8 RT-08: a leading combination counts for what it interrupts together
        top_n = max(top_n, len(top["combination"].get("interrupts") or []))
    base = {"scenario_count": scenario_count, "top_interrupts": top_n,
            "non_trivial_choke_point": top_n >= 2 or len((top or {}).get("pivot_interrupted") or []) >= 1}
    if result.get("status") == "too-large":
        return {**base, "meaningful": False, "reason": "too-large"}
    if result.get("status") != "ok":
        return {**base, "meaningful": False, "reason": "status-not-ok"}
    if result.get("provenance") not in real_provenances:
        return {**base, "meaningful": False, "reason": "provenance-not-real"}
    if scenario_count < 2:
        return {**base, "meaningful": False, "reason": "too-few-scenarios"}
    if top_n < 1:
        return {**base, "meaningful": False, "reason": "top-fix-interrupts-nothing"}
    if not base["non_trivial_choke_point"]:
        return {**base, "meaningful": False, "reason": "no-choke-point"}
    return {**base, "meaningful": True, "reason": "ok"}
