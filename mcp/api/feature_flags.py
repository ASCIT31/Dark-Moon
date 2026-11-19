"""
Darkmoon 2027 (P7) — feature flags of the attack-path candidate fixes.

Every flag is OFF by default — except those listed in ``DEFAULT_ON`` — : with no environment variable set, the
product behaves exactly as before (same documents, same ids, same ranking). A flag is read at call time from the process environment, so
a test can toggle it with ``monkeypatch.setenv``; in production it is set on the API / MCP containers and
takes effect after a restart (the attack-path caches are keyed on file stamps, not on flags).

Rollback of any flagged change = unset the variable (no migration, no stored data rewritten).
See docs/research/darkmoon-2027/09_implementation_diff.md.
"""

from __future__ import annotations

import os
from typing import Dict

# name -> one-line description (also the registry checked by the tests: every flag is OFF by default)
FLAGS: Dict[str, str] = {
    "DM_ARTIFACT_FINGERPRINTS": "server-side salted fingerprints of the credentials of a finding's evidence at push "
                                "time; R1 joins on fingerprint equality (value index, no quadratic scan)",
    "DM_CAUSAL_HINTS": "non-blocking chain hints in the dashboard_push_finding answer and a non-blocking chain "
                       "checklist in the finalize answer",
    "DM_R3_EXPLOIT_ORIGIN": "R3 starts at the node the exploit was sent to (endpoint), not at the node the finding "
                            "is attached to, when the finding is attached to the reached data store",
    "DM_DERIVE_KEEP_REACHED_OBJECTIVE": "derive_scenarios keeps an inlined producer's own chain when it reaches an "
                                        "objective no kept chain reaches (P2-D1)",
    "DM_STABLE_PATH_IDS": "path ids hash the source chain id (stable across remediations) and the list document "
                          "carries a legacy-id alias table for one version (P5-B2)",
    "DM_RANKING_COMBOS": "the ranking is completed by combinations of fixes when no single fix interrupts an open "
                         "scenario (graphbench C1); the greedy prefix and its gap stay visible",
    "DM_TOPOLOGY_PATHS": "/infrastructure also returns the BFS topology routes as topology_paths and marks "
                         "attack_paths as its deprecated alias",
    "DM_LEGACY_DERIVED_PROOF": "ROLLBACK ONLY: count a derived path (and a multi-step chain declared at finalisation) as "
                               "proven from the agent's declared fields alone "
                               "(pre-P8 behaviour, RT-04); never set it in production",
    # local-AI track (api/local_causal.py, docs/research/darkmoon-2027/14_local_ai_hybrid.md)
    "DM_LOCAL_CAUSAL_VERIFIER": "deterministic expert system over the tool-layer event log: producer -> consumer links, "
                                "proven only with a negative control (trace or budgeted active replay)",
    "DM_LOCAL_AI_PROPOSER": "orders the verifier's candidates with a local artefact proposer (int8 ONNX encoder from "
                            "DM_LOCAL_AI_MODEL_DIR when loadable, else rules); never changes a proof level",
    "DM_TOOL_PROVENANCE": "run ledger: the MCP server fingerprints (salted, per run) the artefacts that appear in "
                          "execute_command inputs / outputs and records each command's outcome (nothing shown to the agent); "
                          "architecture D qualifies the declared links (enabled_by) on it by exact value attribution. ON BY "
                          "DEFAULT (DEFAULT_ON); DM_TOOL_PROVENANCE=0 rolls back",
    "DM_FINALIZE_CHAINS_AS_PATHS": "ROLLBACK ONLY (architecture D): turn the chains of the finalisation ATTACK_CHAINS "
                                   "block into attack paths again (paths-v2 behaviour); by default they are report text "
                                   "only and paths come from the per-finding enabled_by declarations",
    "DM_MAX_RANKED_PATHS":"integer: proven paths above which the ranking is refused as too-large (default 200)",
    # tokens track (src/token_store.py, docs/research/darkmoon-2027/08_decision_records.md)
    "DM_TOKENS_OUTPUT_OFFLOAD": "execute_command outputs above DM_TOKENS_OUTPUT_MAX_CHARS are shown head+tail with a "
                                "run-scoped reference; the full output is stored unchanged (evidence_get)",
    "DM_TOKENS_OUTPUT_MAX_CHARS": "integer: characters of an execute_command output shown before offload (default 4000)",
    "DM_TOKENS_STORE_MAX_MB": "integer: size cap of one run's evidence store; above it outputs are shown in full (default 256)",
    "DM_TOKENS_DEDUP": "an execute_command output identical (sha256) to one already returned in the run is replaced "
                       "by a notice naming its stored reference",
    "DM_TOKENS_EVIDENCE_FTS": "stored outputs are indexed in a per-run SQLite FTS5 table; evidence_search tool",
    "DM_TOKENS_EVIDENCE_REFS": "dashboard_push_finding resolves ev_ references of the evidence fields into the stored "
                               "output and records their sha256 (evidence.output_refs)",
    "DM_TOKENS_COMPACT_TOOLS": "compact MCP tool descriptions (examples/history removed; every argument, rule and "
                               "enumeration kept verbatim); read at MCP start-up",
    # attack-chains proof bridge (api/attack_chains_evidence.py, docs/research/darkmoon-2027 E3/E4):
    # OFF = no proof data is injected anywhere and every historical document/contract is byte-identical; ON = the
    # proven E3/E4 exploitations are qualified (path_class, per-step proof_level/oracle/permission_ref, anonymised
    # fingerprints) and fed, unchanged, to the existing prioritize_corrections optimiser. Additive only.
    "DM_ATTACK_CHAINS": "qualify the proven E3/E4 exploitations (path_class + additive step proof fields) and feed "
                        "them to the existing attack-path optimiser; never promotes a declared/inferred path to proven. "
                        "At finalisation it runs the frozen E3 engine PASSIVELY over the campaign's own traces (no LLM, "
                        "no active replay) and persists per-campaign evidence",
    "DM_ATTACK_CHAINS_ACTIVE": "GATE (default OFF): would allow the E4 active counterfactual replay to confirm paths "
                               "passive E3 leaves inconclusive. Requires an explicit scope authorisation + the ADR-CF3 "
                               "allowlist / rules of engagement before any active request. NOT triggered by finalisation",
    "DM_HTTP_TAP": "reliable capture: route the sandbox's HTTP egress through a trusted recording proxy (api/http_tap) "
                   "that observes each exchange end-to-end and emits a transport-tap record — the ONLY provenance "
                   "qualify_records promotes to a proven direct. HTTPS is host-only (no MITM) -> inconclusive. With DM_TOOL_PROVENANCE on, each relayed "
                   "plain-HTTP exchange also feeds the run's provenance ledger (wire values fingerprinted: covers "
                   "$(curl …) substitutions). OFF by default: it reroutes the sandbox egress and needs "
                   "DARKMOON_TARGET_ALLOWLIST (docs/research/observed-paths.md)",
    "DM_HTTP_TAP_RECORD_ONLY": "with DM_HTTP_TAP: never block — an out-of-scope request is relayed unrecorded instead "
                               "of a proxy 403. Evaluated 16/11 and kept OFF: routing through a proxy is not "
                               "output-neutral (re-framed responses, curl -v shows the hop), so it cannot be token-neutral "
                               "(tools/research/observed_paths/tap_neutrality.py)",
    "DM_PCAP_CAPTURE": "passive capture -> run ledger: the MCP server parses the rotated pcap files a capture sidecar (sharing "
                       "the toolbox network namespace, docker-compose.pcap.yml, caps on the sidecar only) writes to "
                       "DM_PCAP_DIR, rebuilds the plain HTTP/1.x exchanges of the campaign's own commands and feeds them "
                       "to the run ledger exactly like the HTTP tap (api/pcap_capture). Nothing changes in the toolbox: "
                       "command outputs are byte-identical (token-neutral). HTTPS / HTTP/2 give nothing. Needs "
                       "DARKMOON_TARGET_ALLOWLIST; ignored while DM_HTTP_TAP is on. OFF by default (to be measured)",
    "DM_PCAP_BUDGET_MS": "integer: time budget of one capture ingestion (default 400 ms)",
    "DM_PCAP_SETTLE_MS": "integer: how long the ingestion after a command waits for its last packets (default 300 ms)",
    "DM_PCAP_MAX_AGE_S": "integer: raw capture files older than this are deleted, parsed or not (default 900 s)",
    "DM_CAMPAIGN_CAPTURE":"voie B: at the EXISTING execute_command provenance hook, record a MINIMISED structural "
                           "skeleton of each observed HTTP exchange per campaign (method, path-template, status, "
                           "principal anon/role, secret CLASSES, salted object/host fingerprints — never a value) so an "
                           "ordinary campaign with no lab tap can be qualified passively at finalisation. Best-effort "
                           "coverage; unobserved operations are counted, never guessed",
    # optional hybrid semantic validator (api/semantic_validator.py): called ONLY on ambiguous proofs, oracle
    # contradictions or N4 chain candidates — never per HTTP request. Deterministic core (always available); an OPTIONAL
    # LLM refinement runs on anonymised, value-free metadata only, routed through the Privacy Gateway, and can NEVER
    # promote a finding/chain to proven (only deterministic E3 oracles / authorised E4 counter-proofs do). OFF by default.
    "DM_SEMANTIC_VALIDATOR": "advisory semantic validator over ambiguous/contradictory/N4 evidence: returns "
                             "likely_valid / likely_false_positive / insufficient_evidence (+ evidence ids & missing "
                             "checks); never promotes to proven; deterministic if no LLM is wired or it is unavailable",
    # agent-native evidence tagging (api/evidence_annotations.py): the primary pentest agent publishes short, value-free
    # structured annotations (enum classification + server finding-id refs) through one MCP tool while it works. Stored
    # per campaign, bound to real finding ids, consumed ONLY as advisory context (finding hints, FP-suppression hints,
    # candidate N4 relations). No second LLM, no new engine. A tag NEVER promotes to proven, never creates an exchange,
    # never self-declares transport provenance, never triggers E4. OFF by default (no extra tool imposed on the agent).
    "DM_AGENT_EVIDENCE_TAGGING": "let the acting pentest agent record short enum-only evidence annotations (classification "
                                 "+ server finding-id refs + candidate causal relation) via one MCP tool; advisory context "
                                 "only, bound to real findings, never a proof and never an E4 trigger; deterministic oracles "
                                 "keep final authority",
    # expert-engine track (api/expert_engine/, docs/research/darkmoon-2027/17_expert_engine.md)
    "DM_EXPERT_ENGINE": "active deterministic expert engine: drives the toolbox (execute_command allowlist + Privacy "
                        "Gateway, read-only / auth requests only) over generic service rules OR an observation-only "
                        "data-flow arm, verifies each link with the local_causal counterfactual, no LLM; uncovered "
                        "cases fall back to a named existing agent (logged, counted)",
}

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

# ON unless the variable says otherwise (decision 16/11/2026, docs/research/observed-paths.md).
# DM_TOOL_PROVENANCE: the server-side record of what the MCP server itself observed (fingerprints only). It adds no
# model-visible text (architecture D removed the 40-paths-v2 EXEC ID line). Rollback: DM_TOOL_PROVENANCE=0.
DEFAULT_ON = frozenset({"DM_TOOL_PROVENANCE"})


def enabled(name: str) -> bool:
    """An explicit 1/true/yes/on or 0/false/no/off wins (case-insensitive); unset or malformed: ON only for DEFAULT_ON."""
    raw = str(os.environ.get(name, "")).strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return name in DEFAULT_ON


def int_value(name: str, default: int, lo: int, hi: int) -> int:
    """Integer flag, clamped to [lo, hi]; an unset or malformed value gives ``default``."""
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, v))
