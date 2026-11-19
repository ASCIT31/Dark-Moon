"""
JSON Schema of ``darkmoon-attack-paths/v1`` (list, detail and simulation documents).

``validate(doc, schema)`` uses ``jsonschema`` when it is installed and falls back to a small
validator covering the keywords used here (type, required, properties, items, enum, const,
pattern, minimum). Additional properties are allowed: the contract is additive.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

SEVERITY = {"enum": ["critical", "high", "medium", "low", "info", "none"]}
# « inferred » (revision 1.3): a possible path deduced from topology + findings, always hypothesis: true
PROVENANCE = {"enum": ["declared", "derived", "observed", "inferred", "agent-declared"]}
PATH_ID = {"type": "string", "pattern": "^ap_[0-9a-f]{12}$"}
STR_LIST = {"type": "array", "items": {"type": "string"}}
NODE_REF = {"type": "object", "required": ["node_id", "label"], "properties": {"node_id": {"type": "string"}, "label": {"type": "string"}}}

# 40-paths-v2: level of a declared link (decided by api/edge_verifier), of an R1-R3
# server rule (« observed ») and of a finalisation chain (« declared »)
LINK_STATES = ["declared_unverified", "observed_flow", "causal_necessity_demonstrated"]
LINK_REASONS = ["not_declared", "cross_run", "unknown_execution", "execution_after_push", "no_execution_ids",
                "value_not_consumed", "ambiguous_origin", "exogenous_value", "consumer_not_success", "duplicate_finding",
                "cycle", "depth_exceeded"]
# architecture D, additive: the default state of a declared link,
# the two states of a declaration that is never an edge of a path, and their closed reason sets
D_LINK_STATES = ["declared_by_agent", "invalidated", "rejected_declaration"]
D_LINK_REASONS = ["finding_not_live", "missing_data", "run_compacted", "session_unknown", "no_shared_value",
                  "several_findings", "unknown_finding", "self_reference", "ambiguous_reference", "forward_reference",
                  "same_weakness"] + [f"{role}_{why}" for role in ("producer", "consumer")
                                      for why in ("false_positive", "remediated", "withdrawn", "merged")]
PATH_LEVEL = {"enum": ["observed", "declared", "declared_by_agent", "inferred"] + LINK_STATES}
VERIFICATION = {"type": "object", "required": ["state", "reason", "evidence_refs"],
                "properties": {"state": {"enum": LINK_STATES + D_LINK_STATES},
                               "reason": {"enum": LINK_REASONS + D_LINK_REASONS + [None]},
                               "evidence_refs": {"type": "object"}}}
OBSERVED_LINK = {
    "type": "object", "required": ["kind", "producers", "consumer", "usage", "necessity", "ranked", "level"],
    "properties": {
        "kind": {"enum": ["R1", "R2", "R3", "D"]}, "producers": {"type": "array", "items": {"type": "string"}},
        "consumer": {"type": "string"}, "usage": {"enum": ["observed", "evidence", "declared"]},
        "necessity": {"enum": ["demonstrated", "not_demonstrated", "intrinsic", "not_assessed"]},
        "ranked": {"type": "boolean"}, "level": {"enum": ["observed", "inferred"] + LINK_STATES + D_LINK_STATES},
        "provenance": {"enum": ["inferred"]},
        "verification": VERIFICATION,
    },
}

FINDING_REF = {
    "type": "object",
    "required": ["id", "title", "severity", "status", "cvss_score", "evidence_meta"],
    "properties": {
        "id": {"type": "string"}, "title": {"type": "string"}, "severity": SEVERITY, "status": {"type": "string"},
        "cvss_score": {"type": "number"},
        "evidence_meta": {"type": "object", "required": ["commands", "requests", "has_extracted_data"],
                          "properties": {"commands": {"type": "integer", "minimum": 0}, "requests": {"type": "integer", "minimum": 0},
                                         "has_extracted_data": {"type": "boolean"}}},
    },
}
STEP = {
    "type": "object",
    "required": ["n", "node_id", "node_label", "plain", "satisfied_by", "findings", "produces", "requires", "why", "first_seen_at"],
    "properties": {
        "n": {"type": "integer", "minimum": 1}, "node_id": {"type": "string"}, "node_label": {"type": "string"},
        "plain": {"type": "string"}, "why": {"type": "string"},
        "satisfied_by": {"type": "array", "items": STR_LIST},
        "findings": {"type": "array", "items": FINDING_REF},
        "produces": {"type": "array", "items": {"type": "object", "required": ["artifact_ref"],
                                                "properties": {"artifact_ref": {"type": "string", "pattern": "^[0-9a-f]{16}$"}}}},
        "requires": {"type": "array", "items": {"type": "object"}},
        "first_seen_at": {"type": ["string", "null"]},
        "kind": {"enum": ["exposure", "hop", "exploit", "objective"]}, "rule": {"type": "string"}, "inferred": {"const": True},
        "tactics": {"type": "array", "items": {"type": "object", "required": ["id", "name"]}},
        "fix": {"type": ["object", "null"], "required": ["finding_id", "label"]},
        "impact": {"type": ["object", "null"], "required": ["label", "rule", "source"],
                   "properties": {"label": {"type": "string"}, "rule": {"enum": ["entry", "R1", "R2", "R3", "D", "sink"]},
                                  "source": {"enum": ["observed-rule", "declared-by-agent", "server-verified", "inferred-rule"]},
                                  "level": {"enum": LINK_STATES + D_LINK_STATES + ["inferred"]},
                                  "reason": {"enum": LINK_REASONS + D_LINK_REASONS}}},
    },
}
EDGE = {"type": "object", "required": ["from", "to", "type", "observed"],
        "properties": {"from": {"type": "string"}, "to": {"type": "string"}, "type": {"const": "reaches"},
                       "finding_id": {"type": ["string", "null"]}, "observed": {"type": "boolean"}, "inferred": {"const": True}}}
INFERENCE = {
    "type": "object", "required": ["rule", "rule_label", "capability", "findings_certainty", "lead_finding_id"],
    "properties": {"rule": {"enum": ["I-EXEC", "I-CRED", "I-SESSION", "I-DATA", "I-UPLOAD"]}, "rule_label": {"type": "string"},
                   "capability": {"type": "string"}, "findings_certainty": {"enum": ["exploited", "confirmed"]},
                   "lead_finding_id": {"type": "string"}},
}
PATH = {
    "type": "object",
    "required": ["id", "title", "objective", "entry", "criticality", "certainty", "provenance", "hypothesis",
                 "steps_count", "finding_ids", "breaks_if_fixed", "status"],
    "properties": {
        "id": PATH_ID, "title": {"type": "string"},
        "objective": {"type": "object", "required": ["node_id", "label", "criticality", "criticality_source"],
                      "properties": {"node_id": {"type": "string"}, "label": {"type": "string"}, "criticality": SEVERITY,
                                     "criticality_source": {"enum": ["agent", "user", "default"]}}},
        "entry": NODE_REF, "criticality": SEVERITY,
        "certainty": {"enum": ["exploited", "confirmed", "unconfirmed"]},
        "provenance": PROVENANCE, "hypothesis": {"type": "boolean"},
        "steps_count": {"type": "integer", "minimum": 1}, "finding_ids": STR_LIST,
        "breaks_if_fixed": {"type": "array", "items": STR_LIST},
        "status": {"enum": ["open", "interrupted_by_retest"]},
        "steps": {"type": "array", "items": STEP}, "edges": {"type": "array", "items": EDGE},
        "node_ids": STR_LIST, "note": {"type": ["string", "null"]}, "inference": INFERENCE,
        # weakest link of the path: declared_unverified < observed_flow < observed (R1-R3) < causal_necessity_demonstrated
        "level": PATH_LEVEL, "level_label": {"type": "string"},
        "assembly": {"type": "object", "properties": {"chains_stop": {"enum": [None, "count", "time", "depth"]}}},
    },
}
FIX = {
    "type": "object",
    "required": ["fix_id", "label", "finding_ids", "interrupts", "interrupts_count", "of_total",
                 "objectives_closed", "objectives_still_reachable"],
    "properties": {
        "rank": {"type": "integer", "minimum": 1}, "fix_id": {"type": "string"}, "label": {"type": "string"},
        "finding_ids": STR_LIST, "interrupts": {"type": "array", "items": PATH_ID},
        "interrupts_count": {"type": "integer", "minimum": 0}, "of_total": {"type": "integer", "minimum": 0},
        "objectives_closed": STR_LIST, "objectives_still_reachable": STR_LIST,
        "tie_break": {"type": ["string", "null"]},
    },
}
LIST_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["schema_version", "campaign_id", "generated_at", "demo", "summary", "paths", "ranking", "issues"],
    "properties": {
        "schema_version": {"const": "darkmoon-attack-paths/v1"},
        "campaign_id": {"type": "string"}, "generated_at": {"type": "string"}, "demo": {"type": "boolean"},
        "summary": {
            "type": "object",
            "required": ["paths_total", "critical_paths", "objectives_reachable", "provenances", "coverage"],
            "properties": {
                "paths_total": {"type": "integer", "minimum": 0}, "critical_paths": {"type": "integer", "minimum": 0},
                "objectives_reachable": STR_LIST, "provenances": {"type": "array", "items": PROVENANCE},
                # « proven » = observed flow: paths with no hypothesis, every link at least observed_flow (or an R1-R3
                # server rule); NOT causal necessity (that is the link level causal_necessity_demonstrated)
                "proven_paths": {"type": "integer", "minimum": 0},
                "declared_paths": {"type": "integer", "minimum": 0}, "declared_critical_paths": {"type": "integer", "minimum": 0},
                "inferred_paths": {"type": "integer", "minimum": 0}, "inferred_critical_paths": {"type": "integer", "minimum": 0},
                "findings_on_inferred_paths": {"type": "integer", "minimum": 0},
                "coverage": {"type": "object", "required": ["findings_total", "findings_on_paths", "findings_without_node"],
                             "properties": {k: {"type": "integer", "minimum": 0} for k in ("findings_total", "findings_on_paths", "findings_without_node")}},
            },
        },
        "paths": {"type": "array", "items": PATH},
        "ranking": {
            "type": "object", "required": ["allowed", "provenance", "note", "fixes"],
            "properties": {"allowed": {"type": "boolean"}, "provenance": {"type": ["string", "null"]},
                           "note": {"type": ["string", "null"]}, "fixes": {"type": "array", "items": FIX},
                           "pivots": {"type": "array", "items": FIX}},
        },
        "issues": {"type": "array", "items": {"type": "object", "required": ["kind"], "properties": {"kind": {"type": "string"}}}},
        "note": {"type": ["string", "null"]},
        "observed_links": {"type": "array", "items": OBSERVED_LINK},
    },
}
DETAIL_SCHEMA: Dict[str, Any] = {
    "type": "object", "required": ["schema_version", "path"],
    "properties": {"schema_version": {"const": "darkmoon-attack-paths/v1"},
                   "path": {**PATH, "required": PATH["required"] + ["steps", "edges"]}},
}
SIMULATION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["schema_version", "simulation", "label", "removed", "interrupted", "still_open", "objectives_reachable", "cut_at"],
    "properties": {
        "schema_version": {"const": "darkmoon-attack-paths/v1"}, "simulation": {"const": True},
        "label": {"const": "SIMULATION · not applied"}, "removed": STR_LIST,
        "interrupted": {"type": "array", "items": PATH_ID}, "still_open": {"type": "array", "items": PATH_ID},
        "objectives_reachable": STR_LIST, "cut_at": {"type": "object"},
        # FAIL-CLOSED admissibility: "verified" → the certified fields below are present; "unavailable" → the
        # admissibility check failed and the certified fields are ABSENT (never raw figures under certified names).
        "admissibility": {"enum": ["verified", "unavailable"]},
        # certified fields — present only when admissibility == "verified": the non-admissible consequences among the
        # removed findings, and the coverage attributable to the ADMISSIBLE removals alone (a consequence's graph-cut is
        # never read as real coverage).
        "non_admissible": STR_LIST,
        "interrupted_admissible": {"type": "array", "items": PATH_ID}, "paths_after_admissible": {"type": "integer", "minimum": 0},
        # P7 fix 6 (P2-D2), optional and additive: the same counts restricted to proven paths (no hypothesis)
        "proven_interrupted": {"type": "array", "items": PATH_ID}, "proven_still_open": {"type": "array", "items": PATH_ID},
        "proven_paths_before": {"type": "integer", "minimum": 0}, "proven_paths_after": {"type": "integer", "minimum": 0},
    },
}

_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _type_ok(value: Any, t: str) -> bool:
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[t])


def _check(value: Any, schema: Dict[str, Any], path: str, errors: List[str]) -> None:
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, t) for t in types):
            errors.append(f"{path}: expected {types}, got {type(value).__name__}")
            return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if "minimum" in schema and isinstance(value, (int, float)) and value < schema["minimum"]:
        errors.append(f"{path}: below minimum")
    if isinstance(value, dict):
        for k in schema.get("required", []):
            if k not in value:
                errors.append(f"{path}: missing {k}")
        for k, sub in (schema.get("properties") or {}).items():
            if k in value:
                _check(value[k], sub, f"{path}.{k}", errors)
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _check(item, schema["items"], f"{path}[{i}]", errors)


def validate(doc: Any, schema: Dict[str, Any]) -> List[str]:
    """Return the list of validation errors (empty when valid)."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        errors: List[str] = []
        _check(doc, schema, "$", errors)
        return errors
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in validator.iter_errors(doc)]
