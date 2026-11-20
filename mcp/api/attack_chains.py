"""
Darkmoon — structured attack-chain data (optional, backward compatible).

Why: findings used to carry no causal data. Infrastructure edges are containment
only, the tokens an agent reuses appear only in narrative logs (masked,
truncated), and the same weakness reported twice is never merged. The frontend
can therefore never prove "fixing X interrupts N chains" on a real campaign.

This module adds, WITHOUT changing any existing field:

1. Optional finding fields, validated and normalised at push time
   (``sanitize_chain_fields``):
     reached_assets[]     {node_id, access, proof_ref}
     produced_artifacts[] {ref, type, privilege}     ref = sha256(secret)[:16]
     prerequisites[]      {artifact_ref | kind, produced_by_finding_id?}
     negative_control     {unauthenticated_reproducible, proof_ref?}
     dedup_key            stable weakness id -> duplicate_of / dedup_group_id
   A raw secret is NEVER stored: a value that is not a hash is hashed here and
   discarded, and raw-value keys (value/secret/token/...) are stripped.

2. An optional ``darkmoon-attack-chains/v1`` block passed at finalisation
   (``parse_attack_chains_block``), validated strictly against THIS campaign.

3. Scenarios for ``GET /campaigns/{id}/infrastructure`` (``derive_scenarios``):
   the validated chains plus scenarios obtained by a plain JOIN of the finding
   fields (consumer prerequisites <-> producer produced_artifacts). No text is
   parsed, nothing is guessed: no structured data -> no scenario.

Pure functions only (no I/O) except where stated, so they are unit-testable.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SCHEMA = "darkmoon-attack-chains/v1"

ACCESS_KINDS = ("file_read", "cmd_exec", "db_read", "authenticated_as", "ssrf_response")
ARTIFACT_TYPES = ("token", "session", "credential", "account")
PREREQ_KINDS = ("self_registered", "anonymous", "supplied_credentials")
CRITICALITIES = ("critical", "high", "medium", "low", "info")
LIVE_EXCLUDED = ("false_positive", "remediated", "quarantined")
EVIDENCE_STATUSES = ("exploited", "confirmed")

# Keys under which an agent might (by mistake) send the secret itself.
RAW_SECRET_KEYS = (
    "value", "secret", "raw", "raw_value", "token", "password", "passwd",
    "cookie", "jwt", "api_key", "apikey", "key", "credential", "session",
)

_REF_RE = re.compile(r"^[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
# Free text that looks like a secret: a JWT, a long opaque token, a bearer value.
_SECRETISH = re.compile(
    r"eyJ[\w-]{6,}\.[\w-]{6,}(?:\.[\w-]*)?"           # JWT
    r"|(?i:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{12,}"  # Authorization values
    # long opaque blobs (letters AND digits, no path separator: slugs and paths are kept)
    r"|(?<![\w/=+-])(?=[\w+=-]*\d)(?=[\w+=-]*[A-Za-z])[\w+=-]{32,}(?![\w/=+-])"
)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def _normalise_secret(secret: str) -> str:
    s = str(secret).strip()
    # The reference is the hash of the value itself, not of the header scheme.
    return re.sub(r"^(?i:bearer|token|basic)\s+", "", s)


def artifact_ref(secret: str, key: Optional[bytes] = None) -> str:
    """Reference of a secret: first 16 hex chars of HMAC-SHA256(key, value) when a per-campaign key is given (P8
    RT-02, what the server uses at push time), else of sha256(value) (legacy / offline callers)."""
    v = _normalise_secret(secret).encode("utf-8")
    if key:
        import hmac as _hmac
        return _hmac.new(key, v, hashlib.sha256).hexdigest()[:16]
    return hashlib.sha256(v).hexdigest()[:16]


def normalise_ref(value: Any, key: Optional[bytes] = None) -> Tuple[Optional[str], bool]:
    """Return (ref, hashed_by_server).

    - 16 lowercase/uppercase hex chars -> accepted as is (lowercased);
    - a full sha256 (64 hex, optionally ``sha256:``) -> truncated to 16;
    - anything else is treated as a RAW secret sent by mistake: hashed here,
      the raw value is never returned nor stored.
    Limitation: a raw secret that is itself exactly 16 hex characters cannot be
    told apart from a reference and is stored as is (documented).
    """
    if value is None:
        return None, False
    s = str(value).strip()
    if not s:
        return None, False
    low = s.lower()
    if _REF_RE.match(low):
        return low, False
    m = _SHA256_RE.match(low)
    if m:
        return m.group(1)[:16], False
    return artifact_ref(s, key), True


def redact_text(text: Any, limit: int) -> Tuple[str, bool]:
    """Clip free text and replace anything that looks like a secret."""
    s = str(text or "")
    red = _SECRETISH.sub("[redacted]", s)
    return red[:limit], red != s


def _coerce_json(value: Any) -> Any:
    """LLM tool calls sometimes pass JSON as a string."""
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except ValueError:
            return value
    return value


def _as_list(value: Any) -> Optional[List[Any]]:
    value = _coerce_json(value)
    if value is None:
        return None
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    return None


def _strip_raw(item: Dict[str, Any]) -> Optional[str]:
    """Remove every raw-secret key from ``item``; return the first raw value."""
    raw = None
    for k in list(item.keys()):
        if k.lower() in RAW_SECRET_KEYS:
            v = item.pop(k)
            if raw is None and v not in (None, ""):
                raw = str(v)
    return raw


# ---------------------------------------------------------------------------
# 1. Finding fields (push time)
# ---------------------------------------------------------------------------

def sanitize_chain_fields(finding: Dict[str, Any], known_node_ids: Optional[Set[str]] = None,
                          ref_key: Optional[bytes] = None) -> List[str]:
    """Validate and normalise the optional chain fields of ``finding`` in place.

    Invalid entries are dropped (never fatal: an old agent or a malformed field
    must not lose the finding). Returns human-readable warnings, also stored in
    ``finding["chain_data_warnings"]`` when non-empty.
    """
    warnings: List[str] = []
    nodes = known_node_ids

    # reached_assets
    if "reached_assets" in finding:
        items = _as_list(finding.get("reached_assets"))
        out = []
        for i, it in enumerate(items or []):
            if not isinstance(it, dict):
                warnings.append(f"reached_assets[{i}] ignored: not an object")
                continue
            nid = str(it.get("node_id") or "").strip()
            access = str(it.get("access") or "").strip().lower()
            if not nid or access not in ACCESS_KINDS:
                warnings.append(f"reached_assets[{i}] ignored: node_id and access in {ACCESS_KINDS} are required")
                continue
            entry: Dict[str, Any] = {"node_id": nid, "access": access}
            if it.get("proof_ref"):
                proof, red = redact_text(it.get("proof_ref"), 300)
                entry["proof_ref"] = proof
                if red:
                    warnings.append(f"reached_assets[{i}].proof_ref: secret-looking value redacted")
            if nodes is not None and nid not in nodes:
                warnings.append(f"reached_assets[{i}].node_id '{nid}' is not a known node yet (checked again when read)")
            out.append(entry)
        if items is None and finding.get("reached_assets") not in (None, ""):
            warnings.append("reached_assets ignored: expected a list of objects")
        if out:
            finding["reached_assets"] = out
        else:
            finding.pop("reached_assets", None)

    # produced_artifacts
    if "produced_artifacts" in finding:
        items = _as_list(finding.get("produced_artifacts"))
        out = []
        for i, it in enumerate(items or []):
            if not isinstance(it, dict):
                warnings.append(f"produced_artifacts[{i}] ignored: not an object")
                continue
            it = dict(it)
            raw = _strip_raw(it)
            ref, hashed = normalise_ref(it.get("ref"), ref_key)
            if ref is None and raw is not None:
                ref, hashed = artifact_ref(raw, ref_key), True
            elif raw is not None:
                hashed = True
            if hashed:
                warnings.append(f"produced_artifacts[{i}]: raw secret received, hashed server-side and discarded")
            atype = str(it.get("type") or "").strip().lower()
            if not ref or atype not in ARTIFACT_TYPES:
                warnings.append(f"produced_artifacts[{i}] ignored: ref and type in {ARTIFACT_TYPES} are required")
                continue
            entry = {"ref": ref, "type": atype}
            if it.get("privilege"):
                priv, red = redact_text(it.get("privilege"), 64)
                entry["privilege"] = priv
                if red:
                    warnings.append(f"produced_artifacts[{i}].privilege: secret-looking value redacted")
            out.append(entry)
        if out:
            finding["produced_artifacts"] = out
        else:
            finding.pop("produced_artifacts", None)

    # prerequisites
    if "prerequisites" in finding:
        items = _as_list(finding.get("prerequisites"))
        out = []
        for i, it in enumerate(items or []):
            if not isinstance(it, dict):
                warnings.append(f"prerequisites[{i}] ignored: not an object")
                continue
            it = dict(it)
            raw = _strip_raw(it)
            ref, hashed = normalise_ref(it.get("artifact_ref"), ref_key)
            if ref is None and raw is not None:
                ref, hashed = artifact_ref(raw, ref_key), True
            elif raw is not None:
                hashed = True
            if hashed:
                warnings.append(f"prerequisites[{i}]: raw secret received, hashed server-side and discarded")
            kind = str(it.get("kind") or "").strip().lower() or None
            if kind is not None and kind not in PREREQ_KINDS:
                warnings.append(f"prerequisites[{i}].kind '{kind}' ignored: expected one of {PREREQ_KINDS}")
                kind = None
            producer = str(it.get("produced_by_finding_id") or "").strip() or None
            if not ref and not kind:
                warnings.append(f"prerequisites[{i}] ignored: artifact_ref or kind is required")
                continue
            entry: Dict[str, Any] = {}
            if ref:
                entry["artifact_ref"] = ref
            if kind:
                entry["kind"] = kind
            if producer:
                entry["produced_by_finding_id"] = producer[:64]
            out.append(entry)
        if out:
            finding["prerequisites"] = out
        else:
            finding.pop("prerequisites", None)

    # negative_control
    if "negative_control" in finding:
        nc = _coerce_json(finding.get("negative_control"))
        entry = None
        if isinstance(nc, dict) and "unauthenticated_reproducible" in nc:
            flag = nc.get("unauthenticated_reproducible")
            if isinstance(flag, str):
                flag = {"true": True, "false": False}.get(flag.strip().lower(), flag)
            if isinstance(flag, bool):
                entry = {"unauthenticated_reproducible": flag}
                if nc.get("proof_ref"):
                    proof, red = redact_text(nc.get("proof_ref"), 300)
                    entry["proof_ref"] = proof
                    if red:
                        warnings.append("negative_control.proof_ref: secret-looking value redacted")
        if entry is None and nc not in (None, "", {}):
            warnings.append("negative_control ignored: expected {unauthenticated_reproducible: true|false}")
        if entry:
            finding["negative_control"] = entry
        else:
            finding.pop("negative_control", None)

    # dedup_key
    if "dedup_key" in finding:
        key = re.sub(r"\s+", " ", str(finding.get("dedup_key") or "")).strip().lower()[:200]
        if key:
            red, changed = redact_text(key, 200)
            if changed:
                warnings.append("dedup_key: secret-looking value redacted")
            finding["dedup_key"] = red
        else:
            finding.pop("dedup_key", None)

    # node_id must reference an existing node; otherwise keep it (the read-time
    # resolver falls back to host/port/application) and flag it.
    nid = str(finding.get("node_id") or "").strip()
    if nid and nodes is not None and nid not in nodes:
        finding["node_id_unverified"] = True
        warnings.append(f"node_id '{nid}' is not a known node: attachment falls back to the resolver")
    else:
        finding.pop("node_id_unverified", None)

    if warnings:
        finding["chain_data_warnings"] = warnings
    else:
        finding.pop("chain_data_warnings", None)
    return warnings


def dedup_group_id(campaign_id: str, key: str) -> str:
    return "dup_" + hashlib.sha256(f"{campaign_id}\0{key}".encode("utf-8")).hexdigest()[:12]


def apply_dedup(finding: Dict[str, Any], existing: List[Dict[str, Any]], campaign_id: str) -> None:
    """Merge ``finding`` into the group of earlier findings with the same dedup_key.

    The first finding of a key is the canonical one; later ones get
    ``duplicate_of``. Every member carries ``dedup_group_id``. Nothing is
    deleted: counts and existing fields are unchanged.
    """
    key = finding.get("dedup_key")
    if not key:
        return
    gid = dedup_group_id(campaign_id, key)
    first = next((v for v in existing if v.get("dedup_key") == key and v.get("id") != finding.get("id")), None)
    finding["dedup_group_id"] = gid
    if first is not None:
        first["dedup_group_id"] = gid
        finding["duplicate_of"] = first.get("duplicate_of") or first.get("id")


# ---------------------------------------------------------------------------
# 2. darkmoon-attack-chains/v1 block (finalisation)
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"```darkmoon-attack-chains[ \t]*\r?\n([\s\S]*?)\r?\n```")


def parse_attack_chains_block(
    block: Optional[str],
    campaign_id: str,
    vulns: List[Dict[str, Any]],
    node_ids: Set[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """Parse and strictly validate the agent's chain block.

    Returns (valid_chains, issues). A chain is rejected (never repaired) when:
    the schema is not v1, it is not ``observed: true``, a finding id is not a
    finding of THIS campaign, a step has no alternative or an unknown node, the
    entry/objective do not match the first/last step, or no evidence finding is
    ``exploited``.
    """
    issues: List[Dict[str, str]] = []
    if not block or not str(block).strip():
        return [], issues
    text = str(block)
    bodies = [m.group(1) for m in _FENCE_RE.finditer(text)]
    if not bodies and text.strip().startswith("{"):
        bodies = [text.strip()]  # tolerate the JSON without its fence
    if not bodies:
        return [], [{"message": "no ```darkmoon-attack-chains block found"}]

    known = {str(v.get("id")): v for v in vulns if v.get("id")}
    chains: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for body in bodies:
        try:
            doc = json.loads(body)
        except ValueError as exc:
            issues.append({"message": f"invalid JSON: {exc}"})
            continue
        if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("chains"), list):
            issues.append({"message": f"schema missing or not {SCHEMA}"})
            continue
        if doc.get("campaign_id") not in (None, "", campaign_id):
            issues.append({"message": f"block is for campaign {doc.get('campaign_id')}, not {campaign_id}"})
            continue
        for raw in doc["chains"]:
            c = raw if isinstance(raw, dict) else {}
            cid = str(c.get("id") or "")

            def bad(msg: str) -> None:
                issues.append({"chain_id": cid[:64], "message": msg})

            if not _ID_RE.match(cid):
                bad("id missing or not [A-Za-z0-9_.:-]{1,64}")
                continue
            if cid in seen:
                bad("duplicate chain id")
                continue
            if c.get("observed") is not True:
                bad("observed is not true: only chains actually executed are accepted")
                continue
            crit = str(c.get("criticality") or "").lower()
            if crit not in CRITICALITIES:
                bad(f"criticality must be one of {CRITICALITIES}")
                continue
            steps = c.get("steps")
            if not isinstance(steps, list) or not steps:
                bad("steps must be a non-empty list")
                continue
            norm_steps = []
            ok = True
            for j, st in enumerate(steps):
                st = st if isinstance(st, dict) else {}
                nid = str(st.get("node_id") or "")
                alts = st.get("satisfied_by")
                if nid not in node_ids:
                    bad(f"steps[{j}].node_id '{nid}' is not a node of this campaign")
                    ok = False
                    break
                if (not isinstance(alts, list) or not alts
                        or any(not isinstance(a, list) or not a or any(not isinstance(x, str) for x in a) for a in alts)):
                    bad(f"steps[{j}].satisfied_by must be a non-empty list of non-empty lists of finding ids")
                    ok = False
                    break
                unknown = sorted({x for a in alts for x in a if x not in known})
                if unknown:
                    bad(f"steps[{j}] references finding(s) not in this campaign: {', '.join(unknown)}")
                    ok = False
                    break
                entry: Dict[str, Any] = {"node_id": nid, "satisfied_by": [sorted(set(a)) for a in alts]}
                if st.get("rationale"):
                    entry["rationale"] = redact_text(st.get("rationale"), 500)[0]
                norm_steps.append(entry)
            if not ok:
                continue
            entry_node = str(c.get("entry_node_id") or "")
            objective = str(c.get("objective_node_id") or "")
            if entry_node != norm_steps[0]["node_id"] or objective != norm_steps[-1]["node_id"]:
                bad("entry_node_id / objective_node_id must equal the first / last step node")
                continue
            evidence = c.get("evidence_vuln_ids")
            if not isinstance(evidence, list) or any(x not in known for x in evidence):
                bad("evidence_vuln_ids must list findings of this campaign")
                continue
            if not any(str(known[x].get("status", "")).lower() == "exploited" for x in evidence):
                bad("no evidence finding is exploited")
                continue
            seen.add(cid)
            chain = {
                "id": cid,
                "title": redact_text(c.get("title") or cid, 200)[0],
                "entry_node_id": entry_node,
                "objective_node_id": objective,
                "criticality": crit,
                "observed": True,
                "steps": norm_steps,
                "evidence_vuln_ids": sorted(set(evidence)),
            }
            chains.append(chain)
    return chains, issues


def render_report_section(chains: List[Dict[str, Any]], issues: List[Dict[str, str]],
                          node_labels: Dict[str, str], titles: Dict[str, str]) -> str:
    """Markdown section "## 5. ATTACK CHAINS" of the server-generated report."""
    if not chains and not issues:
        return ""
    L: List[str] = ["---\n\n<!-- dm-section: attack-chains -->\n## 5. ATTACK CHAINS\n\n"]
    L.append("> Chains declared by the agents at finalisation (`darkmoon-attack-chains/v1`) and "
             "validated by the server against this campaign's findings. Only chains actually executed "
             "(`observed: true`, at least one exploited finding as evidence) are listed.\n\n")
    if not chains:
        L.append("_No declared chain passed validation._\n\n")

    def fid(x: str) -> str:
        t = titles.get(x)
        return f"`{x}` ({t[:60]})" if t else f"`{x}`"

    for i, c in enumerate(chains, 1):
        L.append(f"### 5.{i} — {c['title']}\n\n")
        path = " → ".join(node_labels.get(s["node_id"], s["node_id"]) for s in c["steps"])
        L.append(f"**Criticality:** {c['criticality'].upper()}  \n**Path:** {path}  \n")
        L.append(f"**Evidence:** {', '.join(fid(x) for x in c['evidence_vuln_ids'])}\n\n")
        L.append("| Step | Asset | Satisfied by (any line; all ids of a line) | Rationale |\n")
        L.append("|------|-------|------------------------------------------|-----------|\n")
        for j, s in enumerate(c["steps"], 1):
            alts = " OR ".join(" + ".join(f"`{x}`" for x in a) for a in s["satisfied_by"])
            why = str(s.get("rationale") or "").replace("|", "\\|").replace("\n", " ")
            L.append(f"| {j} | {node_labels.get(s['node_id'], s['node_id'])} | {alts} | {why} |\n")
        L.append("\n")
    if issues:
        L.append(f"_{len(issues)} declared chain(s) or block(s) rejected by validation:_\n\n")
        for it in issues[:20]:
            cid = f"`{it['chain_id']}`: " if it.get("chain_id") else ""
            L.append(f"- {cid}{it['message']}\n")
        L.append("\n")
    return "".join(L)


# ---------------------------------------------------------------------------
# 3. Scenarios for /infrastructure (read time)
# ---------------------------------------------------------------------------

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}


def _max_sev(vulns: Iterable[Dict[str, Any]]) -> str:
    best = "info"
    for v in vulns:
        s = str(v.get("severity") or "info").lower()
        if _SEV_RANK.get(s, 9) < _SEV_RANK.get(best, 9):
            best = s
    return best if best in CRITICALITIES else "info"


def remediation_groups(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Server duplicate groups (same dedup_key) with at least two live findings."""
    groups: Dict[str, Dict[str, Any]] = {}
    for v in vulns:
        if str(v.get("status", "")).lower() in LIVE_EXCLUDED or not v.get("id"):
            continue
        gid = v.get("dedup_group_id")
        if not gid or not v.get("dedup_key"):
            continue
        g = groups.setdefault(gid, {"id": gid, "dedup_key": v["dedup_key"], "finding_ids": []})
        if v["id"] not in g["finding_ids"]:
            g["finding_ids"].append(v["id"])
    out = []
    for g in sorted(groups.values(), key=lambda x: x["id"]):
        if len(g["finding_ids"]) >= 2:
            g["finding_ids"].sort()
            g["reason"] = f"same weakness reported {len(g['finding_ids'])} times (server dedup_key \"{g['dedup_key']}\")"
            out.append(g)
    return out


def derive_scenarios(
    campaign: Dict[str, Any],
    nodes: List[Dict[str, Any]],
    vulns: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Server scenarios (provenance ``server``) for the frontend engine.

    ``nodes`` must already carry ``vulnerability_ids`` (``_enrich_infrastructure``),
    so a finding's step node is the asset it is attached to on the map.
    """
    node_ids = {n["id"] for n in nodes if n.get("id")}
    attached: Dict[str, str] = {}
    for n in nodes:
        for vid in n.get("vulnerability_ids") or []:
            attached.setdefault(vid, n["id"])
    live = {str(v["id"]): v for v in vulns
            if v.get("id") and str(v.get("status", "")).lower() not in LIVE_EXCLUDED}
    excluded = {str(v["id"]) for v in vulns if v.get("id")} - set(live)
    issues: List[Dict[str, Any]] = []

    for v in live.values():
        nid = str(v.get("node_id") or "").strip()
        if nid and nid not in node_ids:
            issues.append({"kind": "unknown-node-id", "finding_id": v["id"],
                           "message": f"node_id '{nid}' does not exist; attached by the resolver to '{attached.get(v['id'])}'"})

    scenarios: List[Dict[str, Any]] = []

    # 3a. validated chains declared at finalisation (re-checked against today's data)
    chain_objectives: Set[str] = set()
    block = campaign.get("attack_chains") or {}
    for c in block.get("chains") or []:
        steps = []
        alive = True
        for s in c.get("steps") or []:
            if s.get("node_id") not in node_ids:
                alive = False
                issues.append({"kind": "chain-node-missing", "scenario_id": f"chain:{c.get('id')}",
                               "message": f"node {s.get('node_id')} no longer exists; chain ignored"})
                break
            # An AND-set containing an already remediated / false-positive finding is already broken.
            alts = [a for a in s.get("satisfied_by") or [] if not any(x in excluded for x in a)]
            if not alts:
                alive = False
                issues.append({"kind": "chain-already-interrupted", "scenario_id": f"chain:{c.get('id')}",
                               "message": "every alternative of a step is remediated or false positive; chain already interrupted"})
                break
            steps.append({"node_id": s["node_id"], "satisfied_by": alts, "rationale": s.get("rationale") or ""})
        if not alive or not steps:
            continue
        for x in steps[-1]["satisfied_by"]:
            chain_objectives.update(x)
        scenarios.append({
            "id": f"chain:{c['id']}",
            "title": c.get("title") or c["id"],
            "entry_node_id": steps[0]["node_id"],
            "objective_node_id": steps[-1]["node_id"],
            "criticality": c.get("criticality", "info"),
            "observed": True,
            "provenance": "server",
            "source": "attack_chains_block",
            "steps": steps,
            "evidence_vuln_ids": [x for x in c.get("evidence_vuln_ids") or [] if x in live],
        })

    # 3b. JOIN of the finding fields
    producers_of: Dict[str, Set[str]] = {}
    for v in live.values():
        for a in v.get("produced_artifacts") or []:
            if isinstance(a, dict) and a.get("ref"):
                producers_of.setdefault(a["ref"], set()).add(v["id"])

    def resolve_prereq(consumer: Dict[str, Any], p: Dict[str, Any]) -> Tuple[Optional[Set[str]], str]:
        ref = p.get("artifact_ref")
        kind = p.get("kind")
        if not ref and kind in ("anonymous", "supplied_credentials"):
            return None, ""  # no weakness of the campaign is needed
        prods: Set[str] = set()
        if ref:
            prods |= producers_of.get(ref, set())
        pb = p.get("produced_by_finding_id")
        if pb:
            if pb in live:
                prods.add(pb)
            else:
                issues.append({"kind": "unknown-producer", "finding_id": consumer["id"],
                               "message": f"produced_by_finding_id {pb} is not a live finding of this campaign"})
        prods.discard(consumer["id"])
        keep = {x for x in prods if str(live[x].get("status", "")).lower() in EVIDENCE_STATUSES}
        if prods - keep:
            issues.append({"kind": "unproven-producer", "finding_id": consumer["id"],
                           "message": f"producer(s) {', '.join(sorted(prods - keep))} not exploited/confirmed; ignored"})
        if not keep:
            what = f"artifact {ref}" if ref else (kind or "prerequisite")
            issues.append({"kind": "unresolved-prerequisite", "finding_id": consumer["id"],
                           "message": f"{what} is produced by no exploited/confirmed finding of this campaign"})
            return set(), ""
        label = f"reuses {ref}" if ref else ("self-registered account" if kind == "self_registered" else "prerequisite")
        return keep, label

    def prereq_steps(consumer_id: str, stack: Tuple[str, ...], inlined: Set[str]) -> Optional[List[Dict[str, Any]]]:
        """Steps that give ``consumer_id`` its prerequisites; None if one cannot be resolved."""
        consumer = live[consumer_id]
        steps: List[Dict[str, Any]] = []
        unauth = (consumer.get("negative_control") or {}).get("unauthenticated_reproducible") is True
        for p in consumer.get("prerequisites") or []:
            prods, label = resolve_prereq(consumer, p)
            if prods is None:
                continue
            if not prods:
                return None
            ordered = sorted(prods)
            # A single producer that itself depends on something: fold its chain in.
            if len(ordered) == 1 and ordered[0] not in stack and len(stack) < 6:
                upstream = prereq_steps(ordered[0], stack + (ordered[0],), inlined)
                if upstream:
                    steps.extend(upstream)
                    inlined.add(ordered[0])
            alts = [[x] for x in ordered]
            why = f"{consumer_id} {label} produced by {', '.join(ordered)}"
            if unauth:
                # Negative control: the consumer also works without it -> not a necessary dependency.
                alts.append([consumer_id])
                why += "; also reproducible without authentication (negative control), so not necessary"
            node = attached.get(ordered[0]) or f"unresolved:{ordered[0]}"
            # RT-04: the link is only CLAIMED by the consumer's fields; attack_paths checks it against server evidence
            steps.append({"node_id": node, "satisfied_by": alts, "rationale": why,
                          "_claim": {"kind": "reuse", "producers": ordered, "consumer": consumer_id,
                                     "artifact_ref": p.get("artifact_ref"), "prereq_kind": p.get("kind")}})
        return steps

    inlined_global: Set[str] = set()
    joins: List[Dict[str, Any]] = []
    claims: Dict[str, List[Dict[str, Any]]] = {}
    for cid in sorted(live):
        c = live[cid]
        if str(c.get("status", "")).lower() not in EVIDENCE_STATUSES:
            continue
        if not c.get("prerequisites") and not c.get("reached_assets"):
            continue
        inlined: Set[str] = set()
        steps = prereq_steps(cid, (cid,), inlined)
        if steps is None:
            continue
        own_node = attached.get(cid) or f"unresolved:{cid}"
        steps.append({"node_id": own_node, "satisfied_by": [[cid]],
                      "rationale": f"exploitation of {cid} ({c.get('category') or 'finding'})"})
        for r in c.get("reached_assets") or []:
            rn = r.get("node_id")
            if rn not in node_ids:
                issues.append({"kind": "unknown-reached-node", "finding_id": cid,
                               "message": f"reached_assets node '{rn}' does not exist; step ignored"})
                continue
            if rn == steps[-1]["node_id"]:
                continue
            proof = f" ({r['proof_ref']})" if r.get("proof_ref") else ""
            steps.append({"node_id": rn, "satisfied_by": [[cid]], "rationale": f"{r.get('access')} on {rn} proven by {cid}{proof}",
                          "_claim": {"kind": "reach", "finding": cid, "node_id": rn, "access": r.get("access"),
                                     "proof_ref": r.get("proof_ref")}})
        if len(steps) < 2:
            continue  # a lone finding with no dependency and no reach is not a chain
        inlined_global |= inlined
        claims[f"join:{cid}"] = [st.pop("_claim") for st in steps if "_claim" in st]
        ids = sorted({x for s in steps for a in s["satisfied_by"] for x in a})
        joins.append({
            "id": f"join:{cid}",
            "title": f"{c.get('title') or cid}",
            "entry_node_id": steps[0]["node_id"],
            "objective_node_id": steps[-1]["node_id"],
            "criticality": _max_sev(live[x] for x in ids if x in live),
            "observed": True,
            "provenance": "server",
            "source": "finding_fields",
            "steps": steps,
            "evidence_vuln_ids": [x for x in ids if str(live[x].get("status", "")).lower() in EVIDENCE_STATUSES],
            "_consumer": cid,
        })
    # P7 fix 5 (P2-D1, flag DM_DERIVE_KEEP_REACHED_OBJECTIVE): an inlined producer whose own chain ends on a
    # reached_assets objective (not its own node) used to be dropped with that objective, which then appeared in no
    # proven path. Under the flag it is kept unless a kept chain that contains it already reaches the same objective.
    from api import feature_flags
    keep_reached = feature_flags.enabled("DM_DERIVE_KEEP_REACHED_OBJECTIVE")
    deferred: List[Dict[str, Any]] = []
    for j in joins:
        cid = j.pop("_consumer")
        if cid in chain_objectives:
            continue  # the agent declared this chain explicitly: the declaration wins
        if cid in inlined_global:
            if keep_reached and j["objective_node_id"] != (attached.get(cid) or f"unresolved:{cid}"):
                deferred.append(dict(j, _consumer=cid))
            continue  # already the upstream part of a longer chain
        scenarios.append(j)
    for j in deferred:
        cid = j.pop("_consumer")
        covered = any(s.get("source") == "finding_fields" and s["objective_node_id"] == j["objective_node_id"]
                      and any(cid in a for st in s["steps"] for a in st["satisfied_by"]) for s in scenarios)
        if not covered:
            scenarios.append(j)

    return {
        "scenarios": scenarios,
        "remediation_groups": remediation_groups(list(live.values())),
        "scenario_issues": issues,
        # RT-04 (P8): what each derived (finding_fields) scenario rests on: agent CLAIMS, corroborated by the server
        # (attack_paths._corroborate) before the path may count as proven. Never returned by /infrastructure.
        "claims": {sid: claims[sid] for sid in (sc["id"] for sc in scenarios) if sid in claims},
    }
