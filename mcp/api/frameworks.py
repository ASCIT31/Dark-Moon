"""
Darkmoon - framework views, schema ``darkmoon-frameworks/v1`` (ISO 27001 · ATT&CK · EBIOS RM · MITRE ATLAS).

Server-side pure functions; the only I/O is reading the vendored tables in ``frameworks_data/`` and the
ATT&CK extract in ``vendor/mitre_attack/`` (the single ATT&CK directory: one licence, one NOTICE;
provenance, sha256 and licences in frameworks_data/README-PROVENANCE.md). Nothing is invented:

- ATT&CK: IDs from findings; names/tactics/revoked-by from the vendored MITRE table (Enterprise 20.0).
- Feasibility: per finding, Darkmoon scale DM-FEAS-1 (F1-F4). It is NOT an EBIOS RM likelihood.
- EBIOS RM (ANSSI, fiche methode 8, atelier 4): only candidate technical paths with a PROPOSED upper bound of the
  technical difficulty and a PROPOSED likelihood (grid column, indicative); probability of success, gravity, feared
  events, risk sources and strategic scenarios come from the owner/RSSI or stay "to_assess".
- ATLAS: only AI findings (closed vocabulary), via a curated crosswalk checked against ATLAS 2026.10.
- ISO 27001: version detection of the agent's free text only; no ISO text, no 2013->2022 conversion.

Every public function tolerates malformed input: bad elements go to ``issues`` (never an exception).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SCHEMA_VERSION = "darkmoon-frameworks/v1"
DATA = Path(__file__).parent / "frameworks_data"
ATTACK_DIR = Path(__file__).parent / "vendor" / "mitre_attack"
EXCLUDED = ("false_positive", "remediated")
CERTAINTIES = ("exploited", "confirmed", "unconfirmed")


@lru_cache(maxsize=None)
def _load(name: str, base: Optional[Path] = None) -> Dict[str, Any]:
    return json.loads(((base or DATA) / name).read_text(encoding="utf-8"))


def attack_catalog() -> Dict[str, Any]:
    return _load("attack-enterprise-20.0.min.json", ATTACK_DIR)


def atlas_catalog() -> Dict[str, Any]:
    return _load("atlas-2026.10.min.json")


def llm_crosswalk() -> Dict[str, Any]:
    return _load("llm-atlas-crosswalk.json")


def _d(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _l(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def _s(x: Any) -> str:
    return x.strip() if isinstance(x, str) else ""


def _status(v: Dict[str, Any]) -> str:
    s = _s(_d(v).get("status")).lower() or "unconfirmed"
    return s if s in CERTAINTIES or s in EXCLUDED else "unconfirmed"


def held(v: Any) -> bool:
    """Held by the strict privacy policy (quarantined, not reviewed by an operator).
    Same rule as live_push.is_quarantined: counted nowhere (Fix first, paths, report, breakdowns, here)."""
    return isinstance(v, dict) and bool(v.get("quarantined")) and not v.get("quarantine_reviewed_by")


def live(vulns: Any) -> List[Dict[str, Any]]:
    return [v for v in _l(vulns) if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]
            and _status(v) not in EXCLUDED and not held(v)]


def _norm_title(t: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _s(t).lower()).strip()


# ---------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------

_MAX_REVOKE_HOPS = 5


def attack_ref(v: Dict[str, Any]) -> Dict[str, Any]:
    tid = _s(_d(v).get("mitre_attack_id")).upper()
    if not tid or tid == "NONE":
        return {"state": "missing"}
    techs = attack_catalog()["techniques"]
    t = techs.get(tid)
    if t is None:
        return {"state": "unknown", "id": tid}
    agent_name = _s(_d(v).get("mitre_attack_name")).lower()
    if t["revoked"]:
        # follow the official revoked-by chain (T1073 -> T1574.002 -> T1574.001), bounded and cycle-safe
        chain, cur = [tid], t
        while cur.get("revoked") and cur.get("revoked_by") and len(chain) <= _MAX_REVOKE_HOPS:
            nxt = cur["revoked_by"]
            if nxt in chain or nxt not in techs:
                break
            chain.append(nxt)
            cur = techs[nxt]
        if cur.get("revoked") or len(chain) == 1:
            return {"state": "revoked", "id": tid, "name": t["display_name"], "replaced_by": None, "revoked_chain": chain}
        differs = bool(agent_name) and agent_name not in (cur["name"].lower(), cur["display_name"].lower(),
                                                          t["name"].lower(), t["display_name"].lower())
        return {"state": "revoked_replaced", "agent_id": tid, "id": chain[-1], "name": cur["display_name"],
                "tactics": list(cur["tactics"]), "agent_name_differs": differs, "revoked_chain": chain,
                "note": f"agent ID {tid} revoked; mapped to {chain[-1]} via MITRE revoked-by"
                        + (f" ({' -> '.join(chain)})" if len(chain) > 2 else "")}
    differs = bool(agent_name) and agent_name not in (t["name"].lower(), t["display_name"].lower())
    if t["deprecated"]:
        return {"state": "deprecated", "id": tid, "name": t["display_name"]}
    return {"state": "valid", "id": tid, "name": t["display_name"], "tactics": list(t["tactics"]),
            "agent_name_differs": differs}


def _duplicate_rep(rows: List[Dict[str, Any]]) -> Dict[str, str]:
    """finding id -> representative id of its strict duplicate group (attack_paths_observed.group_duplicate_findings)."""
    rep = {v["id"]: v["id"] for v in rows}
    try:
        from api.attack_paths_observed import group_duplicate_findings
        for g in group_duplicate_findings(rows):
            ids = sorted(_l(g.get("finding_ids")))
            for i in ids:
                if i in rep:
                    rep[i] = ids[0]
    except Exception:  # pragma: no cover - grouping is an enhancement, never a failure
        pass
    return rep


def attack_matrix(vulns: Any) -> Dict[str, Any]:
    cat = attack_catalog()
    rows = live(vulns)
    rep = _duplicate_rep(rows)
    cells: Dict[Tuple[str, str], Dict[str, Any]] = {}
    cov = {"findings": len(rows), "valid": 0, "revoked_replaced": 0, "missing": 0, "unknown": 0, "revoked": 0,
           "deprecated": 0}
    issues = []
    for v in rows:
        ref = attack_ref(v)
        cov[ref["state"]] += 1
        if ref.get("agent_name_differs"):
            issues.append({"finding_id": v["id"], "kind": "agent-technique-name-differs", "id": ref["id"],
                           "agent_name": _s(v.get("mitre_attack_name"))[:120], "official_name": ref["name"]})
        if ref["state"] not in ("valid", "revoked_replaced"):
            if ref["state"] != "missing":
                issues.append({"finding_id": v["id"], "kind": f"attack-id-{ref['state']}", "id": ref.get("id")})
            continue
        if ref["state"] == "revoked_replaced":
            issues.append({"finding_id": v["id"], "kind": "attack-id-revoked-replaced", "id": ref["agent_id"],
                           "replaced_by": ref["id"], "chain": ref["revoked_chain"]})
        for tac in ref["tactics"]:
            c = cells.setdefault((tac, ref["id"]), {"technique_id": ref["id"], "technique_name": ref["name"],
                                                    "finding_ids": [], "via_revoked_by": [],
                                                    "by_certainty": {k: 0 for k in CERTAINTIES}})
            c["finding_ids"].append(v["id"])
            c["by_certainty"][_status(v)] += 1
            if ref["state"] == "revoked_replaced":
                c["via_revoked_by"].append(v["id"])
    for c in cells.values():
        c["distinct_findings"] = len({rep[f] for f in c["finding_ids"]})
    tactics = []
    for t in cat["tactics_in_matrix_order"]:
        techs = sorted((c for (tac, _), c in cells.items() if tac == t["shortname"]),
                       key=lambda c: (-c["distinct_findings"], c["technique_id"]))
        ids = {f for c in techs for f in c["finding_ids"]}
        tactics.append({**t, "findings": len(ids), "distinct_findings": len({rep[f] for f in ids}), "techniques": techs})
    return {"schema_version": SCHEMA_VERSION, "framework": cat["framework"], "version": cat["version"],
            "license": cat["license"], "copyright": cat["copyright"], "source_sha256": cat["source_sha256"],
            "coverage": cov, "tactics": tactics, "counts_not_additive": True, "issues": issues,
            "reading": "Techniques observed in findings. Counts are distinct findings (strict duplicates merged). A technique "
                       "can belong to several tactics, so tactic totals do not add up. A tactic without findings means "
                       "'not observed in this campaign', never 'protected'."}


# ---------------------------------------------------------------------------
# Prerequisite + feasibility (Darkmoon rule DM-FEAS-1) - NOT an EBIOS likelihood
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# CVSS base metrics (all required) and allowed values; optional (temporal / environmental / supplemental) metric names.
_V3 = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}
_V3_OPT = {"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
_V4 = {"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN",
       "SC": "HLN", "SI": "HLN", "SA": "HLN"}
_V4_OPT = {"E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
           "S", "AU", "R", "V", "RE", "U"}


def parse_vector(vec: Any) -> Dict[str, Any]:
    """Strict CVSS parser: every base metric present once with a legal value, no unknown metric.
    state: ok | absent | invalid | unsupported."""
    if vec is None or (isinstance(vec, str) and not vec.strip()):
        return {"state": "absent"}
    if not isinstance(vec, str):
        return {"state": "invalid", "reason": "not a string"}
    parts = vec.strip().split("/")
    head = parts[0]
    if head not in ("CVSS:3.0", "CVSS:3.1", "CVSS:4.0"):
        known = re.fullmatch(r"CVSS:\d\.\d", head)
        return {"state": "unsupported" if known else "invalid"}
    spec, opt = (_V4, _V4_OPT) if head == "CVSS:4.0" else (_V3, _V3_OPT)
    m: Dict[str, str] = {}
    for p in parts[1:]:
        if ":" not in p:
            return {"state": "invalid", "reason": "malformed metric"}
        k, val = p.split(":", 1)
        if k in m:
            return {"state": "invalid", "reason": f"duplicate metric {k}"}
        if k not in spec and k not in opt:
            return {"state": "invalid", "reason": f"unknown metric {k}"}
        if not re.fullmatch(r"[A-Z]", val):
            return {"state": "invalid", "reason": f"metric {k}"}
        m[k] = val
    for k, allowed in spec.items():
        if k not in m or m[k] not in allowed:
            return {"state": "invalid", "reason": f"base metric {k} missing or out of domain"}
    return {"state": "ok", "version": head[5:], "m": m}


# Credentials seen in the proof: a SIGNAL to review, never a prerequisite. Anchored on an HTTP
# header at the start of a request line, a curl -H header, curl --cookie / -b, or curl -u user:pass. Scanner flags
# (nuclei -u URL, sqlmap -u URL) are not credentials. Forged tokens (JWT alg none) and placeholders are excluded.
_HDR_LINE = re.compile(r"(?im)^\s*(authorization|proxy-authorization|cookie|x-api-key)\s*:\s*(.*)$")
_CURL_H = re.compile(r"(?i)-H\s*['\"]\s*(authorization|cookie|x-api-key)\s*:\s*([^'\"]*)['\"]")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*")


def _jwt_alg(token: str) -> Optional[str]:
    try:
        head = token.split(".")[0]
        head += "=" * (-len(head) % 4)
        return str(json.loads(base64.urlsafe_b64decode(head.encode()).decode("utf-8", "replace")).get("alg", "")).lower()
    except Exception:
        return None


def _value_is_forged_or_placeholder(value: str) -> Optional[str]:
    if re.search(r"<[^>]{1,60}>", value) or re.search(r"(?i)\b(stolen|forged|attacker|placeholder|redacted)\b", value):
        return "placeholder"
    for tok in _JWT.findall(value):
        if _jwt_alg(tok) == "none":
            return "forged_jwt_alg_none"
    return None


def proof_credentials_signal(v: Dict[str, Any]) -> Dict[str, Any]:
    """{seen, kinds, excluded}: did the proof request/commands carry credentials? Review signal only."""
    ev = _d(_d(v).get("evidence"))
    texts = [_s(ev.get("raw_request"))] + [c for c in _l(ev.get("commands")) if isinstance(c, str)]
    kinds: List[str] = []
    excluded: List[str] = []

    def take(kind: str, value: str) -> None:
        why = _value_is_forged_or_placeholder(value)
        (excluded if why else kinds).append(f"{kind}:{why}" if why else kind)

    for t in texts:
        if not t:
            continue
        for m in _HDR_LINE.finditer(t):
            take(m.group(1).lower(), m.group(2))
        for line in t.splitlines():
            if not re.match(r"^\s*(sudo\s+)?curl\b", line):
                continue
            for m in _CURL_H.finditer(line):
                take(m.group(1).lower(), m.group(2))
            for m in re.finditer(r"(?:\s--cookie|\s-b)\s+(['\"]?)([^\s'\"]+=[^'\"]*)\1", line):
                take("cookie", m.group(2))
            for m in re.finditer(r"\s(?:-u|--user)\s+(['\"]?)([^\s'\":/]+:(?!//)[^\s'\"]+)\1", line):
                take("basic_user_password", m.group(2))
    return {"seen": bool(kinds), "kinds": sorted(set(kinds)), "excluded": sorted(set(excluded))}


# Explicit prerequisite declared by the agent (closed vocabulary). A self-
# registrable account is a negligible-effort prerequisite: it does not count as an obstacle.
PREREQ_VOCAB = {"none": False, "account_self_registrable": False, "account": True, "privileged_account": True,
                "user_interaction": True, "network_position": True, "local_access": True}


def prerequisite(v: Dict[str, Any]) -> Dict[str, Any]:
    """Prerequisite to exploit, with its basis: agent-declared prerequisites (closed vocabulary), else the agent's
    strictly-parsed CVSS vector, else unknown. Credentials seen in the proof are exposed as a signal only."""
    v = _d(v)
    signal = proof_credentials_signal(v)
    decl = v.get("prerequisites")
    if isinstance(decl, list) and decl and all(isinstance(x, str) and x in PREREQ_VOCAB for x in decl):
        return {"required": any(PREREQ_VOCAB[x] for x in decl), "trivial": None, "basis": "agent_declared",
                "declared": sorted(set(decl)), "credentials_seen_in_proof": signal}
    pv = parse_vector(v.get("cvss_vector"))
    if pv["state"] != "ok":
        return {"required": None, "trivial": None, "basis": f"vector_{pv['state']}", "credentials_seen_in_proof": signal}
    m = pv["m"]
    req = m["AV"] != "N" or m["PR"] != "N" or m["UI"] != "N" or m.get("AT", "N") != "N"
    return {"required": req, "trivial": m["AC"] == "L", "basis": f"agent_cvss_{pv['version']}",
            "metrics": {k: m[k] for k in ("AV", "AC", "PR", "UI", "AT") if k in m}, "credentials_seen_in_proof": signal}


FEAS_LABELS = {4: "Exploitée sans prérequis", 3: "Exploitée avec prérequis (ou prérequis inconnu)",
               2: "Vérifiée, triviale, non exploitée", 1: "Vérifiée, non exploitée"}


def feasibility(v: Dict[str, Any], pre: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Darkmoon rule DM-FEAS-1 'Faisabilité technique démontrée' (F1-F4), a Darkmoon scale, not ANSSI:
    F4 exploited and no prerequisite; F3 exploited with a prerequisite or unknown prerequisite;
    F2 verified (not exploited), no prerequisite, low complexity; F1 verified otherwise;
    unconfirmed -> not rated (a lead is not evidence)."""
    st = _status(v)
    pre = pre or prerequisite(v)
    if st == "unconfirmed":
        return {"level": None, "label": "non cotée (piste)", "rule": "DM-FEAS-1/unconfirmed", "prerequisite": pre}
    if st == "exploited":
        lvl = 4 if pre["required"] is False else 3
    else:
        lvl = 2 if (pre["required"] is False and pre.get("trivial")) else 1
    return {"level": lvl, "label": FEAS_LABELS[lvl], "rule": "DM-FEAS-1", "prerequisite": pre}


def finding_type_key(v: Dict[str, Any]) -> Optional[str]:
    """Same finding type across campaigns: a real CVE, else normalised title + ATT&CK technique."""
    v = _d(v)
    c = _s(v.get("cve")).upper()
    if _CVE_RE.match(c):
        return f"cve:{c}"
    t = _norm_title(v.get("title"))
    tid = _s(v.get("mitre_attack_id")).upper()
    return f"type:{t}|{tid}" if t else None


def feasibility_index(vulns: Any, scope: Any = None) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Feasibility for each live finding of ``vulns``. The prerequisite is consolidated over ``scope`` (default:
    ``vulns``; the API passes every campaign of the project) per finding type (real CVE, else title + technique), on
    the DEFENDER side: if any member shows no prerequisite, the type has none (highest feasibility); the conflict is
    reported with every value (issue same_type_different_prereq), never resolved silently."""
    rows = live(vulns)
    pool = {v["id"]: v for v in live(scope)} if scope is not None else {}
    pool.update({v["id"]: v for v in rows})
    pre = {i: prerequisite(v) for i, v in pool.items()}
    groups: Dict[str, List[str]] = {}
    for i, v in pool.items():
        k = finding_type_key(v)
        if k:
            groups.setdefault(k, []).append(i)
    issues: List[Dict[str, Any]] = []
    wanted = {v["id"] for v in rows}
    for key, ids in sorted(groups.items()):
        if len(ids) < 2:
            continue
        known = [pre[i] for i in ids if pre[i]["required"] is not None]
        reqs = {p["required"] for p in known}
        trivs = {p.get("trivial") for p in known if p["required"] is False}
        if not known or (len(reqs) == 1 and len(trivs) <= 1 and len(known) == len(ids)):
            continue
        chosen_req = False if False in reqs else True
        chosen_triv = True if True in trivs else (False if trivs else None)
        conflict = len(reqs) > 1 or len(trivs) > 1
        if conflict and set(ids) & wanted:
            issues.append({"kind": "same_type_different_prereq", "type": key, "finding_ids": sorted(set(ids) & wanted),
                           "other_campaign_findings": len(set(ids) - wanted),
                           "values": sorted({(str(pre[i]["required"]), pre[i]["basis"]) for i in ids}),
                           "retained": "defender side: no prerequisite" if chosen_req is False else "prerequisite"})
        for i in ids:
            own = pre[i]
            pre[i] = {**own, "required": chosen_req, "trivial": chosen_triv if chosen_req is False else own.get("trivial"),
                      "consolidated_by_type": key, "own": {"required": own["required"], "basis": own["basis"]},
                      "basis": own["basis"] if own["required"] == chosen_req else "consolidated_by_type"}
    return {v["id"]: feasibility(v, pre[v["id"]]) for v in rows}, issues


def min_attacker_profile(v: Dict[str, Any]) -> Optional[str]:
    """Minimum attacker position (input for workshop 2, NOT a risk source). From the agent CVSS only."""
    pv = parse_vector(_d(v).get("cvss_vector"))
    if pv["state"] != "ok":
        return None
    m = pv["m"]
    if m["AV"] in ("L", "P"):
        return "local_access"
    if m["AV"] == "A":
        return "adjacent_network"
    return {"N": "external_unauthenticated", "L": "authenticated_user", "H": "privileged_user"}[m["PR"]]


# ---------------------------------------------------------------------------
# EBIOS RM - candidate technical paths for workshop 4 (ANSSI fiche methode 8)
# ---------------------------------------------------------------------------

# Scales quoted from ANSSI, Guide EBIOS Risk Manager, Fiche methode 8 - Atelier 4 "Evaluer la
# vraisemblance des scenarios operationnels" (generic scales, adaptable per study).
V_LABELS = {0: "Invraisemblable", 1: "Peu vraisemblable", 2: "Vraisemblable", 3: "Très vraisemblable", 4: "Quasi-certain"}
PR_LABELS = {0: "Très faible", 1: "Faible", 2: "Significative", 3: "Très élevée", 4: "Quasi-certaine"}
DIF_LABELS = {0: "Négligeable", 1: "Faible", 2: "Modérée", 3: "Élevée", 4: "Très élevée"}
G_LABELS = {1: "Mineure", 2: "Significative", 3: "Grave", 4: "Critique"}
# Crossed grid of fiche 8: GRID[probability of success][technical difficulty] -> likelihood
GRID = {4: [4, 4, 3, 2, 1], 3: [4, 3, 3, 2, 1], 2: [3, 3, 2, 2, 1], 1: [2, 2, 2, 1, 0], 0: [1, 1, 1, 0, 0]}
# DM-DIF-1: an UPPER BOUND of the technical difficulty, demonstrated by the pentest. Exploited
# without prerequisite -> at most Négligeable; exploited with prerequisite, or verified trivial -> at most Faible.
# Verified but not exploited (F1) -> NOT proposed: an absence of exploitation proves no difficulty level.
FEAS_TO_DIF: Dict[int, Optional[int]] = {4: 0, 3: 1, 2: 1, 1: None}
CRITERIA = ("D", "I", "C", "T")
CRITERIA_LABELS = {"D": "Disponibilité", "I": "Intégrité", "C": "Confidentialité", "T": "Traçabilité"}
EBIOS_SOURCE = ("ANSSI, Guide EBIOS Risk Manager - Fiche méthode 8, Atelier 4 « Évaluer la vraisemblance des "
                "scénarios opérationnels » (échelles génériques, grille croisée, règle Max/Min de la méthode avancée)")
EBIOS_DISCLAIMER = ("Matière technique pour l'atelier 4 uniquement. Ce ne sont pas des scénarios opérationnels EBIOS RM : "
                    "ils doivent être rattachés à un scénario stratégique (source de risque, objectif visé, valeur métier). "
                    "Probabilité de succès, vraisemblance retenue, gravité et événements redoutés relèvent du RSSI / propriétaire.")
LIKELIHOOD_NOTE = ("Fiche 8 : la vraisemblance obtenue par la grille peut être augmentée d'un niveau selon la nature de la "
                   "source de risque (décision du RSSI) ; la grille est adaptable par l'étude ; au-delà d'une dizaine "
                   "d'actions élémentaires, la difficulté cumulée est sous-estimée. Proposition indicative, jamais une cotation.")
PR_NOTE = ("Probabilité de succès globale du mode opératoire, à évaluer par le RSSI (défense, supervision, réaction) "
           "selon la règle Min/Max de la fiche 8 ; un pentest ne la mesure pas.")

# Owner-input limits
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
LINK_KEY_RE = re.compile(r"^lk_[0-9a-f]{16}$")
MAX_LABEL = 200
MAX_ITEMS = 100
MAX_LINKS = 50


def _int_level(x: Any, lo: int, hi: int) -> Optional[int]:
    return x if isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi else None


def _label(x: Any) -> Optional[str]:
    """A bounded single-line label, or None when invalid (wrong type, empty, too long, control characters)."""
    if not isinstance(x, str):
        return None
    s = x.strip()
    if not s or len(s) > MAX_LABEL or re.search(r"[\x00-\x1f\x7f]", s):
        return None
    return s


def _unique_items(raw: Any, field: str, issues: List[Dict[str, Any]], parse) -> Dict[str, Dict[str, Any]]:
    """Parse a list of {id, ...}. Duplicate ids are REJECTED (none of them kept) and reported."""
    if raw is None:
        return {}
    if not isinstance(raw, list):
        issues.append({"kind": "context-invalid", "field": field, "message": f"{field} must be a list"})
        return {}
    if len(raw) > MAX_ITEMS:
        issues.append({"kind": "context-invalid", "field": field, "message": f"at most {MAX_ITEMS} items"})
        return {}
    seen: Dict[str, int] = {}
    parsed: List[Tuple[str, Dict[str, Any]]] = []
    for i, item in enumerate(raw):
        it = _d(item)
        iid = it.get("id")
        if not isinstance(iid, str) or not ID_RE.match(iid):
            issues.append({"kind": f"{field}-invalid", "index": i, "message": "id: 1-32 characters [A-Za-z0-9._-]"})
            continue
        out = parse(it, i)
        if out is None:
            continue
        seen[iid] = seen.get(iid, 0) + 1
        parsed.append((iid, out))
    dups = sorted(k for k, n in seen.items() if n > 1)
    for k in dups:
        issues.append({"kind": f"{field}-duplicate-id", "id": k,
                       "message": f"{seen[k]} entries share the id {k}: none is kept (merge them explicitly)"})
    return {iid: out for iid, out in parsed if iid not in dups}


def validate_context(ctx: Any, known_link_keys: Optional[Set[str]] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Owner/RSSI EBIOS context of a project. Strict types; invalid entries are dropped and reported, never coerced.

    ``known_link_keys``: every link_key of the project's campaigns; a feared event or assessment pointing elsewhere
    is reported (``feared-event-unlinked`` / ``stale_owner_link``), never dropped silently."""
    out: Dict[str, Any] = {"business_values": {}, "risk_sources": {}, "feared_events": {}, "path_assessments": {},
                           "updated_by": None, "updated_at": None, "revision": 0}
    issues: List[Dict[str, Any]] = []
    if ctx is None:
        return out, issues
    if not isinstance(ctx, dict):
        return out, [{"kind": "context-invalid", "message": "context must be an object"}]
    # author and date are server-stamped (never read from a request body: see routes_frameworks)
    out["updated_by"] = _label(ctx.get("updated_by"))
    out["updated_at"] = _label(ctx.get("updated_at"))
    out["revision"] = _int_level(ctx.get("revision"), 0, 10 ** 9) or 0

    def p_value(it, i):
        lab = _label(it.get("label"))
        if lab is None:
            issues.append({"kind": "business_values-invalid", "index": i, "message": f"label: text of 1-{MAX_LABEL} characters"})
            return None
        return {"id": it["id"], "label": lab}

    def p_source(it, i):
        lab = _label(it.get("label"))
        obj = it.get("objective")
        objv = _label(obj) if obj is not None else None
        if lab is None or (obj is not None and objv is None):
            issues.append({"kind": "risk_sources-invalid", "index": i,
                           "message": f"label (and optional objective): text of 1-{MAX_LABEL} characters"})
            return None
        return {"id": it["id"], "label": lab, "objective": objv}

    out["business_values"] = _unique_items(ctx.get("business_values"), "business_values", issues, p_value)
    out["risk_sources"] = _unique_items(ctx.get("risk_sources"), "risk_sources", issues, p_source)

    def p_event(it, i):
        g = _int_level(it.get("gravity"), 1, 4)
        crit = it.get("criterion")
        keys = it.get("link_keys")
        lab = _label(it.get("label"))
        bv = it.get("business_value")
        bad = []
        if g is None:
            bad.append("gravity: integer 1-4")
        if not isinstance(crit, str) or crit not in CRITERIA:
            bad.append("criterion: one of D, I, C, T")
        if lab is None:
            bad.append(f"label: text of 1-{MAX_LABEL} characters")
        if not isinstance(keys, list) or len(keys) > MAX_LINKS or not all(isinstance(k, str) and LINK_KEY_RE.match(k) for k in keys):
            bad.append(f"link_keys: list of at most {MAX_LINKS} path link keys (lk_ + 16 hex)")
        if bv is not None and (not isinstance(bv, str) or bv not in out["business_values"]):
            bad.append("business_value: id of a declared business value")
        if bad:
            issues.append({"kind": "feared-event-invalid", "index": i, "id": it.get("id"), "message": "; ".join(bad)})
            return None
        keys = list(dict.fromkeys(keys))
        if not keys:
            issues.append({"kind": "feared-event-unlinked", "id": it["id"], "link_keys": [],
                           "message": "no attack path linked: the gravity applies to no candidate path"})
        elif known_link_keys is not None and set(keys) - known_link_keys:
            issues.append({"kind": "feared-event-unlinked", "id": it["id"],
                           "link_keys": sorted(set(keys) - known_link_keys),
                           "message": "linked to a path key that no campaign of this project produces"})
        return {"id": it["id"], "label": lab, "gravity": g, "criterion": crit, "business_value": bv, "link_keys": keys}

    out["feared_events"] = _unique_items(ctx.get("feared_events"), "feared_events", issues, p_event)
    for k in [k for k in issues if k.get("kind") == "feared_events-invalid"]:
        k["kind"] = "feared-event-invalid"
    for k in [k for k in issues if k.get("kind") == "feared_events-duplicate-id"]:
        k["kind"] = "feared-event-duplicate-id"

    pa = ctx.get("path_assessments")
    if pa is not None and not isinstance(pa, dict):
        issues.append({"kind": "context-invalid", "message": "path_assessments must be an object"})
        pa = {}
    if len(_d(pa)) > MAX_ITEMS:
        issues.append({"kind": "context-invalid", "message": f"path_assessments: at most {MAX_ITEMS} paths"})
        pa = {}
    for key, a in _d(pa).items():
        if not isinstance(key, str) or not LINK_KEY_RE.match(key):
            issues.append({"kind": "path-assessment-invalid", "link_key": str(key)[:40], "message": "key must be a path link key"})
            continue
        if not isinstance(a, dict):
            issues.append({"kind": "path-assessment-invalid", "link_key": key, "message": "assessment must be an object"})
            continue
        unknown = sorted(set(a) - {"probability_of_success", "risk_source_adjustment", "likelihood_validated",
                                   "strategic_scenario", "risk_source"})
        pr = _int_level(a.get("probability_of_success"), 0, 4)
        adj = _int_level(a.get("risk_source_adjustment"), 0, 1)
        lv = _int_level(a.get("likelihood_validated"), 0, 4)
        ss_raw, sr_raw = a.get("strategic_scenario"), a.get("risk_source")
        ss = _label(ss_raw) if ss_raw is not None else None
        bad = []
        if unknown:
            bad.append(f"unknown fields {unknown}")
        if a.get("probability_of_success") is not None and pr is None:
            bad.append("probability_of_success: integer 0-4")
        if a.get("risk_source_adjustment") is not None and adj is None:
            bad.append("risk_source_adjustment: 0 or 1 (fiche 8: at most one level, RSSI decision)")
        if a.get("likelihood_validated") is not None and lv is None:
            bad.append("likelihood_validated: integer 0-4")
        if ss_raw is not None and ss is None:
            bad.append(f"strategic_scenario: text of 1-{MAX_LABEL} characters")
        if sr_raw is not None and (not isinstance(sr_raw, str) or sr_raw not in out["risk_sources"]):
            bad.append("risk_source: id of a declared risk source")
        if bad:
            issues.append({"kind": "path-assessment-invalid", "link_key": key, "message": "; ".join(bad)})
            continue
        if known_link_keys is not None and key not in known_link_keys:
            issues.append({"kind": "stale_owner_link", "link_key": key,
                           "message": "assessment of a path that no campaign of this project produces any more"})
        out["path_assessments"][key] = {"pr": pr, "adj": adj or 0, "v": lv, "strategic_scenario": ss,
                                        "risk_source": sr_raw}
    return out, issues


def _merge_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in steps:
        if out and out[-1]["technique_id"] == s["technique_id"] and out[-1]["finding_ids"] == s["finding_ids"]:
            out[-1]["merged_steps"].append(s["n"])
            continue
        out.append({**s, "merged_steps": [s["n"]]})
    return out


def _finding_fingerprint(v: Dict[str, Any]) -> str:
    c = _s(v.get("cve")).upper()
    if _CVE_RE.match(c):
        return c
    return _s(v.get("category")).lower() or _norm_title(v.get("title")) or "?"


def link_key(objective_type: str, steps: List[Dict[str, Any]], vmap: Dict[str, Dict[str, Any]]) -> str:
    """Content key of a path, independent of the campaign: objective node type, ordered ATT&CK
    techniques of the merged steps, sorted set of finding fingerprints (CVE, else category). Same weakness chain on
    the next campaign of the project -> same key, so owner inputs carry over."""
    techs = [s["technique_id"] or "?" for s in steps]
    prints = sorted({_finding_fingerprint(vmap[f]) for s in steps for f in s["finding_ids"] if f in vmap})
    raw = "\x1f".join(["v1", objective_type or "?", ">".join(techs), "|".join(prints)])
    return "lk_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def candidate_ref(key: str) -> str:
    return "CAND-" + key[3:9].upper()


def _likelihood(dif: Optional[int], a: Dict[str, Any], hypothesis: bool, unrated: bool) -> Dict[str, Any]:
    if dif is None:
        why = ("hypothesis path" if hypothesis else "a step rests on a lead (unconfirmed finding)" if unrated
               else "a step is verified but not exploited: its difficulty is not demonstrated (DM-DIF-1)")
        return {"state": "not_proposed", "reason": why, "note": LIKELIHOOD_NOTE}
    pr = a.get("pr")
    if pr is None:
        col = {str(p): GRID[p][dif] for p in range(4, -1, -1)}
        return {"state": "indicative_grid_column", "grid_column": col,
                "labels": {k: V_LABELS[x] for k, x in col.items()},
                "reason": "probability of success (defence, supervision, reaction) not measured by the pentest: "
                          "to assess by the RSSI", "note": LIKELIHOOD_NOTE}
    base = GRID[pr][dif]
    adj = a.get("adj") or 0
    lvl = min(4, base + adj)
    return {"state": "proposed", "base_level": base, "risk_source_adjustment": adj, "level": lvl, "label": V_LABELS[lvl],
            "reason": "fiche 8 crossed grid from the RSSI probability of success and the proposed difficulty bound"
                      + (", +1 for the risk source (RSSI decision)" if adj else ""), "note": LIKELIHOOD_NOTE}


def ebios_view(paths_doc: Any, vulns: Any, context: Any = None, scope: Any = None,
               known_link_keys: Optional[Set[str]] = None, nodes: Any = None) -> Dict[str, Any]:
    """``paths_doc`` = attack_paths.build_paths(..., include_steps=True). ``scope`` = the project's findings (cross-
    campaign consolidation of the feasibility). ``known_link_keys`` = link keys of every campaign of the project."""
    issues: List[Dict[str, Any]] = []
    feas, cve_issues = feasibility_index(vulns, scope)
    issues += cve_issues
    vmap = {v["id"]: v for v in live(vulns)}
    ntype = {_s(n.get("id")): _s(n.get("node_type")) for n in _l(nodes) if isinstance(n, dict)}
    candidates, single, on_path = [], [], set()
    built: List[Tuple[Dict[str, Any], Dict[str, Any], List[Optional[int]], bool]] = []
    for p in _l(_d(paths_doc).get("paths")):
        if not isinstance(p, dict) or not _s(p.get("id")):
            issues.append({"kind": "path-invalid", "message": "path without id ignored"})
            continue
        if p.get("status") != "open":
            continue
        raw_steps, step_dif, unrated = [], [], False
        for s in _l(p.get("steps")):
            s = _d(s)
            alts = [[x for x in _l(a) if isinstance(x, str) and x in vmap] for a in _l(s.get("satisfied_by"))]
            alts = [a for a in alts if a]
            # ANSSI dual rule on difficulty: an alternative needs all its findings (max), the attacker takes the easiest (min)
            difs = []
            for a in alts:
                fl = [feas[x]["level"] for x in a]
                unrated = unrated or any(f is None for f in fl)
                db = [FEAS_TO_DIF.get(f) if f is not None else None for f in fl]
                difs.append(None if any(d is None for d in db) else max(db))
            known = [d for d in difs if d is not None]
            step_dif.append(min(known) if known else None)
            tech = s.get("technique")
            tid = _s(tech.get("id")) if isinstance(tech, dict) else _s(tech)
            ref = attack_ref({"mitre_attack_id": tid})
            fids = sorted({x for a in alts for x in a})
            raw_steps.append({"n": s.get("n"), "node_label": _s(s.get("node_label"))[:200] or None,
                              "technique_id": ref.get("id"), "technique_name": ref.get("name"), "tactics": ref.get("tactics", []),
                              "proof": _s(s.get("proof")) or None, "finding_ids": fids,
                              "feasibility": {f: feas[f]["level"] for f in fids},
                              "difficulty_bound": step_dif[-1]})
            on_path.update(fids)
        steps = _merge_steps(raw_steps)
        obj = _d(p.get("objective"))
        key = link_key(ntype.get(_s(obj.get("node_id")), ""), steps, vmap)
        built.append((p, {"steps": steps, "key": key, "obj": obj}, step_dif, unrated))
    key_count: Dict[str, int] = {}
    for _, b, _, _ in built:
        key_count[b["key"]] = key_count.get(b["key"], 0) + 1
    ctx, ctx_issues = validate_context(context, known_link_keys)
    issues += ctx_issues
    for p, b, step_dif, unrated in built:
        steps, key, obj = b["steps"], b["key"], b["obj"]
        ambiguous = key_count[key] > 1
        distinct_tech = {s["technique_id"] for s in steps if s["technique_id"]}
        pid = _s(p["id"])
        base = {"candidate_id": candidate_ref(key), "link_key": key, "link_key_ambiguous": ambiguous, "path_id": pid,
                "title": _s(p.get("title"))[:300] or None, "provenance": p.get("provenance"),
                "certainty": p.get("certainty"), "hypothesis": bool(p.get("hypothesis")),
                "objective": {"node_id": _s(obj.get("node_id")) or None, "label": _s(obj.get("label"))[:200] or None},
                "steps": steps}
        if len(steps) < 2 or len(distinct_tech) < 2:
            single.append({**base, "reason": "fewer than 2 distinct steps/techniques after merging: a single exploited "
                                             "weakness, not an attack sequence"})
            continue
        if ambiguous:
            issues.append({"kind": "link_key_ambiguous", "link_key": key, "path_id": pid,
                           "message": "two open paths of this campaign have the same content: owner inputs are not applied"})
        hyp = bool(p.get("hypothesis"))
        dif = None if (hyp or any(d is None for d in step_dif)) else max(step_dif)
        a = {} if ambiguous else ctx["path_assessments"].get(key, {})
        lk = _likelihood(dif, a, hyp, unrated)
        if a.get("v") is not None:
            lk = {**lk, "validated": {"level": a["v"], "label": V_LABELS[a["v"]], "state": "owner_validated",
                                      "by": ctx["updated_by"], "at": ctx["updated_at"]}}
        fes = [] if ambiguous else [fe for fe in ctx["feared_events"].values() if key in fe["link_keys"]]
        if fes:
            top = max(fes, key=lambda fe: (fe["gravity"], fe["id"]))
            grav = {"state": "owner_assessed", "level": top["gravity"], "label": G_LABELS[top["gravity"]],
                    "feared_events": sorted(({"id": fe["id"], "label": fe["label"], "gravity": fe["gravity"],
                                              "gravity_label": G_LABELS[fe["gravity"]], "criterion": fe["criterion"],
                                              "criterion_label": CRITERIA_LABELS[fe["criterion"]],
                                              "business_value": fe["business_value"]} for fe in fes), key=lambda x: x["id"]),
                    "by": ctx["updated_by"], "at": ctx["updated_at"]}
        else:
            grav = {"state": "to_assess", "level": None, "label": "À évaluer par le métier"}
        v_ok = _d(lk.get("validated")).get("level")
        pr = a.get("pr")
        candidates.append({**base,
                           "difficulty_proposed": {"state": "proposed_upper_bound" if dif is not None else "not_proposed",
                                                   "level": dif, "label": DIF_LABELS.get(dif) if dif is not None else None,
                                                   "rule": "DM-DIF-1 (upper bound) + fiche 8 Max/Min"},
                           "probability_of_success": ({"state": "owner_assessed", "level": pr, "label": PR_LABELS[pr], "note": PR_NOTE}
                                                      if pr is not None else {"state": "to_assess", "level": None, "note": PR_NOTE}),
                           "likelihood": lk, "gravity": grav,
                           "strategic_scenario": a.get("strategic_scenario"), "risk_source": a.get("risk_source"),
                           "risk": ({"gravity": grav["level"], "likelihood": v_ok, "state": "owner_validated"}
                                    if (grav["state"] == "owner_assessed" and v_ok is not None and a.get("strategic_scenario")) else None)})
    unlinked = [{"finding_id": fid, "title": _s(v.get("title"))[:300] or None, "severity": _s(v.get("severity")) or None,
                 "status": _status(v), "technique": attack_ref(v), "feasibility": feas[fid],
                 "min_attacker_profile": min_attacker_profile(v)}
                for fid, v in vmap.items() if fid not in on_path]
    fdist = {"F4": 0, "F3": 0, "F2": 0, "F1": 0, "not_rated": 0}
    for f in feas.values():
        fdist[f"F{f['level']}" if f["level"] else "not_rated"] += 1
    return {"schema_version": SCHEMA_VERSION,
            "method": "EBIOS Risk Manager (ANSSI) - technical input for workshop 4", "source": EBIOS_SOURCE,
            "scales": {"likelihood": V_LABELS, "probability_of_success": PR_LABELS, "technical_difficulty": DIF_LABELS,
                       "gravity": G_LABELS, "grid": GRID, "feasibility_DM_FEAS_1": FEAS_LABELS,
                       "feasibility_to_difficulty_bound_DM_DIF_1": FEAS_TO_DIF, "criteria": CRITERIA_LABELS},
            "candidate_paths": candidates, "single_step_paths": single, "unlinked_vulnerabilities": unlinked,
            "feasibility_distribution": fdist,
            # additive: the DM-FEAS-1 level of EVERY live finding, on a path or not
            "feasibility_by_finding": {fid: {"level": f["level"], "label": f["label"]} for fid, f in feas.items()},
            "context": {"business_values": list(ctx["business_values"].values()),
                        "risk_sources": list(ctx["risk_sources"].values()),
                        "feared_events": [{**fe, "link_keys": list(fe["link_keys"])} for fe in ctx["feared_events"].values()],
                        "revision": ctx["revision"], "updated_by": ctx["updated_by"], "updated_at": ctx["updated_at"]},
            "needs_owner_input": ["business_values", "feared_events", "gravity", "risk_sources", "strategic_scenarios",
                                  "probability_of_success", "likelihood_validation"],
            "counts": {"candidate_paths": len(candidates), "single_step_paths": len(single),
                       "with_validated_likelihood": sum(1 for c in candidates if _d(c["likelihood"].get("validated"))),
                       "with_risk_level": sum(1 for c in candidates if c["risk"]), "unlinked_vulnerabilities": len(unlinked)},
            "issues": issues, "disclaimer": EBIOS_DISCLAIMER, "likelihood_note": LIKELIHOOD_NOTE}


def path_link_keys(paths_doc: Any, vulns: Any, nodes: Any = None) -> Set[str]:
    """Link keys of every open path of one campaign (used to validate owner links across a project)."""
    eb = ebios_view(paths_doc, vulns, None, None, None, nodes)
    return {c["link_key"] for c in eb["candidate_paths"]} | {c["link_key"] for c in eb["single_step_paths"]}


# ---------------------------------------------------------------------------
# MITRE ATLAS
# ---------------------------------------------------------------------------

def _norm(s: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.strip().lower()).strip("_") if isinstance(s, str) else ""


_AI_HINT = re.compile(r"(?i)\b(ollama|vllm|llama\.cpp|text-generation-inference|openai-compatible|lm studio|localai|"
                      r"triton inference|open-webui|open webui|litellm)\b|/v1/(models|chat/completions)\b|/api/(generate|chat)\b")


def ai_surface_hints(nodes: Any) -> List[str]:
    out = []
    for n in _l(nodes):
        n = _d(n)
        txt = " ".join(_s(n.get(k)) for k in ("label", "technology", "title", "endpoint", "service", "product", "details"))
        if _AI_HINT.search(txt) or n.get("port") == 11434:
            out.append(_s(n.get("id")) or "?")
    return out


def llm_agent_state(agents_dispatched: Any) -> Tuple[str, List[Dict[str, Any]]]:
    """Real shape: [{"agent": "php", "findings": 9, "level": 0, "status": "completed"}]. Legacy strings tolerated."""
    issues: List[Dict[str, Any]] = []
    agents = []
    for a in _l(agents_dispatched):
        if isinstance(a, dict) and _norm(a.get("agent")):
            agents.append((_norm(a.get("agent")), _norm(a.get("status")) or "unknown"))
        elif isinstance(a, str) and _norm(a):
            agents.append((_norm(a), "unknown"))
        else:
            issues.append({"kind": "agent-entry-invalid"})
    if not agents:
        return "none_recorded", issues
    llm = [st for name, st in agents if name == "llm"]
    if not llm:
        return "llm_absent", issues
    return ("llm_completed" if "completed" in llm else "llm_incomplete"), issues


STATE_LABELS = {
    "findings": "Findings IA rattachés à ATLAS",
    "tested_no_ai_finding": "Agent IA/LLM exécuté jusqu'au bout — aucun finding IA (périmètre testé uniquement)",
    "ai_test_incomplete": "Agent IA/LLM lancé mais non terminé (échec / en cours) — aucune conclusion possible",
    "ai_surface_not_tested": "Surface IA détectée dans l'inventaire, mais non testée par l'agent IA/LLM",
    "not_tested": "Aucun test IA/LLM dans cette campagne — ATLAS hors périmètre testé",
    "unknown": "Impossible de dire si une surface IA a été testée (agents lancés non enregistrés)",
}


def atlas_view(vulns: Any, agents_dispatched: Any = None, nodes: Any = None) -> Dict[str, Any]:
    cw, cat = llm_crosswalk(), atlas_catalog()
    rows = live(vulns)
    ai, unmapped = [], []
    for v in rows:
        c = _norm(v.get("category"))
        entry = cw["categories"].get(c)
        if entry is None:
            if _norm(v.get("discovered_by_agent")) == "llm":
                unmapped.append({"finding_id": v["id"], "title": _s(v.get("title"))[:300] or None, "category": c,
                                 "reason": "llm agent finding outside the closed LLM vocabulary"})
            continue
        st = _status(v)
        techs = [{"id": t["id"], "name": cat["techniques"][t["id"]]["display_name"],
                  "tactics": [{"id": x, "name": cat["tactics"].get(x)} for x in cat["techniques"][t["id"]]["tactics"]],
                  "relation": "demonstrated" if (st == "exploited" and t["max_relation"] == "demonstrated") else "enabled",
                  "source": t["source"]} for t in entry["atlas"]]
        ai.append({"finding_id": v["id"], "title": _s(v.get("title"))[:300] or None, "category": c,
                   "owasp_llm": entry["owasp_llm"], "status": st, "atlas": techs, "no_atlas_equivalent": not techs})
    agent_state, issues = llm_agent_state(agents_dispatched)
    hints = ai_surface_hints(nodes)
    if ai or unmapped:
        state = "findings"
    elif agent_state == "llm_completed":
        state = "tested_no_ai_finding"
    elif agent_state == "llm_incomplete":
        state = "ai_test_incomplete"
    elif hints:
        state = "ai_surface_not_tested"
    elif agent_state == "llm_absent":
        state = "not_tested"
    else:
        state = "unknown"
    return {"schema_version": SCHEMA_VERSION, "framework": "MITRE ATLAS", "version": cat["version"],
            "license": cat["license"], "copyright": cat["copyright"], "source_sha256": cat["source_sha256"],
            "crosswalk_status": cw["status"], "owasp_version": cw["owasp_version"],
            "state": state, "state_label": STATE_LABELS[state], "ai_surface_hint_nodes": hints,
            "findings_total": len(rows), "ai_findings": ai, "unmapped_ai_findings": unmapped, "issues": issues}


# ---------------------------------------------------------------------------
# ISO/IEC 27001 Annex A - version detection of the agent's free text (indicative)
# ---------------------------------------------------------------------------

_VER_RE = re.compile(r"(?i)2700[12]\s*[:/\-]?\s*(2013|2022)\b")
_REF_RE = re.compile(r"(?i)(?<![A-Za-z0-9.])(?:annex\s+a\s+|a\.\s?|^\s*)(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?(?![\d.]*\d)(?!\.\d)")
_2022_MAX = {5: 37, 6: 8, 7: 14, 8: 34}
_2022_THEME = {5: "Organizational", 6: "People", 7: "Physical", 8: "Technological"}
# ISO/IEC 27001:2013 Annex A: number of control objectives (categories) per clause A.5-A.18
_2013_CAT_MAX = {5: 1, 6: 2, 7: 3, 8: 3, 9: 4, 10: 1, 11: 2, 12: 7, 13: 2, 14: 3, 15: 2, 16: 1, 17: 2, 18: 2}
_TITLE_RE = re.compile(r"\s*[-–:]?\s*[A-Za-z][A-Za-z ,&'-]{3,}")


def _v2013_ok(a: int, b: int) -> bool:
    return 1 <= b <= _2013_CAT_MAX.get(a, 0)


def iso_refs(control: Any) -> Dict[str, Any]:
    text = control if isinstance(control, str) else ""
    if not text.strip():
        return {"state": "missing", "refs": []}
    versions = {m.group(1) for m in _VER_RE.finditer(text)}
    issues: List[Dict[str, Any]] = []
    if len(versions) > 1:
        explicit_v = None
        issues.append({"kind": "explicit_version_conflict", "message": "both 27001:2013 and 27001:2022 are written"})
    else:
        explicit_v = next(iter(versions), None)
    scan = _VER_RE.sub(" ", text)
    refs = []
    for m in _REF_RE.finditer(scan):
        a, b, c = int(m.group(1)), int(m.group(2)), m.group(3)
        tail = scan[m.end():]
        has_title = bool(_TITLE_RE.match(tail)) and not re.match(r"\s*/", tail)
        r: Dict[str, Any]
        if len(versions) > 1:
            v = "ambiguous"
            ref = f"A.{a}.{b}" + (f".{c}" if c is not None else "")
        elif c is not None:
            ref = f"A.{a}.{b}.{c}"
            v = "2013" if _v2013_ok(a, b) else "invalid"
            if v == "2013" and explicit_v == "2022":
                issues.append({"kind": "explicit_version_conflict", "ref": ref,
                               "message": "written as 27001:2022 but A.x.y.z is the 2013 numbering"})
        else:
            ref = f"A.{a}.{b}"
            is22 = a in _2022_MAX and 1 <= b <= _2022_MAX[a]
            is13 = _v2013_ok(a, b)
            if explicit_v == "2013":
                v = "2013" if is13 else "invalid"
                if not is13 and is22:
                    issues.append({"kind": "explicit_version_conflict", "ref": ref,
                                   "message": "written as 27001:2013 but this number only exists in 2022"})
            elif explicit_v == "2022":
                v = "2022" if is22 else "invalid"
                if not is22 and is13:
                    issues.append({"kind": "explicit_version_conflict", "ref": ref,
                                   "message": "written as 27001:2022 but this number only exists in 2013"})
            elif is22:
                v = "2022" if not is13 else "ambiguous"  # A.5-8.1-3 also exist as 2013 categories, title not trusted
            elif is13:
                v = "2013"
            else:
                v = "invalid"
        r = {"ref": ref, "version": v, "agent_title_follows": has_title}
        if v == "2022":
            r["theme"] = _2022_THEME[a]
        refs.append(r)
    vs = {r["version"] for r in refs}
    if "ambiguous" in vs and "2022" in vs and not ({"2013"} & vs) and len(versions) <= 1:
        for r in refs:
            if r["version"] == "ambiguous":
                r["version"], r["theme"], r["resolved_by"] = "2022", _2022_THEME[int(r["ref"].split(".")[1])], "other refs are 2022"
    return {"state": "parsed" if refs else "unparsed", "explicit_version": explicit_v, "refs": refs, "issues": issues}


ISO_READING = ("Mesure de l'Annexe A associée par l'agent (indicatif) — pas une non-conformité, pas une "
               "déclaration de conformité. Aucun texte ni titre ISO n'est affiché par Darkmoon.")


def iso_view(vulns: Any) -> Dict[str, Any]:
    rows = live(vulns)
    cov = {"findings": len(rows), "iso2022": 0, "iso2013_only": 0, "mixed": 0, "ambiguous": 0, "invalid": 0,
           "unparsed": 0, "missing": 0}
    by_ref: Dict[Tuple[str, str], List[str]] = {}
    issues: List[Dict[str, Any]] = []
    for v in rows:
        p = iso_refs(v.get("iso27001_control"))
        for i in p.get("issues", []):
            issues.append({**i, "finding_id": v["id"]})
        if p["state"] in ("missing", "unparsed"):
            cov[p["state"]] += 1
            if p["state"] == "unparsed":
                by_ref.setdefault(("unparsed", "—"), []).append(v["id"])
            continue
        vs = {r["version"] for r in p["refs"]}
        key = ("iso2022" if vs == {"2022"} else "iso2013_only" if vs == {"2013"} else "invalid" if "invalid" in vs
               else "ambiguous" if "ambiguous" in vs else "mixed")
        cov[key] += 1
        for r in p["refs"]:
            by_ref.setdefault((r["version"], r["ref"]), []).append(v["id"])
    order = {"2022": 0, "2013": 1, "ambiguous": 2, "invalid": 3, "unparsed": 4}
    groups = [{"version": k[0], "ref": k[1], "finding_ids": ids} for k, ids in
              sorted(by_ref.items(), key=lambda kv: (order.get(kv[0][0], 9), -len(kv[1]), kv[0][1]))]
    return {"schema_version": SCHEMA_VERSION, "framework": "ISO/IEC 27001 Annex A", "coverage": cov,
            "groups_by_cited_ref": groups, "matrix_2022_available": cov["iso2022"] > cov["findings"] / 2,
            "versions_cited": {"2013": cov["iso2013_only"], "2022": cov["iso2022"]}, "issues": issues,
            "reading": ISO_READING}


# ---------------------------------------------------------------------------
# IEC 62443-3-3 (FR / SR) — derived on the server from what each finding already carries
# ---------------------------------------------------------------------------
# No agent prompt asks for it (no token added to any LLM call): the category and the title are matched against the
# curated rules of frameworks_data/iec62443-3-3-crosswalk.json, and the agent's ISO 27001:2022 control is a fallback.
# Numbering only plus Darkmoon's own summaries; never a conformity or security-level verdict.

IEC_READING = ("Exigence IEC 62443-3-3 concernée, déduite par Darkmoon de la catégorie, du titre ou de la mesure ISO "
               "du finding (indicatif) — pas une non-conformité, pas un niveau de sécurité (SL). Aucun texte IEC "
               "n'est affiché : numérotation et résumés Darkmoon.")


@lru_cache(maxsize=1)
def iec62443_crosswalk() -> Dict[str, Any]:
    return _load("iec62443-3-3-crosswalk.json")


@lru_cache(maxsize=1)
def _iec_rules() -> List[Tuple[Any, List[str], str]]:
    return [(re.compile(r["match"], re.I), list(r["srs"]), r["why"]) for r in iec62443_crosswalk()["rules"]]


def iec62443_refs(v: Dict[str, Any]) -> List[Dict[str, str]]:
    """The SRs a finding concerns, each with its basis: 'category' / 'title' (curated rule) or 'iso' (fallback)."""
    cat = _s(v.get("category")).replace("_", " ").replace("-", " ")
    title = _s(v.get("title"))
    out: Dict[str, Dict[str, str]] = {}
    for rx, srs, why in _iec_rules():
        basis = "category" if rx.search(cat) else "title" if rx.search(title) else None
        if basis:
            for sr in srs:
                out.setdefault(sr, {"sr": sr, "basis": basis, "why": why})
    if not out:
        fb = iec62443_crosswalk()["iso2022_fallback"]
        p = iso_refs(v.get("iso27001_control"))
        for r in p.get("refs", []):
            if r.get("version") != "2022":
                continue
            for sr in fb.get(r["ref"], []):
                out.setdefault(sr, {"sr": sr, "basis": "iso", "why": f"ISO 27001:2022 {r['ref']} cited by the agent"})
    order = {s["id"]: i for i, s in enumerate(iec62443_crosswalk()["system_requirements"])}
    return sorted(out.values(), key=lambda x: order.get(x["sr"], 999))


def iec62443_view(vulns: Any) -> Dict[str, Any]:
    cw = iec62443_crosswalk()
    fr_of = {s["id"]: s["fr"] for s in cw["system_requirements"]}
    rows = live(vulns)
    by_sr: Dict[str, List[str]] = {}
    by_finding: Dict[str, List[Dict[str, str]]] = {}
    basis = {"category": 0, "title": 0, "iso": 0}
    unmapped: List[str] = []
    for v in rows:
        refs = iec62443_refs(v)
        if not refs:
            unmapped.append(v["id"])
            continue
        by_finding[v["id"]] = refs
        for r in refs:
            by_sr.setdefault(r["sr"], []).append(v["id"])
        for b in {r["basis"] for r in refs}:
            basis[b] += 1
    frs = []
    for fr in cw["foundational_requirements"]:
        srs = [{"id": s["id"], "finding_ids": by_sr.get(s["id"], [])} for s in cw["system_requirements"] if s["fr"] == fr["id"]]
        ids = sorted({i for s in srs for i in s["finding_ids"]})
        frs.append({"id": fr["id"], "code": fr["code"], "finding_ids": ids, "requirements": [s for s in srs if s["finding_ids"]]})
    return {"schema_version": SCHEMA_VERSION, "framework": "IEC 62443-3-3", "edition": "2013",
            "coverage": {"findings": len(rows), "mapped": len(by_finding), "unmapped": len(unmapped),
                         "by_basis": basis, "requirements_concerned": len(by_sr)},
            "foundational": frs, "by_finding": by_finding, "unmapped_finding_ids": unmapped,
            "fr_of": {sr: fr_of[sr] for sr in by_sr}, "reading": IEC_READING}


# ---------------------------------------------------------------------------
# Catalogues (the full grids the matrices are drawn on) - GET /api/v1/frameworks/catalogue
# ---------------------------------------------------------------------------

CATALOGUE_SCHEMA = "darkmoon-framework-catalogue/v1"
# MITRE ATLAS matrix order: ATLAS.yaml matrices[0].tactics (mitre-atlas/atlas-data dist, read 08/11/2026); the vendored
# min.json keeps the tactics keyed by id only. Any vendored tactic missing here is appended in id order, never dropped.
ATLAS_MATRIX_ORDER = ("AML.TA0002", "AML.TA0003", "AML.TA0004", "AML.TA0000", "AML.TA0005", "AML.TA0006", "AML.TA0012",
                      "AML.TA0007", "AML.TA0013", "AML.TA0008", "AML.TA0015", "AML.TA0009", "AML.TA0001", "AML.TA0014",
                      "AML.TA0010", "AML.TA0011")


def _grid(tactics: List[Dict[str, str]], techniques: Dict[str, Dict[str, Any]], tactic_key: str) -> List[Dict[str, Any]]:
    """tactics -> parent techniques (alphabetical, as the MITRE matrix) -> their sub-techniques in that tactic.
    A technique listed under several tactics appears in each (counts per tactic do not add up)."""
    parents: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    subs: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
    for tid, t in techniques.items():
        for tac in t["tactics"]:
            if t["parent"]:
                subs.setdefault((tac, t["parent"]), []).append({"id": tid, "name": t["name"]})
            else:
                parents.setdefault(tac, []).append((tid, t))
    out = []
    for tac in tactics:
        k = tac[tactic_key]
        cells = sorted(parents.get(k, []), key=lambda p: (p[1]["name"].lower(), p[0]))
        out.append({**tac, "techniques": [
            {"id": tid, "name": t["name"], "subs": sorted(subs.get((k, tid), []), key=lambda s: (s["name"].lower(), s["id"]))}
            for tid, t in cells]})
    return out


@lru_cache(maxsize=1)
def framework_catalogue() -> Dict[str, Any]:
    """Static: the vendored MITRE catalogues and the Annex A numbering the parsers already use. No ISO title or text."""
    a, t = attack_catalog(), atlas_catalog()
    a_techs = {tid: {"name": x["name"] if x["is_subtechnique"] else x["display_name"], "tactics": x["tactics"],
                     "parent": tid.split(".")[0] if x["is_subtechnique"] else None}
               for tid, x in a["techniques"].items() if not x["revoked"] and not x["deprecated"]}
    order = [x for x in ATLAS_MATRIX_ORDER if x in t["tactics"]] + sorted(x for x in t["tactics"] if x not in ATLAS_MATRIX_ORDER)
    t_techs = {tid: {"name": x["name"], "tactics": x["tactics"], "parent": x["parent"]} for tid, x in t["techniques"].items()}
    return {
        "schema_version": CATALOGUE_SCHEMA,
        "attack": {"framework": a["framework"], "version": a["version"], "source_sha256": a["source_sha256"],
                   "tactics": _grid([dict(x) for x in a["tactics_in_matrix_order"]], a_techs, "shortname")},
        "atlas": {"framework": t["framework"], "version": t["version"], "source_sha256": t["source_sha256"],
                  "tactics": _grid([{"id": x, "name": t["tactics"][x]} for x in order], t_techs, "id")},
        "iso": {"2022": [{"clause": c, "ref": f"A.{c}", "theme": _2022_THEME[c], "controls": n} for c, n in sorted(_2022_MAX.items())],
                "2013": [{"clause": c, "ref": f"A.{c}", "categories": n} for c, n in sorted(_2013_CAT_MAX.items())],
                "note": "Annex A numbering only (number of controls per theme in 2022, of categories per clause in 2013); "
                        "no ISO title or text."},
        "iec62443": {"framework": "IEC 62443-3-3", "edition": "2013",
                     "foundational": [{"id": fr["id"], "code": fr["code"], "summary": fr["summary"],
                                       "requirements": [{"id": s["id"], "summary": s["summary"]}
                                                        for s in iec62443_crosswalk()["system_requirements"] if s["fr"] == fr["id"]]}
                                      for fr in iec62443_crosswalk()["foundational_requirements"]],
                     "note": "IEC 62443-3-3 numbering; the summaries are Darkmoon's own wording, no IEC/ISA text or title."},
    }


def framework_licences() -> List[Dict[str, str]]:
    a, t = attack_catalog(), atlas_catalog()
    return [
        {"framework": "MITRE ATT&CK", "text": f"MITRE ATT&CK® Enterprise v{a['version']} — © The MITRE Corporation. "
                                              "Reproduced and distributed with the permission of The MITRE Corporation."},
        {"framework": "MITRE ATLAS", "text": f"MITRE ATLAS™ {t['version']} — Apache-2.0 — © MITRE"},
        {"framework": "OWASP", "text": "OWASP Top 10 for LLM Applications 2025 — OWASP Foundation (CC BY-SA 4.0), IDs only"},
        {"framework": "ISO/IEC 27001", "text": "No ISO text or title is reproduced; references are the agent's own"},
        {"framework": "EBIOS RM", "text": "ANSSI, Guide EBIOS Risk Manager, fiche méthode 8 — scales quoted"},
        {"framework": "IEC 62443", "text": "IEC 62443-3-3 numbering only — summaries and mapping are Darkmoon's own "
                                           "(indicative); no IEC/ISA text or title is reproduced"},
    ]
