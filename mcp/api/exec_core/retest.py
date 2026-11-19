"""Retest verdicts with the exec_core finding identity (both editions; only Pro launches retests today).

A retest is a later campaign on the same target. Each finding of the base campaign gets one verdict:

* ``still_present`` / ``regressed`` (the base finding was declared closed): a finding of the retest matches it;
* ``fixed``: no finding of the retest matches it. Its label is « Not reproduced at retest »: the retest did not
  reproduce it, which is not a proof that it is resolved (no negative control is recorded);
* ``new``: a finding of the retest that matches no base finding.

Matching is deliberately generous (a doubtful match reads « still present », never « not reproduced »), in order:

1. the same ``fingerprint`` (exec_core.identity: dedup_key, else category + endpoint path + CVE/CWE; the target is
   ignored, a retest is on the base target by construction);
2. the historical key ``title|endpoint|category`` (the key stored retests were computed with until 2026-11);
3. the same weakness class on the same endpoint path (an agent naming the flaw differently on the next run).

A retest finding marked false positive (an operator decision) reproduces nothing. The verdict never writes anything
back onto a finding: a past campaign keeps the findings it had. Pure, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from . import identity

RETEST_VERSION = "darkmoon-retest-verdicts/2"
VERDICT_LABEL = {
    "fixed": "Not reproduced at retest",
    "still_present": "Reproduced at retest",
    "regressed": "Reproduced at retest after being declared closed",
    "new": "New at retest",
}
MATCH_BASIS = {
    "fingerprint": "same weakness (category, endpoint path, CVE/CWE or dedup key)",
    "legacy_key": "same title, endpoint and category",
    "class_endpoint": "same weakness class on the same endpoint path",
}


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def legacy_key(v: Dict[str, Any]) -> str:
    """The key retests used before exec_core: title|endpoint|category (kept as the second matching rule)."""
    endpoint = v.get("endpoint") or v.get("url") or v.get("location") or ""
    return "|".join((_norm(v.get("title")), _norm(endpoint), _norm(v.get("category"))))


def _fp(v: Dict[str, Any]) -> str:
    return identity.fingerprint({**v, "target_id": ""})


def _class_endpoint(v: Dict[str, Any]) -> Optional[str]:
    wc = identity.weakness_class(v)
    ep = identity.norm_endpoint(v.get("endpoint") or v.get("url") or v.get("location") or "")
    if wc == "unclassified" or not ep:
        return None
    return wc + "|" + ep


def _index(new: List[Dict[str, Any]]):
    by: Dict[str, Dict[str, Dict[str, Any]]] = {"fingerprint": {}, "legacy_key": {}, "class_endpoint": {}}
    for v in new:
        by["fingerprint"].setdefault(_fp(v), v)
        by["legacy_key"].setdefault(legacy_key(v), v)
        ce = _class_endpoint(v)
        if ce:
            by["class_endpoint"].setdefault(ce, v)
    return by


def _keys(v: Dict[str, Any]) -> Dict[str, Optional[str]]:
    return {"fingerprint": _fp(v), "legacy_key": legacy_key(v), "class_endpoint": _class_endpoint(v)}


def compute_verdicts(base: Iterable[Any], new: Iterable[Any],
                     finding_ids: Optional[Iterable[Any]] = None) -> List[Dict[str, Any]]:
    """Per-finding verdicts, same shape as the historical ``retest_store.compute_verdicts`` plus ``match_basis`` and
    ``label`` (additive). ``finding_ids`` limits the base findings (a focused retest)."""
    base_l = [v for v in base or [] if isinstance(v, dict)]
    if finding_ids:
        wanted = {str(x) for x in finding_ids}
        base_l = [v for v in base_l if str(v.get("id")) in wanted]
    new_l = [v for v in new or [] if isinstance(v, dict) and identity.exclusion_reason(v) != "false_positive"]
    idx = _index(new_l)
    results: List[Dict[str, Any]] = []
    matched_new = set()
    for v in base_l:
        base_status = _norm(v.get("status")) or "unconfirmed"
        keys = _keys(v)
        match, basis = None, None
        for rule in ("fingerprint", "legacy_key", "class_endpoint"):
            k = keys[rule]
            if k and k in idx[rule]:
                match, basis = idx[rule][k], rule
                break
        if match is not None:
            matched_new.add(id(match))
            verdict = "regressed" if base_status in identity.CLOSED_STATUSES else "still_present"
            results.append({"finding_id": v.get("id"), "new_finding_id": match.get("id"), "base_status": base_status,
                            "new_status": _norm(match.get("status")) or "unconfirmed",
                            "severity": match.get("severity") or v.get("severity"), "verdict": verdict,
                            "match_basis": basis, "label": VERDICT_LABEL[verdict]})
        else:
            results.append({"finding_id": v.get("id"), "new_finding_id": None, "base_status": base_status,
                            "new_status": None, "severity": v.get("severity"), "verdict": "fixed",
                            "match_basis": None, "label": VERDICT_LABEL["fixed"]})
    base_keys = {rule: {k for k in (_keys(v)[rule] for v in base_l) if k} for rule in idx}
    for v in new_l:
        if id(v) in matched_new:
            continue
        ks = _keys(v)
        if any(ks[r] and ks[r] in base_keys[r] for r in ks):
            continue
        results.append({"finding_id": None, "new_finding_id": v.get("id"), "base_status": None,
                        "new_status": _norm(v.get("status")) or "unconfirmed", "severity": v.get("severity"),
                        "verdict": "new", "match_basis": None, "label": VERDICT_LABEL["new"]})
    return results
