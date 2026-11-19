"""The one campaign statistics function (severity and proof counts).

Every counter of the product (campaign stats stored at push, API campaign view, report, explorer) calls
``compute_stats`` so they agree. Rules:

* a finding held by the strict privacy policy (quarantined, not reviewed) is counted nowhere;
* a finding marked false positive is counted nowhere;
* both exclusions are reported in ``excluded`` (additive field) so a reader knows they exist;
* a closed finding (remediated/resolved/...) is still a finding of the campaign: it is counted;
* the severity counted is the displayed severity (aliases such as ``crit`` or ``moderate`` normalised); a severity
  that is none of the five levels is counted in ``total_findings`` only, as before.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from . import identity

STATS_VERSION = "darkmoon-stats/1"


def split(findings: Iterable[Any]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """(counted findings, excluded counts by reason)."""
    kept: List[Dict[str, Any]] = []
    excluded = {r: 0 for r in identity.EXCLUSION_REASONS}
    for v in findings or []:
        if not isinstance(v, dict):
            continue
        reason = identity.exclusion_reason(v)
        if reason is None:
            kept.append(v)
        else:
            excluded[reason] = excluded.get(reason, 0) + 1
    return kept, excluded


def compute_stats(findings: Iterable[Any]) -> Dict[str, Any]:
    """Counts of the counted findings. Keys and meaning of the historical ``campaign.stats`` are kept."""
    kept, excluded = split(findings)
    sev = {s: 0 for s in identity.SEVERITIES}
    stt = {s: 0 for s in identity.PROOF_STATUSES}
    xsev = {s: 0 for s in identity.SEVERITIES}
    for v in kept:
        s = identity.severity_of(v)
        if s in sev:
            sev[s] += 1
        t = identity.status_of(v)
        if t in stt:
            stt[t] += 1
        if t == "exploited" and s in xsev:
            xsev[s] += 1
    return {"total_findings": len(kept), **sev, **stt, "exploited_by_severity": xsev, "excluded": excluded}


def overall_risk(stats: Dict[str, Any]) -> str:
    """Worst severity present among critical..low, else ``none`` (info alone is ``none``)."""
    for s in identity.SEVERITIES[:4]:
        if int(stats.get(s) or 0) > 0:
            return s
    return "none"


def open_findings(findings: Iterable[Any]) -> List[Dict[str, Any]]:
    """Counted findings that are not closed."""
    return [v for v in findings or [] if isinstance(v, dict) and identity.is_open(v)]


def open_fingerprints(findings: Iterable[Any], target_id: str = "") -> List[str]:
    """Distinct fingerprints of the open findings (a missing target_id takes ``target_id``)."""
    out = set()
    for v in open_findings(findings):
        out.add(identity.fingerprint({**v, "target_id": v.get("target_id") or target_id}))
    return sorted(out)
