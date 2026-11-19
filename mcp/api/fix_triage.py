"""
One server-side « Fix first » per campaign (design P1 v2, adversarial reviews P1-review-1 and P1-review-2).

``fix_first`` is the ONLY list the Exposure KPI and the Fix first list read. Its ``source`` is:

- ``attack-paths`` when the attack-path ranking gate allows (>= 2 proven paths, a real choke point): items =
  ``ranking.fixes``; the top tie group = fix #1 + its ``equivalent_alternatives`` (the engine broke the tie by id).
  The gate itself is unchanged;
- ``reported-severity-x-proof`` otherwise, as long as one finding is still open: items = ``triage.items``. It is
  NOT an attack-path ranking and says so;
- ``none`` only when no finding is open at all.

``triage`` (reported severity x proof) is always emitted as a secondary view; when the path ranking exists it is
shown only under its own title, never as « Fix first ».

Vocabulary (EBIOS RM lens): the agent's severity is a *reported severity*, not an EBIOS gravity (impact on a
business value); the proof level is a likelihood proxy. Ordinal scales are never multiplied: the order is
lexicographic on documented keys (ORDER_KEYS).

Review-2 fixes carried here:

- M1: a missing or malformed severity never drops an open finding. Aliases are normalised (``Critical ``,
  ``crit``, ``moderate``…); an unknown severity takes the band of a valid CVSS vector (« severity not reported:
  band from the CVSS vector ») or stays visible at the end of the list as ``severity: "unknown"``. ``source`` is
  ``none`` only when nothing is open; info-only campaigns say how many findings remain open.
- M2: every item carries ``simulate_ids`` (ids ``:simulate`` understands) and ``finding_id`` (navigation).
  ``:simulate(simulate_ids).interrupted`` restricted to proven open paths == ``breaks_paths``.
- M3: reports are grouped under one item only when the grouping is certain enough: same ``dedup_key``, same
  CVE/CWE, or the same injection parameter. Different hosts/ports and different titles are never merged
  otherwise. Groups on an uncertain endpoint (site root, single entry point, privacy placeholder, empty) are
  flagged ``fold.weak`` and then only their head counts for « breaks a path ».

Only server data: severity, status, evidence, cvss_vector (score recomputed), retest verdicts, the server weakness
fingerprint and the server path engine. Pure, no I/O.
"""
from __future__ import annotations

import hashlib
import itertools
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl

from api.url_parts import safe_port, safe_urlparse

from api import cvss31
from api.attack_paths_engine import first_blocked_step
from api.attack_paths_observed import normalise_title
from api.exec_core import identity as _identity
from api.exec_core.identity import fingerprint

CLOSED_STATUSES = frozenset({"remediated", "resolved", "closed", "fixed"})   # json_storage/campaign_view/retest_store
_FALSE_POSITIVE = re.compile(r"^false[\s_-]?positive$")
SEVERITY_LEVEL = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}   # info -> excluded (counted)
_SEVERITY_ALIAS = {
    "critical": "critical", "crit": "critical",
    "high": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "low": "low",
    "info": "info", "informational": "info", "information": "info", "none": "info",
}
PROOF_LEVEL = {"exploited": 4, "confirmed": 3, "unconfirmed": 1}             # unknown status -> 1, labelled
ORDER_KEYS = ["reported_severity", "proof", "proven_chains_broken", "retest_regressed", "cvss_from_vector"]
MAX_ITEMS = 20
BASIS = "reported-severity-x-proof"
LABEL = "By reported severity × proof"
PATHS_LABEL = "By attack paths"
NOTE = ("Not an attack-path ranking. Order: severity reported by the agent, then proof level (exploited, confirmed, "
        "unconfirmed), then proven attack chains of several findings broken, then regression after a retest, then the "
        "CVSS score computed from the finding's vector. Equal keys share the same rank. Severity is the agent's "
        "rating, not an impact on your business assets.")
PATHS_NOTE = "Ranked by proven attack paths broken (simulation, not applied)."
# ranking gate reasons (attack_paths_engine.ranking_gate) in plain words, for « Why not ranked by attack paths? »
WHY_NOT_PATHS = {
    "too-few-scenarios": "Fewer than 2 proven attack paths: a path ranking needs at least 2 paths with a shared step.",
    "no-choke-point": "No fix breaks more than one proven attack path: ranking them by paths would not tell them apart.",
    "top-fix-interrupts-nothing": "No single fix breaks a proven attack path on its own.",
    "too-large": "Too many attack paths to rank them reliably in one request.",
    "status-not-ok": "No proven attack path in this campaign: nothing to rank by paths.",
    "provenance-not-real": "The paths of this campaign are not proven by real findings.",
}
# categories whose name says nothing precise about the flaw (review-2 M3)
GENERIC_CATEGORIES = frozenset({"security_misconfiguration", "misconfiguration", "insecure_configuration",
                                "information_disclosure", "sensitive_data_exposure", "business_logic_flaw",
                                "business_logic"})
_INJECTION = re.compile(r"injection|xss|xxe|ssti|traversal|lfi|rfi")
_SINGLE_ENTRY = re.compile(r"^/(index|default|main)\.(php|html?|aspx?|jsp)$")
_LOOPBACK = {"localhost", "127.0.0.1", "[::1]", "::1"}
_METHOD = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", re.I)


def _status(v: Dict[str, Any]) -> str:
    return str(v.get("status") or "unconfirmed").strip().lower()


def _severity(v: Dict[str, Any]) -> Optional[str]:
    """Normalised reported severity, or None when it is missing or not a known rating."""
    return _SEVERITY_ALIAS.get(str(v.get("severity") or "").strip().lower())


def _has_proof(v: Dict[str, Any]) -> bool:
    """Recorded execution artefacts only. The agent's narrative (explanation, logs) is not a proof, nor is a payload
    that was sent (it does not show its effect). Evidence may be one dict or a list of dicts."""
    ev = v.get("evidence")
    items = ev if isinstance(ev, list) else [ev]
    keys = ("request", "requests", "raw_request", "response", "responses", "raw_response", "command", "commands",
            "extracted_data")
    return any(isinstance(e, dict) and any(e.get(k) for k in keys) for e in items)


def _endpoint_parts(v: Dict[str, Any]) -> Tuple[Optional[str], str, frozenset]:
    """(authority or None, path, query parameter names) of the finding's endpoint."""
    ep = _METHOD.sub("", str(v.get("endpoint") or "").strip()).split(" ")[0]
    u = safe_urlparse(ep if "://" in ep else "http://h/" + ep.lstrip("/"))  # PR 1A: never raises
    authority = None
    if "://" in ep and u.hostname:
        host = u.hostname.lower()
        host = "loopback" if host in _LOOPBACK or f"[{host}]" in _LOOPBACK else host
        # a real campaign endpoint can carry a malformed authority (e.g. « host:8080:50000 »): degrade to the
        # scheme-default port so the authority stays a single host:port (test_fix_triage a12d9369), never raise.
        port = safe_port(u)
        authority = f"{host}:{port or (443 if u.scheme == 'https' else 80)}"
    path = re.sub(r"/+", "/", u.path or "/").rstrip("/") or "/"
    query = u.query or (u.fragment.split("?", 1)[1] if "?" in (u.fragment or "") else "")
    params = frozenset(k.lower() for k, _ in parse_qsl(query, keep_blank_values=True))
    if u.fragment and u.fragment.startswith("/"):
        path = path + "#" + u.fragment.split("?", 1)[0]      # single-page app route
    return authority, path, params


def _weak_endpoint(v: Dict[str, Any]) -> Optional[str]:
    """Why reports grouped on this endpoint may be distinct weaknesses (None = a specific endpoint)."""
    if not str(v.get("endpoint") or "").strip():
        return "no endpoint recorded"
    if re.search(r"URL_\d+", str(v.get("endpoint"))):
        return "endpoint is a privacy placeholder"
    base, _, route = _endpoint_parts(v)[1].partition("#")
    if route.strip("/"):
        return None                                    # a single-page app route is specific
    if base == "/":
        return "endpoint is the site root"
    if _SINGLE_ENTRY.match(base):
        return "endpoint is the application's single entry point"
    return None


def _member(v: Dict[str, Any], verdict: Optional[str]) -> Dict[str, Any]:
    st = _status(v)
    sev = _severity(v)
    proof = st if st in PROOF_LEVEL else "unknown"
    notes: List[str] = []
    if proof == "exploited" and not _has_proof(v):
        proof = "confirmed"
        notes.append("marked exploited without any recorded request, response or command: counted as confirmed")
    cv = cvss31.assess(v)
    vband = cvss31.band(cv["score"])
    severity_source = "reported"
    if sev is None:                                   # M1: never drop it, never disguise it
        raw = str(v.get("severity") or "").strip()
        if vband in ("critical", "high", "medium", "low"):
            sev, severity_source = vband, "cvss-vector"
        else:
            sev, severity_source = "unknown", "unknown"
        notes.append(f"reported severity {raw!r} is not a known rating" if raw else "no severity reported")
    if cv["status"] == "mismatch":
        notes.append(f"CVSS {cv['score']} computed from the vector; agent reported {cv['reported']}")
    if cv["score"] is not None and severity_source == "reported" and sev in SEVERITY_LEVEL and vband != sev:
        notes.append(f"reported severity {sev} but the vector scores {cv['score']} ({vband})")
    if cv["status"] == "no-valid-vector":
        notes.append("no valid CVSS vector: CVSS not used in the order")
    return {"id": str(v["id"]), "severity": sev, "severity_source": severity_source, "proof": proof,
            "sev_level": SEVERITY_LEVEL.get(sev, 0), "proof_level": PROOF_LEVEL.get(proof, 1), "cvss": cv,
            "verdict": verdict, "notes": notes, "title": v.get("title") or str(v["id"])}


def _head_key(m: Dict[str, Any]) -> tuple:
    return (-m["sev_level"], -m["proof_level"], -(m["cvss"]["score"] if m["cvss"]["score"] is not None else -1), m["id"])


def _split_fingerprint(members: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> List[Tuple[str, List[Tuple[Dict[str, Any], Dict[str, Any]]], Optional[str]]]:
    """M3: split one server fingerprint into report groups that are certain enough to share one fix.
    Returns [(sub_key, members, basis)] where basis says why several reports are grouped (None = one report)."""
    v0 = members[0][0]
    if v0.get("dedup_key"):
        return [("", members, "same dedup_key")]
    # never merge different hosts/ports (only when the reports name them)
    auths = {_endpoint_parts(v)[0] for v, _ in members} - {None}
    by_auth: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for v, m in members:
        a = _endpoint_parts(v)[0] if len(auths) > 1 else ""
        by_auth.setdefault(a or "", []).append((v, m))
    out = []
    for a, grp in by_auth.items():
        ref = str(v0.get("cve") or v0.get("cwe") or "").strip()
        cat = str(v0.get("category") or v0.get("type") or "").strip().lower()
        params = {_endpoint_parts(v)[1:] for v, _ in grp}
        if len(grp) == 1:
            out.append((a, grp, None))
        elif ref:
            out.append((a, grp, "same CVE/CWE"))
        elif _INJECTION.search(cat) and len(params) == 1 and next(iter(params))[1]:
            out.append((a, grp, "same injection parameter"))
        else:                                          # different titles are never merged
            by_title: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
            for v, m in grp:
                by_title.setdefault(normalise_title(v.get("title")), []).append((v, m))
            for t, sub in by_title.items():
                out.append((f"{a}|{t}", sub, "same title, endpoint and category" if len(sub) > 1 else None))
    return out


def triage(a: Dict[str, Any], label_of: Callable[[str, List[str]], str], path_info: Dict[str, Dict[str, Any]],
           retest_verdicts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """``a`` = attack_paths._analyse(); ``path_info`` = {path_id: {provenance, objective, access}} of the paths listed
    in the same document."""
    verdicts = {str(k): str(v).strip().lower() for k, v in (retest_verdicts or {}).items()}
    excluded = {"closed": 0, "false_positive": 0, "fixed_by_retest": 0, "informational": 0, "quarantined": 0}
    unknown_ids: List[str] = []
    open_total = 0
    by_fp: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for v in a["vmap"].values():
        vid = str(v["id"])
        # integration P4 x P1: held by the strict privacy policy (quarantined, not reviewed by an operator) ->
        # never ordered nor counted as open, like attack paths and the report (_analyse marks the status too)
        # exclusion rules shared with the stats and the score (exec_core.identity)
        reason = _identity.exclusion_reason(v)
        if reason == "quarantined":
            excluded["quarantined"] += 1
            continue
        if _identity.is_closed(v):
            excluded["closed"] += 1
            continue
        if reason == "false_positive":
            excluded["false_positive"] += 1
            continue
        if verdicts.get(vid) == "fixed":
            excluded["fixed_by_retest"] += 1
            continue
        open_total += 1
        m = _member(v, verdicts.get(vid))
        if m["severity"] == "info":
            excluded["informational"] += 1
            continue
        if m["severity_source"] != "reported":
            unknown_ids.append(vid)
        fp = fingerprint({**v, "target_id": v.get("target_id") or ""})
        by_fp.setdefault(fp, []).append((v, m))

    # paths: index finding -> open, non-hypothesis records (O(units x their paths), not units x all paths)
    records = [r for r in a["records"] if not r["hypothesis"] and r["status"] == "open" and r["id"] in path_info]
    by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        for x in r["finding_ids"]:
            by_finding.setdefault(x, []).append(r)

    items: List[Dict[str, Any]] = []
    for fp, fp_members in by_fp.items():
        groups = _split_fingerprint(fp_members)
        for sub_key, grp, basis in groups:
            members = sorted((m for _, m in grp), key=_head_key)
            head = members[0]
            weak = None
            if len(members) > 1 and basis != "same dedup_key":
                weak = next((w for w in (_weak_endpoint(v) for v, _ in grp) if w), None)
            # an uncertain group may hide distinct weaknesses: only the head is assumed fixed by this fix
            fixed = {head["id"]} if weak else {m["id"] for m in members}
            cand = {r["id"]: r for x in fixed for r in by_finding.get(x, [])}
            breaks = sorted(pid for pid, r in cand.items() if first_blocked_step({"steps": r["steps"]}, fixed) is not None)
            on = sorted(cand)
            # only a chain of several findings is a sort key; a single-finding path is the finding's own proven impact
            chain_breaks = [pid for pid in breaks if len(cand[pid]["finding_ids"]) >= 2]
            regressed = any(m["verdict"] == "regressed" for m in members)
            still = any(m["verdict"] == "still_present" for m in members)
            reasons = [f"{head['severity']} (reported)" if head["severity_source"] == "reported" else
                       f"{head['severity']} (severity not reported: band from the CVSS vector)"
                       if head["severity_source"] == "cvss-vector" else "severity unknown",
                       head["proof"] if head["proof"] != "unknown" else "unknown status"]
            for pid in breaks:
                p = path_info[pid]
                how = f"{p['access']} on {p['objective']}" if p["access"] else f"reaches {p['objective']}"
                if pid in chain_breaks:
                    reasons.append(f"breaks {'the only' if len(records) == 1 else 'a'} proven chain ({p['provenance']}: {how})")
                else:
                    reasons.append(f"its exploitation is a proven path on its own ({p['provenance']}: {how})")
            if on and not breaks:
                reasons.append(f"on {len(on)} proven path{'s' if len(on) != 1 else ''}, does not break it alone")
            if regressed:
                reasons.append("regressed after a retest")
            elif still:
                reasons.append("still present after a retest")
            sc = head["cvss"]["score"]
            fix_id = fp if len(groups) == 1 else f"{fp}_{hashlib.sha256(sub_key.encode()).hexdigest()[:6]}"
            n = len(members)
            fold = None
            if n > 1:
                fold = {"basis": basis, "weak": bool(weak), "why": weak,
                        "label": (f"{n} reports grouped by the server ({basis})"
                                  + (f" · {weak}: may be distinct weaknesses" if weak else ""))}
            items.append({
                "fix_id": fix_id, "kind": "weakness", "fingerprint": fp,
                "finding_id": head["id"], "head_finding_id": head["id"], "finding_ids": [m["id"] for m in members],
                "simulate_ids": [head["id"]] if weak else [m["id"] for m in members],
                "label": label_of(head["id"], [head["id"]]), "severity": head["severity"],
                "severity_source": head["severity_source"], "proof": head["proof"],
                "cell": f"S{head['sev_level']}·P{head['proof_level']}",
                "cvss": {"score": sc, "reported": head["cvss"]["reported"], "status": head["cvss"]["status"]},
                "on_paths": on, "breaks_paths": breaks, "chain_paths_broken": chain_breaks,
                "retest": "regressed" if regressed else ("still_present" if still else None),
                "reports": n, "similar_finding_ids": [m["id"] for m in members[1:]], "fold": fold,
                "reasons": reasons, "notes": head["notes"],
                "_key": (-head["sev_level"], -head["proof_level"], -len(chain_breaks), -int(regressed),
                         -(sc if sc is not None else -1)),
            })
    items.sort(key=lambda i: (i["_key"], i["head_finding_id"]))
    # competition ranking 1,1,1,4 ... ; tie groups computed once (O(n log n))
    pos = 0
    for gi, (_, grp_it) in enumerate(itertools.groupby(items, key=lambda i: i["_key"])):
        grp_l = list(grp_it)
        for it in grp_l:
            it["rank"] = pos + 1
            it["tie_group"] = f"tg{gi + 1}"
            it["tie_size"] = len(grp_l)
            del it["_key"]
        pos += len(grp_l)
    top = [i for i in items if i["rank"] == 1]
    return {"basis": BASIS, "label": LABEL, "note": NOTE, "is_path_ranking": False, "order_keys": ORDER_KEYS,
            "scales": {"reported_severity": SEVERITY_LEVEL, "proof": PROOF_LEVEL,
                       "excluded_from_order": ["info (informational)"]},
            "total": len(items), "fingerprints": len(by_fp), "open_findings": open_total,
            "items": items[:MAX_ITEMS], "_top": top, "_all": items, "excluded": excluded,
            "unknown_severity_ids": sorted(unknown_ids)}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _fixes(n: int) -> str:
    return f"{n} fix{'' if n == 1 else 'es'}"


def _more(total: int, shown: int, top_size: int) -> Optional[Dict[str, Any]]:
    """m-2: what the truncated list leaves out, in words (the top tie group is never cut silently)."""
    hidden = total - shown
    if hidden <= 0:
        return None
    tied = max(0, top_size - shown)
    text = f"+ {tied} more tied at #1" if tied else f"+ {hidden} more"
    if tied and hidden > tied:
        text += f", {hidden - tied} below"
    return {"count": hidden, "tied_at_top": tied, "text": text}


def _counts(all_items: List[Dict[str, Any]], shown: int, top_ids: List[str]) -> Dict[str, Any]:
    """D5 (pentest 03/11): the numbers every screen shows for « Fix first », computed once here over the WHOLE list
    (never over the truncated ``items``). ``by_finding`` gives any finding its rank even when its fix is below the
    first MAX_ITEMS; ``top_finding_ids`` is the complete rank-1 tie group (findings), so no screen rebuilds either
    from the truncated list. ``text`` names the unit of every number (fixes vs findings)."""
    by_finding: Dict[str, Dict[str, Any]] = {}
    for it in all_items:
        for fid in it.get("finding_ids") or ([it["finding_id"]] if it.get("finding_id") else []):
            by_finding.setdefault(str(fid), {"rank": it["rank"], "tie_size": it.get("tie_size", 1), "fix_id": it["fix_id"]})
    top = set(top_ids)
    top_findings = sorted({str(f) for it in all_items if it["fix_id"] in top
                           for f in (it.get("finding_ids") or [it.get("finding_id")]) if f})
    fixes, findings = len(all_items), len(by_finding)
    text = {"fixes": _fixes(fixes),
            "findings": _plural(findings, "finding"),
            "shown": (f"Showing {shown} of {_fixes(fixes)}" if shown < fixes else None),
            "top": (f"Top fix group: {_fixes(len(top))} · "
                    f"{_plural(len(top_findings), 'finding')}") if top else None}
    counts = {"fixes": fixes, "fixes_shown": shown, "findings": findings, "top_fixes": len(top),
              "top_findings": len(top_findings), "text": text}
    return {"counts": counts, "by_finding": by_finding, "top_finding_ids": top_findings}


def fix_first(ranking: Dict[str, Any], tri: Dict[str, Any], vmap: Dict[str, Dict[str, Any]],
              label_of: Callable[[str, List[str]], str], group_ids: Dict[str, List[str]]) -> Dict[str, Any]:
    """The single Fix first of the campaign (the KPI and the list read only this)."""
    first = tri.pop("_top", [])                         # full top tie group, never truncated (m-2)
    all_tri = tri.pop("_all", tri.get("items") or [])   # whole ordered list (D5: counts and ranks over all of it)
    open_total = tri["open_findings"]
    if ranking.get("allowed") and ranking.get("fixes"):
        def _rep_measure(finding_ids: List[str]) -> Optional[Dict[str, Any]]:
            """The representative (highest severity, then proof) member of a fix group, for its displayed severity/status.
            Server-authoritative (same per-finding measurement as the non-paths branch); None when no member is known."""
            ms = [_member(vmap[str(fid)], None) for fid in finding_ids if str(fid) in vmap]
            return max(ms, key=lambda m: (m["sev_level"], m["proof_level"])) if ms else None

        items = []
        for f in ranking["fixes"]:
            alts = f.get("equivalent_alternatives") or []
            rep = _rep_measure(f["finding_ids"])        # integration fix: carry the group's severity/status to the UI
            items.append({"rank": f["rank"], "fix_id": f["fix_id"], "label": f["label"], "finding_ids": f["finding_ids"],
                          "finding_id": f["finding_ids"][0] if f["finding_ids"] else None,
                          "simulate_ids": [f["fix_id"]],
                          "breaks": f["interrupts_count"], "of_total": f["of_total"],
                          "severity": rep["severity"] if rep else "unknown",
                          "severity_source": rep["severity_source"] if rep else "unknown",
                          "proof": rep["proof"] if rep else "unknown",
                          "tie_size": 1 + len(alts),
                          "tied_with": [{"fix_id": x, "label": label_of(x, group_ids.get(x, [x]))} for x in alts],
                          "tie_break": f.get("tie_break")})
        t = items[0]
        top = {"rank": 1, "tie_size": t["tie_size"], "fix_ids": [t["fix_id"]] + [x["fix_id"] for x in t["tied_with"]],
               "labels": [t["label"]] + [x["label"] for x in t["tied_with"]], "finding_id": t["finding_id"],
               "breaks": t["breaks"], "of_total": t["of_total"],
               "severity": t["severity"], "severity_source": t["severity_source"], "proof": t["proof"],
               "chosen_by": "id order among equivalent fixes" if t["tied_with"] else None}
        c = _counts(items, len(items), top["fix_ids"])
        # equivalent alternatives are not list items of their own: their findings come from the server groups
        alt_ids = {str(f) for x in t["tied_with"] for f in group_ids.get(x["fix_id"], [x["fix_id"]])}
        top["finding_ids"] = sorted(set(c.pop("top_finding_ids")) | alt_ids)
        c["counts"]["top_findings"] = len(top["finding_ids"])
        c["counts"]["text"]["top"] = (f"Top fix group: {_fixes(len(top['fix_ids']))} · "
                                      f"{_plural(len(top['finding_ids']), 'finding')}")
        return {**c, "source": "attack-paths", "label": PATHS_LABEL, "why_not_paths": None, "why_not_paths_text": None,
                "top": top, "items": items, "items_total": len(items), "more": None, "open_findings": open_total,
                "note": PATHS_NOTE}
    why = ranking.get("gate_reason")
    why_text = WHY_NOT_PATHS.get(why or "", None)
    if tri["total"]:
        top = {"rank": 1, "tie_size": len(first), "fix_ids": [i["fix_id"] for i in first],
               "labels": [i["label"] for i in first], "finding_id": first[0]["finding_id"],
               "severity": first[0]["severity"], "severity_source": first[0]["severity_source"],
               "proof": first[0]["proof"], "chosen_by": None}
        c = _counts(all_tri, len(tri["items"]), top["fix_ids"])
        top["finding_ids"] = c.pop("top_finding_ids")
        return {**c, "source": BASIS, "label": LABEL, "why_not_paths": why, "why_not_paths_text": why_text, "top": top,
                "items": tri["items"], "items_total": tri["total"], "more": _more(tri["total"], len(tri["items"]), len(first)),
                "open_findings": open_total, "note": tri["note"]}
    if open_total:                                      # M1: open findings remain, none rated low or above
        info = tri["excluded"]["informational"]
        return {"source": BASIS, "label": LABEL, "why_not_paths": why, "why_not_paths_text": why_text, "top": None,
                "items": [], "items_total": 0, "more": None, "open_findings": open_total,
                **{k: v for k, v in _counts([], 0, []).items() if k != "top_finding_ids"},
                "note": (f"No finding rated low or above: {_plural(info, 'informational finding')} "
                         f"remain{'s' if info == 1 else ''} open.")}
    held = tri["excluded"].get("quarantined", 0)
    note = "No open finding left to fix in this campaign."
    if held:                                            # integration P4 x P1: say why the list is empty
        note = (f"No finding to order: {_plural(held, 'finding')} held for privacy review "
                f"(see the Expert view; released findings count again).")
    return {"source": "none", "label": None, "why_not_paths": why, "why_not_paths_text": why_text,
            "top": None, "items": [], "items_total": 0, "more": None, "open_findings": 0,
            **{k: v for k, v in _counts([], 0, []).items() if k != "top_finding_ids"},
            "note": note}
