"""
Report annex — the campaign's own data as report sections.

Markdown sections built ONLY from what the server already computes (attack paths, infrastructure, fix-first ranking,
framework views), never from LLM-written text. In Darkmoon Community they are appended to the report written at
finalisation (``api.report_annex_local``):

  ATTACK PATHS          the attack-path document (provenance all, steps): proven paths and possible paths kept apart; a hypothesis
                        (``hypothesis: true``, provenance ``inferred``) is always written « possible · not proven »
  INFRASTRUCTURE MAP    the infrastructure graph: zones, hosts, services, ports, findings per asset
  FIX FIRST             ranking.fixes when the path ranking is allowed, else the server's fix-first list (fix_first.items,
                        its own basis and « why not paths » text) and the proven pivots; what each fix interrupts =
                        the server's ``interrupts`` / ``breaks_paths``, each path labelled proven or possible
  FRAMEWORK MAPPING     the framework views + the vendored catalogue: ATT&CK tactics (all, in matrix order), ATLAS state, ISO, IEC 62443
                        Annex A references (references only, no ISO text), EBIOS RM workshop-4 technical input

Diagrams are Mermaid fences whose first line is ``%% figure: <id>`` (attack-paths, infrastructure); a Markdown viewer
with Mermaid support renders them. Mermaid labels are reduced to a safe character set (no quotes, brackets, pipes, ``%%``
or directives can come from a finding title).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "darkmoon-report-annex/v1"


def section_marker(section_id: str) -> str:
    """Stable section id on the line before a ``## `` heading (an HTML comment: invisible in a Markdown viewer). Readers
    group sections by this id, never by the heading text (headings may be renamed; old reports have no marker)."""
    return f"<!-- dm-section: {section_id} -->"

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}
ZONE_ORDER = ["internet", "edge", "app", "data", "internal", "unknown"]
ZONE_LABEL = {"internet": "Internet", "edge": "Edge (exposed)", "app": "Application", "data": "Data", "internal": "Internal",
              "unknown": "Unplaced"}
HOST_TYPES = {"target", "host"}

_SAFE = re.compile(r"[^A-Za-z0-9 .,:/_+@&'=()\-À-ſ«»·→]")


def mm_label(text: Any, limit: int = 46) -> str:
    """A Mermaid label from data: safe characters only, one line, bounded (no quote, bracket, pipe, %%, <, >)."""
    s = _SAFE.sub(" ", str(text or "")).replace("%", " ")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s or "unnamed"


_HTML_ESC = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def md_cell(text: Any, limit: int = 0) -> str:
    """A Markdown table cell: one line, pipes and backticks neutralised. The annex is part of the report file, read in
    any Markdown viewer: raw HTML from a finding title is shown as text and an image is never fetched."""
    s = re.sub(r"\s+", " ", str("" if text is None else text)).strip().replace("|", "\\|").replace("`", "'")
    if limit and len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s.translate(_HTML_ESC).replace("![", "!\\[")


def _plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _sev(v: Any) -> str:
    s = str(v or "none").lower()
    return s if s in SEV_ORDER else "none"


# ── attack paths ─────────────────────────────────────────────────────────────────────────────────────────────────


def _path_kind(p: Dict[str, Any]) -> str:
    # Defence in depth: an ``inferred`` path is a hypothesis BY CONTRACT (the inferred engine always
    # sets hypothesis=True). Guard on the provenance too, so a malformed/legacy record whose ``hypothesis`` flag was lost
    # can never be promoted to « observed » — a hypothesis is never presented as proven on any single-field failure.
    # a chain declared by the agent (enabled_by, or the finalisation block) is its own kind, never
    # « possible / inferred » nor proven
    if p.get("provenance") == "agent-declared" or (p.get("provenance") == "declared" and p.get("hypothesis")):
        return "agent"
    if p.get("hypothesis") or p.get("provenance") == "inferred":
        return "possible"
    return "interrupted" if p.get("status") == "interrupted_by_retest" else "proven"


KIND_WORD = {"proven": "observed", "possible": "possible · not proven (hypothesis)", "interrupted": "observed · interrupted by a retest",
             "agent": "declared by the agent · not verified by the server"}
AGENT_SEG = "declared by the agent (not verified by the server)"


def _is_observed(p: Dict[str, Any]) -> bool:
    """Evidence-backed: provenance observed/derived, not a hypothesis. A `declared` path (ranked like a proven one, but
    operator/agent-asserted, not corroborated) is NOT observed — it is never worded or counted « observed » (proof
    consistency with the legend). `_path_kind` keeps it in « proven » so the ranking/coverage math is unchanged; only
    the WORDING distinguishes it."""
    return (p.get("provenance") in ("observed", "derived")) and not p.get("hypothesis")


def _path_word(p: Dict[str, Any]) -> str:
    """The honest per-path proof word: a declared path in the « proven » (ranked) group is « declared · not proven »;
    a path resting on a link the AGENT declared (enabled_by) says so."""
    k = _path_kind(p)
    if k == "agent" and p.get("provenance") == "declared" and p.get("level_label"):
        return str(p["level_label"]).replace("Declared", "declared", 1)
    return "declared · not proven" if (k == "proven" and not _is_observed(p)) else KIND_WORD[k]


def _obj_label_of(nid: Optional[str], raw_label: Optional[str]) -> str:
    """Display label for an objective key: the real label when present, else the label recovered from a synthetic
    fallback key (``label::`` / ``path::``), else the key itself."""
    if raw_label:
        return raw_label
    if isinstance(nid, str) and nid.startswith("label::"):
        return nid[len("label::"):]
    if isinstance(nid, str) and nid.startswith("path::"):
        return "the objective"
    return nid or "the objective"


def _path_objective_id(p: Dict[str, Any]) -> Optional[str]:
    """Objective IDENTITY is the stable ``node_id``, NEVER the display label — two distinct assets can share a
    label and must not be merged in the objective counts. The label is resolved only for display (``objective_names``).
    A proven objective WITHOUT a node_id must still be COUNTED (never silently dropped) and distinct labels
    must stay distinct, so fall back to a stable, non-merging key — the label, else the path id — never ``None`` when
    there is anything to key on. Two labelless objectives on two paths count separately (safe over-count: never a
    false « no path reaches it »)."""
    obj = p.get("objective") or {}
    nid = obj.get("node_id") or p.get("objective_node_id")
    if nid:
        return nid
    lbl = obj.get("label")
    if lbl:
        return f"label::{lbl}"
    return f"path::{p['id']}" if p.get("id") else None


def _short_id(nid: str) -> str:
    """A sober short identifier for display: strip the synthetic-key prefix and shorten a long internal id so the report
    never shows a long opaque string."""
    s = nid
    for pre in ("label::", "path::"):
        if s.startswith(pre):
            s = s[len(pre):]
    return s if len(s) <= 14 else f"{s[:6]}…{s[-4:]}"


def _objective_display_map(entries: Iterable[Tuple[Optional[str], Optional[str]]]) -> Dict[str, str]:
    """node_id → display name, disambiguating a label shared by several node_ids as ``label · short-id``. GROUP-AWARE and collision-free: within a colliding label, if two short ids would collide, the full node_ids are
    used for that group so two distinct assets are ALWAYS distinguishable. A unique label is shown clean."""
    label_of: Dict[str, str] = {}
    groups: Dict[str, List[str]] = {}
    for nid, raw in entries:
        if nid and nid not in label_of:
            lbl = _obj_label_of(nid, raw)
            label_of[nid] = lbl
            groups.setdefault(lbl, []).append(nid)
    disp: Dict[str, str] = {}
    for lbl, nids in groups.items():
        if len(nids) == 1:
            disp[nids[0]] = lbl
            continue
        shorts = {n: _short_id(n) for n in nids}
        collide = len(set(shorts.values())) < len(nids)        # two short ids clash → fall back to full ids
        for n in nids:
            disp[n] = f"{lbl} · {n if collide else shorts[n]}"
    return disp


def objective_names(node_ids: Iterable[str], paths: List[Dict[str, Any]]) -> List[str]:
    """Display names for objective node_ids Disambiguation is computed over PROVEN
    objectives only — the set actually displayed — so a hypothesis path that happens to share a label never forces a
    spurious suffix; it is collision-free and group-aware."""
    disp = _objective_display_map(
        (_path_objective_id(p), (p.get("objective") or {}).get("label")) for p in paths if _path_kind(p) == "proven")
    return [disp.get(nid) or _obj_label_of(nid, None) for nid in node_ids]


def _all_proven_objectives(paths: List[Dict[str, Any]]) -> List[str]:
    return sorted({oid for p in paths if _path_kind(p) == "proven" and (oid := _path_objective_id(p))})


def objectives_closed_after(fixes_prefix: List[Dict[str, Any]], paths: List[Dict[str, Any]]) -> List[str]:
    """PATH-based counterpart of ``objectives_reachable_after``: the objective NODE_IDS for which NO
    proven path remains open after the cumulative fixes — all proven-path objectives minus the still-reachable ones.
    Keyed by node_id so « closed » and « still reachable » partition the objectives and homonyms stay distinct."""
    still = set(objectives_reachable_after(fixes_prefix, paths))
    return [o for o in _all_proven_objectives(paths) if o not in still]


def objectives_reachable_after(fixes_prefix: List[Dict[str, Any]], paths: List[Dict[str, Any]]) -> List[str]:
    """OBJECTIVE reachability, PATH-based, keyed by stable node_id: the objective node_ids still
    reached by a PROVEN path left OPEN after the cumulative fixes (union of their disjoint ``marginal_interrupts``).
    Not the engine's ``objectives_still_reachable`` (node-finding-closure) — a fix that breaks every ranked path to an
    objective still leaves it reachable here if another proven path reaches it."""
    proven = [p for p in paths if _path_kind(p) == "proven"]
    interrupted: set = set()
    for f in fixes_prefix:
        interrupted |= set(f.get("marginal_interrupts") or f.get("interrupts") or [])
    remaining = [p for p in proven if p.get("id") not in interrupted]
    return sorted({oid for p in remaining if (oid := _path_objective_id(p))})


def attack_paths_section(ap: Dict[str, Any], titles: Dict[str, str]) -> str:
    paths = ap.get("paths") or []
    proven = [p for p in paths if _path_kind(p) == "proven"]
    interrupted = [p for p in paths if _path_kind(p) == "interrupted"]
    possible = [p for p in paths if _path_kind(p) == "possible"]
    agent = [p for p in paths if _path_kind(p) == "agent"]
    # the Objective column of the path tables is disambiguated too (not only the
    # closed/reachable columns), over every objective shown here, so two assets sharing a label are distinguishable.
    obj_disp = _objective_display_map((_path_objective_id(p), (p.get("objective") or {}).get("label")) for p in paths)
    out = [section_marker("attack-paths"), "## ATTACK PATHS", ""]
    observed = [p for p in proven if _is_observed(p)]
    declared = [p for p in proven if not _is_observed(p)]
    seg = [_plural(len(observed), 'observed attack path')]
    if declared:
        seg.append(f"{_plural(len(declared), 'declared path')} (not proven)")
    seg.append(f"{_plural(len(possible), 'possible path')} (hypotheses, not proven)")
    if agent:
        seg.append(f"{_plural(len(agent), 'path')} {AGENT_SEG}")
    if interrupted:
        seg.append(f"{_plural(len(interrupted), 'path')} interrupted by a retest")
    out.append(" · ".join(seg) + ".")
    out.append("")
    out.append("> An **observed attack path** is an **observed exploitation chain**: every step is a finding this campaign actually "
               "exploited, and the chain was walked end to end. This is *observed causality*, **not** a strict per-"
               "transition necessity proof — unless a path's provenance is `observed` with recorded negative controls, "
               "the report does **not** claim an active counter-test showed each step B would fail without the capability "
               "from step A (that is E3/E4 adjudication, gated off here). A **possible** path is a hypothesis inferred "
               "from the topology and the confirmed findings: not a proof, never counted as one. A path **declared by the "
               "agent** rests on at least one link the agent stated (enabled_by) and the server did not observe: not "
               "verified, never counted as observed.")
    if ap.get("note"):
        out += ["", md_cell(ap["note"])]
    if not paths:
        out += ["", "No attack path is recorded for this campaign."]
        return "\n".join(out)

    # diagram: nodes shared by the paths; observed/declared (eligible) hops thick, hypotheses dotted, interrupted solid
    ids: Dict[str, str] = {}
    lines = ["```mermaid", "%% figure: attack-paths", "flowchart LR"]

    def nid(node_id: str, label: str) -> str:
        if node_id not in ids:
            ids[node_id] = f"n{len(ids)}"
            lines.append(f'  {ids[node_id]}["{mm_label(label)}"]')
        return ids[node_id]

    seen_edges = set()
    for p in proven + interrupted + possible + agent:
        kind = _path_kind(p)
        steps = p.get("steps") or []
        labels = {s.get("node_id"): s.get("node_label") for s in steps if s.get("node_id")}
        labels.setdefault((p.get("entry") or {}).get("node_id"), (p.get("entry") or {}).get("label"))
        labels.setdefault((p.get("objective") or {}).get("node_id"), (p.get("objective") or {}).get("label"))
        edges = p.get("edges") or []
        if not edges:
            chain = [n for n in (p.get("node_ids") or []) if n]
            edges = [{"from": a, "to": b} for a, b in zip(chain, chain[1:])]
        for e in edges:
            a, b = e.get("from"), e.get("to")
            if not a or not b:
                continue
            key = (a, b, kind)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            na, nb = nid(a, labels.get(a) or a), nid(b, labels.get(b) or b)
            tech = (e.get("technique") or {}).get("id") if isinstance(e.get("technique"), dict) else None
            if kind == "possible":
                lines.append(f'  {na} -.->|"{mm_label("hypothesis" + (" · " + tech if tech else ""))}"| {nb}')
            elif kind == "agent":
                lines.append(f'  {na} -.->|"{mm_label("declared by the agent" + (" · " + tech if tech else ""))}"| {nb}')
            elif kind == "interrupted":
                lines.append(f'  {na} -->|"{mm_label("interrupted" + (" · " + tech if tech else ""))}"| {nb}')
            else:
                # kind == "proven" covers observed/derived AND corroborated-declared paths. A declared step is asserted,
                # not traced, so it must never be labelled « proven »: observed/derived keeps its recorded per-step
                # proof, a declared step is labelled « declared ».
                proof = (e.get("proof") or "observed") if _is_observed(p) else "declared"
                lines.append(f'  {na} ==>|"{mm_label((tech + " · " if tech else "") + proof)}"| {nb}')
    lines.append("```")
    out += ["", *lines, "",
            "Thick arrows: steps of an observed or declared attack path — the label is the step's recorded proof for an "
            "observed step, « declared » for an asserted (not traced) step. Dotted arrows: steps of a possible (inferred) "
            "path — a hypothesis, not proven — or of a path declared by the agent (labelled so), not verified. Solid arrows: a step a retest interrupted. Arrow thickness is not a strict "
            "per-transition causal-necessity proof (N4).", ""]

    def table(rows: List[Dict[str, Any]], title: str) -> None:
        out.extend([f"### {title}", ""])
        if not rows:
            out.extend(["None.", ""])
            return
        out.extend(["| Path | Status | Entry | Objective | Criticality | Certainty | Findings |",
                    "|---|---|---|---|---|---|---|"])
        for p in rows:
            out.append("| " + " | ".join([
                md_cell(p.get("title"), 120), _path_word(p), md_cell((p.get("entry") or {}).get("label")),
                md_cell(obj_disp.get(_path_objective_id(p)) or (p.get("objective") or {}).get("label")), md_cell(p.get("criticality")), md_cell(p.get("certainty")),
                str(len(p.get("finding_ids") or []))]) + " |")
        out.append("")
        for p in rows:
            out.extend([f"#### {md_cell(p.get('title'), 160)}", ""])
            out.append(f"Status: **{_path_word(p)}** · provenance `{md_cell(p.get('provenance'))}` · path `{p.get('id')}`")
            inf = p.get("inference") or {}
            if inf:
                out.append("")
                out.append(f"Inferred by rule {md_cell(inf.get('rule'))} ({md_cell(inf.get('rule_label'))}); the findings it rests "
                           f"on are {md_cell(inf.get('findings_certainty'))}, the chain itself is not shown by the evidence.")
            if p.get("note"):
                out.extend(["", f"> {md_cell(p['note'])}"])
            out.append("")
            steps = p.get("steps") or []
            if steps:
                # a table, not « key: value » prose: the evidence masking reads « Credentials …: value » as a secret
                out.extend(["| Step | Asset | What happens | Technique | Proof | Findings |", "|---|---|---|---|---|---|"])
                for s in steps:
                    tech = s.get("technique") or {}
                    tcell = f"`{md_cell(tech.get('id'))}` {md_cell(tech.get('name'))}" if isinstance(tech, dict) and tech.get("id") else "—"
                    fids = [f.get("id") for f in (s.get("findings") or []) if isinstance(f, dict)]
                    out.append("| " + " | ".join([
                        str(s.get("n")), md_cell(s.get("node_label")), md_cell(s.get("plain"), 160), tcell,
                        md_cell(s.get("proof") or "—"), ", ".join(md_cell(titles.get(f) or f, 90) for f in fids) or "—"]) + " |")
                out.append("")

    # the ranked universe (observed + declared) + interrupted; each row carries its own honest proof word (« observed »
    # / « declared · not proven » / « … interrupted by a retest »), so the section header is neutral, never « observed ».
    table(proven + interrupted, "Attack paths (ranked: observed and declared)")
    table(possible, "Possible paths (hypotheses, not proven)")
    if agent:
        table(agent, "Paths declared by the agent (not verified by the server)")
    return "\n".join(out).rstrip()


# ── infrastructure ───────────────────────────────────────────────────────────────────────────────────────────────


def _port(n: Dict[str, Any]) -> str:
    port, proto = n.get("port"), n.get("protocol")
    if port in (None, ""):
        return ""
    return f"{port}/{proto}" if proto else str(port)


def infrastructure_section(infra: Dict[str, Any]) -> str:
    nodes = infra.get("nodes") or []
    edges = infra.get("edges") or []
    by_id = {n.get("id"): n for n in nodes if n.get("id")}
    out = [section_marker("infrastructure"), "## INFRASTRUCTURE MAP", ""]
    if not nodes:
        out.append("No asset is mapped by this campaign.")
        return "\n".join(out)
    hosts = [n for n in nodes if n.get("node_type") in HOST_TYPES]
    services = [n for n in nodes if n.get("node_type") == "service"]
    by_port: Dict[str, str] = {}
    for n in nodes:
        if _port(n):  # one entry per port number; the label with its protocol wins
            k = str(n.get("port"))
            by_port[k] = by_port.get(k) if "/" in by_port.get(k, "") else _port(n)
    ports = [by_port[k] for k in sorted(by_port, key=lambda x: (len(x), x))]
    zones = [z for z in ZONE_ORDER if any((n.get("zone") or "unknown") == z for n in nodes)]
    zones += sorted({n.get("zone") for n in nodes if n.get("zone") and n.get("zone") not in ZONE_ORDER})
    out.append(f"{_plural(len(nodes), 'asset')} in {_plural(len(zones), 'zone')} · {_plural(len(hosts), 'host')} · "
               f"{_plural(len(services), 'service')} · {_plural(len(ports), 'distinct port')}"
               + (f" ({', '.join(ports)})" if ports else "") + ".")
    out.append("")

    # diagram: one subgraph per zone (exposure order), parent → child edges
    ids = {n.get("id"): f"a{i}" for i, n in enumerate(nodes) if n.get("id")}
    lines = ["```mermaid", "%% figure: infrastructure", "flowchart LR"]
    for zi, z in enumerate(zones):
        lines.append(f'  subgraph z{zi}["{mm_label(ZONE_LABEL.get(z, z))}"]')
        for n in nodes:
            if (n.get("zone") or "unknown") != z or n.get("id") not in ids:
                continue
            # short labels (the tables below carry every field): name · port or type · findings
            sub = [_port(n) or str(n.get("node_type") or "asset")]
            nf = len(n.get("vulnerability_ids") or [])
            if nf:
                sub.append(_plural(nf, "finding"))
            label = mm_label(n.get("label") or n.get("id"), 30) + " · " + mm_label(" · ".join(sub), 30)
            lines.append(f'    {ids[n["id"]]}["{label}"]')
        lines.append("  end")
    seen = set()
    for e in edges:
        a, b = ids.get(e.get("from")), ids.get(e.get("to"))
        if not a or not b or (a, b) in seen:
            continue
        seen.add((a, b))
        lines.append(f"  {a} --> {b}")
    risky = [ids[n["id"]] for n in nodes if n.get("id") in ids and SEV_ORDER[_sev(n.get("effective_risk") or n.get("risk_level"))] >= 3]
    if risky:
        lines.append("  classDef risk stroke-width:3px")
        lines.append(f"  class {','.join(risky)} risk")
    lines.append("```")
    out += [*lines, "", "Thick frames: assets whose highest risk is high or critical.", ""]

    out += ["### Zones", "", "| Zone | Assets | Findings | Highest risk |", "|---|---|---|---|"]
    for z in zones:
        zn = [n for n in nodes if (n.get("zone") or "unknown") == z]
        top = max((_sev(n.get("effective_risk") or n.get("risk_level")) for n in zn), key=lambda s: SEV_ORDER[s], default="none")
        out.append(f"| {md_cell(ZONE_LABEL.get(z, z))} | {len(zn)} | {sum(len(n.get('vulnerability_ids') or []) for n in zn)} | {top} |")
    out.append("")

    out += ["### Hosts, services and ports", "", "| Host | Asset | Type | Port | Product | Zone | Findings | Risk |",
            "|---|---|---|---|---|---|---|---|"]

    def host_of(n: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cur, hops = n, 0
        while cur and hops < 32:
            if cur.get("node_type") in HOST_TYPES:
                return cur
            cur, hops = by_id.get(cur.get("parent_node_id")), hops + 1
        return None

    def sort_key(n: Dict[str, Any]) -> Tuple[str, int, str]:
        h = host_of(n)
        return (str((h or {}).get("label") or "~"), 0 if n is h else 1, str(n.get("label") or ""))

    for n in sorted(nodes, key=sort_key):
        h = host_of(n)
        product = " ".join(str(x) for x in (n.get("product"), n.get("version")) if x) or n.get("technology") or n.get("service") or ""
        out.append("| " + " | ".join([
            md_cell((h or {}).get("label") or "—"), md_cell(n.get("label") or n.get("id"), 80), md_cell(n.get("node_type") or "asset"),
            md_cell(_port(n) or "—"), md_cell(product or "—", 60), md_cell(ZONE_LABEL.get(n.get("zone") or "unknown", n.get("zone"))),
            str(len(n.get("vulnerability_ids") or [])), _sev(n.get("effective_risk") or n.get("risk_level"))]) + " |")
    return "\n".join(out).rstrip()


# ── fix first ────────────────────────────────────────────────────────────────────────────────────────────────────


def _path_refs(path_ids: Iterable[str], paths: Dict[str, Dict[str, Any]]) -> str:
    refs = []
    for pid in path_ids or []:
        p = paths.get(pid)
        if not p:
            refs.append(f"`{md_cell(pid)}`")
            continue
        refs.append(f"{md_cell(p.get('title'), 90)} — {_path_word(p)}")
    return "; ".join(refs) or "—"


def fix_first_section(ap: Dict[str, Any], titles: Dict[str, str]) -> str:
    paths = {p.get("id"): p for p in ap.get("paths") or []}
    ranking = ap.get("ranking") or {}
    ff = ap.get("fix_first") or {}
    out = [section_marker("fix-first"), "## FIX FIRST", ""]
    fixes = ranking.get("fixes") or []
    if ranking.get("allowed") and fixes:
        out.append(f"Ranked on the ranked attack paths (observed + declared; provenance {md_cell(ranking.get('provenance'))}): fixing the first "
                   "rows interrupts the most paths. Possible paths (hypotheses) are not ranked.")
        out += ["", "| Rank | Fix | Findings | Paths interrupted | Marginal gain | Cumulative coverage | Objectives with no open ranked attack path | Objectives still reachable via another ranked attack path |",
                "|---|---|---|---|---|---|---|---|"]
        cum = 0
        for i, f in enumerate(fixes):
            mlist = f.get("marginal_interrupts")                       # NEW paths at this rank (disjoint across ranks)
            marginal = len(mlist) if isinstance(mlist, list) else int(f.get("interrupts_count") or 0)
            standalone = int(f.get("interrupts_count", marginal))      # the fix's OWN count (may overlap higher ranks)
            of_total = int(f.get("of_total") or 0)
            cum = min(of_total, cum + marginal) if of_total else cum + marginal
            pct = round(100.0 * cum / of_total) if of_total else 0
            # HONESTY: path coverage is not objective closure — after the fixes so far, which objectives are
            # still reached by another OPEN proven path. « none » means every proven path to every objective is cut.
            pv = list(paths.values())
            closed_by_path = objective_names(objectives_closed_after(fixes[: i + 1], pv), pv)   # no open proven path remains
            still_reach = objective_names(objectives_reachable_after(fixes[: i + 1], pv), pv)   # an open proven path remains
            out.append("| " + " | ".join([
                str(f.get("rank")), md_cell(f.get("label"), 120),
                ", ".join(md_cell(titles.get(x) or x, 70) for x in f.get("finding_ids") or []) or "—",
                f"{standalone} of {of_total}: {_path_refs(f.get('interrupts'), paths)}",
                f"+{marginal}", f"{cum} of {of_total} ({pct}%)",
                ", ".join(md_cell(o) for o in closed_by_path) or "—",
                ", ".join(md_cell(o) for o in still_reach) or "none"]) + " |")
        synth = coverage_sentence(fix_rows_cumulative(ranking, None, {}, paths=list(paths.values())))
        if synth:
            out += ["", synth]
        return "\n".join(out).rstrip()

    if ranking.get("note") or ff.get("why_not_paths_text"):
        out.append(f"No attack-path ranking for this campaign: {md_cell(ff.get('why_not_paths_text') or ranking.get('note'))}")
        out.append("")
    pivots = ranking.get("pivots") or []
    if pivots:
        out += ["### Observed pivots", "", "Fixes that interrupt the ranked attack paths (too few paths to rank them against each other).", "",
                "| Fix | Findings | Interrupts | Objectives still reachable |", "|---|---|---|---|"]
        for f in pivots:
            out.append("| " + " | ".join([
                md_cell(f.get("label"), 120), ", ".join(md_cell(titles.get(x) or x, 70) for x in f.get("finding_ids") or []) or "—",
                f"{f.get('interrupts_count', 0)} of {f.get('of_total')}: {_path_refs(f.get('interrupts'), paths)}",
                ", ".join(md_cell(o) for o in f.get("objectives_still_reachable") or []) or "—"]) + " |")
        out.append("")
    items = ff.get("items") or []
    if items:
        counts = (ff.get("counts") or {}).get("text") or {}
        out += [f"### {md_cell(ff.get('label') or 'Fix-first list')}", ""]
        intro = [md_cell(x) for x in (counts.get("fixes"), counts.get("findings"), counts.get("top")) if x]
        if intro:
            out += [" · ".join(intro) + ".", ""]
        if (ap.get("triage") or {}).get("note"):
            out += [f"> {md_cell(ap['triage']['note'])}", ""]
        out += ["| Rank | Fix | Severity | Proof | Reports | Interrupts | Also on | Why |", "|---|---|---|---|---|---|---|---|"]
        for it in items:
            breaks = it.get("breaks_paths") or []
            fids = set(it.get("finding_ids") or [])
            also = [pid for pid, p in paths.items() if pid not in breaks and fids & set(p.get("finding_ids") or [])]
            rank = f"{it.get('rank')}" + (f" (tie of {it.get('tie_size')})" if (it.get("tie_size") or 1) > 1 else "")
            out.append("| " + " | ".join([
                rank, md_cell(it.get("label"), 120), md_cell(it.get("severity")), md_cell(it.get("proof")), str(it.get("reports") or len(fids)),
                _path_refs(breaks, paths), _path_refs(also, paths), md_cell("; ".join(it.get("reasons") or []), 220) or "—"]) + " |")
        more = (ff.get("items_total") or len(items)) - len(items)
        if more > 0:
            out += ["", f"{_plural(more, 'further fix', 'further fixes')} of lower rank are not listed here: their findings are in the findings table of the report."]
    elif not pivots:
        out.append("No open finding to fix.")
    return "\n".join(out).rstrip()


# ── frameworks ───────────────────────────────────────────────────────────────────────────────────────────────────


def frameworks_section(fw: Dict[str, Any], catalogue: Dict[str, Any]) -> str:
    out = [section_marker("frameworks"), "## FRAMEWORK MAPPING", ""]
    att = fw.get("attack") or {}
    fdocs = fw.get("findings") or {}
    out.append("Readings of this campaign's findings in five references. A tactic, control or step without a finding means "
               "« not observed in this campaign », never « protected » or « compliant ».")
    out.append("")

    # ATT&CK: every tactic of the catalogue, in the matrix order
    by_id = {t.get("id"): t for t in att.get("tactics") or []}
    cat_tactics = (catalogue.get("attack") or {}).get("tactics") or [{"id": t.get("id"), "name": t.get("name")} for t in att.get("tactics") or []]
    total_tech = sum(len(t.get("techniques") or []) for t in cat_tactics)
    seen_tech = {x.get("technique_id") for t in att.get("tactics") or [] for x in t.get("techniques") or []}
    lit = sum(1 for t in cat_tactics if (by_id.get(t.get("id")) or {}).get("findings"))
    out += [f"### MITRE ATT&CK® Enterprise v{md_cell(att.get('version'))}", "",
            f"{_plural(len(seen_tech), 'technique')} observed in {lit} of {len(cat_tactics)} tactics"
            + (f" (the matrix has {total_tech} techniques)" if total_tech else "") + ".", "",
            "| Tactic | Findings | Techniques observed |", "|---|---|---|"]
    for t in cat_tactics:
        row = by_id.get(t.get("id")) or {}
        techs = row.get("techniques") or []
        cell = "; ".join(f"`{md_cell(x.get('technique_id'))}` {md_cell(x.get('technique_name'))} ({x.get('distinct_findings', len(x.get('finding_ids') or []))})"
                         for x in techs) or "not observed"
        out.append(f"| {md_cell(t.get('name'))} `{md_cell(t.get('id'))}` | {row.get('distinct_findings', 0)} | {cell} |")
    if att.get("reading"):
        out += ["", f"> {md_cell(att['reading'])}"]
    out.append("")

    # ATLAS
    atl = fw.get("atlas") or {}
    out += [f"### MITRE ATLAS™ {md_cell(atl.get('version'))}", ""]
    ai = atl.get("ai_findings") or []
    if ai:
        out += ["| Finding | OWASP LLM | ATLAS techniques (relation) |", "|---|---|---|"]
        for a in ai:
            techs = "; ".join(f"`{md_cell(t.get('id'))}` {md_cell(t.get('name'))} ({md_cell(t.get('relation'))})" for t in a.get("atlas") or [])
            owasp = a.get("owasp_llm")
            owasp = ", ".join(md_cell(x) for x in owasp) if isinstance(owasp, list) else md_cell(owasp or "—")
            out.append(f"| {md_cell(a.get('title') or a.get('finding_id'), 90)} | {owasp} | {techs or 'no ATLAS equivalent'} |")
    unmapped = atl.get("unmapped_ai_findings") or []
    if unmapped:
        out += ["", f"{_plural(len(unmapped), 'AI finding')} outside the crosswalk vocabulary (not mapped)."]
    else:
        out.append(f"No AI finding in this campaign. Surface state: {md_cell(atl.get('state_label') or atl.get('state') or 'unknown')}.")
    if atl.get("crosswalk_status"):
        out += ["", f"Crosswalk {md_cell(atl['crosswalk_status'])}."]
    out.append("")

    # ISO 27001 Annex A (references only: no ISO text is reproduced)
    iso = fw.get("iso") or {}
    groups = iso.get("groups_by_cited_ref") or []
    vc = iso.get("versions_cited") or {}
    out += ["### ISO/IEC 27001 Annex A", "",
            f"Controls cited by the agents: {_plural(len(groups), 'reference')}"
            + (" (" + ", ".join(f"{v}: {_plural(int(n), 'finding')}" for v, n in sorted(vc.items()) if n) + ")" if vc else "") + "."]
    if groups:
        out += ["", "| Version | Control | Findings |", "|---|---|---|"]
        for g in groups:
            names = ", ".join(md_cell((fdocs.get(x) or {}).get("title") or x, 70) for x in (g.get("finding_ids") or [])[:6])
            extra = len(g.get("finding_ids") or []) - 6
            out.append(f"| {md_cell(g.get('version'))} | `{md_cell(g.get('ref'))}` | {len(g.get('finding_ids') or [])}: {names}{f' (+{extra})' if extra > 0 else ''} |")
    if iso.get("reading"):
        out += ["", f"> {md_cell(iso['reading'])}"]
    out.append("")

    # IEC 62443-3-3: numbering + Darkmoon summaries (catalogue); the mapping is derived by the server (indicative)
    iec = fw.get("iec62443") or {}
    if iec:
        cat_frs = {f.get("id"): f for f in (catalogue.get("iec62443") or {}).get("foundational") or []}
        cov = iec.get("coverage") or {}
        out += ["### IEC 62443-3-3 (system requirements)", "",
                f"Requirements concerned: {_plural(int(cov.get('requirements_concerned') or 0), 'system requirement')} "
                f"for {_plural(int(cov.get('mapped') or 0), 'finding')}"
                + (f"; {_plural(int(cov.get('unmapped') or 0), 'finding')} without a match" if cov.get("unmapped") else "") + "."]
        rows = [(fr, r) for fr in iec.get("foundational") or [] for r in fr.get("requirements") or []]
        if rows:
            out += ["", "| FR | Requirement | What it is about (Darkmoon summary) | Findings |", "|---|---|---|---|"]
            for fr, r in rows:
                summ = next((x.get("summary") for x in (cat_frs.get(fr.get("id")) or {}).get("requirements") or [] if x.get("id") == r.get("id")), "")
                ids = r.get("finding_ids") or []
                names = ", ".join(md_cell((fdocs.get(x) or {}).get("title") or x, 70) for x in ids[:6])
                out.append(f"| {md_cell(fr.get('id'))} {md_cell(fr.get('code'))} | `{md_cell(r.get('id'))}` | {md_cell(summ, 120)} | "
                           f"{len(ids)}: {names}{f' (+{len(ids) - 6})' if len(ids) > 6 else ''} |")
        quiet = [f"{fr.get('id')} {fr.get('code')}" for fr in iec.get("foundational") or [] if not fr.get("finding_ids")]
        if quiet:
            out += ["", "Not observed in this campaign: " + ", ".join(md_cell(q) for q in quiet) + "."]
        if iec.get("reading"):
            out += ["", f"> {md_cell(iec['reading'])}"]
        out.append("")

    # EBIOS RM, workshop 4 technical input
    eb = fw.get("ebios") or {}
    c = eb.get("counts") or {}
    out += ["### EBIOS Risk Manager (ANSSI), workshop 4 input", "",
            f"{_plural(int(c.get('candidate_paths') or 0), 'candidate operational sequence')} · "
            f"{_plural(int(c.get('single_step_paths') or 0), 'single-step path')} · "
            f"{_plural(int(c.get('unlinked_vulnerabilities') or 0), 'finding')} not linked to a path."]
    dist = eb.get("feasibility_distribution") or {}
    if dist:
        out += ["", "| Technical feasibility (DM-FEAS-1) | Findings |", "|---|---|"]
        for k in ("F4", "F3", "F2", "F1", "not_rated"):
            if k in dist:
                out.append(f"| {'not rated' if k == 'not_rated' else k} | {dist[k]} |")
    seqs = (eb.get("candidate_paths") or []) + (eb.get("single_step_paths") or [])
    if seqs:
        out += ["", "| Sequence | Status | Steps |", "|---|---|---|"]
        for s in seqs:
            # the EBIOS candidate sequences carry a provenance (observed / derived / declared): the Status must tell an
            # observed step from a declared (asserted, not traced) one exactly as the ATTACK PATHS section does, never a
            # bare « proven » that would present a declared path as proof. Reuse the canonical per-path word.
            kind = _path_word(s)
            steps = " → ".join(md_cell((st.get("node_label") or "") + (f" ({st.get('technique_id')})" if st.get("technique_id") else ""), 60)
                               for st in s.get("steps") or [])
            out.append(f"| {md_cell(s.get('title'), 100)} | {kind} | {steps or '—'} |")
    need = eb.get("needs_owner_input") or []
    if need:
        out += ["", "Owner input still needed: " + ", ".join(md_cell(x).replace("_", " ") for x in need) + "."]
    if eb.get("disclaimer"):
        out += ["", f"> {md_cell(eb['disclaimer'])}"]
    lic = fw.get("licences") or []
    if lic:
        out += ["", "Licences: " + " · ".join(md_cell(x.get("text")) for x in lic if isinstance(x, dict)) + "."]
    return "\n".join(out).rstrip()


# ── remediation priorities (lead) ────────────────────────────────────────────────────────────────────────────────

def _fid_maps(findings: Optional[List[Dict[str, Any]]], infra: Dict[str, Any]):
    """finding_id -> (severity, proof, node_label). Server data only; used to enrich the ranking rows for the report
    with the same per-finding severity/status as every other view."""
    node_label = {n.get("id"): (n.get("label") or n.get("title") or n.get("id")) for n in (infra or {}).get("nodes") or []}
    sev, proof, asset = {}, {}, {}
    for v in findings or []:
        fid = v.get("id")
        if not fid:
            continue
        sev[fid] = _sev(v.get("severity"))
        s = str(v.get("status") or "").lower()
        proof[fid] = s if s in ("exploited", "confirmed", "unconfirmed") else "unconfirmed"
        asset[fid] = node_label.get(v.get("node_id"), v.get("node_id") or "")
    return sev, proof, asset


def fix_rows_cumulative(ranking: Dict[str, Any], findings: Optional[List[Dict[str, Any]]], infra: Dict[str, Any],
                        fix_first: Optional[Dict[str, Any]] = None, paths: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Presentation rows for the allowed path-ranking: marginal gain (``interrupts_count`` — the engine's new paths at
    this rank) and the running CUMULATIVE coverage, with the per-fix severity/proof/asset derived from the member
    findings. No new computation: the cumulative is just the running sum of the engine's marginal counts, so every view
    reads the same numbers."""
    sev, proof, asset = _fid_maps(findings, infra)
    # With a written report the findings list is not passed (findings=None) and
    # the map above is empty -> the rows would read severity « unknown ». fix_first.items already carry the same
    # server-enriched per-finding severity/proof (fix_triage), present whether or not a report file exists; fill the
    # gap from them so the priorities table shows the real severity/proof on a real campaign too.
    for it in (fix_first or {}).get("items") or []:
        isev = _sev(it.get("severity"))
        iproof = str(it.get("proof") or "").lower()
        for fid in it.get("finding_ids") or []:
            if fid not in sev and isev != "none":
                sev[fid] = isev
            if fid not in proof and iproof in ("exploited", "confirmed", "unconfirmed"):
                proof[fid] = iproof
    rows, cum = [], 0
    all_fixes = ranking.get("fixes") or []
    for i, f in enumerate(all_fixes):
        fids = f.get("finding_ids") or []
        # MARGINAL = paths NEWLY interrupted at this rank (the engine's ``marginal_interrupts``, disjoint across ranks by
        # the greedy construction). The cumulative is their running sum, so it can never exceed of_total. We do NOT sum
        # ``interrupts_count`` (the fix's STANDALONE count): two ranked fixes could share a path and that would
        # double-count it (cumulative > of_total, % > 100). Fall back to interrupts_count only if the marginal list is
        # absent (older documents), and clamp to of_total.
        mlist = f.get("marginal_interrupts")
        marginal = len(mlist) if isinstance(mlist, list) else int(f.get("interrupts_count") or 0)
        of_total = int(f.get("of_total") or 0)
        cum = min(of_total, cum + marginal) if of_total else cum + marginal
        rsev = max((sev.get(x, "unknown") for x in fids), key=lambda s: SEV_ORDER.get(s, 0), default="unknown")
        rproof = max((proof.get(x, "unconfirmed") for x in fids), key=lambda p: {"exploited": 3, "confirmed": 2, "unconfirmed": 1}.get(p, 0), default="unconfirmed")
        assets = sorted({asset.get(x) for x in fids if asset.get(x)})
        rows.append({"rank": f.get("rank"), "label": f.get("label"), "finding_ids": fids,
                     "severity": rsev, "proof": rproof, "assets": assets,
                     "marginal": marginal, "cumulative": cum, "of_total": of_total,
                     "cumulative_pct": round(100.0 * cum / of_total) if of_total else 0,
                     "interrupts": f.get("interrupts") or [], "objectives_closed": f.get("objectives_closed") or [],
                     # path-based, keyed by node_id then resolved to display names: objectives
                     # still reached by an OPEN proven path after the cumulative fixes
                     "objectives_still_reachable": objective_names(objectives_reachable_after(all_fixes[: i + 1], paths or []), paths or [])})
    return rows


def coverage_sentence(rows: List[Dict[str, Any]]) -> Optional[str]:
    """The honest cumulative synthesis for the top fixes. A simulation of fixing them, never a proof of deployment nor a
    reduction of total business risk."""
    if not rows:
        return None
    last = rows[-1]
    of_total = last["of_total"]
    cum = last["cumulative"]
    pct = last["cumulative_pct"]
    rem = max(0, of_total - cum)
    still = last.get("objectives_still_reachable") or []
    # PATH COVERAGE is not OBJECTIVE closure: after the ranked fixes, an objective can stay reachable by
    # another proven path. Say so explicitly, and only claim objectives are closed when the engine says none remain.
    if still:
        obj_clause = (f" **{_plural(len(still), 'targeted objective')} would still be reachable by another attack path** "
                      f"({', '.join(md_cell(x) for x in still)}) — path coverage is not the same as making the objectives unreachable.")
    else:
        obj_clause = " After these fixes no ranked attack path reaches any of this campaign's recorded objectives."
    # DENOMINATOR (the universe is stated): the ranking is over this campaign's observed AND declared attack paths
    # (the engine's ranked universe); hypotheses are not ranked. So this coverage is « of the ranked attack paths », not
    # « of the observed ones » — a declared path is never counted as observed.
    return (f"Fixing the {_plural(len(rows), 'priority fix', 'priority fixes')} interrupts **{cum} of {of_total}** "
            f"ranked attack path{'s' if of_total != 1 else ''} (**{pct}%** of this campaign's ranked attack paths); "
            f"{_plural(rem, 'ranked attack path')} would remain open.{obj_clause} "
            f"This is a *simulation* over the campaign's proven/admissible paths, not a proof of deployment, not a cut of "
            f"total business risk, and not a guarantee against untested alternative routes.")


def remediation_priorities_section(ap: Dict[str, Any], infra: Dict[str, Any], campaign: Dict[str, Any],
                                   findings: Optional[List[Dict[str, Any]]], titles: Dict[str, str]) -> str:
    """LEAD section: the immediately-exploitable summary a security lead reads first — what to fix
    first, why, which paths it breaks, and the cumulative coverage. All values come from the backend contracts
    (``ranking.fixes`` / ``fix_first`` / summary); nothing is recomputed. Honest fallback when paths are not proven."""
    paths = ap.get("paths") or []
    proven = [p for p in paths if _path_kind(p) == "proven"]
    possible = [p for p in paths if _path_kind(p) == "possible"]
    agent = [p for p in paths if _path_kind(p) == "agent"]
    s = ap.get("summary") or {}
    objectives = s.get("objectives_reachable") or []
    stats = (campaign or {}).get("stats") or {}
    n_find = len(findings) if findings else int(stats.get("total_findings") or 0)
    exploited = (sum(1 for v in findings if str(v.get("status") or "").lower() == "exploited")
                 if findings else int(stats.get("exploited") or 0))
    ranking = ap.get("ranking") or {}
    ff = ap.get("fix_first") or {}
    out = [section_marker("remediation-priorities"), "## REMEDIATION PRIORITIES & ATTACK PATHS", ""]
    # Honesty: a product-demo campaign is synthetic data, not a real engagement. Say so before any
    # « exploited » / « proven » figure, so the scripted demo is never read as the result of a live test.
    if (campaign or {}).get("demo"):
        out.append("> **Demonstration data — not a real engagement.** The findings below are synthetic, scripted for a "
                   "product demo. « Exploited » and « proven attack path » describe this scripted scenario and its "
                   "recorded negative controls, not a live test of a client's system.")
        out.append("")
    # A REAL campaign executed against an ISOLATED LAB with SYNTHETIC data is not a client breach. Separate
    # the execution mode (live) from the target environment (test lab), so « data breach », PII and IBANs are read as
    # fabricated lab records, and no regulatory (e.g. GDPR) obligation is asserted from a lab test.
    if (campaign or {}).get("target_environment") in ("lab", "test_lab", "synthetic"):
        out.append("> **Real execution against an ISOLATED TEST LAB with SYNTHETIC data.** The exploitation below was "
                   "really performed (execution_mode = live), but the target is a lab and every credential, record, PII "
                   "value and IBAN is fabricated. Treat « data breach », « CRM data » and « 60 customer records » as a "
                   "demonstration on fake data: no real-world data was exposed, and no regulatory notification "
                   "obligation (GDPR Art. 33 or otherwise) is established by this test. Any legal conclusion applies "
                   "only once run against a production system holding real data.")
        out.append("")
    # The authoritative severity figures are the SERVER counters (campaign.stats), stated here canonically so
    # a reader never relies on an agent's free-prose count. Every view reads these same numbers.
    sev_order = ["critical", "high", "medium", "low", "info"]
    if stats:
        parts = [f"{int(stats.get(k) or 0)} {k}" for k in sev_order if int(stats.get(k) or 0) > 0]
        if parts:
            out.append(f"**Certified severity (server counts):** {int(stats.get('total_findings') or n_find)} findings — "
                       f"{', '.join(parts)}; {int(stats.get('exploited') or exploited)} exploited. These are the "
                       f"authoritative counts; any narrative prose is secondary to them.")
            out.append("")
    _obs = [p for p in proven if _is_observed(p)]
    _dec = [p for p in proven if not _is_observed(p)]
    out.append(f"{_plural(n_find, 'vulnerability', 'vulnerabilities')} discovered · "
               f"{exploited} exploited · {_plural(len(_obs), 'observed attack path')}"
               + (f" · {_plural(len(_dec), 'declared path')} (not proven)" if _dec else "")
               + f" · {_plural(len(possible), 'possible path')} (hypotheses, not proven) · "
               + (f"{_plural(len(agent), 'path')} {AGENT_SEG} · " if agent else "")
               + f"{_plural(len(objectives), 'targeted asset')}.")
    out.append("")
    if ranking.get("allowed") and ranking.get("fixes"):
        rows = fix_rows_cumulative(ranking, findings, infra, ff, paths=paths)
        out.append(f"**{_plural(len(rows), 'priority fix', 'priority fixes')}** ranked on the ranked attack paths (observed + declared) "
                   f"(provenance {md_cell(ranking.get('provenance'))}), by how many paths each interrupts:")
        out += ["", "| Priority | Vulnerability | Asset | Severity | Proof | Paths interrupted | Marginal gain | Cumulative coverage |",
                "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            out.append("| " + " | ".join([
                str(r["rank"]), md_cell(r["label"], 90), ", ".join(md_cell(a) for a in r["assets"]) or "—",
                md_cell(r["severity"]), md_cell(r["proof"]),
                f"{r['marginal']} of {r['of_total']}", f"+{r['marginal']}",
                f"{r['cumulative']} of {r['of_total']} ({r['cumulative_pct']}%)"]) + " |")
        out += ["", coverage_sentence(rows), ""]
        out.append("> Detail, the diagram and each path's steps are in **Attack paths** and **Fix first** below.")
    else:
        why = ff.get("why_not_paths_text") or ranking.get("note") or "insufficient proof to rank by attack paths"
        out.append(f"**Path-based prioritisation unavailable: {md_cell(why)}**")
        out.append("")
        if possible:
            out.append(f"{_plural(len(possible), 'possible (inferred) path')} were derived from the topology and the "
                       "confirmed findings — hypotheses, not proofs. They are listed, apart, under **Attack paths**.")
        out.append(f"The alternative ranking below is **by severity and proof quality**, clearly marked as such: "
                   f"it does not claim to interrupt attack paths. See **Fix first**.")
    return "\n".join(out).rstrip()


# ── assembly ─────────────────────────────────────────────────────────────────────────────────────────────────────

SECTIONS = [("remediation-priorities", "Remediation priorities"), ("attack-paths", "Attack paths"),
            ("infrastructure", "Infrastructure map"), ("fix-first", "Fix first"), ("frameworks", "Framework mapping")]


# ── no written report (stopped / running / error campaign): the findings themselves, as data — never a written prose ──

STATUS_NOTE = {
    "stopped": "Campaign stopped: no written report from the agents. This report is built from the findings and the server's analysis.",
    "running": "Campaign in progress: no written report yet. This partial report is built from the findings found so far and the server's analysis; it changes until the campaign ends.",
    "error": "Campaign ended with an error: no written report from the agents. This report is built from the findings and the server's analysis.",
    "failed": "Campaign failed: no written report from the agents. This report is built from the findings and the server's analysis.",
}


def status_note(status: Any) -> str:
    s = str(status or "").lower()
    return STATUS_NOTE.get(s, "No written report from the agents for this campaign. This report is built from the findings and the server's analysis.")


def key_figures_section(campaign: Dict[str, Any], vulns: List[Dict[str, Any]]) -> str:
    """Counts only (severity × proof), computed from the findings — the summary a written report would give is absent."""
    sevs = ["critical", "high", "medium", "low", "info"]
    proofs = ["exploited", "confirmed", "unconfirmed"]
    def st(v):
        s = str(v.get("status") or "").lower()
        return s if s in proofs else "unconfirmed"
    # (the note on the missing written report travels apart, as `note` of the annex document)
    out = [section_marker("key-figures"), "## KEY FIGURES", "",
           f"{_plural(len(vulns), 'finding')} · overall risk {md_cell(campaign.get('overall_risk') or 'not rated')}.", "",
           "| Severity | Findings | Exploited | Confirmed | Unconfirmed |", "|---|---|---|---|---|"]
    for s in sevs:
        rows = [v for v in vulns if _sev(v.get("severity")) == s]
        out.append(f"| {s} | {len(rows)} | " + " | ".join(str(sum(1 for v in rows if st(v) == p)) for p in proofs) + " |")
    out.append(f"| total | {len(vulns)} | " + " | ".join(str(sum(1 for v in vulns if st(v) == p)) for p in proofs) + " |")
    return "\n".join(out)


def _ordered(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(vulns, key=lambda v: (-SEV_ORDER[_sev(v.get("severity"))], -(float(v.get("cvss_score") or 0) if str(v.get("cvss_score") or "").replace(".", "", 1).isdigit() else 0), str(v.get("title") or "")))


def findings_sections(vulns: List[Dict[str, Any]]) -> List[str]:
    """FINDINGS TABLE + VULNERABILITY DETAILS from the stored findings: their own fields, their own text."""
    vs = _ordered(vulns)
    table = [section_marker("findings-table"), "## FINDINGS TABLE", "", "| # | ID | Title | Severity | CVSS | Status | Endpoint |", "|---|---|---|---|---|---|---|"]
    for i, v in enumerate(vs, 1):
        table.append("| " + " | ".join([str(i), f"`{md_cell(v.get('id'))}`", md_cell(v.get("title"), 120), _sev(v.get("severity")).upper(),
                                          md_cell(v.get("cvss_score") or "—"), md_cell(v.get("status") or "—"), f"`{md_cell(v.get('endpoint'), 100)}`" if v.get("endpoint") else "—"]) + " |")
    det = [section_marker("vulnerability-details"), "## VULNERABILITY DETAILS", ""]
    if not vs:
        det.append("No finding recorded for this campaign.")
    for i, v in enumerate(vs, 1):
        det += [f"### {i} — {md_cell(v.get('title') or v.get('id'), 200)}", "", "| Field | Value |", "|---|---|"]
        attack = " ".join(x for x in (v.get("mitre_attack_id"), v.get("mitre_attack_name")) if x)
        try:   # derived by the server (indicative), same rules as the frameworks view
            from api.frameworks import iec62443_refs
            iec = ", ".join(r["sr"] for r in iec62443_refs(v)) or None
        except Exception:
            iec = None
        code = {"ID", "CVSS vector", "Endpoint"}  # set as code: the value is cleaned first, then wrapped (md_cell flattens backticks)
        for k, val in (("ID", v.get("id")), ("Severity", _sev(v.get("severity")).upper()), ("CVSS score", v.get("cvss_score")),
                       ("CVSS vector", v.get("cvss_vector")), ("Status", v.get("status")),
                       ("Category", v.get("category")), ("Endpoint", v.get("endpoint")), ("MITRE ATT&CK", attack or None),
                       ("ISO 27001", v.get("iso27001_control")), ("IEC 62443-3-3", iec), ("CVE / CWE", v.get("cve")), ("Component", v.get("plugin_or_component")),
                       ("Discovered by", v.get("discovered_by_agent")), ("Discovered at", v.get("discovered_at"))):
            if val not in (None, "", []):
                cell = md_cell(val, 300)
                det.append(f"| {k} | {'`' + cell + '`' if k in code else cell} |")
        det.append("")
        meta = v.get("evidence_meta") or {}
        if isinstance(meta, dict) and any(meta.get(x) for x in ("requests", "commands")):
            det += [f"Proof on file: {_plural(int(meta.get('requests') or 0), 'request')}, {_plural(int(meta.get('commands') or 0), 'command')} (on the finding's page).", ""]
        for head, key in (("Description", "description"), ("Remediation", "remediation")):
            text = str(v.get(key) or "").strip()
            if text:
                det += [f"#### {head}", "", text, ""]
    return ["\n".join(table), "\n".join(det).rstrip()]


def build_annex(ap: Dict[str, Any], infra: Dict[str, Any], fw: Optional[Dict[str, Any]], catalogue: Dict[str, Any],
                campaign: Optional[Dict[str, Any]] = None, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """`findings` given (no written report): KEY FIGURES first, FINDINGS TABLE and VULNERABILITY DETAILS last."""
    titles = {}
    for p in ap.get("paths") or []:
        for s in p.get("steps") or []:
            for f in s.get("findings") or []:
                if isinstance(f, dict) and f.get("id"):
                    titles[f["id"]] = f.get("title") or f["id"]
    for fid, f in ((fw or {}).get("findings") or {}).items():
        titles.setdefault(fid, (f or {}).get("title") or fid)
    lead = remediation_priorities_section(ap, infra, campaign or {}, findings, titles)
    parts = [lead, attack_paths_section(ap, titles), infrastructure_section(infra), fix_first_section(ap, titles)]
    sections = list(SECTIONS)
    if fw:
        parts.append(frameworks_section(fw, catalogue))
    else:
        sections = sections[:4]          # drop only the frameworks section (keep remediation-priorities + the 3 core)
    written = findings is None
    if not written:
        parts = [key_figures_section(campaign or {}, findings or [])] + parts + findings_sections(findings or [])
        sections = [("key-figures", "Key figures")] + sections + [("findings-table", "Findings table"), ("vulnerability-details", "Vulnerability details")]
    return {"schema_version": SCHEMA, "sections": [{"id": i, "title": t} for i, t in sections],
            "figures": ["attack-paths", "infrastructure"], "content": "\n\n".join(parts) + "\n",
            "written_report": written, "status": (campaign or {}).get("status"),
            "note": None if written else status_note((campaign or {}).get("status"))}
