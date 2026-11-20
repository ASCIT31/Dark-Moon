"""Markdown rendering of the report model (``darkmoon-report/v2``), both editions.

Deterministic: the same model gives the same bytes. Writes only what the model holds (no number is computed here).
Every section starts with ``<!-- dm-section: <id> -->`` on the line before its ``## `` heading (stable ids with ``-``
for ``_``, read by the web report and the terminal explorer), every anchor an internal link points to is written as ``<a id="…"></a>``.
Untrusted text (finding titles, agent texts, evidence) is neutralised: table cells keep one line with pipes and
backticks escaped, raw HTML is shown as text, evidence sits in a fence longer than any backtick run it contains.

Pure Python standard library, no I/O (``exec_core`` rule).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import report_model as _rm

_HTML_ESC = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")
_ANCHOR = re.compile(r"[^A-Za-z0-9_-]")
SEV_WORD = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def cell(value: Any, limit: int = 0) -> str:
    """A Markdown table cell: one line, pipes and backticks neutralised, HTML shown as text, images never fetched."""
    s = re.sub(r"\s+", " ", _CTRL.sub("", "" if value is None else str(value))).strip()
    s = s.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'")
    if limit and len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s.translate(_HTML_ESC).replace("![", "!\\[") or "-"


def prose(value: Any) -> str:
    """A paragraph of text from data: HTML shown as text, headings / rules / images neutralised, lines kept."""
    s = _CTRL.sub("", "" if value is None else str(value)).replace("\r\n", "\n").replace("\r", "\n").strip()
    s = s.translate(_HTML_ESC).replace("![", "!\\[")
    out = []
    for line in s.split("\n"):
        if re.match(r"^\s{0,3}(#{1,6}\s|[-*_]{3,}\s*$|```|~~~|<!--)", line):
            line = "\\" + line.lstrip()
        out.append(line)
    return "\n".join(out)


def fence(body: str, lang: str = "") -> str:
    """A code block whose fence is longer than any backtick run inside (CommonMark: untrusted text cannot close it)."""
    t = _CTRL.sub("", str(body)).rstrip("\n")
    longest = max((len(m) for m in re.findall(r"`+", t)), default=0)
    f = "`" * max(3, longest + 1)
    return f"{f}{lang}\n{t}\n{f}"


def marker_id(section_id: Any) -> str:
    """The section id as written in the marker (readers accept ``[a-z0-9-]``): ``cyber_score`` -> ``cyber-score``."""
    return re.sub(r"[^a-z0-9-]", "-", str(section_id or "").lower())[:64]


def section_marker(section_id: Any) -> str:
    return f"<!-- dm-section: {marker_id(section_id)} -->"


def anchor(aid: Any) -> str:
    return f'<a id="{_ANCHOR.sub("-", str(aid or ""))[:90]}"></a>'


def link(label: str, target: Optional[str]) -> str:
    if not target:
        return label
    label = re.sub(r"(?<!\\)([\[\]])", r"\\\1", label)
    return f"[{label}](#{_ANCHOR.sub('-', str(target))[:90]})"


def _table(columns: List[str], rows: List[List[Any]], links: Optional[List[Optional[str]]] = None) -> List[str]:
    out = ["| " + " | ".join(cell(c) for c in columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for i, r in enumerate(rows):
        cells = [cell(c) for c in r] + ["-"] * (len(columns) - len(r))
        tgt = (links or [None] * len(rows))[i] if links and i < len(links) else None
        if tgt:
            # the first text column links to the detail (the « # » / rank column stays a plain number)
            j = 1 if len(cells) > 1 and re.fullmatch(r"\d+", cells[0]) else 0
            cells[j] = link(cells[j], tgt)
        out.append("| " + " | ".join(cells[: len(columns)]) + " |")
    return out


def _block(b: Dict[str, Any], depth: int) -> List[str]:
    t = b.get("type")
    h = "#" * min(6, depth)
    if t == "paragraph":
        return [prose(b.get("text")), ""] if b.get("text") else []
    if t == "note":
        return ["> " + prose(b.get("text")).replace("\n", "\n> "), ""]
    if t == "quote":
        lines = [f"*{cell(b.get('label'))}*", ""]
        lines.append("> " + prose(b.get("text")).replace("\n", "\n> "))
        return lines + [""]
    if t == "facts":
        return _table(["Field", "Value"], [[r.get("label"), r.get("value")] for r in b.get("rows") or []]) + [""]
    if t == "kpis":
        return _table(["Measure", "Value"], [[i.get("label"), i.get("value")] for i in b.get("items") or []]) + [""]
    if t == "table":
        return _table(list(b.get("columns") or []), list(b.get("rows") or []), b.get("row_links")) + [""]
    if t == "list":
        out = []
        if b.get("title"):
            out += [f"**{cell(b['title'])}**", ""]
        links = b.get("links") or []
        for i, it in enumerate(b.get("items") or []):
            label = prose(it).replace("\n", " ")
            out.append("- " + (link(cell(it), links[i]) if i < len(links) and links[i] else label))
        return out + [""]
    if t == "figure":
        return [fence(b.get("mermaid") or "", "mermaid"), "", prose(b.get("caption")), ""]
    if t == "markdown":
        return [str(b.get("markdown") or "").strip(), ""]
    if t == "subsection":
        out = [anchor(b.get("id")), f"{h} {cell(b.get('title'))}", ""]
        for x in b.get("blocks") or []:
            out += _block(x, depth + 1)
        return out
    if t == "finding":
        return _finding(b, depth)
    return []


def _finding(b: Dict[str, Any], depth: int) -> List[str]:
    h = "#" * min(6, depth)
    out = ["---", "", anchor(b.get("id")), f"{h} {cell(b.get('title'))}", ""]
    out += _table(["Field", "Value"], [[r.get("label"), r.get("value")] for r in b.get("facts") or []])
    out.append("")
    sub = "#" * min(6, depth + 1)
    for label, key in (("Description", "description"), ("Technical analysis", "analysis")):
        if b.get(key):
            out += [f"{sub} {label}", "", prose(b[key]), ""]
    ev = b.get("evidence") or {}
    if ev.get("withheld"):
        out += [f"{sub} Evidence", "", "> Evidence withheld: the redaction engine was not available when this report "
                                       "was written.", ""]
    else:
        if ev.get("commands"):
            out += [f"{sub} Commands", "", fence("\n".join(ev["commands"]), "bash"), ""]
        if ev.get("raw_request"):
            out += [f"{sub} Request", "", fence(ev["raw_request"], "http"), ""]
        if ev.get("raw_response"):
            out += [f"{sub} Response", "", fence(ev["raw_response"], "http"), ""]
        if ev.get("logs"):
            out += [f"{sub} Logs", "", fence("\n".join(ev["logs"])), ""]
    out += [f"{sub} Remediation", ""]
    if b.get("remediation"):
        out += ["*Recommended by the testing agent (quoted as written, not verified).*", "", prose(b["remediation"]), ""]
    else:
        out += ["> No remediation text was recorded by the testing agent.", ""]
    refs = []
    if b.get("action"):
        refs.append(link("Treatment plan action", b["action"]))
    if b.get("controls"):
        refs.append("Framework controls: " + ", ".join(cell(c) for c in b["controls"]))
    if refs:
        out += [" · ".join(refs), ""]
    return out


def render(model: Dict[str, Any]) -> str:
    """The report file of one campaign, from its model."""
    c = model.get("campaign") or {}
    out = [f"# {cell(model.get('title'))}", ""]
    meta = [("Classification", f"{model.get('classification') or 'CONFIDENTIAL'} — Restricted to authorized personnel"),
            ("Generated", model.get("generated_at") or "unknown"), ("Target", c.get("target") or "unknown"),
            ("Campaign", c.get("id") or "unknown")]
    if c.get("project_name"):
        meta.append(("Project", c["project_name"]))
    meta.append(("Method", _rm._legend.methodology_label(c.get("methodology"))))
    st = str(c.get("status") or "unknown")
    if st not in ("completed", "complete", "done", "finished"):
        meta.append(("Status", f"{st} — partial results: the run did not complete"))
    meta.append(("Report model", f"{model.get('schema_version')} ({model.get('edition')})"))
    out += [f"**{k}:** {cell(v)}  " for k, v in meta]
    out += ["", "---", "", "**Contents**", ""]
    for i, s in enumerate(model.get("sections") or [], 1):
        out.append(f"{i}. {link(cell(s.get('title')), s.get('id'))}")
    out.append("")
    for i, s in enumerate(model.get("sections") or [], 1):
        out += [section_marker(s.get("id")), f"## {i}. {cell(s.get('title'))}", anchor(s.get("id")), ""]
        for b in s.get("blocks") or []:
            out += _block(b, 3)
    out += ["---", "", f"*Report generated by Darkmoon from the campaign data ({model.get('schema_version')}).*  ",
            f"*Classification: {cell(model.get('classification') or 'CONFIDENTIAL')} — Restricted to authorized personnel*"]
    text_out = "\n".join(out)
    text_out = re.sub(r"\n{3,}", "\n\n", text_out)
    return text_out.rstrip() + "\n"


def internal_links(md: str) -> List[str]:
    return re.findall(r"\]\(#([A-Za-z0-9_-]+)\)", md)


def anchors(md: str) -> List[str]:
    return re.findall(r'<a id="([A-Za-z0-9_-]+)"></a>', md)


SECTION_IDS = _rm.SECTION_IDS
