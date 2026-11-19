"""Darkmoon's own static texts (framework catalogues, legend, fixed notes): published text, never a secret.

The secret redaction engine works on words and shapes, so a sentence Darkmoon wrote can look like a credential (« Login
and session handling: authentication bypass » reads as « login <user>: <password> ») or contain a word that a
campaign recorded as a secret value (« an attacker »). These texts are the same in every installation and carry no
customer data, so masking them only hides the product's own wording.

Rules (the redaction of real evidence is not weakened):

* ``masked_obj(doc, redact)``: the whole document goes through the redaction engine, then a string that is EXACTLY one
  of Darkmoon's static texts in the input gets its original value back. A string that only contains such a text, or
  any other string, keeps the engine's output.
* ``mask_text(text, masker)``: a Markdown line, or a table cell, that is exactly one of these texts (as written in the
  report) is set aside, the whole remaining text goes through the masker in one piece (multi-line secrets keep
  their context), then the static texts are put back. A placeholder the masker altered is never restored.

Pure Python standard library, no I/O (``exec_core`` rule).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, FrozenSet, Iterable, List

from . import actions, framework_catalogues, frameworks_assess, legend, profile, report_markdown, report_model, score

MIN_LENGTH = 16
# report_model.text() limits applied to catalogue texts in the report model
_REPORT_LIMITS = (120, 160, 200, 300, 400)
_MODULES = (framework_catalogues, frameworks_assess, legend, actions, score, profile, report_model)


def _strings(o: Any, out: set) -> None:
    if isinstance(o, str):
        if len(o) >= MIN_LENGTH and " " in o:
            out.add(o)
    elif isinstance(o, dict):
        for v in o.values():
            _strings(v, out)
    elif isinstance(o, (list, tuple, set, frozenset)):
        for v in o:
            _strings(v, out)


def _constant(name: str) -> bool:
    n = name.lstrip("_")
    return bool(n) and n == n.upper() and any(ch.isalpha() for ch in n)


def _collect() -> FrozenSet[str]:
    base: set = set()
    for m in _MODULES:
        for name, value in vars(m).items():
            if _constant(name):
                _strings(value, base)
    out = set(base)
    for s in base:
        for limit in _REPORT_LIMITS:
            out.add(report_model.text(s, limit))
    return frozenset(out)


STATIC_TEXTS: FrozenSet[str] = _collect()
# the same texts as a Markdown table cell writes them
_FORMS: FrozenSet[str] = STATIC_TEXTS | frozenset(report_markdown.cell(s) for s in STATIC_TEXTS)


def is_static(value: Any) -> bool:
    return isinstance(value, str) and value in STATIC_TEXTS


def restore_static(original: Any, masked: Any) -> Any:
    """``masked`` with every string that is exactly a static text in ``original`` (same place) set back."""
    if isinstance(original, str):
        return original if isinstance(masked, str) and original in STATIC_TEXTS else masked
    if isinstance(original, dict) and isinstance(masked, dict):
        return {k: (restore_static(original[k], v) if k in original else v) for k, v in masked.items()}
    if isinstance(original, (list, tuple)) and isinstance(masked, list) and len(original) == len(masked):
        return [restore_static(o, m) for o, m in zip(original, masked)]
    return masked


def masked_obj(doc: Any, redact: Callable[[Any], Any]) -> Any:
    """``redact(doc)`` (the redaction engine on the whole document), static texts of ``doc`` kept as written."""
    return restore_static(doc, redact(doc))


_CELL = re.compile(r"(?<!\\)\|")
_SLOT = "⟦dm-static-{}⟧"
_SLOT_RE = re.compile(r"⟦dm-static-(\d{1,6})⟧")


def mask_text(text: str, masker: Callable[[str], str]) -> str:
    """``masker(text)`` with the lines and table cells that are exactly a static text kept as written."""
    if not isinstance(text, str) or not text:
        return masker(text)
    kept: List[str] = []

    def slot(s: str) -> str:
        kept.append(s)
        return _SLOT.format(len(kept) - 1)

    lines = []
    for line in text.split("\n"):
        core = line.strip()
        if core in _FORMS:
            lead = line[: len(line) - len(line.lstrip())]
            lines.append(lead + slot(core))
            continue
        if core.startswith("|") and core.count("|") >= 2:
            parts = _CELL.split(line)
            for i in range(1, len(parts) - 1):
                c = parts[i].strip()
                if c in _FORMS:
                    left = parts[i][: len(parts[i]) - len(parts[i].lstrip())]
                    right = parts[i][len(parts[i].rstrip()):]
                    parts[i] = left + slot(c) + right
            line = "|".join(parts)
        lines.append(line)
    if not kept:
        return masker(text)
    out = masker("\n".join(lines))
    if not isinstance(out, str):
        return out
    return _SLOT_RE.sub(lambda m: kept[int(m.group(1))] if int(m.group(1)) < len(kept) else "", out)


def static_texts() -> Iterable[str]:
    return sorted(STATIC_TEXTS)


def stats() -> Dict[str, int]:
    return {"texts": len(STATIC_TEXTS), "forms": len(_FORMS)}
