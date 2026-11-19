# Vendored from Darkmoon (mcp/src/privacy/keyblocks.py), AGPL-3.0 here.
"""Private-key blocks and table-cell secrets, whatever the wrapping (cycle 3, 18/11/2026).

Campaign 7 incident: ``SELECT * FROM ops_secrets`` printed an OpenSSH private key as a psql TABLE CELL::

      1 | ops_ssh_key | -----BEGIN OPENSSH PRIVATE KEY-----        +
        |             | b3BlbnNzaC1rZXktdjEAAAA...                 +
        |             | -----END OPENSSH PRIVATE KEY-----

The vault had no private-key pass at all (only the at-rest redactor and the live stream had one), and the body lines
match no credential pattern, so the key reached the model. This module finds a key block as ONE secret span and
rebuilds the key's canonical bytes from the cell, so the placeholder can be written back to a file byte-exact:

* psql aligned (``|`` borders, ``+`` continuation markers, glued ``+`` on the widest line, terminal-wrapped lines),
  psql ``\\x`` expanded, psql ``-At`` / mysql / sqlite raw newlines, sqlite/mysql box borders (``│``), YAML indent;
* CRLF, ANSI already stripped by the caller;
* JSON / mysql ``-B`` escaped ``\\n`` inside a string (one or two escape levels), space-flattened keys;
* PEM types OPENSSH, RSA, EC, DSA, PRIVATE KEY, ENCRYPTED PRIVATE KEY, PGP PRIVATE KEY BLOCK, SSH2 (``---- BEGIN``),
  and PuTTY PPK (``PuTTY-User-Key-File-N:`` … ``Private-MAC:``);
* truncated blocks (no END: ``head``, a cut JSON string): BEGIN plus the key-like lines that follow;
* a headerless OpenSSH body (``b3BlbnNzaC1rZXktdjE…``, the base64 of ``openssh-key-v1``).
* v3 audit: a key tail without BEGIN (``tail``, a torn BEGIN, a key split over two outputs), markers torn by a
  fixed-width terminal wrap, the base64 of a PEM (Kubernetes secrets) and a URL-encoded PEM; the gateway also hunts
  the rows of an already-known key re-printed without markers (``mask_known_key_fragments``).

Table cells: ``password | value`` rows (key/value tables, psql ``\\x``) and the cells of a column whose header names a
secret (``id | username | password`` followed by a ``---+---`` separator). Values only: names, borders and every other
cell are untouched, so ordinary tables, numbers, uid/gid and ports are never minted.

Pure functions: they return spans and canonical values; the vault registers them.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import json
import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

Span = Tuple[int, int, str]          # (start, end, canonical value)

_BORDERS = "|│┃║"
_LEAD_DECOR = re.compile(r"[ \t|│┃║]*")
_MARKERS_NL = "+↵"                  # psql: the cell continues on the next line (a newline in the data)
_MARKERS_WRAP = ".…"                # psql wrapped format: the same data line continues (no newline)

_BEGIN_RE = re.compile(
    r"(?P<pem>-{4,5} ?BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)? ?-{4,5})"
    r"|(?P<ppk>PuTTY-User-Key-File-\d+: ?[A-Za-z0-9@.\-]+)")
_END_PEM = re.compile(r"-{4,5} ?END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)? ?-{4,5}")
_END_PPK = re.compile(r"Private-MAC: ?[0-9A-Fa-f]+")
_KEYLIKE = re.compile(r"[A-Za-z0-9+/=]{4,}|[A-Za-z][A-Za-z0-9\-]*: ?.*|=[A-Za-z0-9+/]{4}")
_ESCAPED_RUN = re.compile(r"(?:\\+[nrt]|[A-Za-z0-9+/=])*")
_OPENSSH_MAGIC = re.compile(r"(?<![A-Za-z0-9+/])b3BlbnNzaC1rZXktdjE(?:[A-Za-z0-9+/=]|\\+[nr])*")
_B64_LINE = re.compile(r"[A-Za-z0-9+/=]{16,}")
# A canonical private-key value (what this module registers): used by the gateway to recognise a key placeholder.
KEY_VALUE_RE = re.compile(r"^(?:-{4,5} ?BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY|PuTTY-User-Key-File-\d|b3BlbnNzaC1rZXktdjE)")

_MAX_LINES = 1200                    # a 16k-bit RSA key is ~200 lines; terminal wrapping can double it
_MAX_BYTES = 256 * 1024


def is_private_key_value(value: Optional[str]) -> bool:
    return bool(value) and bool(KEY_VALUE_RE.match(value))


# ── physical lines ────────────────────────────────────────────────────────────────────────────────────────

def _lines_from(text: str, start: int) -> List[Tuple[int, str]]:
    """(abs_start, line) from the line holding ``start``, ``\\n`` excluded, bounded."""
    out: List[Tuple[int, str]] = []
    p = text.rfind("\n", 0, start) + 1
    limit = min(len(text), start + _MAX_BYTES)
    while p <= limit and len(out) < _MAX_LINES:
        e = text.find("\n", p)
        e = len(text) if e < 0 else e
        out.append((p, text[p:e]))
        if e >= len(text):
            break
        p = e + 1
    return out


def _decode_escapes(s: str) -> str:
    for _ in range(3):
        if "\\" not in s:
            break
        try:
            s = json.loads('"' + s.replace('"', '\\"') + '"')
        except ValueError:
            s = s.replace("\\r", "").replace("\\n", "\n").replace("\\t", "\t").replace("\\/", "/")
            break
    return s


def _single_line_value(begin: str, middle: str, end: str) -> str:
    if "\\" in middle:
        body = _decode_escapes(middle)
    else:
        toks = middle.split()
        body = ("\n" + "\n".join(toks) + "\n") if toks else middle
    return (begin + body + end).replace("\r", "")


# ── one key block ─────────────────────────────────────────────────────────────────────────────────────────

def _block_at(text: str, m: "re.Match") -> Optional[Span]:
    end_re = _END_PPK if m.group("ppk") else _END_PEM
    begin = m.group(0)
    line_start = text.rfind("\n", 0, m.start()) + 1
    line_end = text.find("\n", m.end())
    line_end = len(text) if line_end < 0 else line_end

    # 1) the whole block on one line: JSON / mysql -B escapes, or a space-flattened key
    em = end_re.search(text, m.end(), line_end)
    if em:
        middle = text[m.end():em.start()]
        end = em.end()
        if "\\" in middle:   # the escaped newline that ends the key belongs to the secret (« "CRED_001" », not « "CRED_001\n" »)
            tail = re.match(r"(?:\\+[rn])+", text[end:line_end])
            end += tail.end() if tail else 0
        return m.start(), end, _single_line_value(begin, middle, em.group(0))
    # 1b) truncated escaped string (« "-----BEGIN …-----\nb3Bl… » cut before END)
    if text.startswith("\\", m.end()):
        run = _ESCAPED_RUN.match(text, m.end(), line_end)
        if run and run.end() > m.end():
            return m.start(), run.end(), _single_line_value(begin, run.group(0), "").rstrip("\n")

    phys = _lines_from(text, m.start())
    col = m.start() - line_start
    l0 = phys[0][1]
    pre0 = l0[:col]
    borders0 = [i for i, ch in enumerate(pre0) if ch in _BORDERS]

    # 2) aligned table (psql aligned / expanded, sqlite box): every row repeats the border columns of the BEGIN
    #    row; a line without them is the terminal-wrapped remainder of the previous row (joined back, so a wrapped
    #    END marker or PPK MAC is found whole)
    def is_row(s: str) -> bool:
        if not borders0 or len(s) <= borders0[-1]:
            return False
        if any(s[k] != pre0[k] for k in borders0):
            return False
        return all(ch in _BORDERS or ch in " \t" for ch in s[:min(col, len(s))])

    aligned = bool(borders0) and any(is_row(phys[i][1]) for i in range(1, min(len(phys), 64)))
    rows: List[List[int]] = [[0]]               # each row = indices of its physical lines
    for i in range(1, len(phys)):
        if aligned and not is_row(phys[i][1]):
            rows[-1].append(i)                   # terminal wrap: same row
        else:
            rows.append([i])

    def row_text(r: List[int]) -> str:
        return "".join(phys[i][1].rstrip("\r") if k < len(r) - 1 else phys[i][1] for k, i in enumerate(r))

    def row_abs(r: List[int], off: int) -> int:
        """Absolute offset in ``text`` of offset ``off`` of the joined row."""
        for k, i in enumerate(r):
            a, s = phys[i]
            piece = s.rstrip("\r") if k < len(r) - 1 else s
            if off <= len(piece) or k == len(r) - 1:
                return a + off
            off -= len(piece)
        return phys[r[-1]][0]

    # 3) locate the END (stop at another BEGIN: a truncated block never swallows the next key)
    end_row, end_m, end_abs_m = None, None, None
    for j in range(1, len(rows)):
        joined = row_text(rows[j])
        em = end_re.search(joined)
        if em:
            end_row, end_m, end_abs_m = j, em, row_abs(rows[j], em.end())
            break
        if _BEGIN_RE.search(joined):
            rows = rows[:j]
            break
    if end_row is not None:
        rows = rows[:end_row + 1]

    row0 = row_text(rows[0])
    mend = m.end() - line_start
    mm = re.match(r"( *)([+↵.…|│┃║])", row0[mend:])
    marker_col = mend + len(mm.group(1)) if mm else None

    def content(r: List[int], first: bool) -> Tuple[str, str]:
        s = row_text(r).replace("\r", "")
        start = col if aligned else _LEAD_DECOR.match(s).end()
        mark = ""
        if (marker_col is not None and len(s) > marker_col and marker_col >= start
                and s[marker_col] in _MARKERS_NL + _MARKERS_WRAP + _BORDERS):
            mark, s = s[marker_col], s[start:marker_col]
        else:
            # not aligned on the BEGIN row's margin (hand-made / unpadded output): only a spaced marker is a marker
            s = s[start:]
            tm = re.search(r"\s+([+↵])\s*$", s) if marker_col is not None else None
            if tm:
                mark, s = tm.group(1), s[:tm.start()]
        return s.rstrip(), mark

    if end_row is not None:
        parts = [begin]
        sep = "\n"
        _, mark0 = content(rows[0], True)
        if mark0 and mark0 in _MARKERS_WRAP:
            sep = ""
        for j, r in enumerate(rows[1:], start=1):
            if j == end_row:
                parts.append(sep + end_m.group(0))
                break
            c, mark = content(r, False)
            parts.append(sep + c)
            sep = "" if (mark and mark in _MARKERS_WRAP) else "\n"
        return m.start(), end_abs_m, "".join(parts)

    # 4) truncated: BEGIN + the key-like rows that follow
    parts, end_abs = [begin], m.end()
    blank_ok = "PGP" in begin                    # an armored PGP block always has a blank line after BEGIN (v3 audit)
    for r in rows[1:]:
        c, _ = content(r, False)
        if c == "" and blank_ok:
            blank_ok = False
            parts.append("")
            continue
        if not c or not _KEYLIKE.fullmatch(c) or (" " in c and ":" not in c):
            break
        blank_ok = ":" in c and not _B64_LINE.fullmatch(c)
        parts.append(c)
        a, s = phys[r[-1]]
        end_abs = a + len(s.rstrip("\r"))
    while parts and parts[-1] == "":
        parts.pop()
    return m.start(), end_abs, "\n".join(parts)


def find_private_keys(text: str) -> List[Span]:
    """Every private-key block of ``text`` as (start, end, canonical value), non-overlapping, in order."""
    out: List[Span] = []
    if not text or ("PRIVATE KEY" not in text and "PuTTY-User-Key-File" not in text):
        return out
    pos = 0
    while True:
        m = _BEGIN_RE.search(text, pos)
        if not m:
            break
        blk = _block_at(text, m)
        if blk and blk[1] > blk[0]:
            out.append(blk)
            pos = blk[1]
        else:
            pos = m.end()
    return out


def find_headerless_openssh(text: str) -> List[Span]:
    """An OpenSSH key body without its BEGIN line (a column holding only the body, a BEGIN line torn by a
    terminal wrap): the run starting at the base64 of ``openssh-key-v1`` plus the base64 rows that follow."""
    out: List[Span] = []
    if not text or "b3BlbnNzaC1rZXktdjE" not in text:
        return out
    for m in _OPENSSH_MAGIC.finditer(text):
        if out and m.start() < out[-1][1]:
            continue
        first = m.group(0)
        if "\\" in first:
            out.append((m.start(), m.end(), _decode_escapes(first).strip()))
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        col = m.start() - line_start
        parts, end_abs = [first], m.end()
        p = text.find("\n", m.end())
        while p >= 0 and len(parts) < _MAX_LINES:
            e = text.find("\n", p + 1)
            e = len(text) if e < 0 else e
            s = text[p + 1:e].rstrip("\r")
            pre = s[:col]
            body = s[col:] if pre.strip(" \t" + _BORDERS) == "" and len(s) > col else s[_LEAD_DECOR.match(s).end():]
            body = re.sub(r"\s+[+↵]$", "", body.rstrip()).rstrip("+") if body.rstrip().endswith(("+", "↵")) and \
                not _B64_LINE.fullmatch(body.rstrip()) else body.rstrip()
            endm = _END_PEM.match(body)
            if endm:
                parts.append(endm.group(0))
                end_abs = p + 1 + s.find(endm.group(0)) + len(endm.group(0))
                break
            if not _B64_LINE.fullmatch(body) and not re.fullmatch(r"[A-Za-z0-9+/=]{1,15}", body or "-"):
                break
            parts.append(body)
            end_abs = p + 1 + len(s)
            p = text.find("\n", p + 1)
        out.append((m.start(), end_abs, "\n".join(parts)))
    return out


# ── v3 privacy audit (18/11/2026): tails, torn markers, encoded forms, known-key fragments ──────────────────

_END_ANY = re.compile(_END_PEM.pattern + "|" + _END_PPK.pattern)
_KEY_HEADER = re.compile(r"(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|Encryption|Public-Lines|Private-Lines"
                         r"|PuTTY-User-Key-File-\d+|Key-Derivation|Argon2-[A-Za-z]+): ?.*")
_B64_PIECE = re.compile(r"[A-Za-z0-9+/=]{4,}")


def _strip_row(s: str) -> str:
    """The content of one physical line of a key body: table decoration and continuation markers removed."""
    s = s.rstrip("\r")
    lead = _LEAD_DECOR.match(s).end()
    bordered = any(ch in _BORDERS for ch in s[:lead])
    c = s[lead:].rstrip()
    if bordered:
        c = re.sub(r"[ \t]*[|│┃║][ \t]*$", "", c)            # a box's right border
        c = re.sub(r"[ \t]*[+↵]$", "", c)                     # psql continuation marker (glued or spaced)
    return c


def find_key_tails(text: str) -> List[Span]:
    """A key END marker (or PPK MAC) without its BEGIN: ``tail id_rsa``, a BEGIN line torn by a terminal wrap, the
    second half of a key split over two outputs. The key-like rows right above the END are one secret span."""
    out: List[Span] = []
    if not text or ("PRIVATE KEY" not in text and "Private-MAC" not in text):
        return out
    for m in _END_ANY.finditer(text):
        if out and m.start() < out[-1][1]:
            continue
        ls = text.rfind("\n", 0, m.start()) + 1
        pre = text[ls:m.start()]
        pre = pre[_LEAD_DECOR.match(pre).end():]
        if pre and not re.fullmatch(r"[A-Za-z0-9+/=]+", pre):
            continue                                          # an END inside prose / source code: not a key dump
        parts: List[str] = [pre] if pre else []
        start = m.start() - len(pre)
        e, blank_used, n = ls - 1, False, 0
        floor = out[-1][1] if out else 0
        while e > floor and n < _MAX_LINES:
            b = text.rfind("\n", 0, e) + 1
            if b < floor:
                break
            raw = text[b:e]
            c = _strip_row(raw)
            if c == "" and not blank_used and parts:
                blank_used = True
            elif _B64_PIECE.fullmatch(c) or _KEY_HEADER.fullmatch(c):
                parts.insert(0, c)
                start = b + (len(raw.rstrip("\r")) - len(raw.rstrip("\r").lstrip(" \t|│┃║")))
            else:
                break
            e, n = b - 1, n + 1
        if not any(_B64_LINE.fullmatch(p) for p in parts):
            continue
        out.append((start, m.end(), "\n".join(parts + [m.group(0)]) if not pre else
                    "\n".join(parts[:-1] + [parts[-1] + m.group(0)])))
    return out


_BARE_ROW = re.compile(r"[A-Za-z0-9+/]{64}|[A-Za-z0-9+/]{70}")
_BEGIN_ANY = re.compile(r"-{5}BEGIN ([A-Z0-9 ]+)-{5}")
_BARE_TAIL = re.compile(r"[A-Za-z0-9+/]{4,69}={0,2}|=[A-Za-z0-9+/]{4}")


def find_bare_key_rows(text: str) -> List[Span]:
    """Production readiness (E2E 18/11): rows of a key printed WITHOUT any marker and never seen whole (``sed -n 3,8p
    id_rsa``, ``head -n`` past the BEGIN line): three or more consecutive full-width key-body rows (PEM 64, OpenSSH 70
    base64 chars) are one secret span. Rows inside a non-private PEM block (certificate, public key) are left alone.
    Over-masks other 64/70-wrapped base64 dumps (``openssl base64``): a placeholder, never a leak."""
    out: List[Span] = []
    if not text or "\n" not in text:
        return out
    rows, pos = [], 0
    for line in text.split("\n"):
        rows.append((pos, line))
        pos += len(line) + 1
    i = 0
    while i < len(rows):
        j = i
        while j < len(rows) and _BARE_ROW.fullmatch(_strip_row(rows[j][1]).rstrip("\r")):
            j += 1
        if j - i >= 3:
            # the last (short) body row and a PGP armour checksum row belong to the same key
            while j < len(rows) and j - i < _MAX_LINES and _BARE_TAIL.fullmatch(_strip_row(rows[j][1]).rstrip("\r")):
                j += 1
            a, b = rows[i][0], rows[j - 1][0] + len(rows[j - 1][1].rstrip("\r"))
            before = text.rfind("-----BEGIN ", 0, a)
            m = _BEGIN_ANY.match(text, before) if before >= 0 else None
            inside_public = (m is not None and "PRIVATE" not in m.group(1)
                             and text.find("-----END " + m.group(1), a) >= 0)
            if not inside_public:
                out.append((a, b, "\n".join(_strip_row(r[1]).rstrip("\r") for r in rows[i:j])))
            i = j
        else:
            i += 1
    return out


def _dewrap(text: str) -> Optional[Tuple[str, List[int], List[int]]]:
    """Undo a fixed-width terminal wrap: every line as long as the widest one is joined to the next. Returns the
    joined view and the join points (view offset, chars removed so far) to map a view span back to ``text``."""
    if "\n" not in text:
        return None
    lines = text.split("\n")
    lens = [len(x.rstrip("\r")) for x in lines]
    w = max(lens)
    if w < 16 or lens.count(w) < 2:
        return None
    pieces, jv, jr, removed, vlen = [], [], [], 0, 0
    for i, ln in enumerate(lines):
        last = i == len(lines) - 1
        if lens[i] == w and not last:
            piece = ln.rstrip("\r")
            pieces.append(piece)
            vlen += len(piece)
            removed += len(ln) - len(piece) + 1
            jv.append(vlen)
            jr.append(removed)
        else:
            pieces.append(ln if last else ln + "\n")
            vlen += len(pieces[-1])
    if not jv:
        return None
    return "".join(pieces), jv, jr


def _view_to_text(off: int, jv: List[int], jr: List[int], inclusive_end: bool = False) -> int:
    k = bisect.bisect_left(jv, off) if inclusive_end else bisect.bisect_right(jv, off)
    return off + (jr[k - 1] if k else 0)


def find_wrapped_private_keys(text: str) -> List[Span]:
    """A key whose BEGIN/END marker was torn by a fixed-width terminal wrap (narrow terminal, long log prefix): the
    markers are only found once the wrap is undone. Spans are mapped back to ``text``."""
    if not text or ("-" not in text and "PuTTY" not in text and "Private" not in text):
        return []
    dw = _dewrap(text)
    if dw is None:
        return []
    view, jv, jr = dw
    spans = find_private_keys(view)
    taken = [(a, b) for a, b, _ in spans]
    spans += [t for t in find_key_tails(view) if not any(a < t[1] and t[0] < b for a, b in taken)]
    out = [(_view_to_text(a, jv, jr), _view_to_text(b, jv, jr, inclusive_end=True), v) for a, b, v in sorted(spans)]
    return [s for s in out if s[1] > s[0]]


def _b64_signatures(raw: bytes) -> List[str]:
    """The base64 of ``raw`` at the three byte alignments (the chars that do not depend on neighbouring bytes)."""
    sigs = []
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + raw).decode()
        skip = (pad * 8 + 5) // 6
        sigs.append(enc[skip:len(enc) - 2])
    return sigs


_B64_KEY_SIG = re.compile("|".join(re.escape(x) for x in _b64_signatures(b"-----BEGIN ")
                                   + _b64_signatures(b"PuTTY-User-Key-File-")))
_B64_RUN_AROUND = re.compile(r"[A-Za-z0-9+/=]*")
_URL_BEGIN = re.compile(r"(?:-|%2[Dd]){4,5}BEGIN(?P<sp>%20|\+)(?:[A-Z0-9]+(?:%20|\+)){0,4}PRIVATE(?:%20|\+)KEY"
                        r"(?:(?:%20|\+)BLOCK)?(?:-|%2[Dd]){4,5}")
_URL_END = re.compile(r"(?:-|%2[Dd]){4,5}END(?:%20|\+)(?:[A-Z0-9]+(?:%20|\+)){0,4}PRIVATE(?:%20|\+)KEY"
                      r"(?:(?:%20|\+)BLOCK)?(?:-|%2[Dd]){4,5}")
_URL_RUN = re.compile(r"[A-Za-z0-9%+._~\-*]*")


def _decodes_to_key(b64: str) -> bool:
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False)
    except (binascii.Error, ValueError):
        return False
    return b"PRIVATE KEY" in raw or b"PuTTY-User-Key-File" in raw


def find_encoded_private_keys(text: str) -> List[Span]:
    """A private key carried in an ENCODED form: the base64 of the PEM (Kubernetes ``kubectl get secret -o json``,
    ``base64 id_rsa``, a CI variable; wrapped or not) and the URL-encoded PEM (form bodies, access logs)."""
    out: List[Span] = []
    if not text:
        return out
    scanned = 0                                               # end of the last run examined: linear on repeats
    for m in _B64_KEY_SIG.finditer(text):
        if m.start() < scanned:
            continue
        a = m.start()
        while a > 0 and (text[a - 1].isalnum() and text[a - 1].isascii() or text[a - 1] in "+/="):
            a -= 1
        b = _B64_RUN_AROUND.match(text, m.end()).end()
        parts, end = [text[a:b]], b
        if b - a >= 60:                                       # a wrapped base64 (``base64 -w76``): the rows below
            p = b
            while p < len(text) and text[p] in "\r\n":
                nl = text.find("\n", p + 1) if text[p] == "\r" else p
                if nl < 0:
                    break
                e = text.find("\n", nl + 1)
                e = len(text) if e < 0 else e
                row = text[nl + 1:e].rstrip("\r")
                core = row.strip()
                if not re.fullmatch(r"[A-Za-z0-9+/=]{4,}", core):
                    break
                parts.append(core)
                end = nl + 1 + row.find(core) + len(core)
                p = end
        scanned = max(end, b)
        joined = "".join(parts)
        if (len(joined) >= 24 and _decodes_to_key(joined)) or (len(joined) >= 40 and _decodes_to_key(joined[: len(joined) // 4 * 4])):
            out.append((a, end, joined))
    url_scanned = 0
    for m in _URL_BEGIN.finditer(text):
        if m.start() < url_scanned:
            continue
        run_end = _URL_RUN.match(text, m.end()).end()
        em = _URL_END.search(text, m.end(), run_end)
        end = em.end() if em else run_end
        if em:
            tail = re.match(r"(?:%0[Dd])?%0[Aa]", text[end:run_end])
            end += tail.end() if tail else 0
        url_scanned = end
        enc = text[m.start():end]
        val = urllib.parse.unquote_plus(enc) if m.group("sp") == "+" else urllib.parse.unquote(enc)
        out.append((m.start(), end, val.replace("\r", "").rstrip("\n")))
    out.sort()
    uniq: List[Span] = []
    for s in out:
        if not uniq or s[0] >= uniq[-1][1]:
            uniq.append(s)
    return uniq


def key_body_windows(value: str, size: int = 16) -> Set[str]:
    """Every ``size``-char window of the base64 rows of a known multi-line key value."""
    ws: Set[str] = set()
    if not value or "\n" not in value:
        return ws
    for ln in value.split("\n"):
        if len(ln) >= size and re.fullmatch(r"[A-Za-z0-9+/=]+", ln):
            ws.update(ln[i:i + size] for i in range(len(ln) - size + 1))
    return ws


_B64_RUN16 = re.compile(r"[A-Za-z0-9+/=]{16,}")


def mask_known_key_fragments(text: str, windows: Dict[str, str], size: int = 16) -> str:
    """Replace every base64 run of ``text`` that shares a ``size``-char window with a KNOWN key body by that key's
    placeholder (``windows``: window -> placeholder). Catches the rows of an already-tokenized key re-printed without
    its markers (``sed -n 5,9p id_rsa``, the middle of a key split over several commands, a narrower wrap)."""
    if not text or not windows:
        return text

    def sub(m: "re.Match") -> str:
        run = m.group(0)
        for i in range(len(run) - size + 1):
            ph = windows.get(run[i:i + size])
            if ph:
                return ph
        return run
    return _B64_RUN16.sub(sub, text)


# ── table cells ───────────────────────────────────────────────────────────────────────────────────────────

_SECRET_WORD = re.compile(
    r"(?:passwords?|passwd|passphrase|pass|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token"
    r"|credentials?|private[_-]?key|secret[_-]?key)$", re.IGNORECASE)
_SEP_CHARS = re.compile(r"[-+=─━┼╪╬├┤┌┐└┘┬┴╞╡│| \t]+")


def _is_sep_line(line: str) -> bool:
    """« ----+---- », « +----+ », « ├──┼──┤ »: a table rule (linear, no backtracking)."""
    return bool(_SEP_CHARS.fullmatch(line)) and sum(line.count(c) for c in "-─━=") >= 3
_JOINTS = "+┼╪╬├┤╞╡|│┌┐└┘┬┴"
_CELL_SECRET = re.compile(r"[^\s]{4,256}")


def is_secret_name(name: str) -> bool:
    """« password », « db_password », « MQTT_PASS », « dbPassword », « api_key », « client_secret »: the WHOLE
    cell names a secret (« bypass », « compass », « password_hash », « token_expiry » do not)."""
    name = name.strip()
    if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        return False
    m = _SECRET_WORD.search(name)
    if not m:
        return False
    i = m.start()
    if i == 0 or name[i - 1] in "_.-":
        return True
    return name[i].isupper() and name[i - 1].islower()     # camelCase: dbPassword, smtpPass


def _cell_value_span(line: str, a: int, b: int) -> Optional[Tuple[int, int]]:
    cell = line[a:b]
    stripped = cell.strip()
    if not stripped:
        return None
    off = a + (len(cell) - len(cell.lstrip()))
    return off, off + len(stripped)


def _split_cells(line: str) -> List[Tuple[int, int]]:
    """(start, end) of each cell of a bordered row, borders excluded."""
    cuts = [i for i, ch in enumerate(line) if ch in _BORDERS]
    if not cuts:
        return []
    spans, prev = [], 0
    for c in cuts:
        spans.append((prev, c))
        prev = c + 1
    spans.append((prev, len(line)))
    return spans


_HEADER_FIELD = re.compile(r"[\"']?[A-Za-z_][\w.\-]{0,63}[\"']?")


def find_delimited_secrets(text: str, accept) -> List[Span]:
    """CSV / TSV with a header row (``psql --csv``, ``mysql -B``, ``sqlite3 -csv -header``): the cells of a column whose
    header names a secret, in the rows that have the header's field count (v3 privacy audit)."""
    out: List[Span] = []
    if not text or ("\t" not in text and "," not in text):
        return out
    lines, p = text.split("\n"), 0
    starts = []
    for ln in lines:
        starts.append(p)
        p += len(ln) + 1
    cols: Optional[List[int]] = None
    delim, nf = "", 0
    for i, raw in enumerate(lines):
        line = raw.rstrip("\r")
        if cols is not None:
            fields = line.split(delim) if delim in line else None
            if not fields or len(fields) != nf:
                if not line.strip():
                    cols = None
                continue
            offs, o = [], 0
            for f in fields:
                offs.append(o)
                o += len(f) + 1
            for k in cols:
                f = fields[k]
                core = f.strip()
                if len(core) >= 2 and core[0] == core[-1] and core[0] in "\"'":
                    core = core[1:-1]
                if not core:
                    continue
                a = offs[k] + f.find(core)
                if _CELL_SECRET.fullmatch(core) and accept(core):
                    out.append((starts[i] + a, starts[i] + a + len(core), core))
            continue
        for d in ("\t", ","):
            if d in line:
                fields = line.split(d)
                if len(fields) >= 2 and all(_HEADER_FIELD.fullmatch(f.strip()) for f in fields):
                    sec = [k for k, f in enumerate(fields) if is_secret_name(f.strip().strip("\"'"))]
                    if sec:
                        cols, delim, nf = sec, d, len(fields)
                break
    return out


def find_table_secrets(text: str, accept) -> List[Span]:
    """Secret values printed as table cells. ``accept(value)`` filters false positives (masks, placeholders)."""
    out: List[Span] = []
    if not text or not any(b in text for b in _BORDERS):
        return out
    lines, starts, p = text.split("\n"), [], 0
    for ln in lines:
        starts.append(p)
        p += len(ln) + 1

    def take(i: int, span: Optional[Tuple[int, int]]) -> None:
        if span is None:
            return
        val = lines[i][span[0]:span[1]]
        if _CELL_SECRET.fullmatch(val) and accept(val):
            out.append((starts[i] + span[0], starts[i] + span[1], val))

    is_sep = [_is_sep_line(ln.rstrip("\r")) for ln in lines]
    secret_cols: Optional[List[Tuple[int, Optional[int], int]]] = None   # (start, end, index) of secret-named columns
    header_ncells = 0
    for i, raw in enumerate(lines):
        line = raw.rstrip("\r")
        if is_sep[i]:
            continue
        if not any(b in line for b in _BORDERS):
            secret_cols = None                      # the table ended
            continue
        cells = _split_cells(line)
        names = [line[a:b].strip() for a, b in cells]
        nxt_sep = i + 1 < len(lines) and is_sep[i + 1]
        prev_sep_or_start = i == 0 or is_sep[i - 1] or not any(b in lines[i - 1] for b in _BORDERS)
        first_row = prev_sep_or_start and not (i >= 2 and is_sep[i - 1] and any(b in lines[i - 2] for b in _BORDERS))
        if nxt_sep and first_row:
            # header row: remember the columns that name a secret, by position (a value may contain « | »); the
            # last column of a borderless (psql) header is open: its cell runs to the end of the line
            cols = [(a, None if k == len(cells) - 1 else b, k) for k, ((a, b), n) in enumerate(zip(cells, names))
                    if is_secret_name(n)]
            secret_cols = cols or None
            header_ncells = len(cells)
            continue
        if secret_cols:
            for a, b, k in secret_cols:
                if not (len(line) > a and (a == 0 or line[a - 1] in _BORDERS)):
                    # v3 audit: a double-width (CJK / emoji) value in an earlier column shifts the borders of this row;
                    # fall back to the cell INDEX when the row has the header's cell count
                    if len(cells) == header_ncells:
                        ca, cb = cells[k]
                        take(i, _cell_value_span(line, ca, cb))
                    continue
                if b is None:
                    end = len(line)
                    tail = re.search(r"[ \t]*[|│┃║][ \t]*$", line[a:])   # a box's right border
                    if tail:
                        end = a + tail.start()
                elif b < len(line) and line[b] in _BORDERS:
                    end = b
                else:
                    nb = [j for j in range(a, len(line)) if line[j] in _BORDERS]
                    end = nb[0] if nb else len(line)
                take(i, _cell_value_span(line, a, end))
        # key/value row: « password | value », the value being the rest of the row (one token, a box's right border
        # excluded): psql \x, key/value tables, psql -At « name|value » (a « | » inside the value stays in it)
        for k, n in enumerate(names[:-1]):
            if is_secret_name(n):
                a = cells[k + 1][0]
                end = len(line)
                tail = re.search(r"[ \t]*[|│┃║][ \t]*$", line[a:])
                if tail and tail.start() > 0:
                    end = a + tail.start()
                span = _cell_value_span(line, a, end)
                if span and not re.search(r"\s", line[span[0]:span[1]]):
                    take(i, span)
                break
    # de-duplicate (a cell hit by both rules)
    seen, uniq = set(), []
    for s in sorted(out):
        if (s[0], s[1]) not in seen and not (uniq and s[0] < uniq[-1][1]):
            seen.add((s[0], s[1]))
            uniq.append(s)
    return uniq
