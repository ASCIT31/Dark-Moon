"""
Darkmoon — observed attack paths (Python port of the frontend derivation).

Port of ``client-app/src/app/_common/attack-paths/observed/{evidence-text,observed-paths,
remediation-groups}.ts`` (branch ``fe/base-secu-attackpaths``), including the adversarial fixes
F1-F15. Scenarios are built ONLY from transitions proven verbatim by the campaign evidence:

- R1 artefact: a typed secret appears in A's output (target response), not in A's input, and is
  presented as a credential in B's executable input (A exploited, A's category can grant access,
  B did not obtain it itself).
- R2 mechanism (HISTORICAL INFERENCE, architecture D final review): B's evidence shows a POST to exactly the
  endpoint of an open-registration finding, with a success status in status position, and the identity it created
  appears in one of B's authenticated requests; otherwise the link is auxiliary. R2 attributes by ENDPOINT, which
  CONTRACT-D does not admit as proof: its links keep their fields but carry ``level: inferred`` /
  ``provenance: inferred``; a path resting on one is an inferred hypothesis, never proven / observed / ranked, and
  an R2 link never corroborates a claim nor promotes a declared (D) link (reports/52-arch-d-final-review/R2-ISOLATION.md).
- R3 reach: an exploited finding's response proves access to ANOTHER node (``root:x:0:0`` -> its
  host node; SQL rows + engine named by the response -> that unique database node).

Pure functions, no I/O. Secrets never leave this module in clear text: proofs are masked
(``mask_secret`` shows no character of the value).
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

from api import feature_flags

PSEUDO_NODE_PREFIX = "unresolved:"
# R2 (open registration, matched by endpoint) is kept for compatibility as an inference, never as an observation
INFERRED = "inferred"
R2_INFERENCE_NOTE = ("historical server rule R2 (open registration matched by endpoint): an inference, not an "
                     "observation; never a proof")
NOT_PROVEN_LEVELS = ("declared_by_agent", "declared_unverified", INFERRED)
SEVERITIES = ("critical", "high", "medium", "low", "info", "none")


_UID_OUTPUT = re.compile(r"uid=\d+\([\w.-]+\)\s+gid=\d+")
_UID_ANY = re.compile(r"uid=\d+\([\w.-]+\)")
# ``id`` only in COMMAND position: after a shell separator (; | || && newline backtick $( ) and followed by the
# end of the command. Never a JSON key ("id"), a query parameter (?id= &id=) or a value (q=id).
_ID_COMMAND = re.compile(r"(?:^|;|\|\|?|&&|`|\$\()[ \t]*(?:/usr/bin/|/bin/)?id(?=[ \t]*(?:$|;|\||&&|`|\)))", re.M)


def _decoded(text: str) -> str:
    out = text or ""
    for _ in range(2):  # %253B -> %3B -> ;
        nxt = unquote(out.replace("+", " ") if "%" in out else out)
        if nxt == out:
            break
        out = nxt
    return out


def _r3_host_capability(raw_response: str, requested: str, commands: str = "") -> str:
    """P2 (D-03 + review 2, M-1): the label follows the PROOF, never the agent's category. ``root:x:0:0``
    proves a read of the system account file. Command execution is claimed only when
    - the TARGET's raw response (never the agent-written ``extracted_data``) carries an ``id`` output
      ``uid=N(x) gid=N`` that is NOT already in what was sent (raw or URL-decoded): otherwise it is an echo;
    - and ``id`` was sent in command position (after a shell separator, URL-decoded), or is a line of the
      agent's commands."""
    sent = (requested or "") + "\n" + (commands or "")
    sent_all = " ".join((sent + "\n" + _decoded(sent)).split())
    echoed = {m.group(0) for m in _UID_ANY.finditer(sent_all)}
    produced = [m.group(0) for m in _UID_OUTPUT.finditer(raw_response or "")
                if _UID_ANY.match(m.group(0)).group(0) not in echoed]
    if produced and (_ID_COMMAND.search(_decoded(requested or "")) or _ID_COMMAND.search(commands or "")):
        return "command execution on the host"
    return "system account file read on the host"


def _declared_ledger(vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Server facts of the runs the findings were pushed in (architecture D, CONTRACT-D.md): the execution records,
    the FULL-value fingerprints each finding's own evidence shares with its run ledger (computed at push time) and the
    number of agent sessions of each run. Read only when a finding has a run; never raises (no record = no evidence)."""
    out: Dict[str, Any] = {"executions": [], "fps": {}, "push_seq": {}, "sessions": {}}
    runs = sorted({str(v["run_id"]) for v in vulns if v.get("run_id")})
    if runs:
        try:
            from api import tool_provenance
            for r in runs[:8]:
                out["executions"] += tool_provenance.executions(r)
                for vid, f in tool_provenance.finding_facts(r).items():
                    out["fps"][(r, vid)] = f["fps"]
                    out["push_seq"][(r, vid)] = f["push_seq"]
                out["sessions"][r] = tool_provenance.run_sessions(r)
        except Exception:  # noqa: BLE001
            return {"executions": [], "fps": {}, "push_seq": {}, "sessions": {}}
    return out


def is_pseudo_node(node_id: Any) -> bool:
    return isinstance(node_id, str) and node_id.startswith(PSEUDO_NODE_PREFIX)


def lc_key(value: str) -> Tuple[str, str]:
    """Approximation of JS ``localeCompare`` ordering (case-insensitive first, then exact)."""
    return (str(value).casefold(), str(value))


# ---------------------------------------------------------------------------
# Evidence text (evidence-text.ts)
# ---------------------------------------------------------------------------

def as_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, (list, tuple)):
        return "\n".join(as_text(i) for i in x)
    if isinstance(x, dict):
        return json.dumps(x, separators=(",", ":"), ensure_ascii=False)
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)


def _as_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return [as_text(i) for i in x]
    return [as_text(x)]


def _ev(e: Any, key: str) -> Any:
    return e.get(key) if isinstance(e, dict) else None


def input_text(e: Any) -> str:
    """What the finding sent (its inputs)."""
    return "\n".join([as_text(_ev(e, "commands")), as_text(_ev(e, "payloads")), as_text(_ev(e, "raw_request"))])


def output_text(e: Any) -> str:
    """What the TARGET returned: raw_response and extracted_data only (F4)."""
    return "\n".join([as_text(_ev(e, "raw_response")), as_text(_ev(e, "extracted_data"))])


def narrative_text(e: Any) -> str:
    """The agent's narration (logs, explanation). Never a source of artefacts or reach."""
    return "\n".join([as_text(_ev(e, "logs")), as_text(_ev(e, "explanation"))])


def _utf16_units(s: str) -> List[int]:
    raw = s.encode("utf-16-le", errors="surrogatepass")
    return [raw[i] | (raw[i + 1] << 8) for i in range(0, len(raw), 2)]


def mask_secret(value: str, kind: str = "secret") -> str:
    """Kind, a 16-bit FNV-1a fingerprint and a rounded length; never a character of the value (F6/F15)."""
    h = 0x811C9DC5
    units = _utf16_units(value)
    for u in units:
        h = ((h ^ u) * 0x01000193) & 0xFFFFFFFF
    fingerprint = format((h ^ (h >> 16)) & 0xFFFF, "04x")
    rounded = max(8, _js_round(len(units) / 8) * 8)
    return f"[masked {kind} #{fingerprint} ~{rounded}]"


def _js_round(x: float) -> int:
    return int(math.floor(x + 0.5))


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def _char_classes(s: str) -> int:
    return sum(1 for rx in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]") if re.search(rx, s))


_PLACEHOLDER = re.compile(
    r"^(x+|\*+|\.+|<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{?[^}]*\}?\}|changeme|change_me|password\d*|passw0rd|secret|token|redacted|masked|example|test(ing)?\d*|admin\d*|root|null|none|undefined|true|false|your[_-].*|xxx.*|placeholder|dummy|foo|bar|default)$",
    re.I | re.ASCII,
)
ANONYMISATION_TOKEN = re.compile(r"^[A-Z]+(?:_[A-Z]+)*_\d+$")
_KNOWN_CONSTANTS = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
LIMITS = {"minLabeledLen": 8, "minLabeledEntropy": 2.8, "minLabeledClasses": 2, "minHexLen": 32, "minHexEntropy": 3.0}


def is_placeholder(v: str) -> bool:
    base = re.sub(r"[\d\W_]+$", "", v, flags=re.ASCII)
    return bool(_PLACEHOLDER.match(v)) or (len(base) > 0 and base != v and bool(_PLACEHOLDER.match(base)))


def _accept_labeled(v: str) -> bool:
    if len(v) < LIMITS["minLabeledLen"] or is_placeholder(v) or ANONYMISATION_TOKEN.match(v):
        return False
    if "..." in v or "\u2026" in v:
        return False
    if re.match(r"^(https?:|/|\$|%|\{|<)", v):
        return False
    return shannon(v) >= LIMITS["minLabeledEntropy"] and _char_classes(v) >= LIMITS["minLabeledClasses"]


_RX_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")
_RX_HEX = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{32,128}(?![A-Za-z0-9])")
_RX_VENDOR = re.compile(
    r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20}|xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b",
    re.ASCII,
)
_RX_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{40,}?-----END [A-Z ]*PRIVATE KEY-----")
_RX_LABELED = re.compile(
    r"""(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|credentials?)[A-Za-z0-9_]*\\?["']?\s*[:=]\s*\\?["']?([^\s"'\\,;}{<>]{8,200})""",
    re.I | re.ASCII,
)
_RX_BASIC_USER = re.compile(r"""(?:curl[^\n]*?\s-u\s+|https?://)([A-Za-z0-9._-]{2,64}):([^@\s'"\\/]{6,128})@?""", re.ASCII)
_RX_INTERNAL = re.compile(
    r"\b((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d{2,5})?|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:svc\.cluster\.local|internal|corp|lan)(?::\d{2,5})?)\b",
    re.ASCII,
)
_RX_SET_COOKIE_VALUE = re.compile(r"""set-cookie:\s*[A-Za-z0-9_.-]+=([^;\s\\"]+)""", re.I | re.ASCII)


def extract_artefacts(text: str, scope_hosts: Optional[Set[str]] = None) -> List[Dict[str, str]]:
    """Typed, reusable artefacts present in a text blob (secrets and internal endpoints)."""
    scope = scope_hosts or set()
    found: Dict[str, Dict[str, str]] = {}

    def add(kind: str, value: str) -> None:
        if value not in found and not ANONYMISATION_TOKEN.match(value):
            found[value] = {"kind": kind, "value": value}

    for m in _RX_JWT.finditer(text):
        add("jwt", m.group(0))
    for m in _RX_VENDOR.finditer(text):
        add("vendor-key", m.group(1))
    for m in _RX_PRIVKEY.finditer(text):
        add("private-key", m.group(0))
    for m in _RX_HEX.finditer(text):
        v = m.group(0)
        if v.lower() not in _KNOWN_CONSTANTS and shannon(v) >= LIMITS["minHexEntropy"] and not re.match(r"^(.)\1+$", v):
            add("hex-secret", v)
    for m in _RX_LABELED.finditer(text):
        raw = m.group(1)
        if re.search(r"(\.\.\.|\u2026)$", raw) or raw.startswith("eyJ"):
            continue
        v = re.sub(r"[.)\]]+$", "", raw)
        if _accept_labeled(v):
            add("labeled-secret", v)
    for m in _RX_BASIC_USER.finditer(text):
        if _accept_labeled(m.group(2)):
            add("basic-auth", f"{m.group(1)}:{m.group(2)}")
    for m in _RX_INTERNAL.finditer(text):
        v = m.group(1)
        if v.split(":")[0] in scope or v in scope:
            continue
        add("internal-endpoint", v)
    for m in _RX_SET_COOKIE_VALUE.finditer(text):
        found.pop(m.group(1), None)
    values = list(found.values())
    return [a for a in values if not _contained_in_longer(a, values)] if len(values) < 2 else _drop_contained(values)


_GRAM = 8


def _contained_in_longer(a: Dict[str, str], values: List[Dict[str, str]]) -> bool:
    return any(b is not a and b["kind"] != "internal-endpoint" and len(b["value"]) > len(a["value"]) and a["value"] in b["value"]
               for b in values)


def _drop_contained(values: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Same result as « drop every value that is a substring of a LONGER non-endpoint value », in O(total length) instead
    of O(n²) (round3-critique B1: 12 000 tokens = 35 M comparisons, 7.7 s under the ledger lock). A value of length >= 8
    can only be inside b if b contains its first 8 characters: b is indexed once by each of its 8-grams."""
    containers = [b for b in values if b["kind"] != "internal-endpoint"]
    grams: Dict[str, List[int]] = {}
    for i, b in enumerate(containers):
        v = b["value"]
        for j in range(max(0, len(v) - _GRAM + 1)):
            lst = grams.setdefault(v[j:j + _GRAM], [])
            if not lst or lst[-1] != i:
                lst.append(i)
    short_containers = sorted(containers, key=lambda b: -len(b["value"]))
    out = []
    for a in values:
        av = a["value"]
        if len(av) >= _GRAM:
            hit = any(len(containers[i]["value"]) > len(av) and av in containers[i]["value"] for i in grams.get(av[:_GRAM], ()))
        else:   # rare (short internal endpoints): bounded scan of the longer values
            hit = any(len(b["value"]) > len(av) and av in b["value"] for b in short_containers[:4096])
        if not hit:
            out.append(a)
    return out


_EXEC = re.compile(
    r"\b(curl|wget|http|httpie|python3?|node|nc|ncat|sqlmap|ssh|scp|mysql|psql|redis-cli|mongo(sh)?|git|nuclei|hydra|ffuf|gobuster|aws|kubectl|docker|smbclient|ldapsearch|impacket|evil-winrm|crackmapexec|nxc)\b|page\.(goto|request|evaluate)|fetch\(|requests\.(get|post|put|patch|delete)|axios\.",
    re.ASCII,
)


def executable_lines(commands: Any) -> List[str]:
    """Executable command lines with comments removed (prose and pseudo-code are ignored)."""
    out: List[str] = []
    for block in _as_list(commands):
        for line in re.split(r"\n|\\n", block):
            line = re.sub(r"\s(#|//)\s.*$", "", line).strip()
            if not line or re.match(r"^(#|//|/\*|\*)", line):
                continue
            if _EXEC.search(line):
                out.append(line)
    return out


_CREDENTIAL_HEADER = re.compile(
    r"""(?:^|[\s"'`]|\\n)((?:proxy-)?authorization|cookie|private-token|x-[a-z0-9-]*(?:token|key|auth)[a-z0-9-]*)\s*:\s*((?:(?!\\n)[^"'`\r\n])*)""",
    re.I | re.M | re.ASCII,
)
_SET_COOKIE_HEADER = re.compile(r"""(?:^|[\s"'`]|\\n)(set-cookie)\s*:\s*((?:(?!\\n)[^"'`\r\n])*)""", re.I | re.M | re.ASCII)
_CREDENTIAL_OPTION = re.compile(r"""(?:^|\s)(?:-u|-b|--user|--cookie)(?:\s+|=)(?:"([^"]*)"|'([^']*)'|([^\s"']+))""", re.ASCII)
_URL_USERINFO = re.compile(r"""[a-z][a-z0-9+.-]*://([^/\s:@"']+:[^/\s@"']+)@""", re.I | re.ASCII)


def credential_slots(text: str) -> List[str]:
    """Values presented as credentials: header values and credential-option arguments only (F3)."""
    out: List[str] = []
    out += [m.group(2) for m in _CREDENTIAL_HEADER.finditer(text)]
    out += [(m.group(1) if m.group(1) is not None else m.group(2) if m.group(2) is not None else m.group(3) or "") for m in _CREDENTIAL_OPTION.finditer(text)]
    out += [m.group(1) for m in _URL_USERINFO.finditer(text)]
    return [x for x in out if x]


def in_credential_context(text: str, value: str, kind: str) -> bool:
    if kind == "internal-endpoint":
        esc = re.escape(value)
        return bool(re.search(rf"(https?|ftp|redis|mysql|postgres(ql)?|mongodb|smb|ssh)://([^/@\s]*@)?{esc}|\s{esc}(\s|$)", text))
    return any(value in slot for slot in credential_slots(text))


AUTH_IN_REQUEST = re.compile(
    r"authorization:|cookie:|\s-b\s|\s-u\s|--cookie|--user|private-token|x-api-key|bearer\s|token=|api_key=|apikey=|//[^/\s:@]+:[^/\s@]+@",
    re.I,
)


def mask_line(line: str, known: Iterable[str] = ()) -> str:
    """Masks every credential of a line before it is shown as proof (F6, whitelist approach)."""
    hidden: List[Tuple[str, str]] = []

    def hide(value: str, kind: str = "secret") -> str:
        if not value:
            return value
        hidden.append((value, kind))
        return f"\u0000{len(hidden) - 1}\u0000"

    out = line
    for v in sorted([k for k in known if k], key=len, reverse=True):
        out = out.replace(v, hide(v))

    def header(name: str, value: str) -> str:
        if re.search("cookie", name, re.I):
            return re.sub(r"([^=;\s]+)=([^;]*)", lambda m: f"{m.group(1)}={hide(m.group(2).strip(), 'cookie')}", value)
        single = re.match(r"^(bearer|basic|token|apikey)(\s+)(\S+)", value, re.I)
        if single:
            kind = "basic-auth" if single.group(1).lower() == "basic" else "credential"
            return f"{single.group(1)}{single.group(2)}{hide(single.group(3), kind)}{value[len(single.group(0)):]}"
        return hide(value.strip(), "credential")

    def header_sub(m: "re.Match[str]") -> str:
        full, name, value = m.group(0), m.group(1), m.group(2)
        return full[: len(full) - len(value)] + header(name, value)

    def option_sub(m: "re.Match[str]") -> str:
        full = m.group(0)
        dq, sq, bare = m.group(1), m.group(2), m.group(3)
        arg = dq if dq is not None else sq if sq is not None else bare or ""
        if not arg:
            return full
        quoted = dq is not None or sq is not None
        tail = '"' if dq is not None else "'" if sq is not None else ""
        return full[: len(full) - len(arg) - (1 if quoted else 0)] + hide(arg, "credential") + tail

    out = _SET_COOKIE_HEADER.sub(header_sub, out)
    out = _CREDENTIAL_HEADER.sub(header_sub, out)
    out = _CREDENTIAL_OPTION.sub(option_sub, out)
    out = _URL_USERINFO.sub(lambda m: m.group(0).replace(m.group(1), hide(m.group(1), "basic-auth"), 1), out)
    out = re.sub(r"(basic\s+)([A-Za-z0-9+/=]{4,})", lambda m: f"{m.group(1)}{hide(m.group(2), 'basic-auth')}", out, flags=re.I)
    for a in extract_artefacts(out):
        if a["kind"] != "internal-endpoint":
            out = out.replace(a["value"], hide(a["value"], a["kind"]))
    out = re.sub(r"eyJ[\w-]{4,}(?:\.[\w-]*)*", lambda m: hide(m.group(0), "jwt"), out, flags=re.ASCII)
    out = re.sub(
        r"""((?:pass(?:word)?|pwd|secret|token|_pass|api[_-]?key|session)\s*[=:]\s*["']?)([^"'\s,&}\u0000]{3,})""",
        lambda m: f"{m.group(1)}{hide(m.group(2))}",
        out,
        flags=re.I,
    )
    return re.sub("\u0000(\\d+)\u0000", lambda m: mask_secret(hidden[int(m.group(1))][0], hidden[int(m.group(1))][1]), out)


def _decode_uri(p: str) -> str:
    try:
        return unquote(p, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return p


def parse_endpoint(raw: Any) -> Optional[Dict[str, Optional[str]]]:
    """Parse ``endpoint`` as written by agents (URL, bare path, optional HTTP method); free text -> None."""
    s = as_text(raw).strip()
    verb = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", s, re.I)
    method = verb.group(1).upper() if verb else None
    if verb:
        s = s[len(verb.group(0)):]
    s = (re.split(r"\s", s) or [""])[0]
    if not s:
        return None
    host: Optional[str] = None
    url = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#]+)(.*)$", s, re.I | re.S)
    if url:
        host = url.group(1).lower()
        rest = url.group(2)
    elif s.startswith("/"):
        rest = s
    else:
        bare = re.match(r"^([a-z0-9.-]+(?::\d+)?)([/?#].*)?$", s, re.I | re.S)
        if not bare or not re.search(r"[.:]|^localhost", bare.group(1), re.I):
            return None
        host = bare.group(1).lower()
        rest = bare.group(2) or ""

    def clean(p: str) -> str:
        out = _decode_uri(p)
        out = re.sub(r"/{2,}", "/", out)
        out = re.sub(r"/+$", "", out)
        return out or "/"

    hash_route = re.search(r"#(/[^?]*)", rest)
    path = clean(re.sub(r"[?#].*$", "", rest, flags=re.S)) + (f"#{clean(hash_route.group(1))}" if hash_route else "")
    return {"method": method, "host": host, "path": path}


# ---------------------------------------------------------------------------
# Remediation groups (remediation-groups.ts)
# ---------------------------------------------------------------------------

_INJECTION = re.compile(r"inject|xss|ssti|sqli|crlf|xpath|ldap|template", re.I)


def _request_host(f: Dict[str, Any]) -> Optional[str]:
    raw = as_text(_ev(f.get("evidence"), "raw_request"))
    m = re.search(r"^host:\s*([^\s\\]+)", raw, re.I | re.M)
    return m.group(1).lower() if m else None


def injected_parameters(f: Dict[str, Any]) -> str:
    def from_query(q: Optional[str]) -> str:
        names = {kv.split("=")[0].strip().lower() for kv in (q or "").split("&")}
        return ",".join(sorted(n for n in names if n))

    endpoint = as_text(f.get("endpoint"))
    lm = re.search(r"^(?:GET|POST|PUT|PATCH|DELETE)\s+(\S+)", as_text(_ev(f.get("evidence"), "raw_request")), re.I | re.M)
    line = lm.group(1) if lm else ""
    qe = re.search(r"\?([^#\s]*)", endpoint)
    ql = re.search(r"\?([^#\s]*)", line)
    return from_query(qe.group(1) if qe else None) or from_query(ql.group(1) if ql else None)


def normalise_endpoint(endpoint: Any) -> Optional[str]:
    e = parse_endpoint(endpoint)
    if not e:
        return None
    return f"{(e['method'] + ' ') if e['method'] else ''}{e['host'] or ''}{e['path']}"


def normalise_cve(cve: Any) -> Optional[str]:
    parts = [p for p in re.split(r"[\s,;]+", str(cve or "").strip().upper()) if p]
    if not parts or not all(re.match(r"^CVE-\d{4}-\d{4,}$", p) for p in parts):
        return None
    return ",".join(sorted(set(parts)))


def normalise_title(title: Any) -> str:
    s = unicodedata.normalize("NFKD", str(title or ""))
    s = re.sub("[\u0300-\u036f]", "", s).lower()
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def group_duplicate_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strict duplicate grouping (same campaign, target, category, endpoint, parameter, CVE or title)."""
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    seen: Set[str] = set()
    for f in findings:
        if not isinstance(f, dict) or not f.get("id") or f["id"] in seen:
            continue
        seen.add(f["id"])
        campaign = str(f.get("campaign_id") or "").strip()
        category = str(f.get("category") or "").strip().lower()
        endpoint = normalise_endpoint(f.get("endpoint"))
        cve = normalise_cve(f.get("cve"))
        title = normalise_title(f.get("title"))
        pe = parse_endpoint(f.get("endpoint"))
        target = str(f.get("target_id") or "").strip() or _request_host(f) or (pe["host"] if pe else None) or ""
        parameter = injected_parameters(f) if _INJECTION.search(category) else "-"
        if not campaign or not category or not endpoint or (not cve and not title) or not target or not parameter:
            continue
        identity = f"cve:{cve}" if cve else f"title:{title}"
        key = json.dumps([campaign, target, category, endpoint, parameter, identity])
        buckets.setdefault(key, []).append(f)
    groups = []
    for lst in buckets.values():
        if len(lst) < 2:
            continue
        ids = sorted(x["id"] for x in lst)
        f = lst[0]
        endpoint = normalise_endpoint(f.get("endpoint"))
        cve = normalise_cve(f.get("cve"))
        if cve:
            reason = f"{len(ids)} findings report {cve} ({f.get('category')}) on the same endpoint {endpoint}: one fix removes them all."
        else:
            reason = (f"{len(ids)} findings report the same weakness \"{str(f.get('title') or '').strip()}\" "
                      f"({f.get('category')}) on the same endpoint {endpoint}: one fix removes them all.")
        groups.append({"id": f"group:{ids[0]}", "finding_ids": ids, "reason": reason})
    return sorted(groups, key=lambda g: lc_key(g["id"]))


# ---------------------------------------------------------------------------
# Observed derivation (observed-paths.ts)
# ---------------------------------------------------------------------------

GRANTING = {
    "sql_injection", "nosql_injection", "authentication_bypass", "auth_bypass", "broken_authentication", "jwt",
    "privilege_escalation", "mass_assignment", "remote_code_execution", "deserialization", "xxe", "ssrf",
    "path_traversal", "lfi", "rfi", "file_disclosure", "file_exposure", "sensitive_file_exposure",
    "sensitive_data_exposure", "information_disclosure", "idor", "broken_access_control",
    "security_misconfiguration", "misconfiguration", "insecure_configuration", "exposed_admin_tool",
    "file_upload", "unrestricted_file_upload",
}
REGISTRATION = re.compile(r"open (user )?registration|registration (enabled|without)", re.I)
_STATUS_SUCCESS = re.compile(
    r"""(?:HTTP/\d(?:\.\d)?\s+|(?:->|=>|\u2192)\s*(?:HTTP/\d(?:\.\d)?\s+)?|\bstatus(?:[ _-]?code)?["']?\s*[:=]\s*["']?|\b(?:returned|responded(?: with)?)\s+)(20[01]|30[23])\b""",
    re.I,
)
_IDENTITY_FIELD = re.compile(r"""(?:user(?:_?name)?|login|email|handle)["']?\s*[:=]\s*["']?([A-Za-z0-9._@+-]{3,64})""", re.I)
_IDENTITY_PROSE = re.compile(r"""(?:created|registered|signed up)[^\n]{0,40}?\bas\s+["']?([A-Za-z0-9._@+-]{3,64})""", re.I)
_MASKED_CREDENTIAL = re.compile(
    r"<[a-z_]*(token|session|cookie|jwt|key|pass)[a-z_]*>|\$\{?[A-Z_]*(TOKEN|SESSION|COOKIE|JWT|KEY|PASS)[A-Z_]*\}?|eyJ[\w-]*(\.\.\.|\u2026)|PHPSESSID=\.\.\.",
    re.ASCII,
)
_PRODUCER_HINT = re.compile(
    r"authentication bypass|login bypass|account takeover|alg.?none|algorithm confusion|mass assignment|admin role|credentials? (exposed|dump)|ssh .*credentials|registration",
    re.I,
)
_SELF_PROVISIONED = re.compile(r"regist|sign.?up|logged in as|freshly|own (valid )?(jwt|token)|low.?priv", re.I)


def severity_of(s: Any) -> str:
    v = str(s).lower()
    return v if v in SEVERITIES else "info"


def _is_post(line: str) -> bool:
    return (bool(re.search(r"""(?:^|[\s"'(\d.])POST\s""", line))
            or bool(re.search(r"""-X\s*["']?POST\b""", line, re.I))
            or (bool(re.search(r"\bcurl\b", line)) and bool(re.search(r"\s(-d|--data[\w-]*|-F|--form)\s", line))
                and not re.search(r"""-X\s*["']?[A-Z]+""", line)))


def _calls_path(line: str, path: str) -> bool:
    return bool(re.search(r"""(?:^|[\s"'(=]|https?://[^/\s"']+)""" + re.escape(path) + r"""(?=$|[\s"'?#),;])""", line))


def _strip_port(h: Optional[str]) -> Optional[str]:
    return re.sub(r":\d+$", "", h).lower() if h else None


_REQ_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)[^\n]*(?:\n|\\n)host:\s*(\S+)", re.I | re.M)


def _requests_of(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    m = _REQ_LINE.search(f["raw_request"])
    if m:
        out.append({"method": m.group(1).upper(), "path": m.group(2).split("?")[0], "host": m.group(3).lower(),
                    "authed": bool(AUTH_IN_REQUEST.search(f["raw_request"]))})
    for line in f["exec"]:
        u = re.search(r"""(https?)://([^/\s"']+)(/[^\s"'?]*)?""", line)
        if not u:
            continue
        mm = re.search(r"-X\s+([A-Z]+)", line)
        method = mm.group(1) if mm else ("POST" if re.search(r"\s-(d|F)\s|--data", line) else "GET")
        out.append({"method": method, "host": u.group(2).lower(), "path": u.group(3) or "/", "authed": bool(AUTH_IN_REQUEST.search(line))})
    return out


_GENERIC_SEGMENTS = {"api", "v1", "v2", "v3", "rest", "repos", "contents", "users", "user", "raw", "branch", "main",
                     "master", "admin", "public", "static", "index.php", "login", "search", "products"}


def _distinctive_segments(path: str) -> List[str]:
    out = []
    for x in path.split("/"):
        x = re.sub(r"\.git$", "", _decode_uri(x))
        if len(x) >= 6 and x.lower() not in _GENERIC_SEGMENTS:
            out.append(x)
    return out


_WHOLE_REPO = re.compile(r"\.git/info/refs|git-upload-pack|\bgit clone\b")
_RESOURCE = re.compile(r"""(?:^|[/\s"'])(\.?[A-Za-z0-9_-]*\.(?:env|ini|ya?ml|json|xml|bak|conf|pem|key))\b""", re.ASCII)


def _resources_in(text: str) -> Set[str]:
    return {m.group(1) for m in _RESOURCE.finditer(text)}


def _leaf(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    return parts[-1] if parts else ""


def _anonymous_get_index(all_: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """P7 fix 2 (DM_ARTIFACT_FINGERPRINTS): unauthenticated GET/HEAD requests by host, computed once per derivation
    (the scan below recomputed every finding's requests for every link: O(F^2) regex work)."""
    out: Dict[str, List[Any]] = {}
    for c in all_:
        for q in _requests_of(c):
            if not q["authed"] and q["method"] in ("GET", "HEAD"):
                out.setdefault(q["host"], []).append((c, q))
    return out


def _unauthenticated_alternatives(b: Dict[str, Any], all_: List[Dict[str, Any]], exclude: Set[str],
                                  anon_index: Optional[Dict[str, List[Any]]] = None) -> List[str]:
    authed = [r for r in _requests_of(b) if r["authed"]]
    if any(r["method"] not in ("GET", "HEAD") for r in authed):
        return []
    twins: Set[str] = set()
    for r in authed:
        leaf = _leaf(r["path"])
        distinct = set(_distinctive_segments(r["path"]))
        pairs = anon_index.get(r["host"], []) if anon_index is not None else [(c, q) for c in all_ for q in _requests_of(c)]
        for c, q in pairs:
            if c["id"] == b["id"] or c["id"] in exclude:
                continue
            if q["authed"] or q["host"] != r["host"] or q["method"] not in ("GET", "HEAD"):
                continue
            shares = any(x in distinct for x in _distinctive_segments(q["path"]))
            same_leaf = len(leaf) > 0 and _leaf(q["path"]) == leaf
            if shares and (same_leaf or _WHOLE_REPO.search(q["path"]) or _WHOLE_REPO.search(c["input"])):
                twins.add(c["id"])
    wanted = list(_resources_in(b["raw_request"] + "\n" + "\n".join(b["exec"])))
    if wanted:
        readers: Dict[str, Set[str]] = {}
        for c in all_:
            if c["id"] == b["id"] or c["id"] in exclude or (b["host"] and c["host"] and b["host"] != c["host"]):
                continue
            for line in [*c["exec"], c["raw_request"]]:
                if not line or AUTH_IN_REQUEST.search(line) or re.search(r"-X\s+(POST|PUT|PATCH|DELETE)|^(POST|PUT|PATCH|DELETE)\s", line, re.M):
                    continue
                for res in _resources_in(line):
                    if res in wanted:
                        readers.setdefault(res, set()).add(c["id"])
        if all(r in readers for r in wanted):
            for ids in readers.values():
                twins |= ids
    return sorted(twins)


def _self_minted(b: Dict[str, Any], value: str) -> bool:
    c = as_text(_ev(b["v"].get("evidence"), "commands"))
    i = c.find(value)
    return i > 0 and bool(re.search(r"\$\(|`", c[:i]))


def _node_type(n: Dict[str, Any]) -> str:
    return str(n.get("node_type"))


def _host_node_of(node_id: Optional[str], nodes: Dict[str, Dict[str, Any]], endpoint_host: Optional[str]) -> Optional[str]:
    cur = nodes.get(node_id) if node_id else None
    seen: Set[str] = set()
    while cur is not None and cur["id"] not in seen:
        seen.add(cur["id"])
        if _node_type(cur) == "host":
            return cur["id"]
        parent = cur.get("parent_node_id")
        cur = nodes.get(parent) if parent else None
    hosts = [n for n in nodes.values() if _node_type(n) == "host"]
    same = sorted(n["id"] for n in hosts if endpoint_host and _strip_port(n.get("host")) == endpoint_host)
    if same:
        return same[0]
    return hosts[0]["id"] if len(hosts) == 1 else None


def _decode_basic(b64: str) -> str:
    try:
        return base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False).decode("latin-1")
    except (binascii.Error, ValueError):
        return ""


def ancestors_of(node_id: Optional[str], nodes: Dict[str, Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    cur = nodes[node_id].get("parent_node_id") if node_id and node_id in nodes else None
    while cur and cur in nodes and cur not in out and cur != node_id:
        out.append(cur)
        cur = nodes[cur].get("parent_node_id")
    return out


def _finite(n: Any) -> float:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return 0.0
    return v if math.isfinite(v) else 0.0


_FP_KEY = "\x00fp:"  # needs[] key of a fingerprint entry (can never be a real artefact value)
_GRAM = 8


_SLOT_INDEX_MAX_CHARS = 4096       # a longer credential slot is not indexed: its finding is always a candidate
_INDEX_MAX_GRAMS = 1_000_000       # memory budget of the index (8-gram insertions); beyond it, plain scan


class _R1Index:
    """P7 fix 2 + P8 RT-09: the CREDENTIAL SLOTS of each finding (header values, -u/-b arguments, URL userinfo:
    short strings) are indexed once by 8-grams, under a memory budget. The free-text inputs are NOT indexed any more
    (they were ~300 bytes of index per input character): ``inputs_containing`` is one C-level substring test per
    finding. ``candidates`` returns a SUPERSET of the findings that can match; callers verify each one with the
    original predicate, so the R1 decisions are unchanged (tested against the verbatim scan)."""

    def __init__(self, findings: List[Dict[str, Any]]) -> None:
        self.findings = findings
        self.slot_grams: Dict[str, Set[int]] = {}
        self.always: Set[int] = set()
        self.disabled = False
        inserted = 0
        for i, f in enumerate(findings):
            slots = credential_slots(f["raw_request"]) + [x for line in f["exec"] for x in credential_slots(line)]
            for txt in slots:
                if len(txt) > _SLOT_INDEX_MAX_CHARS:
                    self.always.add(i)
                    continue
                inserted += max(0, len(txt) - _GRAM + 1)
                if inserted > _INDEX_MAX_GRAMS:
                    self.disabled, self.slot_grams = True, {}
                    return
                for k in range(len(txt) - _GRAM + 1):
                    self.slot_grams.setdefault(txt[k:k + _GRAM], set()).add(i)

    @staticmethod
    def _probe(value: str) -> List[str]:
        mid = (len(value) - _GRAM) // 2
        return list(dict.fromkeys([value[:_GRAM], value[mid:mid + _GRAM], value[-_GRAM:]]))

    def _lookup(self, value: str) -> Optional[Set[int]]:
        if self.disabled or len(value) < _GRAM:
            return None  # index over budget, or value too short to index: every finding is a candidate
        out: Optional[Set[int]] = None
        for g in self._probe(value):
            ids = self.slot_grams.get(g)
            if not ids:
                out = set()
                break
            out = set(ids) if out is None else out & ids
            if not out:
                break
        return (out or set()) | self.always

    def candidates(self, value: str, kind: str) -> List[Dict[str, Any]]:
        ids = None if kind == "internal-endpoint" else self._lookup(value)
        if ids is None:
            return self.findings
        return [self.findings[i] for i in sorted(ids)]

    def inputs_containing(self, value: str) -> List[str]:
        return [f["id"] for f in self.findings if value in f["input"]]


def _r1_fingerprint_links(findings: List[Dict[str, Any]], by_id: Dict[str, Dict[str, Any]],
                          needs: Dict[str, Dict[str, Dict[str, Any]]], reject) -> None:
    """R1 on server fingerprints (artifact_fingerprints.py): producer fingerprint == consumer presented fingerprint."""
    from api.artifact_fingerprints import fingerprints_of
    fps = {f["id"]: fingerprints_of(f["v"]) for f in findings}
    producers: Dict[str, List[Dict[str, str]]] = {}   # fingerprint -> [{id, kind}]
    presenters: Dict[str, Set[str]] = {}              # fingerprint -> findings presenting it as a credential
    seen_in: Dict[str, Set[str]] = {}                 # fingerprint -> findings whose input carries it
    for f in findings:
        d = fps[f["id"]]
        for p in d.get("produced") or []:
            producers.setdefault(p["fp"], []).append({"id": f["id"], "kind": p["kind"]})
        for x in d.get("presented") or []:
            presenters.setdefault(x["fp"], set()).add(f["id"])
        for x in d.get("seen") or []:
            seen_in.setdefault(x, set()).add(f["id"])
    human_chosen = {"labeled-secret", "basic-auth"}
    for b in findings:
        for pr in fps[b["id"]].get("presented") or []:
            fp = pr["fp"]
            for p in producers.get(fp, []):
                a = by_id[p["id"]]
                if a["id"] == b["id"]:
                    continue
                if str(a["v"].get("campaign_id") or "") != str(b["v"].get("campaign_id") or ""):
                    reject(a["id"], b["id"], "other-campaign")  # salts differ per campaign; kept as a hard guard
                    continue
                if any(a["id"] in e["producers"] for e in needs.get(b["id"], {}).values()):
                    continue  # already linked by the verbatim R1
                if p["kind"] in human_chosen and len(producers[fp]) > 1:
                    reject(a["id"], b["id"], "value-not-unique")
                    continue
                if seen_in.get(fp, set()) - {a["id"]} - presenters.get(fp, set()):
                    reject(a["id"], b["id"], "tester-supplied")
                    continue
                if str(a["v"].get("status")) != "exploited":
                    reject(a["id"], b["id"], "producer-not-exploited")
                    continue
                if str(a["v"].get("category") or "").lower() not in GRANTING:
                    reject(a["id"], b["id"], "producer-not-granting")
                    continue
                if any(x["id"] == b["id"] for x in producers[fp]):
                    reject(a["id"], b["id"], "consumer-obtained-it")
                    continue
                entry = needs.setdefault(b["id"], {}).setdefault(
                    _FP_KEY + fp, {"kind": p["kind"], "producers": set(), "where": pr.get("where")})
                entry["producers"].add(a["id"])


_ORIGIN_TYPES = ("endpoint", "application", "service", "web_server", "api")
_STORE_TYPES = {"database", "datastore", "host", "target", "os", "technology"}


_ENDPOINT_URL = re.compile(r"^\s*(?:[A-Z]+\s+)?(https?)://[^/:\s?#]+(?::(\d{1,5}))?", re.I)


def _node_port(n: Dict[str, Any], nodes: Dict[str, Dict[str, Any]]) -> Optional[int]:
    """The node's port, else the nearest ancestor's (an endpoint inherits its application's port)."""
    cur, seen = n, set()
    while cur is not None and cur["id"] not in seen:
        seen.add(cur["id"])
        try:
            if cur.get("port") not in (None, ""):
                return int(cur["port"])
        except (TypeError, ValueError):
            return None
        parent = cur.get("parent_node_id")
        cur = nodes.get(parent) if parent else None
    return None


def _exploit_origin(f: Dict[str, Any], reached: str, nodes: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """P7 fix 4 + P8 RT-05: the node an exploit was SENT to, or None. Candidates are non-data nodes of the endpoint's
    host AND port (scheme default 443/80; a node inherits its ancestor's port). An endpoint node whose label prefixes
    the exploited path wins (longest label); otherwise exactly ONE application / service / web_server / api candidate
    must remain. Several candidates -> no link: the origin is never chosen by id order (no guess)."""
    host = f.get("host")
    if not host:
        return None
    raw = str(f["v"].get("endpoint") or "")
    m = _ENDPOINT_URL.match(raw)
    port = int(m.group(2)) if m and m.group(2) else ({"https": 443, "http": 80}.get(m.group(1).lower()) if m else None)
    cands = [n for n in nodes.values()
             if n["id"] != reached and _strip_port(str(n.get("host") or "").lower()) == host
             and _node_type(n) not in _STORE_TYPES and _node_type(n) in _ORIGIN_TYPES]
    if port is not None:
        same = [n for n in cands if _node_port(n, nodes) == port]
        cands = same or [n for n in cands if _node_port(n, nodes) is None]
    if not cands:
        return None
    pe = parse_endpoint(raw)
    path = (pe or {}).get("path") or ""
    on_path = [n for n in cands if path and _node_type(n) == "endpoint" and str(n.get("label") or "").startswith("/")
               and path.startswith(str(n.get("label")))]
    if on_path:
        longest = max(len(str(n.get("label"))) for n in on_path)
        best = [n for n in on_path if len(str(n.get("label"))) == longest]
        return best[0]["id"] if len(best) == 1 else None
    apps = [n for n in cands if _node_type(n) != "endpoint"]
    return apps[0]["id"] if len(apps) == 1 else None


def derive_observed_input(nodes_list: Optional[List[Dict[str, Any]]], vulns: Optional[List[Dict[str, Any]]],
                          campaign_id: Optional[str] = None) -> Dict[str, Any]:
    """Observed derivation (R1/R2/R3). Returns {campaign_id, input:{scenarios, findings, groups}, links,
    rejected, hypotheses, issues}. Scenario/finding dicts use the engine's snake_case shape."""
    issues: List[Dict[str, Any]] = []
    nodes: Dict[str, Dict[str, Any]] = {}
    for n in nodes_list or []:
        if isinstance(n, dict) and n.get("id") and n["id"] not in nodes:
            nodes[n["id"]] = n
    attached: Dict[str, str] = {}
    for n in nodes.values():
        for vid in n.get("vulnerability_ids") or []:
            attached.setdefault(vid, n["id"])

    excluded: List[str] = []
    seen_ids: Set[str] = set()
    findings: List[Dict[str, Any]] = []
    for v in vulns or []:
        if not isinstance(v, dict) or not v.get("id") or v["id"] in seen_ids:
            continue
        seen_ids.add(v["id"])
        if str(v.get("status")) in ("false_positive", "remediated"):
            excluded.append(v["id"])
            continue
        e = v.get("evidence")
        pe = parse_endpoint(v.get("endpoint"))
        hm = re.search(r"^host:\s*([^\s\\]+)", as_text(_ev(e, "raw_request")), re.I | re.M)
        findings.append({
            "v": v, "id": v["id"],
            "input": input_text(e), "output": output_text(e), "narrative": narrative_text(e),
            "raw_request": as_text(_ev(e, "raw_request")),
            "exec": executable_lines(_ev(e, "commands")),
            "host": _strip_port(pe["host"] if pe else None) or _strip_port(hm.group(1) if hm else None),
        })
    if excluded:
        issues.append({"kind": "excluded-findings", "finding_ids": sorted(excluded),
                       "message": f"{len(excluded)} false-positive or remediated finding(s) ignored."})
    by_id = {f["id"]: f for f in findings}
    if campaign_id is None:
        campaign_id = findings[0]["v"].get("campaign_id") if findings else None

    unresolved: Set[str] = set()

    def attached_node(fid: str) -> Optional[str]:
        if fid in attached:
            return attached[fid]
        nid = (by_id.get(fid) or {}).get("v", {}).get("node_id") or ""
        return nid if nid in nodes else None

    def node_of(fid: str) -> str:
        n = attached_node(fid)
        if n:
            return n
        unresolved.add(fid)
        return f"{PSEUDO_NODE_PREFIX}{fid}"

    scope: Set[str] = set()
    for n in nodes.values():
        if n.get("host"):
            scope.add(str(n["host"]).lower())
    for f in findings:
        if f["host"]:
            scope.add(f["host"])
    hits: Dict[str, int] = {}
    for f in findings:
        own = {a["value"].split(":")[0] for a in extract_artefacts(f["input"]) if a["kind"] == "internal-endpoint"}
        for h in own:
            hits[h] = hits.get(h, 0) + 1
    for h, c in hits.items():
        if c >= 3:
            scope.add(h)

    links: List[Dict[str, Any]] = []
    rejected: List[Dict[str, str]] = []

    def reject(producer: str, consumer: str, rule: str) -> None:
        r = {"producer": producer, "consumer": consumer, "rule": rule}
        if r not in rejected:
            rejected.append(r)

    # ---------- R1 artefact ----------
    needs: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def presents(b: Dict[str, Any], value: str, kind: str) -> bool:
        return ((value in b["raw_request"] and in_credential_context(b["raw_request"], value, kind))
                or any(value in l and in_credential_context(l, value, kind) for l in b["exec"]))

    human_chosen = {"labeled-secret", "basic-auth"}
    sources: Dict[str, int] = {}
    artefacts_of: Dict[str, List[Dict[str, str]]] = {}
    for a in findings:
        lst = [x for x in extract_artefacts(a["output"], scope) if x["value"] not in a["input"]]
        artefacts_of[a["id"]] = lst
        for x in lst:
            sources[x["value"]] = sources.get(x["value"], 0) + 1
    # P7 fix 2 (flag DM_ARTIFACT_FINGERPRINTS): same R1 decisions without the O(F^2) scan. The credential slots and
    # inputs of each finding are indexed once by 8-grams; every candidate is verified with the exact same
    # predicate (`presents` / substring), so the index only prunes findings that cannot match.
    from api import feature_flags
    fp_mode = feature_flags.enabled("DM_ARTIFACT_FINGERPRINTS")
    anon_index: Optional[Dict[str, List[Any]]] = None
    if fp_mode:
        index = _R1Index(findings)
        anon_index = _anonymous_get_index(findings)

        def consumers_of(a: Dict[str, Any], art: Dict[str, str]) -> List[Dict[str, Any]]:
            return [b for b in index.candidates(art["value"], art["kind"]) if b["id"] != a["id"] and presents(b, art["value"], art["kind"])]

        def is_supplied(a: Dict[str, Any], value: str, consumer_ids: Set[str]) -> bool:
            return any(x != a["id"] and x not in consumer_ids for x in index.inputs_containing(value))
    else:
        def consumers_of(a: Dict[str, Any], art: Dict[str, str]) -> List[Dict[str, Any]]:
            return [b for b in findings if b["id"] != a["id"] and presents(b, art["value"], art["kind"])]

        def is_supplied(a: Dict[str, Any], value: str, consumer_ids: Set[str]) -> bool:
            return any(x["id"] != a["id"] and value in x["input"] and x["id"] not in consumer_ids for x in findings)
    for a in findings:
        for art in artefacts_of[a["id"]]:
            consumers = consumers_of(a, art)
            if not consumers:
                continue
            if art["kind"] in human_chosen and sources.get(art["value"], 0) > 1:
                for b in consumers:
                    reject(a["id"], b["id"], "value-not-unique")
                continue
            consumer_ids = {b["id"] for b in consumers}
            supplied = is_supplied(a, art["value"], consumer_ids)
            for b in consumers:
                if supplied:
                    reject(a["id"], b["id"], "tester-supplied")
                    continue
                if str(a["v"].get("status")) != "exploited":
                    reject(a["id"], b["id"], "producer-not-exploited")
                    continue
                if str(a["v"].get("category") or "").lower() not in GRANTING:
                    reject(a["id"], b["id"], "producer-not-granting")
                    continue
                if art["value"] in b["output"] or art["value"] in b["narrative"]:
                    reject(a["id"], b["id"], "consumer-obtained-it")
                    continue
                if _self_minted(b, art["value"]):
                    reject(a["id"], b["id"], "consumer-minted-it")
                    continue
                by_value = needs.setdefault(b["id"], {})
                entry = by_value.setdefault(art["value"], {"kind": art["kind"], "producers": set()})
                entry["producers"].add(a["id"])

    # P7 fix 2: R1 by fingerprint equality (salted fingerprints computed by the server at push time, before the
    # evidence was truncated or tokenised). Value index: one dict lookup per presented fingerprint, linear in F.
    # Same rejection rules as the verbatim R1 above; a pair already linked verbatim is not counted twice.
    if fp_mode:
        _r1_fingerprint_links(findings, by_id, needs, reject)

    for consumer_id in sorted(needs, key=lc_key):
        by_value = needs[consumer_id]
        b = by_id[consumer_id]
        by_set: Dict[str, Dict[str, Any]] = {}
        for value, e in by_value.items():
            ps = sorted(e["producers"])
            key = "|".join(ps)
            s = by_set.setdefault(key, {"producers": ps, "values": [], "kinds": set()})
            s["values"].append(value)
            s["kinds"].add(e["kind"])
        for s in sorted(by_set.values(), key=lambda x: lc_key(",".join(x["producers"]))):
            producers, values, kinds = s["producers"], s["values"], s["kinds"]

            def in_request(v: str) -> bool:
                if v.startswith(_FP_KEY):  # fingerprint entry: was it presented in the request (not only a command)?
                    return by_value[v].get("where") == "request"
                return v in b["raw_request"]

            auxiliary = len(b["raw_request"].strip()) > 0 and not any(in_request(v) for v in values)
            alternatives = [] if auxiliary else _unauthenticated_alternatives(b, findings, set(producers), anon_index)
            shown = ", ".join(f"[fingerprint {by_value[v]['kind']} #{v[len(_FP_KEY):len(_FP_KEY) + 4]}]" if v.startswith(_FP_KEY)
                              else v if by_value[v]["kind"] == "internal-endpoint" else mask_secret(v, by_value[v]["kind"]) for v in values)
            links.append({
                "kind": "R1", "producers": producers, "consumer": consumer_id,
                "from_node_id": attached_node(producers[0]), "to_node_id": attached_node(consumer_id),
                "capability": f"reused {'/'.join(sorted(kinds))}",
                "auxiliary": auxiliary, "alternatives": alternatives,
                "necessary": not auxiliary and not alternatives,
                "necessity_note": ("the canonical proof request does not carry the artefact (side use, not a dependency)" if auxiliary
                                   else f"the same resource was also reached without it by {', '.join(alternatives)}" if alternatives
                                   else "no access without this artefact was observed in the campaign"),
                "proof": f"{' | '.join(producers)} output contains {shown}; {consumer_id} presents it as a credential",
            })

    # ---------- D declared (enabled_by) — architecture D (reports/51-architecture-d-implementation/CONTRACT-D.md) ----------
    # The agent named, on a finding, the earlier findings whose result it used. Every reference becomes a link at once:
    # « rejected_declaration » (unknown / other campaign, self, ambiguous, forward in time, same weakness: never a path
    # edge), « invalidated » (a finding of the link was withdrawn: kept, never counted) or « declared_by_agent », which
    # api/edge_verifier.qualify_edge may raise to observed_flow / causal_necessity_demonstrated by exact value
    # attribution on the server's own records. A server rule (R1-R3) on the same pair wins.
    if any(isinstance(v, dict) and v.get("enabled_by") for v in vulns or []):
        from api.declared_links import flag_label, resolve_one, validate
        from api.edge_verifier import CAUSAL, D_STATE_LABELS, DECLARED_BY_AGENT, qualify_edge
        already = {(p, l["consumer"]) for l in links for p in l["producers"]}
        open_reg_hosts = {f["host"] for f in findings if f["host"] and REGISTRATION.search(str(f["v"].get("title") or ""))
                          and str(f["v"].get("status")) in ("exploited", "confirmed")}
        live_vulns = [v for v in vulns or [] if isinstance(v, dict) and v.get("id")]
        facts = _declared_ledger(live_vulns)
        resolved = []
        for v in live_vulns:   # enabled_by resolved to finding ids + the server facts of its push (never stored back)
            refs = [resolve_one(r, live_vulns, str(v["id"]))[0] for r in (v.get("enabled_by") or [])
                    if isinstance(v.get("enabled_by"), list)]
            key = (str(v.get("run_id") or ""), str(v["id"]))
            resolved.append(dict(v, enabled_by=[r for r in refs if r], value_fps=facts["fps"].get(key, []),
                                 push_seq=facts["push_seq"].get(key, v.get("push_seq"))))
        rmap = {str(v["id"]): v for v in resolved}
        for d in validate(live_vulns, set(nodes)):
            p_id, c_id = d["producer"], d["consumer"]
            if (p_id, c_id) in already:
                continue
            if c_id in by_id and by_id[c_id]["host"] and by_id[c_id]["host"] in open_reg_hosts:
                # anyone can register an account on this host: what the producer gave may not have been needed (same
                # caution); a warning, the link stays declared — we cannot know
                d["warnings"] = list(d.get("warnings") or []) + ["open-registration"]
            if d["state"] != DECLARED_BY_AGENT:
                state, reason, refs = d["state"], d["reason"], {}
            else:
                run = str(rmap[c_id].get("run_id") or "")
                state, reason, refs = qualify_edge(rmap[p_id], rmap[c_id], facts["executions"], resolved,
                                                   sessions=facts["sessions"].get(run))
            links.append({
                "kind": "D", "producers": [p_id], "consumer": c_id,
                "from_node_id": attached_node(p_id) if p_id in rmap else None, "to_node_id": attached_node(c_id),
                "capability": "result of an earlier finding used (declared)",
                "auxiliary": False, "alternatives": [], "necessary": state == CAUSAL,
                "necessity_note": D_STATE_LABELS[state] + (f" ({reason})" if reason else ""),
                "proof": (f"{c_id} declares enabled_by {p_id}; {flag_label(d['flags'], d.get('warnings'))}; "
                          f"server: {state}" + (f" ({reason})" if reason else "")
                          + (f", executions {' -> '.join(refs.get('executions') or [])}" if refs.get("executions") else "")),
                "usage": "declared", "necessity": "demonstrated" if state == CAUSAL else "not_assessed", "level": state,
                "verification": {"state": state, "reason": reason, "evidence_refs": refs},
                "valid": d["valid"] and c_id in by_id, "flags": d["flags"], "warnings": d.get("warnings") or [],
                "attack_context": {"producer_tactics": d["producer_tactics"], "consumer_tactics": d["consumer_tactics"]},
            })

    # ---------- R2 mechanism (open registration) ----------
    registrations = []
    for f in findings:
        if REGISTRATION.search(str(f["v"].get("title") or "")):
            pe = parse_endpoint(f["v"].get("endpoint"))
            path = pe["path"] if pe else None
            if path and len(path) > 1:
                registrations.append({"f": f, "path": path})
    for q in findings:
        if REGISTRATION.search(str(q["v"].get("title") or "")) or not registrations:
            continue
        lines = [*q["exec"], *re.split(r"\n|\\n", q["raw_request"]), *re.split(r"""\n|\\n|",\s*\"""", q["output"] + "\n" + q["narrative"])]

        def calls(r: Dict[str, Any]) -> List[str]:
            return [l for l in lines if _is_post(l) and _calls_path(l, r["path"])]

        producers = [r for r in registrations
                     if (not q["host"] or not r["f"]["host"] or q["host"] == r["f"]["host"])
                     and any(_STATUS_SUCCESS.search(l) for l in calls(r))]
        if not producers:
            continue
        call_lines: List[str] = []
        for r in producers:
            for l in calls(r):
                if l not in call_lines:
                    call_lines.append(l)
        line = next(l for l in call_lines if _STATUS_SUCCESS.search(l))
        identities: Set[str] = set()
        for l in call_lines:
            for m in list(_IDENTITY_FIELD.finditer(l)) + list(_IDENTITY_PROSE.finditer(l)):
                identities.add(re.sub(r"[.,;:]+$", "", m.group(1)))
        authed = []
        for t in [q["raw_request"], *q["exec"]]:
            if t and AUTH_IN_REQUEST.search(t) and t not in call_lines:
                decoded = "\n".join(_decode_basic(m.group(1)) for m in re.finditer(r"basic\s+([A-Za-z0-9+/=]{4,})", t, re.I))
                authed.append(t + "\n" + decoded)
        identity_used = any(
            any(re.search(r"(?<![A-Za-z0-9._@+-])" + re.escape(i) + r"(?![A-Za-z0-9._@+-])", t) for t in authed)
            for i in identities
        )
        unauthenticated = len(q["raw_request"].strip()) > 0 and not AUTH_IN_REQUEST.search(q["raw_request"])
        auxiliary = unauthenticated or not identity_used
        ids = sorted(r["f"]["id"] for r in producers)
        alternatives = [] if auxiliary else _unauthenticated_alternatives(q, findings, set(ids), anon_index)
        links.append({
            "kind": "R2", "producers": ids, "consumer": q["id"],
            "from_node_id": attached_node(ids[0]), "to_node_id": attached_node(q["id"]),
            "capability": "self-created account through open registration",
            "auxiliary": auxiliary, "alternatives": alternatives,
            "necessary": not auxiliary and not alternatives,
            "necessity_note": ("the canonical proof request was sent without authentication" if unauthenticated
                               else "the account created through the registration is not shown in an authenticated request" if auxiliary
                               else f"the same resource was also reached without an account by {', '.join(alternatives)}" if alternatives
                               else "no access without an account was observed in the campaign"),
            "proof": f"{q['id']}: \"{mask_line(line.strip())[:160]}\"",
            "level": INFERRED, "provenance": INFERRED, "inference_note": R2_INFERENCE_NOTE,
        })

    # ---------- R3 reach ----------
    # P7 fix 4 (flag DM_R3_EXPLOIT_ORIGIN): the push_finding docstring asks agents to attach a DB leak to the DATABASE
    # node, while R3 needs the reach to go to ANOTHER node: the same proof then gave no link (02 C6). Under the flag,
    # when the finding's own node IS the reached node, R3 starts at the node the exploit was SENT to (its endpoint's
    # host, an application / service / endpoint node). The reach proof itself is unchanged.
    r3_origin = feature_flags.enabled("DM_R3_EXPLOIT_ORIGIN")

    def origin_or(frm_: Optional[str], to_: str, f_: Dict[str, Any]) -> Optional[str]:
        if not r3_origin or frm_ != to_:
            return frm_
        return _exploit_origin(f_, to_, nodes) or frm_

    for f in findings:
        if str(f["v"].get("status")) != "exploited":
            continue
        frm = attached_node(f["id"])
        requested = f["input"] + "\n" + f["narrative"]
        sm = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", f["output"])
        status = sm.group(1) if sm else None
        success = status is None or status.startswith("2")
        passwd_records = len(re.findall(r"""(?:^|[\s>"'\\n])[a-z_][a-z0-9_-]*:x:\d+:\d+:[^:\n]*:[^:\n]*:""", f["output"]))
        if "root:x:0:0:" in f["output"] and (success or passwd_records >= 2) and re.search(r"(file://|/etc/passwd)", requested):
            to = _host_node_of(frm, nodes, f["host"])
            src = origin_or(frm, to, f) if to else frm
            if to and to != src:
                links.append({
                    "kind": "R3", "producers": [], "consumer": f["id"], "from_node_id": src, "to_node_id": to,
                    "capability": _r3_host_capability(as_text(_ev(f["v"].get("evidence"), "raw_response")), f["input"]),
                    "auxiliary": False, "alternatives": [], "necessary": True, "necessity_note": "intrinsic reach",
                    "proof": f"{f['id']} response contains the system account file (root:x:0:0)",
                })
        if str(f["v"].get("category")) in ("sql_injection", "nosql_injection") and success:
            em = re.search(r"sqlite|mysql|mariadb|postgres|mongo", f["output"], re.I)
            engine = em.group(0).lower() if em else None
            rows = bool(re.search(r"\b[0-9a-f]{32}\b", f["output"])) or bool(re.search(r"sqlite_master|information_schema", f["output"], re.I))
            if not engine or not rows:
                continue
            rx = re.compile("mysql|mariadb" if engine in ("mariadb", "mysql") else engine, re.I)
            stores = [n for n in nodes.values() if rx.search(f"{n['id']} {n.get('label') or ''} {n.get('technology') or ''}")]
            src = origin_or(frm, stores[0]["id"], f) if len(stores) == 1 else frm
            if len(stores) != 1 or stores[0]["id"] == src:
                continue
            links.append({
                "kind": "R3", "producers": [], "consumer": f["id"], "from_node_id": src, "to_node_id": stores[0]["id"],
                "capability": f"{engine} database read",
                "auxiliary": False, "alternatives": [], "necessary": True, "necessity_note": "intrinsic reach",
                "proof": f"{f['id']} response returns extracted rows and names the {engine} engine",
            })

    # ---------- hypotheses (never used) ----------
    proven_pairs = {f"{p}>{l['consumer']}" for l in links for p in l["producers"] if l.get("level") != INFERRED}
    hypotheses = 0
    plausible = [q for q in findings if AUTH_IN_REQUEST.search(q["input"]) and not _SELF_PROVISIONED.search(q["input"] + q["output"] + q["narrative"])]
    for p in findings:
        if str(p["v"].get("status")) == "exploited" and _PRODUCER_HINT.search(str(p["v"].get("title") or "")):
            for q in plausible:
                if q["id"] != p["id"] and f"{p['id']}>{q['id']}" not in proven_pairs:
                    hypotheses += 1

    # ---------- scenarios ----------
    # ranking / Fix first / simulation consume the R1-R3 links (server rules) and the declared links that passed their
    # structural checks (their level is decided by api/edge_verifier).
    for l in links:
        if l["kind"] == "D":            # a declared link is a step when its structural checks passed (level: verified)
            l["ranked"] = bool(l.get("valid"))
            continue
        l.setdefault("level", "observed")      # R2 already carries « inferred »
        l["ranked"] = True
    rejected_declared = [l for l in links if not l["ranked"] and l["kind"] == "D"]
    if rejected_declared:
        issues.append({"kind": "declared-links-not-used", "finding_ids": sorted({l["consumer"] for l in rejected_declared}),
                       "message": (f"{len(rejected_declared)} link(s) declared by the agent (enabled_by) are not used for paths "
                                   f"(rejected reference, withdrawn finding, status or nodes): listed with their reason.")})
    cyclic = sorted({x for l in links if l["kind"] == "D" and "cycle" in (l.get("warnings") or []) for x in (*l["producers"], l["consumer"])})
    if cyclic:
        # CONTRACT-D final-review clarification: a declared cycle is reported as a cycle; path assembly walks simple
        # paths only (no repeated finding) and each edge keeps the state of its own evidence
        issues.append({"kind": "declared-cycle", "finding_ids": cyclic,
                       "message": (f"{len(cyclic)} finding(s) form a cycle of declared links (enabled_by): the cycle is never "
                                   f"walked; paths through these findings are simple paths, each link keeps its own level.")})
    dependencies = [l for l in links if l["kind"] != "R3" and not l["auxiliary"] and l["ranked"]]
    feeds = {p for l in dependencies for p in l["producers"]}
    reaches = [l for l in links if l["kind"] == "R3"]
    reached = {l["consumer"] for l in reaches}

    def prerequisite_steps(objective: str, observed_only: bool = False) -> Tuple[List[Dict[str, Any]], Set[str], Optional[str]]:
        """Steps of the chains ending at ``objective``: bounded DFS (api/edge_verifier.bounded_chains: depth <= 6,
        at most 100 chains, time budget, stop reason) over the usable links, then the links on those chains in
        dependency order. ``observed_only``: links whose level is at least observed (R1, R3, verified declarations; never
        an R2 inference nor an unverified declaration)."""
        from api.edge_verifier import CAUSAL, bounded_chains
        usable = [d for d in dependencies if not (observed_only and d.get("level") in NOT_PROVEN_LEVELS)]
        back: Dict[str, List[str]] = {}
        for l in usable:
            for p in l["producers"]:
                back.setdefault(l["consumer"], []).append(p)
        chains, stop = bounded_chains(back, objective)
        on_chain = {(c[i + 1], c[i]) for c in chains for i in range(len(c) - 1)}
        steps: List[Dict[str, Any]] = []
        evidence: Set[str] = set()

        def visit(fid: str, stack: Set[str]) -> None:
            if len(stack) > 7:   # the chains are <= 6 links; a mix of two chains never goes deeper
                return
            for l in [d for d in usable if d["consumer"] == fid]:
                prods = [p for p in l["producers"] if (p, fid) in on_chain and p not in stack]
                alts = sorted({x for x in [*prods, *l["alternatives"]] if x not in stack})
                if not prods or not alts:
                    continue
                for p in prods:
                    visit(p, stack | {p})
                satisfied_by = [[x] for x in alts]
                if l["kind"] == "D" and l.get("level") != CAUSAL:
                    # 40-paths-v2: fixing the producer « breaks the chain » only through a demonstrated necessity; an
                    # observed or declared link keeps a way no fix is known to cut (empty AND-set, never broken)
                    satisfied_by.append([])
                if any(s["satisfied_by"] == satisfied_by for s in steps):
                    continue
                evidence.update(x for alt in satisfied_by for x in alt)
                also = f" (also reachable without it: {', '.join(l['alternatives'])})" if l["alternatives"] else ""
                steps.append({"node_id": node_of(l["producers"][0]), "satisfied_by": satisfied_by,
                              "rationale": f"{l['kind']} {l['capability']}: {l['proof']}{also}",
                              "impact": {"rule": l["kind"], "capability": l["capability"], "level": l.get("level", "observed"),
                                         **({"reason": (l.get("verification") or {}).get("reason")} if l["kind"] == "D" else {})}})

        visit(objective, {objective})
        return steps, evidence, stop

    scenarios: List[Dict[str, Any]] = []

    def push_scenario(sid: str, consumer: str, objective_node_id: str, tail: List[Dict[str, Any]], kind: str,
                      observed_only: bool = False) -> None:
        steps, evidence, stop = prerequisite_steps(consumer, observed_only)
        if not observed_only and any((s.get("impact") or {}).get("level") in NOT_PROVEN_LEVELS for s in steps):
            # 17/11 (owner): a path takes the level of its weakest step, so a chain mixing declared (or R2-inferred) and
            # server-observed steps is « declared » / « inferred » as a whole; its fully OBSERVED part is a proven path
            # of its own — shown beside it (a reach is such a part even without any observed prerequisite: its R3 step
            # is the server's own observation)
            o_steps, _, _ = prerequisite_steps(consumer, True)
            if o_steps or kind == "reach":
                push_scenario(f"{sid}-observed", consumer, objective_node_id, tail, kind, observed_only=True)
        if kind == "sink" and not steps:
            return      # no prerequisite step survived: a lone finding is not an attack path
        evidence.add(consumer)
        all_steps = steps + tail
        ids = sorted(evidence)
        crit = next((s for s in SEVERITIES if any(severity_of(by_id[x]["v"].get("severity")) == s for x in ids if x in by_id)), "info")
        scenarios.append({
            "id": sid, "entry_node_id": all_steps[0]["node_id"], "objective_node_id": objective_node_id,
            "criticality": crit, "steps": all_steps, "evidence_finding_ids": ids,
            # R2 isolation: a scenario resting on the R2 inference is « inferred » (the engine's ranking gate never
            # treats it as real); attack_paths._analyse also makes it a hypothesis record
            "provenance": INFERRED if any((s.get("impact") or {}).get("level") == INFERRED for s in all_steps) else "observed",
            "consumer": consumer, "kind": kind, "assembly": {"chains_stop": stop},
        })

    for r in reaches:
        cat = by_id[r["consumer"]]["v"].get("category")
        entry_node = node_of(r["consumer"])
        if r3_origin and r["from_node_id"] and entry_node == r["to_node_id"]:
            entry_node = r["from_node_id"]  # P7 fix 4: the exploit starts at its origin, not at the reached store
        push_scenario(f"obs-{r['consumer']}-reach-{r['to_node_id']}", r["consumer"], r["to_node_id"], [
            {"node_id": entry_node, "satisfied_by": [[r["consumer"]]], "rationale": f"exploitation of {r['consumer']} ({cat})",
             "impact": {"rule": "entry", "category": cat, "status": by_id[r["consumer"]]["v"].get("status")}},
            {"node_id": r["to_node_id"], "satisfied_by": [[r["consumer"]]], "rationale": f"R3 {r['capability']}: {r['proof']}",
             "impact": {"rule": "R3", "capability": r["capability"]}},
        ], "reach")
    sinks = sorted({l["consumer"] for l in dependencies
                    if l["consumer"] not in feeds and l["consumer"] not in reached
                    and str(by_id.get(l["consumer"], {}).get("v", {}).get("status")) in ("exploited", "confirmed")})
    for sink in sinks:
        node = node_of(sink)
        push_scenario(f"obs-{sink}", sink, node, [{"node_id": node, "satisfied_by": [[sink]],
                                                   "rationale": f"objective: {sink} exploited with the capability",
                                                   "impact": {"rule": "sink", "category": by_id[sink]["v"].get("category"), "status": by_id[sink]["v"].get("status")}}], "sink")

    if unresolved:
        issues.append({"kind": "unresolved-node", "finding_ids": sorted(unresolved),
                       "message": f"{len(unresolved)} finding(s) on a path are not attached to any infrastructure node."})
    masked = sorted(f["id"] for f in findings if AUTH_IN_REQUEST.search(f["input"]) and _MASKED_CREDENTIAL.search(f["input"]))
    if masked:
        issues.append({"kind": "masked-credentials", "finding_ids": masked,
                       "message": f"{len(masked)} finding(s) use a masked or truncated credential: where it came from cannot be proven."})

    candidates = [{
        "id": f["id"], "title": f["v"].get("title") or f["id"], "severity": severity_of(f["v"].get("severity")),
        "cvss_score": _finite(f["v"].get("cvss_score")), "node_id": attached_node(f["id"]),
        "node_ancestors": ancestors_of(attached_node(f["id"]), nodes),
    } for f in findings]
    groups = group_duplicate_findings([f["v"] for f in findings])

    # two columns on every link (docs/research/observed-paths.md): « usage » (shown in the stored evidence and checked by
    # a server rule = R1-R3; declared = D) and « necessity » (D: demonstrated only by the edge verifier's negative
    # control; R3 is an intrinsic reach; R1/R2 are not assessed)
    for l in links:
        l.setdefault("level", "observed")
        if "usage" not in l:
            l["usage"] = "evidence"
            l["necessity"] = "intrinsic" if l["kind"] == "R3" else "not_assessed"
    kind_order = {"R1": 0, "R2": 1, "R3": 2, "D": 3}
    links.sort(key=lambda l: (kind_order[l["kind"]], lc_key(l["consumer"]), lc_key(",".join(l["producers"])), lc_key(str(l["to_node_id"]))))
    scenarios.sort(key=lambda s: lc_key(s["id"]))
    rejected.sort(key=lambda r: (lc_key(r["producer"]), lc_key(r["consumer"]), r["rule"]))
    return {
        "campaign_id": campaign_id,
        "input": {"scenarios": scenarios, "findings": candidates, "groups": groups},
        "links": links, "rejected": rejected, "hypotheses": hypotheses, "issues": issues,
    }
