# Vendored from the Darkmoon redaction engine (mcp/api/evidence_redaction.py),
# distributed here under GPL-3.0 with the rest of Darkmoon Community. Used by darkmoon_explore.py to mask
# evidence before the Terminal Explorer shows it; if it cannot load, evidence is withheld (fail closed).
"""P6 (phase B1.1) — server-side redaction of every output that carries findings,
pull requests, reports or run logs.

The store keeps the raw proof (documented: P6 masks OUTPUTS, not the disk), except the
run logs (``campaign_logs/run_*.jsonl``), masked by this module BEFORE they are written
(``routes_run._append_log``, logs-privacy 17/11). Every API answer goes through this module:

* ``redact_text(s)``      one string -> (masked string, Counter of kinds)
* ``redact_obj(o)``       deep copy of a JSON value, every string masked, values
                          under secret-named keys masked as a whole
* ``redact_finding(v)``   one projection per finding (detail or list form)
* ``redact_pr(pr)``       one projection per pull request
* ``redact_event(ev)``    one decoded run-log / SSE event

A masked value becomes ``«redacted:<kind>»``. URL-encoded (twice), base64, HTML
entities, NFKC forms and zero-width characters are normalised before detection.

Performance contract (review B, H3): every pattern is linear in the text length.
Quantifiers that could be retried from many start positions are BOUNDED (key
prefixes ≤ 6 parts of ≤ 40 chars, values ≤ 1024 chars, header names ≤ 40), so a
start position costs O(1); a string longer than ``MAX_SCAN`` is replaced as a whole
(fail closed). ``tests/test_p6_redaction.py`` fuzzes 50 KB adversarial inputs.

Oracle contract (review B, H2): the store-wide "known secret" pass (a value masked
somewhere in the store is masked wherever it is repeated) only runs on STORED data
(``known=None`` → store index). The response guard uses the index MINUS every value
the request carried (``known_for_response``): a string echoed from the request is
never compared with the store.

Known-secret index (cycle 1, 18/11): store files | the SEALED index of values learned
from RAW sources before their redaction (``api.known_index``: run-log writer, MCP raw
tool output, vault secrets, legacy raw logs; SecretBox-encrypted, survives a restart)
| this process's learned values. Slot values that are never secrets (vault
placeholders, shell expansions, letters-only paths, member paths) are not indexed.
"""
from __future__ import annotations

import base64
import binascii
import copy
import html
import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import unquote

VERSION = 2
MARK = "«redacted:{}»"
_MARK_RE = re.compile(r"«redacted:[a-z0-9-]+»")
MAX_SCAN = 2_000_000   # characters; a longer single string is replaced as a whole


def _m(kind: str) -> str:
    return MARK.format(kind)


# ── patterns (all linear: see the module docstring) ───────────────────

_PEM = re.compile(
    r"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
    r"[\s\S]{0,20000}?"
    r"(?:-----END [A-Z0-9 ]{0,40}-----|\Z)")
_PUTTY = re.compile(r"PuTTY-User-Key-File-\d{1,2}:[\s\S]{0,20000}?Private-MAC: ?[0-9a-fA-F]{0,128}")

# header value: up to end of line, a quote, a literal "\n"/"\r" (escaped JSON), plus
# folded continuation lines (obs-fold: newline + space/tab). Bounded.
_HV1 = r"""(?:(?!\\[rn])[^"'`\r\n]){0,4096}"""
_HVAL = r"(" + _HV1 + r"(?:\r?\n[ \t]+" + _HV1 + r"){0,8})"
_HEADER = re.compile(
    r"""(?=[acpsxACPSX])(?:(?<![A-Za-z0-9_-])|(?<=\\[rn]))((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|"""
    r"""private-token|x-[a-z0-9-]{0,40}?(?:token|secret|api-?key|auth|session)[a-z0-9-]{0,40})(["']?[ \t]{0,8}[:=][ \t]{0,8}["']?)"""
    + _HVAL, re.I)
_SCHEME = re.compile(r"^(\s*)(bearer|basic|token|digest|negotiate|ntlm|apikey|hmac)(\s+)(.*)$", re.I | re.S)
_BEARER = re.compile(r"(?<![A-Za-z0-9])(bearer|basic)([ \t]{1,8})([A-Za-z0-9._~+/=-]{8,4096})", re.I)
_JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,4096}\.[A-Za-z0-9_-]{4,8192}\.[A-Za-z0-9_-]{0,4096}")

# secret-named key followed by ':' '=' or '=>' (query, form, YAML, INI, JSON, env, CLI, PHP)
_KEYWORD = (r"(?:password|passwd|passphrase|pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
            r"|client[_-]?secret|private[_-]?key|secret[_-]?key|auth|psk"
            r"|phpsessid|jsessionid|aspsessionid[a-z]{0,12}|laravel_session|ci_session|connect\.sid)")
# A key starts at a real word start, never inside "a-b-c" / "a.b.c" (the compound prefix covers those);
# "--password", "...Password" and an escaped "\n" before it are starts. Prefix parts: snake/kebab/dotted,
# a camelCase head ("deluxeToken"), or an UPPER env prefix glued to the keyword ("PGPASSWORD").
_KEY = (r"(?:(?<![\w/])(?<!\w[.-])|(?<=\\[rnt]))("
        r"(?:[A-Za-z0-9]{1,40}[_.-]|(?-i:[a-z][a-z0-9]{0,39}(?=[A-Z]))|(?-i:[A-Z][A-Z0-9]{0,11}(?=PASS|PWD|SECRET|TOKEN))){0,6}"
        + _KEYWORD + r"(?:[_.-][A-Za-z0-9]{1,40}){0,6})")
_KV = re.compile(
    _KEY + r"""(\\?["']?[ \t]{0,8}(?:=>|=|:(?!//))[ \t]{0,8})"""
    r"""(?:(\\?")((?:[^"\\]|\\[^"]){0,1024})\\?"|(')([^'\n]{0,1024})'|((?:(?!\\[rnt])[^\s"'&,;}<>\]\)]){1,1024}))""",
    re.I)
_URL_USERINFO = re.compile(r"(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,30}://)([^/\s:@\"'<>]{1,256}):([^/\s@\"'<>]{1,512})@", re.I)
# user:pass@host without a scheme; impacket "DOMAIN/user:pass@host"
_BARE_USERINFO = re.compile(
    r"(?<![\w/@:.%+«-])((?:[A-Za-z0-9._-]{1,64}/)?[A-Za-z0-9._%+-]{1,64}):([^\s/@:\"'<>`|]{1,128})@"
    r"(?=\[|[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}(?::\d{1,5})?(?:[/\s`'\"|)]|$))")
_AWS = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}(?![A-Z0-9])")
_GCP = re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])")
_GITHUB = re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})")
_SLACK = re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,255}")
_VENDOR = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:"
    r"[sr]k_(?:live|test)_[A-Za-z0-9]{16,255}"            # Stripe
    r"|glpat-[A-Za-z0-9_-]{20,255}"                       # GitLab
    r"|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255}"           # OpenAI / Anthropic
    r"|hv[sbr]\.[A-Za-z0-9_-]{20,255}"                    # HashiCorp Vault (new)
    r"|s\.[A-Za-z0-9]{24}(?![A-Za-z0-9])"                 # HashiCorp Vault (legacy service token)
    r"|npm_[A-Za-z0-9]{36}"
    r"|AGE-SECRET-KEY-1[A-Z0-9]{50,70}"
    r")")
_SHADOW = re.compile(r"\$(?:1|2[abxy]?|5|6|y|7|gy|sha1|md5|apr1)\$(?:rounds=\d{1,8}\$)?[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{8,512}")
_KDF = re.compile(r"(?<![\w$])(?:pbkdf2_sha(?:1|256|512)\$\d{1,8}\$[^\s$\"']{1,128}\$[A-Za-z0-9+/=]{16,512}"
                  r"|(?:scrypt|argon2(?:id|i|d)?|bcrypt)\$[^\s\"'<>]{16,512})")
_HTPASSWD_SHA = re.compile(r"\{S?SHA\}[A-Za-z0-9+/=]{8,512}")
_KRB = re.compile(r"\$krb5(?:tgs|asrep|pa|tgt)\$[^\s\"'<>]{8,16384}")
_SECRETSDUMP = re.compile(r"(?<![\w$])([^\s:\"']{1,64}):(\d{1,10}):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")
_NETNTLM = re.compile(r"(?<![\w$])([^\s:\"']{1,64})::([^\s:\"']{0,64}):([0-9a-fA-F]{16}):([0-9a-fA-F]{32,48}):([0-9a-fA-F]{16,4096})")
_HASH_KV = re.compile(r"(?i)(?<![\w-])((?:pw_?|password_?|nt_?|lm_?)?(?:hash|md5|ntlm|nthash))([ \t]{0,4}[:=][ \t]{0,4})([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])")
_PAN = re.compile(r"(?<![\d.-])(?:[3-6]\d{3})(?:[ -]?\d){9,15}(?![\d.-])")

# command lines of pentest tools: options that carry a secret, by tool
_TOOL = re.compile(
    r"(?<![\w./-])(curl|wget|hydra|medusa|ncrack|crackmapexec|cme|netexec|nxc|evil-winrm|sshpass|redis-cli"
    r"|ldapsearch|ldapwhoami|ldapmodify|ldapadd|smbclient|smbmap|rpcclient|mysql|mariadb|mysqldump|mysqladmin"
    r"|snmpwalk|snmpget|snmpbulkwalk|snmpset|onesixtyone|xfreerdp|wfreerdp|kerbrute|psql"
    r"|net|impacket-[a-z0-9]{1,20}|[a-z0-9_-]{1,20}\.py)(?![\w-])([^\n\r;|&]{0,4096})", re.I)
_OPT_VAL = r"""(?:"([^"\n]{1,512})"|'([^'\n]{1,512})'|([^\s"']{1,512}))"""
_TOOL_OPTS = {
    "pw": re.compile(r"(?:(?<=\s)|^)(-p|--pass|--password|-password)(?:[ \t]{1,8}|=)" + _OPT_VAL),
    "pw_long": re.compile(r"(?:(?<=\s)|^)(--password)(?:[ \t]{1,8}|=)" + _OPT_VAL),
    "pw_attached": re.compile(r"(?:(?<=\s)|^)(-p)(?=[^\s-])" + _OPT_VAL),
    "hash": re.compile(r"(?:(?<=\s)|^)(-H|--hash|--hashes|-hashes|-aesKey|/pth:)(?:[ \t]{1,8}|=|(?<=:))" + _OPT_VAL),
    "redis": re.compile(r"(?:(?<=\s)|^)(-a|--pass)(?:[ \t]{1,8}|=)" + _OPT_VAL),
    "ldap": re.compile(r"(?:(?<=\s)|^)(-w)(?:[ \t]{1,8})" + _OPT_VAL),
    "snmp": re.compile(r"(?:(?<=\s)|^)(-c)(?:[ \t]{1,8})" + _OPT_VAL),
    "rdp": re.compile(r"(?:(?<=\s)|^)(/p:)" + _OPT_VAL),
    "smbu": re.compile(r"(?:(?<=\s)|^)(-U[ \t]{0,8}|--user=)(\"?)([^\s%\"]{1,128})%([^\s\"]{1,256})"),
    "netuser": re.compile(r"(?i)(?:(?<=\s)|^)(user[ \t]{1,8}[^\s/]{1,64})[ \t]{1,8}" + _OPT_VAL + r"(?=[ \t]{1,8}/(?:add|domain))"),
    "wget_pw": re.compile(r"(?:(?<=\s)|^)(--http-password|--ftp-password|--proxy-password|--password)(?:[ \t]{1,8}|=)" + _OPT_VAL),
    "curl_user": re.compile(r"(?:(?<=\s)|^)(-u|--user|--proxy-user|-U)(?:[ \t]{1,8}|=)" + _OPT_VAL),
    "curl_cookie": re.compile(r"(?:(?<=\s)|^)(-b|--cookie)(?:[ \t]{1,8}|=)" + _OPT_VAL),
}
_TOOL_GATES = ("curl", "wget", "hydra", "medusa", "ncrack", "crackmapexec", "cme ", "netexec", "nxc ", "evil-winrm",
               "sshpass", "redis-cli", "ldap", "smbclient", "smbmap", "rpcclient", "mysql", "mariadb", "snmp",
               "onesixtyone", "freerdp", "kerbrute", "psql", "impacket-", ".py", "net user")
_TOOL_FAMILY = {
    "curl": ("curl_user", "curl_cookie"), "wget": ("wget_pw",),
    "hydra": ("pw",), "medusa": ("pw",), "ncrack": ("pw",), "kerbrute": ("pw",),
    "crackmapexec": ("pw", "hash"), "cme": ("pw", "hash"), "netexec": ("pw", "hash"), "nxc": ("pw", "hash"),
    "evil-winrm": ("pw", "hash"), "sshpass": ("pw", "pw_attached"), "redis-cli": ("redis",),
    "ldapsearch": ("ldap",), "ldapwhoami": ("ldap",), "ldapmodify": ("ldap",), "ldapadd": ("ldap",),
    "smbclient": ("smbu", "pw"), "smbmap": ("pw", "smbu"), "rpcclient": ("smbu",),
    "mysql": ("pw_attached", "pw_long"), "mariadb": ("pw_attached", "pw_long"), "mysqldump": ("pw_attached", "pw_long"),
    "mysqladmin": ("pw_attached", "pw_long"), "net": ("netuser",),
    "snmpwalk": ("snmp",), "snmpget": ("snmp",), "snmpbulkwalk": ("snmp",), "snmpset": ("snmp",), "onesixtyone": ("snmp",),
    "xfreerdp": ("rdp", "hash"), "wfreerdp": ("rdp", "hash"), "psql": (),
}

# protocol transcripts, forms and markup
_FTP_PASS = re.compile(r"(?:^|(?<=\n)|(?<=\\n))PASS[ \t]{1,4}([^\s\\]{1,256})", re.M)
_IMAP_LOGIN = re.compile(r"(?<![\w-])LOGIN[ \t]{1,4}(\"?[^\s\"]{1,256}\"?)[ \t]{1,4}(\"?)([^\s\"]{1,256})\2")
_AUTH_PLAIN = re.compile(r"(?<![\w-])AUTH[ \t]{1,4}(?:PLAIN|LOGIN)[ \t]{1,4}([A-Za-z0-9+/=]{4,1024})")
_MULTIPART = re.compile(
    r"""name=\\?"([^"\\\r\n]{0,64}(?:pass|pwd|secret|token|key|auth)[^"\\\r\n]{0,64})\\?"(?:\r\n|\n|\\r\\n|\\n){2}([^\r\n\\]{1,1024})""",
    re.I)
_XML = re.compile(
    r"<((?:[A-Za-z][\w.-]{0,30}:)?(?:[A-Za-z_][\w.-]{0,40}?)?(?:password|passwd|pwd|secret|token|apikey|api_key|accesskey|privatekey))"
    r"(?:\s[^<>]{0,256})?>([^<]{1,1024})</\1>", re.I)
_INPUT = re.compile(
    r"""<input\b[^<>]{0,512}?name=["']?[\w.-]{0,40}(?:pass|pwd|secret|token)[\w.-]{0,40}["']?[^<>]{0,512}?value=["']([^"'<>]{1,512})["']"""
    r"""|<input\b[^<>]{0,512}?value=["']([^"'<>]{1,512})["'][^<>]{0,512}?name=["']?[\w.-]{0,40}(?:pass|pwd|secret|token)""",
    re.I)
_SQL_IDENT = re.compile(r"(?i)\bIDENTIFIED[ \t]{1,4}(?:WITH[ \t]{1,4}\w{1,40}[ \t]{1,4})?BY[ \t]{1,4}(?:PASSWORD[ \t]{1,4})?'([^'\n]{1,512})'")

# a high-entropy value right after a secret word in prose: « Vault root token (s.Xy…) », « password: `P4ss…` »
_NEAR = re.compile(
    r"(?i)(?<![\w-])(password|passwd|pwd|passphrase|token|secret|api[ _-]?key|cookie|hash|key(?![ \t]{1,3}[a-z])|mot de passe|mdp)"
    r"(?:[ \t]{1,3}(?:is|was|of|value|set to|est|vaut))?[ \t]{0,3}[:=(`'\"«]{0,2}[ \t]{0,3}[`'\"(]?([A-Za-z0-9+/._~$!#%^*-]{8,256})")
# « credentials (admin:S3cret) », « default login postgres:postgres » (pair near a credential word)
_PAIR = re.compile(
    r"(?i)(?<![\w/.-])(credentials?|creds|identifiants?|login|logins|default[ \t]{1,3}(?:user|account|password)s?|user(?:name)?[ \t]{0,2}[:/][ \t]{0,2}pass(?:word)?)"
    r"(?:[^\n:/\\]{0,24}?)(?<![\w.«/-])([A-Za-z0-9._@-]{1,64})([ \t]{0,2}[:/][ \t]{0,2})([^\s:/)`'\"\],;«\\]{1,128})")

_GATE_HEXCOLON = re.compile(r"[0-9a-fA-F]{32}:")
_GATE_PGPASS = re.compile(r":(?:\d{1,5}|\*):[^:\s]{1,128}:[^:\s]{1,128}:")
_LINE_END = r"(?=\r?\n|\\r|\\n|$)"
_LINE_START = r"(?:^|(?<=\n)|(?<=\\n))"
_MIMIKATZ = re.compile(r"(?i)((?<![\w-])(?:NTLM|SHA1|LM|aes256_hmac|aes128_hmac|des_cbc_md5)[ \t]{0,12}:[ \t]{0,4})([0-9a-f]{32,64})(?![0-9a-f])")
_CRACKED = re.compile(_LINE_START + r"((?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|\$krb5[^\s:]{8,2048}|[^\s:]{1,64}::[^\s:]{0,64}:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{16,2048})):([^\r\n\\]{1,256})" + _LINE_END, re.M)
_JOHN = re.compile(_LINE_START + r"([^\s(]{1,128})([ \t]{2,40}\([^\s()]{1,64}\)[ \t]{0,8})" + _LINE_END, re.M)
_MSF = re.compile(r"(\d{1,5}/(?:tcp|udp)[ \t]{1,40}\(?[\w-]{1,30}\)?[ \t]{1,40}[^\s]{1,128}[ \t]{1,40})([^\s]{1,256})"
                  r"([ \t]{1,40}(?:\S{1,64}[ \t]{1,40})?(?:Password|NTLM hash|Nonreplayable hash|Replayable hash))")
_NETSH = re.compile(r"(?i)(Key Content[ \t]{0,40}:[ \t]{0,8})([^\r\n\\]{1,256})")
_PGPASS = re.compile(_LINE_START + r"((?:[^:\s\\]{1,253}):(?:\d{1,5}|\*):(?:[^:\s\\]{1,128}):(?:[^:\s\\]{1,128}):)([^\s:\\]{1,256})" + _LINE_END, re.M)
_HTTP_WORDS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "HTTP", "HTTPS"}
_REQ_LINE = re.compile(
    r"((?=[GPDHOTC])(?:^|(?<=\n)|(?<=\\n)|(?<=[\s\"']))(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)[ \t]{1,4}[^\s?#\\]{1,2048})"
    r"(\?[^\s\\]{0,4096})?([ \t]{1,4}HTTP/\d(?:\.\d)?)")
_HOST_HDR = re.compile(r"(?i)(?=[hH])(?:(?<=^)|(?<=\n)|(?<=\\n)|(?<=[\s\"']))Host:[ \t]{0,8}[A-Za-z0-9.\[\]:_-]{1,262}(?![^\s\\\"'])")
_SAFE_VALUE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<[^>]*>|\*+|x{3,}|null|none|true|false|undefined|"
    r"redacted|\[redacted[^\]]*\]|«redacted:[a-z0-9-]+»|\{\{[^}]*\}\}|%[sd]|\?|.{0,128}:\*{3})$", re.I)
_URLENC_RUN = re.compile(r"(?<![^\s\"'<>])[^\s\"'<>%]{0,4096}(?:%[0-9A-Fa-f]{2}[^\s\"'<>%]{0,4096}){1,4096}")
_GATE_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_GATE_HEADER = re.compile(r"authorization|cookie|x-[a-z0-9-]{0,40}(?:token|secret|key|auth|session)|private-token")
_GATE_KV = re.compile(r"pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|sess|auth|psk")
_GATE_PAN = re.compile(r"[3-6]\d{3}[ -]?\d")
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,8192}={0,2}(?![A-Za-z0-9+/=_-])")
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad]")
_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_CONFUSABLES = str.maketrans("аеорсухіјѕАЕОРСХІΑΕΟΡΤΧ", "aeopcyxijsAEOPCXIAEOPTX")
_CONFUSABLE_RE = re.compile("[аеорсухіјѕАЕОРСХІΑΕΟΡΤΧ]")
_ENTITY_RE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_PROSE_WORDS = {"required", "missing", "none", "empty", "other", "invalid", "expired", "not", "is", "the", "a", "an",
                "set", "unset", "changed", "reset", "disabled", "enabled", "weak", "strong", "default", "unknown",
                "optional", "provided", "present", "absent", "revoked", "valid", "denied", "refused", "ok", "yes", "no",
                "n/a", "na", "redacted", "masked", "hidden", "same", "see", "use", "must", "should"}
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "priority", "partitioned"}


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _entropy(v: str) -> float:
    n = len(v)
    return -sum(k / n * math.log2(k / n) for k in Counter(v).values()) if n else 0.0


def _credential_shaped(v: str) -> bool:
    """A value that looks like a credential rather than a word: a digit or symbol with letters, or
    mixed case, and enough entropy (« password policy », « token-based » stay)."""
    if len(v) < 8 or "«redacted:" in v:
        return False
    has_alpha = any(ch.isalpha() for ch in v)
    has_digit = any(ch.isdigit() for ch in v)
    has_sym = any(not ch.isalnum() for ch in v)
    mixed = any(ch.islower() for ch in v) and any(ch.isupper() for ch in v[1:])
    return has_alpha and (has_digit or (mixed and has_sym) or (mixed and len(v) >= 12)) and _entropy(v) >= 2.8


def _safe(value: str) -> bool:
    v = value.strip().strip("\"'")
    # a value that IS a marker (or a set-aside marker) is safe; one that merely CONTAINS one is not
    return (not v or "\x00" in v or "«redacted:" in v or v.startswith("redacted:")
            or bool(_SAFE_VALUE.match(v)))


class Hits(Counter):
    """A Counter of masked kinds that also remembers the masked VALUES (in memory
    only) so that the same value repeated elsewhere without its context ("the
    cookie 'abc123…'") is masked too."""
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.known = set()


_PASSWORD_KINDS = {"password", "credentials", "url-credentials", "basic-auth", "secret-field"}


def _hit(c: Counter, kind: str, value: str) -> None:
    c[kind] += 1
    known = getattr(c, "known", None)
    if known is not None and value:
        v = str(value).strip().strip("\"'")
        if _knownable(v, kind in _PASSWORD_KINDS):
            known.add(v)


# well-known identifiers that appear as « values » (cookie names, storage APIs, header names, labels):
# never indexed, whatever their shape (review B2, N1)
_NOT_KNOWN = {w.lower() for w in (
    "PHPSESSID", "JSESSIONID", "ASPSESSIONID", "ASP.NET_SessionId", "connect.sid", "laravel_session", "ci_session",
    "XSRF-TOKEN", "X-XSRF-TOKEN", "csrftoken", "csrf_token", "_csrf", "__RequestVerificationToken", "sessionid",
    "localStorage", "sessionStorage", "document.cookie", "Browser-Validated", "HttpOnly", "SameSite", "Secure",
    "Bearer", "Basic", "Authorization", "Set-Cookie", "access_token", "refresh_token", "id_token", "api_key",
    "password", "Password1", "changeme", "undefined", "null", "true", "false")}


# Values a secret SLOT can hold that are never secrets themselves (cycle 1, 18/11: the 7 values the API served
# « bare » while they were in the index — closure 53, LOGS-MIGRATION §5 — were all of these shapes):
# * a privacy-vault placeholder (« password=CRED_001 »): what the model saw, numbered per run, public by design;
# * a shell expansion (« PASSWORD=$(cat … », « ${DB_PASS} »): the command, not the value;
# * an absolute URL path of letters only (« "reset-password-flow": "/rest/user/reset-password" »);
# * a lower-case dotted member path (« password: req.body », « password:.data »): source code / jq, not a value.
# Inside its slot such a value is still masked by the slot rule; it only stops being hunted everywhere else.
try:   # the vault's own categories (exact prefixes: « ADMIN_PASS_123 » is not a placeholder)
    from src.privacy.vault import _PREFIXES as _VAULT_PREFIXES
except Exception:  # pragma: no cover - an API-only process without the MCP tree
    _VAULT_PREFIXES = "CRED|USER|IP_PRIVATE|IP_PUBLIC|DOMAIN|URL|EMAIL|HOST"
_PLACEHOLDER_SHAPE = re.compile(rf"(?:{_VAULT_PREFIXES})_\d{{3,}}")
_SHELL_EXPANSION = re.compile(r"(?:\$[({]|`).*")
_LETTER_PATH = re.compile(r"(?:/[A-Za-z_~-]+(?:\.[A-Za-z]+)?){2,}/?")
_MEMBER_PATH = re.compile(r"\.?[a-z_$][a-z_$]*(?:\.[a-z_$][a-z_$]*)*")


def not_a_secret_value(v: str) -> bool:
    """A slot value that is never hunted elsewhere (placeholder, shell expansion, letters-only path, member path)."""
    return bool(_PLACEHOLDER_SHAPE.fullmatch(v.strip("[](){}<>\"'`*_")) or _SHELL_EXPANSION.match(v)
                or _LETTER_PATH.fullmatch(v) or ("." in v and _MEMBER_PATH.fullmatch(v)))


def _knownable(v: str, password: bool = False) -> bool:
    """A value worth hunting elsewhere (review B2, N1): a real secret shape — letters AND digits (≥ 6 chars),
    or ≥ 12 chars with ≥ 3.5 bits/char — never a bare identifier (« localStorage », « XSRF-TOKEN »), never a
    well-known name. A plain word or an identifier would mask ordinary prose everywhere."""
    if not (6 <= len(v) <= 4096) or "«redacted:" in v or any(ch.isspace() for ch in v):
        return False
    if v.lower() in _NOT_KNOWN or not_a_secret_value(v):
        return False
    if password:
        # a value found in a PASSWORD slot (password=, user:pass@, -u u:p) is a secret even when it is a
        # plain word ("SummerPassword"): indexed if it is not a common word of the denylist
        return len(v) >= 8 or any(ch.isdigit() for ch in v)
    if re.fullmatch(r"[A-Za-z][A-Za-z_.-]*", v):
        return False
    has_alpha = any(ch.isalpha() for ch in v)
    has_digit = any(ch.isdigit() for ch in v)
    return (has_alpha and has_digit) or (len(v) >= 12 and _entropy(v) >= 3.5)


_TOKEN_RUN = re.compile(r"[^\s\"'`<>()\[\]{},;|]{6,4096}")


def apply_known(s: str, known, c: Optional[Counter] = None) -> str:
    """Mask every exact occurrence of a known secret value (token-run lookup, O(n)).
    STORED data only (see the oracle contract in the module docstring)."""
    if not known or not s:
        return s

    def fine(part: str) -> str:
        """A part not in the index as a whole: the same value glued to a short option (« -pS3cret »), to a query /
        fragment mark or between punctuation (« ?S3cret », « #S3cret! ») — cycle 1, 18/11."""
        m = _GLUED.fullmatch(part)
        if m and m.group(2) in known:
            return m.group(1) + _m("known-secret") + m.group(3)
        sub = re.split(r"([?#!+])", part)
        if len(sub) > 1 and any(x in known for x in sub):
            return "".join(_m("known-secret") if x in known else x for x in sub)
        return part

    def run(m):
        tok = m.group(0)
        if tok in known:
            if c is not None:
                c["known-secret"] += 1
            return _m("known-secret")
        if not any(ch in tok for ch in "=:&/@\\"):
            stripped = tok.rstrip(".!?:")
            if stripped != tok and stripped in known:
                if c is not None:
                    c["known-secret"] += 1
                return _m("known-secret") + tok[len(stripped):]
            out = fine(tok)
            if out != tok and c is not None:
                c["known-secret"] += 1
            return out
        parts = re.split(r"(\\[rnt]|[=:&/@\\])", tok)   # also at escaped line breaks (« pass\\nnext »)
        changed = False
        for i, part in enumerate(parts):
            if part in known:
                parts[i] = _m("known-secret")
                changed = True
            elif len(part) > 6:
                f = fine(part)
                if f != part:
                    parts[i] = f
                    changed = True
        if changed and c is not None:
            c["known-secret"] += 1
        return "".join(parts) if changed else tok
    return _TOKEN_RUN.sub(run, s)


# a value glued to a short option or wrapped in punctuation: « -pS3cret », « ?S3cret. », « .S3cret! »
_GLUED = re.compile(r"(-[A-Za-z]|[?#!.+~*]{1,2}|)(.{6,4096}?)([?#!.:+~*]{0,2})")


def _cookie_value(value: str, c: Counter) -> str:
    """Cookie / Set-Cookie value: every cookie value masked, attributes (Path, Domain…) kept; a first
    segment without '=' (« Set-Cookie: abc123; Path=/ ») is the value itself."""
    segs = value.split(";")
    out = []
    for i, seg in enumerate(segs):
        if "=" in seg:
            name, _, val = seg.partition("=")
            if name.strip().lower() in _COOKIE_ATTRS or _safe(val):
                out.append(seg)
            else:
                _hit(c, "cookie", val.strip())
                out.append(f"{name}={_m('cookie')}")
        elif i == 0 and seg.strip() and seg.strip().lower() not in _COOKIE_ATTRS and not _safe(seg) \
                and not re.fullmatch(r"[A-Za-z_][A-Za-z_.-]*", seg.strip()) and " " not in seg.strip():
            lead = seg[: len(seg) - len(seg.lstrip())]
            _hit(c, "cookie", seg.strip())
            out.append(lead + _m("cookie"))
        else:
            out.append(seg)
    # a Cookie header can also separate pairs with ","
    return ";".join(out)


def _header_value(name: str, value: str, c: Counter) -> str:
    if not value.strip() or _safe(value):
        return value
    lname = name.lower()
    if "cookie" in lname:
        return _cookie_value(value, c)
    sm = _SCHEME.match(value)
    if sm and sm.group(4).strip():
        kind = "basic-auth" if sm.group(2).lower() == "basic" else "authorization"
        cred = (re.split(r"(\s)", sm.group(4), maxsplit=1) + ["", ""])[0]
        rest = sm.group(4)[len(cred):]
        if _safe(cred):
            return value
        _hit(c, kind, cred)
        # only the credential token; what follows on the line goes through the other patterns
        return f"{sm.group(1)}{sm.group(2)}{sm.group(3)}{_m(kind)}{rest}"
    v = value.strip()
    if " " in v or (len(v) < 8 and not any(ch.isdigit() for ch in v)):
        return value   # prose (« authorization: before applying the update… »), not a header value
    _hit(c, "authorization" if "auth" in lname else "api-key", v)
    lead = value[: len(value) - len(value.lstrip())]
    return lead + _m("authorization" if "auth" in lname else "api-key")


def _tool_args(tool: str, args: str, c: Counter) -> str:
    fam = _TOOL_FAMILY.get(tool.lower())
    if fam is None:   # impacket-* and *.py scripts: hashes and -p
        fam = ("hash", "pw")
    for name in fam:
        def sub(m, name=name):
            if name == "smbu":
                if _safe(m.group(4)):
                    return m.group(0)
                _hit(c, "credentials", m.group(4))
                return f"{m.group(1)}{m.group(2)}{m.group(3)}%{_m('credentials')}"
            vi = 2 if m.group(2) is not None else 3 if m.group(3) is not None else 4
            val = m.group(vi)
            head, tail = m.group(0)[: m.start(vi) - m.start()], m.group(0)[m.end(vi) - m.start():]
            if _safe(val):
                return m.group(0)
            if name == "curl_user":
                if ":" not in val:
                    return m.group(0)   # « -u admin »: a user name, the password is prompted
                user, _, pw = val.partition(":")
                if _safe(pw):
                    return m.group(0)
                _hit(c, "credentials", pw)
                return f"{head}{user}:{_m('credentials')}{tail}"
            kind = {"hash": "password-hash", "curl_cookie": "cookie", "snmp": "credentials"}.get(name, "password")
            if name == "curl_cookie" and "=" in val:
                return head + _cookie_value(val, c) + tail
            _hit(c, kind, val)
            return f"{head}{_m(kind)}{tail}"
        args = _TOOL_OPTS[name].sub(sub, args)
    return args


_PEM_HEAD = re.compile(r"-----[ ]?BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)[ ]?-----"
                       r"|PuTTY-User-Key-File-\d{1,2}:")
_PEM_END = re.compile(r"-----[ ]?END [A-Z0-9 ]{0,40}[ ]?-----|Private-MAC: ?[0-9a-fA-F]{0,128}")


def _pem_blocks(s: str, c: Counter) -> str:
    """Private-key blocks, linear: from each BEGIN to its END (or to the next BEGIN / end of text when the
    block is cut short). A text with many BEGINs is scanned once (review B H3)."""
    out, pos = [], 0
    for m in _PEM_HEAD.finditer(s):
        if m.start() < pos:
            continue
        nxt = _PEM_HEAD.search(s, m.end())
        nxt = nxt.start() if nxt else -1
        limit = len(s) if nxt < 0 else nxt
        e = _PEM_END.search(s, m.end(), limit)
        stop = e.end() if e else limit
        out.append(s[pos:m.start()])
        out.append(_m("private-key"))
        c["private-key"] += 1
        pos = stop
    out.append(s[pos:])
    return "".join(out)


def _core(s: str, c: Counter) -> str:
    """One pass of every pattern on a decoded string. Each pattern is gated by a
    cheap literal test on the lowercased text (perf: 200 KB proof, plan <= 20 ms)."""
    # markers already in the text are set aside: no pattern may re-mask « «redacted:x» »
    kept: list = []

    def keep(text: str) -> str:
        kept.append(text)
        return f"\x00{len(kept) - 1}\x00"
    if "«redacted:" in s:
        s = _MARK_RE.sub(lambda m: keep(m.group(0)), s)
    # an HTTP request line (method, path, version) and a Host header are never credentials (review B2 follow-up):
    # set aside, only the query string of the request line goes through the patterns
    if " HTTP/" in s or "\tHTTP/" in s:   # a request line has « <path> HTTP/x »; a response line starts with it
        s = _REQ_LINE.sub(lambda m: keep(m.group(1)) + (m.group(2) or "") + keep(m.group(3)), s)
    if "ost:" in s or "OST:" in s:
        s = _HOST_HDR.sub(lambda m: keep(m.group(0)), s)
    s = _core_patterns(s, c)
    if "«redacted:«" in s or "«redacted:redacted:" in s:   # never a broken marker (review B2, N4)
        s = re.sub(r"«redacted:(?:«redacted:|redacted:)+", "«redacted:", s)
        s = re.sub(r"(«redacted:[a-z0-9-]+»)»+", r"\1", s)
    if kept:
        s = re.sub("\x00(\\d+)\x00", lambda m: kept[int(m.group(1))], s)
    return s


def _key_fragments(s: str, c: Counter) -> str:
    """Production readiness: the at-rest engine reuses the LLM-side key detectors (``src.privacy.keyblocks``) for the
    renderings it had no pattern for: a key TAIL (``tail id_rsa``: END marker, no BEGIN), a key torn by terminal
    wrapping, a headerless OpenSSH body. Gated by cheap literals; any error leaves the text to the other patterns."""
    if "\n" not in s and "-----END" not in s and "b3BlbnNzaC1rZXktdjE" not in s:
        return s
    try:
        from src.privacy import keyblocks as _kb
        spans = (_kb.find_key_tails(s) + _kb.find_wrapped_private_keys(s) + _kb.find_headerless_openssh(s)
                 + _kb.find_bare_key_rows(s))
    except Exception:  # noqa: BLE001 — the other patterns still run
        return s
    floor = len(s) + 1
    for a, b, value in sorted({(a, b, v) for a, b, v in spans}, key=lambda t: (-t[0], -t[1])):
        if a < b <= floor and "«redacted:" not in s[a:b]:
            _hit(c, "private-key", value)
            s = s[:a] + _m("private-key") + s[b:]
            floor = a
    return s


def _core_patterns(s: str, c: Counter) -> str:
    low = s.lower()
    has = low.__contains__

    def whole(kind):
        def f(m):
            _hit(c, kind, m.group(0))
            return _m(kind)
        return f

    if has("begin") or has("putty-user-key-file"):
        s = _pem_blocks(s, c)
    s = _key_fragments(s, c)

    if _GATE_HEADER.search(low):
        s = _HEADER.sub(lambda m: m.group(1) + m.group(2) + _header_value(m.group(1), m.group(3), c), s)

    if "eyJ" in s:
        s = _JWT.sub(whole("jwt"), s)

    def bearer(m):
        tok = m.group(3)
        if _safe(tok):
            return m.group(0)
        # prose ("Bearer authentication"): a credential has a digit, a symbol or mixed case
        if not (re.search(r"[\d._~+/=-]", tok) or (re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok[1:]))):
            return m.group(0)
        kind = "basic-auth" if m.group(1).lower() == "basic" else "authorization"
        _hit(c, kind, tok)
        return f"{m.group(1)}{m.group(2)}{_m(kind)}"
    if has("bearer") or has("basic"):
        s = _BEARER.sub(bearer, s)

    def userinfo(m):
        if _safe(m.group(3)):
            return m.group(0)
        _hit(c, "url-credentials", m.group(3))
        return f"{m.group(1)}{m.group(2)}:{_m('url-credentials')}@"
    if has("://"):
        s = _URL_USERINFO.sub(userinfo, s)

    def bare_userinfo(m):  # user:pass@host without a scheme (report tables, impacket targets)
        if _safe(m.group(2)) or m.group(1).lower() in ("mailto", "http", "https"):
            return m.group(0)
        _hit(c, "url-credentials", m.group(2))
        return f"{m.group(1)}:{_m('url-credentials')}@"
    if has("@"):
        s = _BARE_USERINFO.sub(bare_userinfo, s)

    if any(map(has, _TOOL_GATES)):
        s = _TOOL.sub(lambda m: m.group(1) + _tool_args(m.group(1), m.group(2), c), s)

    def kv(m):
        key, sep = m.group(1), m.group(2)
        if m.group(3) is not None:
            q, val, end = m.group(3), m.group(4), m.group(3)
        elif m.group(5) is not None:
            q, val, end = "'", m.group(6), "'"
        else:
            q, val, end = "", m.group(7), ""
        if _safe(val):
            return m.group(0)
        lk = key.lower()
        # prose / messages: « token: other campaign », « password: required »
        if not q and ":" in sep and (val.lower() in _PROSE_WORDS or (
                re.fullmatch(r"[a-z]{1,12}", val) and re.match(r" [a-z]", m.string[m.end():m.end() + 2]))):
            return m.group(0)
        # "auth" alone is too common in prose ("auth: required"): only as a compound key.
        if re.fullmatch(r"auth", lk) and ":" in sep:
            return m.group(0)
        # a token / key VALUE is high-entropy: code (« localStorage.getItem( ») or a bare label
        # (« Browser-Validated ») is not one (a password can be a plain word: still masked)
        if not q and not re.search(r"pass|pwd|secret", lk) and (
                "(" in val or re.fullmatch(r"[A-Za-z_$][A-Za-z_$-]*(?:\.[A-Za-z_$][\w$]*)*\(?", val)):
            return m.group(0)
        kind = ("token" if re.search(r"token|session|sessid", lk) else
                "api-key" if re.search(r"api|access|key", lk) else
                "secret" if "secret" in lk else "password")
        _hit(c, kind, val)
        return f"{key}{sep}{q}{_m(kind)}{end}"
    if _GATE_KV.search(low):
        s = _KV.sub(kv, s)

    def multipart(m):
        if _safe(m.group(2)):
            return m.group(0)
        _hit(c, "password", m.group(2))
        return m.group(0)[: m.start(2) - m.start()] + _m("password")
    if has("name=") and (has("pass") or has("secret") or has("token") or has("key") or has("auth") or has("pwd")):
        s = _MULTIPART.sub(multipart, s)
        s = _INPUT.sub(lambda m: (lambda g, i: (m.group(0) if _safe(g) else (_hit(c, "password", g), m.group(0)[: m.start(i) - m.start()] + _m("password") + m.group(0)[m.end(i) - m.start():])[1]))(m.group(1) or m.group(2), 1 if m.group(1) else 2), s)
    if "<" in s:
        s = _XML.sub(lambda m: m.group(0) if _safe(m.group(2)) else (_hit(c, "password", m.group(2)), m.group(0)[: m.start(2) - m.start()] + _m("password") + m.group(0)[m.end(2) - m.start():])[1], s)
    if has("identified"):
        s = _SQL_IDENT.sub(lambda m: m.group(0) if _safe(m.group(1)) else (_hit(c, "password", m.group(1)), m.group(0)[: m.start(1) - m.start()] + _m("password") + "'")[1], s)
    if "PASS" in s:
        s = _FTP_PASS.sub(lambda m: m.group(0) if _safe(m.group(1)) else (_hit(c, "password", m.group(1)), m.group(0)[: m.start(1) - m.start()] + _m("password"))[1], s)
    if "LOGIN" in s:
        s = _IMAP_LOGIN.sub(lambda m: m.group(0) if _safe(m.group(3)) else (_hit(c, "password", m.group(3)), m.group(0)[: m.start(3) - m.start()] + _m("password") + m.group(2))[1], s)
    if "AUTH" in s:
        s = _AUTH_PLAIN.sub(lambda m: (_hit(c, "credentials", m.group(1)), m.group(0)[: m.start(1) - m.start()] + _m("credentials"))[1], s)

    for rx, kind, gate in ((_AWS, "aws-key", ("akia", "asia", "agpa", "aida", "aroa")), (_GCP, "gcp-key", ("aiza",)),
                           (_GITHUB, "github-token", ("gh", "github_pat_")), (_SLACK, "slack-token", ("xox",)),
                           (_VENDOR, "api-key", ("sk_", "rk_", "glpat-", "sk-", "hvs.", "hvb.", "hvr.", "s.", "npm_", "age-secret")),
                           (_SHADOW, "password-hash", ("$",)), (_KDF, "password-hash", ("pbkdf2", "scrypt$", "argon2", "bcrypt$")),
                           (_KRB, "kerberos-hash", ("$krb5",)), (_HTPASSWD_SHA, "password-hash", ("{sha}", "{ssha}"))):
        if any(map(has, gate)):
            s = rx.sub(whole(kind), s)

    if ":::" in s:
        s = _SECRETSDUMP.sub(lambda m: (_hit(c, "password-hash", m.group(4)), f"{m.group(1)}:{m.group(2)}:{_m('password-hash')}:{_m('password-hash')}:::")[1], s)
    if "::" in s:
        s = _NETNTLM.sub(lambda m: (_hit(c, "password-hash", m.group(4)), f"{m.group(1)}::{m.group(2)}:{_m('password-hash')}")[1], s)
    if has("hash") or has("md5") or has("ntlm"):
        s = _HASH_KV.sub(lambda m: (_hit(c, "password-hash", m.group(3)), f"{m.group(1)}{m.group(2)}{_m('password-hash')}")[1], s)

    def near(m):
        val = m.group(2).rstrip(".,;:)`'\"»")
        # prose: a value needs letters AND digits (« localStorage », « Browser-Validated » are words)
        if not _credential_shaped(val) or _safe(val) or not any(ch.isdigit() for ch in val):
            return m.group(0)
        c["secret"] += 1   # prose: counted, never indexed (N1)
        start = m.start(2) - m.start()
        return m.group(0)[:start] + _m("secret") + m.group(0)[start + len(val):]
    if any(map(has, ("pass", "pwd", "token", "secret", "key", "cookie", "hash", "mot de passe", "mdp"))):
        s = _NEAR.sub(near, s)

    def pair(m):
        user, sep, pw = m.group(2), m.group(3), m.group(4)
        after = m.string[m.end():m.end() + 1]
        if _safe(pw) or (pw.isdigit() and len(pw) <= 5) or len(pw) < 4 or pw[0] in "\\\"'" \
                or user.lower() in ("user", "username", "login", "password", "pass", "redacted") \
                or user.upper() in _HTTP_WORDS or re.fullmatch(r"\d+(?:\.\d+)*", pw):
            return m.group(0)
        # « a/b » is a pair only when it is not a PATH: no spaces around the slash, nothing path-like after
        if "/" in sep and (sep.strip() != "/" or after in ("/", "?", "#") or after.isalnum()):
            return m.group(0)
        c["credentials"] += 1   # prose: counted, never indexed (N1)
        return m.group(0)[: m.start(4) - m.start()] + _m("credentials")
    if any(map(has, ("cred", "identifiant", "login", "default", "user"))):
        s = _PAIR.sub(pair, s)

    # N6: cracking output, mimikatz, metasploit creds, netsh wlan, .pgpass
    if any(map(has, ("ntlm", "sha1", "aes256", "aes128"))):
        s = _MIMIKATZ.sub(lambda m: m.group(1) + (_hit(c, "password-hash", m.group(2)) or _m("password-hash")), s)
    if "::" in s or "$krb5" in low or _GATE_HEXCOLON.search(s):
        s = _CRACKED.sub(lambda m: m.group(0) if _safe(m.group(2)) else
                         (_hit(c, "password-hash", m.group(1)) or _m("password-hash")) + ":"
                         + (_hit(c, "password", m.group(2)) or _m("password")), s)
    if _GATE_PGPASS.search(s):
        s = _PGPASS.sub(lambda m: m.group(0) if _safe(m.group(2)) else
                        m.group(1) + (_hit(c, "password", m.group(2)) or _m("password")), s)
    if "(" in s:
        s = _JOHN.sub(lambda m: m.group(0) if _safe(m.group(1)) else
                      (_hit(c, "password", m.group(1)) or _m("password")) + m.group(2), s)
    if "/tcp" in s or "/udp" in s:
        s = _MSF.sub(lambda m: m.group(0) if _safe(m.group(2)) else
                     m.group(1) + (_hit(c, "password", m.group(2)) or _m("password")) + m.group(3), s)
    if has("key content"):
        s = _NETSH.sub(lambda m: m.group(0) if _safe(m.group(2)) else
                       m.group(1) + (_hit(c, "password", m.group(2)) or _m("password")), s)

    def pan(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            c["pan"] += 1
            return _m("pan")
        return m.group(0)
    if _GATE_PAN.search(s):
        s = _PAN.sub(pan, s)
    return s


def _decoded_layers(s: str, c: Counter) -> str:
    """URL-encoded (twice), HTML-entity, NFKC / zero-width and base64 forms: a form whose
    decoded text carries a secret is replaced by its masked decoded form (one marker for base64)."""
    def url_run(m):
        run = m.group(0)
        dec = run
        for _ in range(2):   # %253D: double encoding
            try:
                nxt = unquote(dec)
            except Exception:
                break
            if nxt == dec:
                break
            dec = nxt
        if dec == run:
            return run
        sub = Counter()
        red = _core(dec, sub)
        if red == dec:
            return run
        c.update(sub)
        return red

    if _GATE_PCT.search(s):
        s = _URLENC_RUN.sub(url_run, s)

    # whole-string variants: HTML entities (&#61;), NFKC (full-width "＝", homoglyph keys), zero-width chars
    def norm(t: str) -> str:
        t = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", t))
        return t.translate(_CONFUSABLES) if _CONFUSABLE_RE.search(t) else t
    for variant in (lambda t: html.unescape(t) if _ENTITY_RE.search(t) else t,
                    lambda t: _UESC.sub(lambda m: chr(int(m.group(1), 16)), t) if "\\u" in t else t,
                    norm):
        v = variant(s)
        if v != s:
            sub = Counter()
            red = _core(v, sub)
            if red != v:
                c.update(sub)
                s = red

    def b64_run(m):
        run = m.group(0)
        raw = run.replace("-", "+").replace("_", "/")
        try:
            dec = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return run
        if not dec or sum(ch.isprintable() or ch in "\r\n\t" for ch in dec) < 0.95 * len(dec):
            return run
        sub = Counter()
        if _core(dec, sub) == dec and not re.fullmatch(r"[^:\s]{1,128}:[^\s]{1,256}", dec):
            return run
        c["encoded-secret"] += 1
        return _m("encoded-secret")

    return _B64_RUN.sub(b64_run, s)


def redact_text(value: Any, counter: Optional[Counter] = None, *, known=None) -> Tuple[str, Counter]:
    """``known=None``: STORED data, the store-wide known-secret index applies.
    ``known=frozenset()``: anything echoed from a request (the response guard)."""
    c = counter if counter is not None else Counter()
    s = value if isinstance(value, str) else str(value)
    if not s:
        return s, c
    if len(s) > MAX_SCAN:
        c["oversize"] += 1
        return _m("oversize"), c
    out = _core(s, c)
    out = _decoded_layers(out, c)
    out = apply_known(out, store_known() if known is None else known, c)
    return out, c


# ── store-wide known secrets ──────────────────────────────────────────
# Values the engine masks in the stored findings / PRs / campaigns (in memory only,
# never written or served). A value quoted again elsewhere without its header or
# key ("the session cookie 'abc123…'", a hash reused in a report table) is masked
# by exact match. Rebuilt when a store file changes (checked at most once a second);
# a rebuild runs once at a time and readers keep the previous index meanwhile.
import threading as _threading
import time as _time

_KNOWN_LOCK = _threading.Lock()
_KNOWN_CACHE = {"sig": None, "values": frozenset(), "store": frozenset(), "checked": 0.0}


def _store_files():
    try:
        from api.json_storage import CAMPAIGNS_DIR, VULNERABILITIES_DIR, store_files
    except Exception:  # pragma: no cover
        return []
    dirs = [VULNERABILITIES_DIR, CAMPAIGNS_DIR]
    try:  # pull-request records exist only where the remediation store is installed
        from api.pr_store import PULL_REQUESTS_DIR
        dirs.insert(1, PULL_REQUESTS_DIR)
    except Exception:
        pass
    out = []
    for d in dirs:
        try:
            out += store_files(d)   # never follows a planted symlink out of the store (H1)
        except OSError:
            continue
    try:   # reports and run logs hold the same secrets, sometimes in a form recognised only there
        from api.json_storage import REPORTS_DIR, DATA_DIR
        out += store_files(REPORTS_DIR, "*.md")
        out += [f for f in store_files(DATA_DIR / "campaign_logs", "*.jsonl") if f.stat().st_size <= 20_000_000]
    except Exception:
        pass
    return out


def _sealed_known() -> Tuple[frozenset, Any]:
    """The sealed index of values learned from RAW sources (``api.known_index``) and its file signature."""
    try:
        from api import known_index
        vals = known_index.load()
        return vals, known_index._sig(known_index.path())
    except Exception:  # pragma: no cover - never break a reader
        return frozenset(), None


def store_known() -> frozenset:
    """The known-secret index: values learned from the store files (rebuilt when one changes) | the sealed index of
    values learned from RAW sources (re-read when the sealed file changes) | this process's learned values."""
    now = _time.monotonic()
    if now - _KNOWN_CACHE["checked"] < 1.0:
        return _KNOWN_CACHE["values"]
    first = _KNOWN_CACHE["sig"] is None
    # never make a reader wait for a rebuild run by someone else (H3): use the previous index
    if not _KNOWN_LOCK.acquire(blocking=first):
        return _KNOWN_CACHE["values"]
    try:
        files = _store_files()
        sig = []
        for f in files:
            try:
                st = f.stat()
                sig.append((str(f), st.st_mtime_ns, st.st_size))
            except OSError:
                continue
        sig = tuple(sig)
        if sig != _KNOWN_CACHE["sig"]:
            import json as _json
            hits = Hits()
            log_hits = Hits()   # values learned from run logs: the only RAW source that gets masked (at write / by
            for f in files:     # the migration), so they are sealed before the log can lose them (cycle 1, 18/11)
                try:
                    text = f.read_text(encoding="utf-8")
                    if f.suffix == ".md":
                        redact_text(text, hits, known=frozenset())
                        continue
                    if f.suffix == ".jsonl":
                        for line in text.splitlines():
                            try:
                                redact_obj(_json.loads(line), log_hits, known=frozenset())
                            except ValueError:
                                redact_text(line, log_hits, known=frozenset())
                        continue
                    data = _json.loads(text)
                except (OSError, ValueError):
                    continue
                redact_obj(data, hits, known=frozenset())
            if log_hits.known:
                try:
                    from api import known_index
                    known_index.add(log_hits.known)
                except Exception:  # pragma: no cover
                    pass
            _KNOWN_CACHE["store"] = frozenset(hits.known) | frozenset(log_hits.known)
            _KNOWN_CACHE["sig"] = sig
        sealed, _ = _sealed_known()
        _KNOWN_CACHE["values"] = _KNOWN_CACHE.get("store", frozenset()) | sealed | frozenset(_WRITTEN_KNOWN)
        _KNOWN_CACHE["checked"] = _time.monotonic()
        return _KNOWN_CACHE["values"]
    finally:
        _KNOWN_LOCK.release()


# Values learned from a RAW source before its redaction (the run-log writer ``routes_run._at_rest``, the MCP
# ``execute_command`` hook, the vault's secrets): the masked log can no longer feed the index above, so they join it
# here AND the sealed index (``api.known_index``, SecretBox-encrypted, survives a restart; cycle 1, 18/11 — the
# in-memory-only set lost them at every restart). Bounded.
_WRITTEN_KNOWN: set = set()
WRITTEN_KNOWN_MAX = 100_000


def learn_known(value: Any) -> int:
    """Run the engine over a RAW value (a tool output, a command, an event) only to LEARN the secrets it holds, and
    seal them. Nothing is returned to anyone but a count. Never raises."""
    try:
        hits = Hits()
        if isinstance(value, str):
            redact_text(value, hits, known=frozenset())
        else:
            redact_obj(value, hits, known=frozenset())
        return remember_known(hits.known)
    except Exception:  # pragma: no cover - learning never breaks a caller
        return 0


def remember_known(values: Iterable[str]) -> int:
    vals = {v for v in values if isinstance(v, str) and _knownable(v, True)}
    new = {v for v in vals if v not in _WRITTEN_KNOWN}
    if new and len(_WRITTEN_KNOWN) + len(new) <= WRITTEN_KNOWN_MAX:
        _WRITTEN_KNOWN.update(new)
        _KNOWN_CACHE["values"] = _KNOWN_CACHE["values"] | frozenset(new)
    if not vals:
        return 0
    try:
        from api import known_index
        return known_index.add(vals)
    except Exception:  # pragma: no cover
        return 0


def known_snapshot() -> frozenset:
    """The last built known-secret index, without rebuilding it from the store (a per-event writer must not re-read
    the store, which its own writes keep changing) | the sealed index (a stat, re-read only when it changed)."""
    sealed, ssig = _sealed_known()
    base = _KNOWN_CACHE["values"]
    if not sealed:
        return base
    snap = _KNOWN_CACHE.get("snap")
    if snap and snap[0] is base and snap[1] == ssig:
        return snap[2]
    out = base | sealed
    _KNOWN_CACHE["snap"] = (base, ssig, out)
    return out


def reset_known_cache() -> None:
    """Forget the in-process index (tests, a data-dir switch). The sealed file is untouched (it is re-read)."""
    _WRITTEN_KNOWN.clear()
    _KNOWN_CACHE.update(sig=None, values=frozenset(), store=frozenset(), checked=0.0)
    try:
        from api import known_index
        known_index.reset_cache()
    except Exception:  # pragma: no cover
        pass


def echo_candidates(*texts: str) -> set:
    """Every string ``apply_known`` could compare with the index in ``texts`` (token runs, their parts, glued and
    punctuation variants), URL-decoded too. The response guard removes them from the index: a value the CALLER sent
    is never masked because it is in the store, so the answer cannot be used as an oracle (H2)."""
    out: set = set()
    for t in texts:
        if not t:
            continue
        for s in {t, unquote(t), unquote(unquote(t))}:
            for m in _TOKEN_RUN.finditer(s):
                tok = m.group(0)
                out.add(tok)
                out.add(tok.rstrip(".!?:"))
                for part in re.split(r"(?:\\[rnt]|[=:&/@\\?#!+])", tok):
                    if part:
                        out.add(part)
                        g = _GLUED.fullmatch(part)
                        if g:
                            out.add(g.group(2))
    return out


def known_for_response(request_texts: Iterable[str]) -> frozenset:
    """The store index for an API answer, minus every value the request itself carried (cycle 1, 18/11: the guard
    used ``frozenset()``, so a route that did not project its answer served known values bare)."""
    known = store_known()
    if not known:
        return known
    echo = echo_candidates(*request_texts)
    return known - echo if echo & known else known


def mask(value: Any, *, known=None) -> str:
    return redact_text(value, known=known)[0]


# ── objects ───────────────────────────────────────────────────────────

# key → words (camelCase, snake, kebab, dotted)
_SECRET_LAST = {"password", "passwd", "passphrase", "pass", "pwd", "secret", "token", "tokens", "apikey", "cookie",
                "cookies", "credential", "credentials", "creds", "jwt", "authorization", "ntlm", "nthash", "lmhash",
                "phpsessid", "jsessionid", "passcode", "otp", "pin", "bearer"}
_SECRET_PAIRS = {("api", "key"), ("secret", "key"), ("access", "key"), ("private", "key"),
                 ("client", "secret"), ("password", "hash"), ("pw", "hash"), ("nt", "hash"), ("password", "plain"),
                 ("set", "cookie"), ("x", "api"), ("aes", "key"), ("master", "key"), ("signing", "key"), ("encryption", "key")}
# words that NAME a secret without holding it (counts, flags, references, ui hints)
_NOT_SECRET_LAST = {"ref", "refs", "count", "counts", "hint", "type", "kind", "label", "at", "version", "length",
                    "policy", "required", "expires", "expiry", "ttl", "field", "fields", "name", "names", "provider",
                    "header", "redaction", "redacted", "meta", "present", "set_flag", "url"}


def _key_words(k: str) -> list:
    k = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(k))
    return [w for w in re.split(r"[^A-Za-z0-9]+", k.lower()) if w]


def _secret_key(k: str) -> bool:
    w = _key_words(k)
    if not w or len(w) > 8:
        return False
    if w[-1] in _NOT_SECRET_LAST:
        return False
    if w[-1] in _SECRET_LAST:
        return True
    if len(w) >= 2 and (w[-2], w[-1]) in _SECRET_PAIRS:
        return True
    return "password" in w[:-1] and w[-1] in {"plain", "clear", "text", "value", "raw"}


_NUMERIC_SECRET = {"password", "passwd", "pwd", "pin", "otp", "passcode", "secret"}


def _numeric_secret(k: str) -> bool:
    """A NUMBER is a secret only under a password / pin / otp key; elsewhere (category counters under
    « jwt », « insecure_cookie »…) it stays an integer (review B2, N2)."""
    return bool(set(_key_words(k)) & _NUMERIC_SECRET)


def _all_leaves(o: Any, c: Counter, kind: str = "secret-field", feed: bool = True, numeric: bool = False) -> Any:
    """Every scalar under a secret-named key (cookies{sid}, tokens[]) is the secret. ``feed``: the
    value also joins the known-secret index (not for *_id keys: « session_id » in the store also
    holds run keys and ids that appear legitimately elsewhere)."""
    if isinstance(o, dict):
        return {k: _all_leaves(v, c, kind, feed, numeric) for k, v in o.items()}
    if isinstance(o, list):
        return [_all_leaves(v, c, kind, feed, numeric) for v in o]
    if isinstance(o, str):
        if not o.strip() or _safe(o):
            return o
        if feed:
            _hit(c, kind, o)
        else:
            c[kind] += 1
        return _m(kind)
    if isinstance(o, (int, float)) and not isinstance(o, bool) and numeric:
        c[kind] += 1
        return _m(kind)
    return o


def redact_obj(o: Any, counter: Optional[Counter] = None, _key: str = "", *, known=None) -> Any:
    """``known=None``: stored data (known-secret index applies); ``frozenset()``: request echo."""
    c = counter if counter is not None else Counter()
    if known is None:
        known = store_known()
    if _key and _secret_key(_key) and not (_key == "counts" or isinstance(o, bool)):
        return _all_leaves(o, c, feed=_key_words(_key)[-1] != "id", numeric=_numeric_secret(_key))
    if isinstance(o, str):
        return redact_text(o, c, known=known)[0]
    if isinstance(o, dict):
        if _key in ("counts", "by_field") and all(isinstance(v, (int, dict)) and not isinstance(v, bool) for v in o.values()):
            return copy.deepcopy(o)   # redaction / evidence counts: {"password": 6} is a count, not a secret
        # HAR postData.params / k8s env / form fields: {"name"|"key": "<secret name>", "value"|"val": x}
        label = o.get("name", o.get("key"))
        if isinstance(label, str) and _secret_key(label):
            o = {k: (_all_leaves(v, c, feed=True, numeric=_numeric_secret(label)) if k in ("value", "val") else v)
                 for k, v in o.items()}
        out = {}
        for k, v in o.items():
            ks = str(k)
            # a dict KEY can hold a secret too ({"https://u:PASS@h": …})
            nk = redact_text(ks, c, known=known)[0] if isinstance(k, str) and len(ks) > 6 else k
            out[nk] = redact_obj(v, c, ks, known=known)
        return out
    if isinstance(o, list):
        # a header written as a pair: ["Cookie", "sid=…"] / ["Authorization", "Bearer …"]
        if len(o) == 2 and all(isinstance(x, str) for x in o) and _HEADER_NAME.fullmatch(o[0].strip()):
            return [o[0], redact_text(_header_value(o[0], o[1], c), c, known=known)[0]]
        return [redact_obj(v, c, _key, known=known) for v in o]
    return o


_HEADER_NAME = re.compile(r"(?i)(?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|private-token"
                          r"|x-[a-z0-9-]{0,40}?(?:token|secret|api-?key|auth|session)[a-z0-9-]{0,40}")


# ── projections ───────────────────────────────────────────────────────

EVIDENCE_TEXT_KEYS = ("raw_request", "raw_response", "explanation", "commands", "logs",
                      "request", "response", "requests", "responses", "command", "output", "log",
                      "payloads", "payload")


def _evidence_items(ev: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(ev, dict):
        return [ev]
    if isinstance(ev, list):
        return [x for x in ev if isinstance(x, dict)]
    return []


def evidence_counts(ev: Any) -> Dict[str, int]:
    """How many non-empty items each evidence key carries (metadata, no content)."""
    out = {k: 0 for k in ("raw_request", "raw_response", "explanation", "commands", "logs", "payloads",
                          "screenshots", "requests")}
    for item in _evidence_items(ev):
        for k in out:
            val = item.get(k)
            if k == "requests" and not val:
                val = item.get("request")
            if k == "payloads" and not val:
                val = item.get("payload")
            if k == "screenshots" and not val:
                val = item.get("screenshot")
            if isinstance(val, list):
                out[k] += len([x for x in val if x not in (None, "")])
            elif val not in (None, "", {}, []):
                out[k] += 1
    return out


def redact_finding(v: Dict[str, Any], *, list_view: bool = False) -> Dict[str, Any]:
    """The only projection of a finding the API serves.

    ``list_view``: lists never carry proof (``evidence`` removed, ``evidence_meta``
    counts instead). Detail: ``evidence`` masked with ``evidence.redaction``
    {version, fields[], counts{kind: n}, total, by_field{field: {kind: n}}}
    describing what the server masked, field by field (the UI labels each tab)."""
    if not isinstance(v, dict):
        return v
    src = dict(v)
    ev = src.pop("evidence", None)
    known = store_known()
    out = redact_obj(src, known=known)
    if list_view:
        out["evidence_meta"] = {"counts": evidence_counts(ev), "has_evidence": bool(ev),
                                "redaction_version": VERSION}
        return out
    if ev is None:
        return out
    total = Counter()
    fields = []
    by_field: Dict[str, Dict[str, int]] = {}
    if isinstance(ev, dict):
        red_ev = {}
        for k, val in ev.items():
            if k == "redaction":
                continue   # the server writes its own
            c = Counter()
            red_ev[k] = redact_obj(val, c, str(k), known=known)
            if c:
                fields.append(k)
                total.update(c)
                by_field[k] = dict(sorted(c.items()))
    else:
        c = Counter()
        red_ev = redact_obj(ev, c, known=known)
        if c:
            fields.append("*")
            total.update(c)
            by_field["*"] = dict(sorted(c.items()))
    meta = {"version": VERSION, "fields": fields, "counts": dict(sorted(total.items())),
            "total": sum(total.values()), "by_field": by_field}
    if isinstance(red_ev, dict):
        red_ev["redaction"] = meta
        out["evidence"] = red_ev
    else:
        out["evidence"] = {"items": red_ev, "redaction": meta}
    return out


def redact_findings(vs: Iterable[Dict[str, Any]], *, list_view: bool = True):
    return [redact_finding(v, list_view=list_view) for v in vs]


def redact_pr(pr: Dict[str, Any]) -> Dict[str, Any]:
    """Pull request: patch, body, description, title and every other string masked.
    The patch also goes through the line masker used by the fix block."""
    if not isinstance(pr, dict):
        return pr
    out = redact_obj(pr)
    patch = pr.get("patch")
    if isinstance(patch, str) and patch:
        from api.attack_paths_observed import mask_line
        out["patch"] = mask("\n".join(mask_line(line) for line in patch.splitlines()))
    out["redaction"] = {"version": VERSION}
    return out


def redact_event(ev: Any) -> Any:
    """A DECODED run-log / SSE event: every text field masked (not a regex on the
    escaped JSONL line, so multi-line PEM and escaped newlines are handled)."""
    return redact_obj(ev)


def contains_marker(s: str) -> bool:
    return "«redacted:" in s


def deepcopy_json(o: Any) -> Any:
    return copy.deepcopy(o)
