"""
PrivacyVault — reversible, per-session local tokenization of sensitive values.

Design invariants
-----------------
* Deterministic: the same real value always maps to the same placeholder within
  a session (e.g. 10.42.1.5 -> IP_PRIVATE_001 every time it appears).
* Local-only reversibility: real values are stored encrypted in memory. The map
  is never written to disk in plaintext and never logged.
* No plaintext retention: for de-duplication we key on an HMAC of the value, not
  the value itself; the only recoverable copy of a real value is its Fernet
  ciphertext, decrypted on demand by `rehydrate()`.
* TTL / session scope: a vault expires; after expiry it refuses to rehydrate.
* The LLM can never resolve a placeholder: there is no MCP tool that maps a
  placeholder back to its value — rehydration only happens inside the local
  execution path (the CommandGateway), never in a value returned to the model.

Categories & placeholder format: ``<CATEGORY>_<NNN>`` e.g. ``IP_PRIVATE_001``.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import base64
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .keyblocks import (find_delimited_secrets, find_encoded_private_keys, find_bare_key_rows, find_headerless_openssh, find_key_tails, find_private_keys,
                        find_table_secrets, find_wrapped_private_keys, is_private_key_value, is_secret_name,
                        key_body_windows)

try:  # Preferred: authenticated encryption for the at-rest map.
    from cryptography.fernet import Fernet  # type: ignore

    _HAVE_FERNET = True
except Exception:  # pragma: no cover - fallback keeps the vault usable without the lib
    _HAVE_FERNET = False


class Category(str, Enum):
    IP_PRIVATE = "IP_PRIVATE"
    IP_PUBLIC = "IP_PUBLIC"
    HOST_INTERNAL = "HOST_INTERNAL"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    PATH = "PATH"
    USER = "USER"
    CRED = "CRED"


# The documented default protection boundary: every category the regex-based
# tokenizer can auto-detect from free text. This is the SINGLE SOURCE OF TRUTH,
# shared by the vault dataclass default and the MCP server, so the two can never
# drift apart and silently narrow the boundary below what the docs promise.
# (USER/CRED are register-only — never auto-detected — so they are not listed
# here; they are protected once explicitly registered.) See issue #40.
DEFAULT_CATEGORIES: Tuple["Category", ...] = (
    Category.URL,
    Category.EMAIL,
    Category.IP_PRIVATE,
    Category.IP_PUBLIC,
    Category.HOST_INTERNAL,
    Category.DOMAIN,
    Category.PATH,
)


def resolve_categories(raw: Optional[str]) -> Tuple["Category", ...]:
    """Parse a comma-separated category override into a tuple of Categories.

    Returns ``DEFAULT_CATEGORIES`` when ``raw`` is None/empty or lists no valid
    category name, so an unset or malformed ``DARKMOON_PRIVACY_CATEGORIES`` can
    never silently narrow the protection boundary below the documented default.
    """
    if not raw or not raw.strip():
        return DEFAULT_CATEGORIES
    cats: List[Category] = []
    for name in (p.strip().upper() for p in raw.split(",") if p.strip()):
        try:
            cats.append(Category[name])
        except KeyError:
            pass
    return tuple(cats) if cats else DEFAULT_CATEGORIES


# A placeholder is CATEGORY_NNN. Restrict to our known prefixes so we never
# mistake an unrelated uppercase token for a placeholder.
_PREFIXES = "|".join(sorted((c.value for c in Category), key=len, reverse=True))
PLACEHOLDER_RE = re.compile(rf"\b(?P<ph>(?:{_PREFIXES})_\d{{3,}})\b")
# The same token without the leading word boundary, so a placeholder glued to a
# short flag is still seen: `netexec -uUSER_001`, `mysql -pCRED_001`. The
# gateway used this shape for secrets only, which meant `-pCRED_001` was caught
# but `-pIP_PRIVATE_001` was invisible to every other rule and travelled into
# the executed command untouched.
PLACEHOLDER_ANY_RE = re.compile(rf"(?P<ph>(?:{_PREFIXES})_\d{{3,}})\b")

# --- Detection patterns (ordered from most specific to least). ----------------
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`|\\]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# IPv6 is pervasive in AD/network work (mitm6, responder, impacket, link-local
# DC addresses). The classification path already understands IPv6 via ipaddress;
# only detection was IPv4-only. Cover full, compressed (::), zone-scoped
# (fe80::1%eth0) and IPv4-mapped forms. Hex-adjacency guards on both sides stop
# false matches on things like "std::vector" or a bare "12:34:56" clock. A MAC
# (six single-colon octets, no "::") does not match any alternative here.
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:.%])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"                                  # full
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                                              # trailing ::
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"  # v4-mapped
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r")(?:%[0-9A-Za-z._\-]+)?(?![0-9A-Fa-f:.])"                                  # optional zone id
)
# A short hextet glued to "::" (e.g. "d::", "a::b", "ab::cd") is far more likely a
# C++/Rust scope token than a real address; skip it. Real link-local/global
# prefixes are 4 hex digits (fe80, 2001, fc00, ...) and are unaffected, as are
# "::1" and "::ffff:...". Over-tokenizing is safe (never a leak); this only trims
# obvious source-code noise.
_SHORT_V6_ARTEFACT_RE = re.compile(r"[0-9A-Fa-f]{1,2}::[0-9A-Fa-f]{0,2}")
# FQDN with at least one dot and a 2+ char TLD; label-safe.
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)
# LDAP distinguished-name domain, e.g. "DC=evilcorp,DC=local" or
# "DC=ForestDnsZones,DC=evilcorp,DC=local". Pervasive in AD/LDAP/BloodHound output
# and never dotted, so the FQDN pattern misses it. Matched as a whole so the model
# sees one placeholder and the report rehydrates the exact DN.
_LDAP_DN_RE = re.compile(r"\bDC=[A-Za-z0-9_\-]+(?:,\s*DC=[A-Za-z0-9_\-]+)+", re.IGNORECASE)
# Absolute unix paths (>=2 segments) and Windows paths. Kept conservative.
_PATH_RE = re.compile(r"(?<![\w./])(?:/[A-Za-z0-9._\-]+){2,}/?|[A-Za-z]:\\\\?(?:[^\s\"'<>|]+)")

# Internal-looking single-label hosts / suffixes are treated as HOST_INTERNAL.
_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home", ".intra", ".test")

# `_DOMAIN_RE` cannot tell `index.php` from `acme-corp.com`: both are
# "labels separated by dots ending in letters". Once DOMAIN became a default
# category (issue #40) every filename in tool output started minting a DOMAIN
# placeholder, which is worse than a leak — the model stops being able to read
# an extension, spot a pattern or fuzz a name (PR #42), and a later
# `nuclei -u DOMAIN_001` silently resolves to `index.php` instead of the target.
# A trailing label that is a well-known file extension is therefore never a host.
_FILE_EXTENSIONS = frozenset("""
asp aspx bak bat bin bz2 c cfg cgi class conf config cpp crt cs csr css csv db
deb dll dmp doc docx dtd egg env err exe gif go gz h hbs htm html ini jar java
jpeg jpg js json jsp key kt log lst md mdb msi old orig pcap pdf pem php phtml
pl pm png ppt pptx properties ps1 psd1 psm1 py pyc rar rb rpm rs sh sln so sql
sqlite svg swp tar tgz tmp toml ts tsv txt vbs war wav webp xls xlsx xml yaml
yml zip
""".split())


def _looks_like_filename(value: str) -> bool:
    """True when a `_DOMAIN_RE` match is really a filename, not a hostname."""
    tail = value.rsplit(".", 1)[-1].lower()
    return tail in _FILE_EXTENSIONS


# Plain credentials the model must never receive. Issue #40: the gateway only
# ever recognised an already-registered ``CRED_NNN`` placeholder, and nothing in
# production registered one, so a password echoed by a tool went straight into
# the model context. These patterns register the *secret group only*, leaving the
# surrounding flag/key intact so the command stays readable and re-runnable.
# what follows ``x/y@`` or ``x:y@`` when it is a version / ref / digest, not a host (``actions/checkout@v4``,
# ``pkg/name@1.2.3``, ``img/nginx@sha256:…``, ``org/repo@main``): never a credential
_NOT_A_HOST = (r"(?:sha\d{3}:|v\d|\d+(?:\.\d+){0,2}(?![\d.])"
               r"|(?:main|master|latest|head|HEAD|stable|dev|develop|canary|beta|alpha|next|nightly|edge|snapshot|rc\d*)\b)")
# a HOST after a scheme-less ``user:password@`` (round3-critique M2): an IP, a bracketed IPv6, host:port, or a single-label
# service name (``rabbitmq``, ``mysql``) — never a dotted mail domain (``alice:wonder@mail.example.com`` is an address)
_BARE_HOST = r"(?=(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.\-]+:\d{1,5}\b|[A-Za-z0-9][A-Za-z0-9\-]*(?![\w.\-])))"

_CRED_PATTERNS = (
    # -pS3cret / --password=S3cret / password: S3cret / "pass": "S3cret"
    re.compile(r"(?<![\w-])(-p|--password[=\s]|--pass[=\s]|-w\s)(?P<secret>[^\s\"',;|&]{4,})"),
    # P4 review-2 E2/E3: ``key=``/``SECRET_KEY =``/``aws_secret_access_key =``/
    # ``private_key=`` (any ``*key`` after a non-alphanumeric) and a scheme word
    # after the key (``token: Bearer X``: X is the secret, not "Bearer").
    re.compile(r"(?i)[A-Za-z0-9_$.\-]{0,32}(?:passwords?|passwd|passphrase|pass|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|credentials?|(?<![A-Za-z0-9])key)\s*[:=]>?\s*[\"']?(?:(?:bearer|basic|token)\s+)?(?P<secret>[^\s\"',;|&<>]{4,})"),
    # a SHORT (2-3 chars) value in an explicit PASSWORD slot (closure 53, decision 2): a cracked « password: a7 »
    # (hydra), « DB_PASSWORD=x9 » reached the model in clear (the line above needs 4+ chars). Password labels only
    # (never token / key: « key: id » is not a secret), never a yes/no word; pure masks are dropped by the caller.
    re.compile(r"(?i)[A-Za-z0-9_$.\-]{0,32}(?:passwords?|passwd|passphrase|pass|pwd)\s*[:=]>?\s*[\"']?"
               r"(?!(?:no|yes|on|off|ok|nil|n/a|set)(?![^\s\"',;|&<>]))(?P<secret>[^\s\"',;|&<>]{2,3})(?![^\s\"',;|&<>])"),
    # Authorization: Bearer <token> / Basic <b64>
    re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic|token)\s+(?P<secret>[A-Za-z0-9._~+/=\-]{8,})"),
    # user:password@host inside a URI, any scheme (postgres, mysql, mongodb(+srv), redis, amqp, ldap, smb, ftp...).
    # The user may be EMPTY (``redis://:pass@host``) — round2-critique « hors sujet »: such DSNs reached a sub-agent in clear.
    # Never a bare port (``http://127.0.0.1:8080@evil`` is an SSRF payload, not a password).
    re.compile(r"(?<=://)[A-Za-z0-9._%\-]*:(?P<secret>(?!\d{1,5}@)[^\s@/:]{2,})(?=@)"),   # 2+ (closure 53: « :a7@ »)
    # the same, JSON-escaped (``postgres:\/\/u:p@h``) or cut after the user on two quoted lines
    re.compile(r"(?<=:\\/\\/)[A-Za-z0-9._%\-]*:(?P<secret>(?!\d{1,5}@)[^\s@/:\\]{3,})(?=@)"),
    re.compile(r"(?<=://)[A-Za-z0-9._%\-]*:[\"']?[ \t]*\r?\n[ \t]*[\"']?(?P<secret>[^\s@/:\"']{3,})(?=@)"),
    # the same, URL-encoded (``postgres%3A%2F%2Fadmin%3AS3cret%40db``)
    re.compile(r"(?i)%3A%2F%2F[A-Za-z0-9._\-]*%3A(?P<secret>(?:(?!%40)[^\s/@&\"'])+?)(?=%40)"),
    # user/password@host (Oracle / psql / mysql CLI-style DSN: ``postgres/postgres@db:5432/crm``, ``root/root@mysql``);
    # never an image digest (``library/nginx@sha256:…``), a tag / ref / version, nor a scoped package (``@scope/pkg``)
    re.compile(r"(?<![\w/.:@%+\-])[A-Za-z0-9._%\-]{1,64}/(?P<secret>[^\s@/:'\"`]{3,})@(?!" + _NOT_A_HOST + r")(?=[A-Za-z0-9\[])"),
    # user:password@host WITHOUT a scheme (``admin:S3cret@10.0.0.5``, ``guest:guest@rabbitmq``); not a URI scheme word,
    # not a port, not a mail address
    re.compile(r"(?<![\w/.:@%+\-])(?!(?:mailto|https?|ftp|sftp|ssh|git|smb|ldaps?|file):)[A-Za-z0-9._%\-]{1,64}"
               r":(?P<secret>(?!\d{1,5}@)[^\s@/:'\"`]{3,})@(?!" + _NOT_A_HOST + r")" + _BARE_HOST),
    # HTTP clients only (round5-critique: ``docker run -u 1000:1000``, ``sudo -u www-data`` are not credentials):
    # curl / curlie / wget / httpie / xh user:password (``-u admin:S3cret``, ``--user=admin:S3cret``); never a numeric
    # uid:gid, never a value without a colon
    re.compile(r"(?<![\w./-])(?:curl|curlie|wget2?|https?|httpie|xh|xhs)(?![\w.-])[^\n|;&]*?\s"
               r"(?:-u|--user|--proxy-user|--http-user)(?:=|\s+)['\"]?(?!\d+:\d+(?![^\s'\"]))"
               r"[^\s:'\"]{1,64}:(?P<secret>[^\s'\"]{3,})"),
    # an UNLABELLED AWS secret access key (40 chars, mixed case + digit) within ~400 characters after an access key id
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}[\s\S]{0,400}?(?<![A-Za-z0-9/+=])"
               r"(?P<secret>(?=[A-Za-z0-9/+]{0,39}[a-z])(?=[A-Za-z0-9/+]{0,39}[A-Z])(?=[A-Za-z0-9/+]{0,39}\d)[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"),
    # cloud / vendor access keys recognisable by their prefix, wherever they appear (no ``key=`` label needed):
    # AWS access key ids (AKIA long-term, ASIA STS, and the other IAM unique-id prefixes), GitHub, GitLab, Slack,
    # Google API keys, Stripe, HashiCorp Vault tokens (hvs./hvb./hvr. and the legacy s.<24>)
    re.compile(r"(?<![A-Za-z0-9])(?P<secret>(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_])(?P<secret>(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_\-]{20,}"
               r"|xox[abposr]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{35}|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"
               r"|hv[sbr]\.[A-Za-z0-9_\-]{20,}))"),
    re.compile(r"(?<![\w.])(?P<secret>s\.[A-Za-z0-9]{24})(?![\w.])"),
    # NTLM / NT hash and long hex digests worth protecting
    re.compile(r"(?<![A-Fa-f0-9])(?P<secret>[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32})(?![A-Fa-f0-9])"),
)

# Quoted-key slots (cycle 1, 18/11), applied by ``register_credentials`` after ``_CRED_PATTERNS``. Kept in their own
# tuple: ``api.tool_provenance._gateway_secrets`` reads ``_CRED_PATTERNS`` to decide what a tool PRODUCED, and a token
# an endpoint issues (« {"token": "<jwt>"} ») is a delivery there, never a proven exposure — the provenance semantics
# (and the architecture-D harness) stay exactly as they were.
_QUOTED_KEY_CRED_PATTERNS = (
    # a QUOTED key (cycle 1, 18/11): JSON / Python dict / quoted YAML « "password": "S3cretXyz" », « 'api_key' : 'k' »,
    # « {\"token\":\"…\"} » (JSON inside a JSON string). The closing quote of the key broke the « key[:=] » rule
    # above, so such a value reached the model in clear at ANY length (closure 53, strict xfail). Only a QUOTED value
    # (a string), any length, never one of the yes/no words, a null/boolean word or a mask; the bare « key » and the
    # « pwd » label (the working directory in most JSON) are not slots here (« pwd » has its own rule below).
    re.compile(r"(?P<q1>\\?[\"'])(?:[A-Za-z0-9_$.\-]{0,32}(?:[_.\-]|(?<=[a-z0-9])(?=[A-Z])))?"
               r"(?i:passwords?|passwd|passphrase|pass|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token"
               r"|auth[_-]?token|refresh[_-]?token|id[_-]?token|token|credentials?|private[_-]?key|secret[_-]?key"
               r"|access[_-]?key)(?P=q1)[ \t]*[:=]>?[ \t]*(?P<q2>\\?[\"'])"
               r"(?!(?i:no|yes|on|off|ok|nil|n/a|set|true|false|null|none|undefined)(?P=q2))"
               r"(?P<secret>(?:(?!(?P=q2))(?:\\.|[^\n\\])){1,512}?)(?P=q2)"),
    # « "pwd": "…" » is a password only when the value is not a path (« "pwd": "/home/app" » is the working directory)
    re.compile(r"(?P<q1>\\?[\"'])(?:[A-Za-z0-9_$.\-]{0,32}(?:[_.\-]|(?<=[a-z0-9])(?=[A-Z])))?(?i:pwd)(?P=q1)"
               r"[ \t]*[:=]>?[ \t]*(?P<q2>\\?[\"'])(?![/~.\\]|[A-Za-z]:[\\/])"
               r"(?!(?i:no|yes|on|off|ok|nil|n/a|set|true|false|null|none|undefined)(?P=q2))"
               r"(?P<secret>(?:(?!(?P=q2))(?:\\.|[^\n\\])){1,512}?)(?P=q2)"),
    # a quoted PASSWORD key with an unquoted NUMBER (« "password": 123456 », « "pin": 4821 »): 4+ digits only (a count
    # or a flag is never under such a key, and « "pass": 1 » is a test result)
    re.compile(r"(?P<q1>\\?[\"'])(?:[A-Za-z0-9_$.\-]{0,32}(?:[_.\-]|(?<=[a-z0-9])(?=[A-Z])))?"
               r"(?i:passwords?|passwd|passphrase|pass|pin|passcode)(?P=q1)[ \t]*[:=][ \t]*(?P<secret>\d{4,64})(?![\d.])"),
)

# Tool- and format-specific password slots (v3 privacy audit, 18/11/2026): each one reached the model in clear. Own
# tuple, applied by ``register_credentials`` only (provenance and storage keep reading ``_CRED_PATTERNS``). A ``name``
# group, when present, must itself name a secret (``keyblocks.is_secret_name``): « <password>x</password> » yes,
# « <name>x</name> » no.
_SLOT_VAL = r"['\"]?(?P<secret>[^\s'\"]{2,256})"
_TOOL_CRED_PATTERNS = (
    # XML element « <password>x</password> », « <db.password>x</db.password> »
    re.compile(r"<(?P<name>[A-Za-z_][\w.\-]{0,63})>(?P<secret>[^<>\s]{2,256})</(?P=name)>"),
    # key/value attributes « <add key="DbPassword" value="x"/> » (web.config), « <param name="password" value="x"> »
    re.compile(r"\b(?:key|name)\s*=\s*(?P<q1>[\"'])(?P<name>[\w.\-:]{1,64})(?P=q1)\s+value\s*=\s*(?P<q2>[\"'])"
               r"(?P<secret>[^\"'\n]{1,512})(?P=q2)"),
    # PHP « define('DB_PASSWORD', 'x') » (wp-config.php)
    re.compile(r"\bdefine\s*\(\s*(?P<q1>[\"'])(?P<name>\w{1,64})(?P=q1)\s*,\s*(?P<q2>[\"'])"
               r"(?P<secret>(?:\\.|(?!(?P=q2))[^\\\n]){1,512})(?P=q2)"),
    # SQL « IDENTIFIED BY 'x' », « IDENTIFIED WITH mysql_native_password BY 'x' », « WITH PASSWORD 'x' »
    re.compile(r"(?i)\bIDENTIFIED\s+(?:WITH\s+\w+\s+)?(?:BY|AS)\s+(?:PASSWORD\s*)?(?P<q>['\"])"
               r"(?P<secret>(?:''|\\.|(?!(?P=q))[^\\\n]){1,256})(?P=q)"),
    re.compile(r"(?i)\bPASSWORD\s+(?P<q>['\"])(?P<secret>(?:''|\\.|(?!(?P=q))[^\\\n]){1,256})(?P=q)"),
    # a QUOTED value glued to -p (« mysql -p'x' », « sshpass -p"x" »), sshpass « -p x », redis-cli « -a x »
    re.compile(r"(?<![\w-])-p(?P<q>['\"])(?!\d{1,5}(?P=q))(?P<secret>[^'\"\n]{2,256})(?P=q)"),   # never a quoted port
    re.compile(r"\bsshpass\b[^\n|;&]*?\s-p\s+" + _SLOT_VAL),
    re.compile(r"\bredis-cli\b[^\n|;&]*?\s(?:-a|--pass)\s+" + _SLOT_VAL),
    # redis.conf « requirepass x » / « masterauth x »; .netrc « login u password x »
    re.compile(r"(?im)^[ \t]*(?:requirepass|masterauth)[ \t]+" + _SLOT_VAL),
    re.compile(r"(?i)\blogin\s+\S+\s+password\s+" + _SLOT_VAL),
    # samba « -U user%x » / « --user=user%x »; impacket « domain/user:x@target »
    re.compile(r"(?<![\w-])(?:-U|--user(?:name)?)(?:=|\s+)['\"]?[^\s%'\"]{1,64}%(?P<secret>[^\s'\"]{2,256})"),
    re.compile(r"(?<![\w/.:@%+\-])[A-Za-z0-9.\-]{1,64}/[A-Za-z0-9._\-$]{1,64}:(?P<secret>[^\s@'\"]{2,256})@(?!"
               + _NOT_A_HOST + r")(?=[A-Za-z0-9\[])"),
    # ~/.pgpass « host:port:db:user:x » (5 fields, a PostgreSQL port or *: « 10.0.0.5:22:open:ssh:OpenSSH_9 » is not one)
    re.compile(r"(?m)^[^:\s#][^:\s]*:(?:543\d|6432|\*):[^:\s]+:[^:\s]+:(?P<secret>[^\s]{2,256})(?=\r?$)"),
)

# Default / dictionary credentials (round3-critique M2): still tokenized WHERE a pattern finds them (``root/root@db``),
# but never hunted for elsewhere in later outputs — « root », « postgres » are also user names, paths and products.
COMMON_CREDENTIAL_WORDS = frozenset({
    "root", "admin", "administrator", "guest", "postgres", "postgresql", "mysql", "mariadb", "oracle", "tiger", "scott",
    "test", "tester", "user", "users", "dev", "demo", "default", "public", "private", "secret", "password", "changeme",
    "letmein", "welcome", "sa", "system", "manager", "redis", "mongo", "mongodb", "rabbitmq", "elastic", "kibana",
    "jenkins", "vagrant", "ubuntu", "debian", "pi", "raspberry", "toor", "pass", "passw0rd", "qwerty", "service",
})

_B64_USERPASS = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{12,200}={0,2}(?![A-Za-z0-9+/=_-])")
_USERPASS_DECODED = re.compile(r"[A-Za-z0-9._@\\-]{2,64}:[\x21-\x7e]{4,128}")

# Values that match a credential pattern but carry no secret.
_CRED_FALSE_POSITIVES = frozenset({
    "bearer", "basic", "digest", "negotiate", "ntlm",
    "none", "null", "true", "false", "changeme", "password", "redacted",
    "xxxx", "****", "<password>", "$password", "password}",
})

# Pure mask strings: what a tool, an agent or a redactor writes IN PLACE of a secret (« *** », « xxxx », « •••• »,
# « <redacted> », « [REDACTED] », « «redacted:password» »). They carry no secret and are shared by every finding that
# masks a value: never minted as a credential (provenance study 17/11: « password: *** » was minted CRED_012).
_PURE_MASK = re.compile(
    r"(?i)^(?:[*•●·]+|x{3,}|\.{3,}|#{3,}|[*x•●]{3,}"
    r"|[<\[({]\s*(?:redacted|hidden|masked|removed|censored|filtered|snipped|snip|omitted|password|secret)\s*[>\])}]"
    r"|«redacted:[a-z0-9-]+»|redacted|\*{0,4}redacted\*{0,4})$")


def is_mask_string(value: Optional[str]) -> bool:
    """A value that only MASKS a secret (« *** », « [REDACTED] »…), never a secret itself."""
    return bool(value) and bool(_PURE_MASK.match(str(value).strip().strip("\"'")))


def is_cred_false_positive(value: Optional[str]) -> bool:
    """A credential-pattern hit that carries no secret: a known word (« bearer », « none »…) or a pure mask."""
    return not value or value.lower() in _CRED_FALSE_POSITIVES or is_mask_string(value)

# Launch-prompt credential pairs, e.g. `CREDS=j.doe:Password1!`,
# `CREDS=EVILCORP\\admin:pw`, `LOGIN=user/pass`. The launch prompt reaches the
# model before any tool call, so these must be tokenized up front (issue #40,
# section 3). The user half is registered as USER and the secret half as CRED so
# credentialed testing still works: the model sees `USER_001:CRED_001`, the
# gateway rehydrates USER into a command normally and injects CRED only into a
# target-bound command. `TOKEN=`/`PASSWORD=` single secrets are left to
# register_credentials(); this pattern handles only the user:secret pair form.
_PROMPT_CRED_PAIR_RE = re.compile(
    r"(?i)(?<![\w-])(?:creds?|credentials?|login|auth)\s*[:=]\s*"
    # user may be an email/UPN (user@domain) or DOMAIN\\user; it ends at the
    # FIRST ':' or '/' separator, so an '@' in the user must not leak the secret.
    r"(?P<user>[^\s:/\"',;|&]+)[:/](?P<secret>[^\s\"',;|&]{1,})"
)


_PROMPT_AUTH_PAIR_RE = re.compile(
    # P4 v2 review-2 E1: the secret ends at whitespace only (``&;|'`` are legal
    # password characters; a shorter class sent the tail of the password in clear).
    r"(?i)(?<![\w-])auth\s*[:=]\s*(?P<user>[^\s:/\"',;|&]+)[:/](?P<secret>\S+)"
)
# Launch-prompt keys whose WHOLE value is credentials (P1/P2), handled item by item
# before the generic pair pattern. Two value shapes (P4 review-2, E1/E2):
#   * quoted  ``CREDS="role:user:p a;s|s\"w,0rd"`` -- what build_cli_prompt emits
#     whenever an item holds whitespace, a quote, a backslash or a comma. Inside the
#     quotes ``\\``, ``\"`` and ``\,`` are escapes and only an UNESCAPED comma
#     separates items, so the exact password (spaces, unicode, ``%41``...) survives.
#   * free    ``CREDS=a:b:P&ss;w|o'rd`` -- ends at whitespace ONLY. A value that ends
#     with ``,`` continues after the whitespace (``a:b:p1, c:d:p2``) and a following
#     line shaped like ``user:secret`` continues it too (hand-typed lists).
# Over-consuming is safe (more text becomes CRED); under-consuming leaks.
_QUOTED_VAL = r"(?P<qc>[\"'])(?P<q>(?:\\.|(?!(?P=qc))[^\\])*)(?P=qc)?"
_FREE_VAL = (
    r"(?P<val>\S+(?:(?<=,)\s+\S+"
    r"|\n[ \t]*(?![A-Za-z_][\w-]*\s*[:=]\s)(?![A-Za-z][\w+.-]*://)[^\s=:/]+[:/]\S+)*)"
)
_PROMPT_CRED_LIST_RE = re.compile(
    r"(?i)(?P<key>(?<![\w-])(?:creds?|credentials?|login)\s*[:=]\s*)(?:" + _QUOTED_VAL + "|" + _FREE_VAL + ")"
)
_AUTH_SCHEMES = r"(?:bearer|basic|token|digest|negotiate|ntlm|apikey)"
_SCHEME_ITEM_RE = re.compile(r"(?i)^(?P<scheme>" + _AUTH_SCHEMES + r")(?P<sp>\s+)(?P<tok>\S.*)$", re.S)
_PROMPT_TOKEN_LIST_RE = re.compile(
    r"(?i)(?P<key>(?<![\w-])(?:tokens?|api[_-]?keys?|bearer)\s*[:=]\s*)(?:" + _QUOTED_VAL
    + r"|(?P<scheme>" + _AUTH_SCHEMES + r")(?P<sp>[ \t]+)(?P<tok>\S+)|" + _FREE_VAL + ")"
)


def split_quoted_items(body: str) -> List[str]:
    """Items of a quoted CREDS/TOKEN value: unescaped ``,`` separates; ``\\x`` -> ``x``."""
    items, cur, i = [], [], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            cur.append(body[i + 1])
            i += 2
            continue
        if ch == ",":
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    items.append("".join(cur))
    return items


_UNESCAPED_QUOTE_RE = re.compile(r'(?<!\\)"')


def unwrap_cli_message(text: str) -> str:
    """Undo the quoting ``opencode run`` applies to its message argument.

    opencode joins its positional args and wraps every arg holding a space as
    ``"..."`` with each ``"`` turned into ``\\"``. The launch prompt always holds a
    space, so the text the privacy plugin receives is ``"TARGET: ... CREDS=\\"a:b:p
    w\\" ..."``: the quoted CREDS/TOKEN values then start with ``\\"`` instead of
    ``"`` and the list parser ended them at the first space, sending the rest of a
    password or token to the model. The wrap is recognised only when the text is
    enclosed in quotes and every inner quote is escaped (what opencode produces);
    removing the backslash in front of each quote is its exact inverse."""
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        inner = text[1:-1]
        if _UNESCAPED_QUOTE_RE.search(inner) is None:
            return inner.replace('\\"', '"')
    return text


def _is_private_ip(value: str) -> Optional[bool]:
    # A link-local address can carry a zone id ("fe80::1%eth0"); strip it before
    # parsing so scoped IPv6 is still classified (and always as private).
    addr = value.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


@dataclass
class _Entry:
    placeholder: str
    ciphertext: bytes
    category: Category


@dataclass
class PrivacyVault:
    """Per-session reversible tokenizer. Not thread-safe by design (one per session)."""

    session_id: str
    ttl_seconds: int = 6 * 3600
    enabled_categories: Tuple[Category, ...] = DEFAULT_CATEGORIES
    created_at: float = field(default_factory=time.time)

    # Optional override for the server-wide default.
    privacy_enabled: Optional[bool] = None

    # P4 v2. ``epoch`` identifies THIS mapping generation: a record stamped with
    # another epoch must never be resolved against this vault (restart, TTL
    # rollover, other run). ``reissued_from`` names the generation it replaced.
    # ``prompt_placeholders`` are the placeholders minted from the operator's
    # launch prompt (the only values trusted to identify a target).
    epoch: str = field(default_factory=lambda: os.urandom(8).hex())
    reissued_from: Optional[str] = None
    prompt_placeholders: set = field(default_factory=set, repr=False)
    # Every epoch of THIS process-local chain (TTL rollovers keep the numbering, so
    # a placeholder name is never reissued inside a lineage). A record or a run
    # stamped with an epoch outside the lineage (MCP restart: numbering restarted
    # at _001) must never be resolved against this vault.
    lineage: set = field(default_factory=set, repr=False)

    # internal state (never logged)
    _key: bytes = field(default_factory=lambda: os.urandom(32), repr=False)
    _hmac_key: bytes = field(default_factory=lambda: os.urandom(32), repr=False)
    _fernet_key: bytes = field(default=b"", repr=False)
    _by_hash: Dict[str, _Entry] = field(default_factory=dict, repr=False)
    _by_ph: Dict[str, _Entry] = field(default_factory=dict, repr=False)
    _counters: Dict[Category, int] = field(default_factory=dict, repr=False)
    # The persistent-http MCP serves the pre-model tokenization socket (a daemon
    # thread) and the tool-call handlers (the asyncio loop) from DIFFERENT threads
    # against this one shared vault. The placeholder counter is a read-modify-write
    # (`n = counter+1; counter = n`), so without a lock two concurrent registers
    # could mint the SAME placeholder for two different values — a rehydration
    # collision. This reentrant lock makes register()/purge() atomic.
    _lock: "threading.RLock" = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        self.lineage.add(self.epoch)
        if _HAVE_FERNET:
            import base64

            self._fernet_key = base64.urlsafe_b64encode(self._key)
            self._fernet = Fernet(self._fernet_key)
        else:  # pragma: no cover
            self._fernet = None

    # -- lifecycle -----------------------------------------------------------
    def inherit_numbering(self, previous: "PrivacyVault") -> None:
        """Continue the placeholder numbering of an expired generation (P4 v2, D4).

        A fresh vault used to restart at ``_001`` while the model still held the
        old ``URL_001``: the next tool output re-minted ``URL_001`` for another
        value and the old token silently resolved to it. Never reissue a name
        within a process."""
        with self._lock:
            for cat, n in previous._counters.items():
                self._counters[cat] = max(self._counters.get(cat, 0), n)
            self.reissued_from = previous.epoch
            self.lineage |= previous.lineage | {previous.epoch}

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds

    def purge(self) -> None:
        """Best-effort zeroization of the mapping."""
        with self._lock:
            self._by_hash.clear()
            self._by_ph.clear()
            self._counters.clear()
            self._key = b""
            self._hmac_key = b""

    # -- crypto helpers ------------------------------------------------------
    def _fingerprint(self, value: str) -> str:
        return hmac.new(self._hmac_key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _encrypt(self, value: str) -> bytes:
        if self._fernet is not None:
            return self._fernet.encrypt(value.encode("utf-8"))
        # Fallback: keyed XOR stream (obfuscation, not authenticated). Only used
        # if the cryptography lib is unavailable; production images ship it.
        raw = value.encode("utf-8")
        stream = hashlib.sha256(self._key + b"stream").digest()
        while len(stream) < len(raw):
            stream += hashlib.sha256(stream).digest()
        return bytes(a ^ b for a, b in zip(raw, stream))

    def _decrypt(self, blob: bytes) -> str:
        if self._fernet is not None:
            return self._fernet.decrypt(blob).decode("utf-8")
        stream = hashlib.sha256(self._key + b"stream").digest()
        while len(stream) < len(blob):
            stream += hashlib.sha256(stream).digest()
        return bytes(a ^ b for a, b in zip(blob, stream)).decode("utf-8")

    # -- registration --------------------------------------------------------
    def register(self, value: str, category: Category) -> str:
        """Register a real value under a category and return its placeholder.

        Deterministic: an identical value returns the same placeholder.
        """
        value = value.strip()
        if not value:
            return value
        fp = self._fingerprint(value)
        # Atomic: the fingerprint lookup, counter bump and inserts must not
        # interleave with a concurrent register() from another thread, or two
        # different values could be minted the same placeholder (see _lock).
        with self._lock:
            existing = self._by_hash.get(fp)
            if existing is not None:
                return existing.placeholder
            n = self._counters.get(category, 0) + 1
            self._counters[category] = n
            placeholder = f"{category.value}_{n:03d}"
            entry = _Entry(placeholder=placeholder, ciphertext=self._encrypt(value), category=category)
            self._by_hash[fp] = entry
            self._by_ph[placeholder] = entry
            return placeholder

    def register_credentials(self, text: str) -> str:
        """Tokenize plain credentials found in ``text`` as ``CRED_NNN``.

        Issue #40: ``CRED`` had no automatic registration path, so a password a
        tool printed (or one the operator typed into the prompt) reached the model
        verbatim while the documentation promised it never would. Detection is
        deliberately narrow - an explicit password flag, a ``key: value`` secret,
        an ``Authorization`` header, URI userinfo, or an NT hash pair - so ordinary
        scan output is not shredded into placeholders.

        Only the secret itself is replaced; the flag or key around it survives, so
        the model still sees ``-pCRED_001`` and can reason about the command shape.
        """
        if not text:
            return text
        # cycle 3: whole private-key blocks first (psql/mysql/sqlite cells, JSON escapes, CRLF…), then table cells,
        # BEFORE the line patterns below can tear a key body or a « password | value » row apart
        text = self.register_private_keys(text)
        text = self.register_table_secrets(text)
        text = self._register_tool_slots(text)     # before the generic « key=… » rule mints a NAME (« key="DbPassword" »)
        for pattern in _CRED_PATTERNS + _QUOTED_KEY_CRED_PATTERNS:
            def sub(m):
                secret = m.group("secret")
                if not secret or is_cred_false_positive(secret):
                    return m.group(0)
                if PLACEHOLDER_RE.fullmatch(secret):
                    return m.group(0)  # already tokenized
                # only the SECRET span is replaced (round3-critique M2): ``postgres/postgres@db`` keeps its user
                a, b = m.start("secret") - m.start(), m.end("secret") - m.start()
                whole = m.group(0)
                return whole[:a] + self.register(secret, Category.CRED) + whole[b:]

            text = pattern.sub(sub, text)
        return _B64_USERPASS.sub(lambda m: self._b64_userpass(m), text)

    def _register_tool_slots(self, text: str) -> str:
        for pattern in _TOOL_CRED_PATTERNS:
            def sub_tool(m):
                if "name" in m.groupdict() and not is_secret_name(m.group("name")):
                    return m.group(0)
                secret = m.group("secret")
                if not secret or is_cred_false_positive(secret) or PLACEHOLDER_ANY_RE.search(secret):
                    return m.group(0)
                a, b = m.start("secret") - m.start(), m.end("secret") - m.start()
                whole = m.group(0)
                return whole[:a] + self.register(secret, Category.CRED) + whole[b:]

            text = pattern.sub(sub_tool, text)
        return text

    def _replace_spans(self, text: str, spans) -> str:
        out, cur = [], 0
        for a, b, value in spans:
            if a < cur or not value or PLACEHOLDER_RE.fullmatch(value.strip()):
                continue
            out.append(text[cur:a])
            out.append(self.register(value, Category.CRED))
            cur = b
        out.append(text[cur:])
        return "".join(out)

    def register_private_keys(self, text: str) -> str:
        """A private-key block is ONE secret, whatever wraps it (campaign 7: an OpenSSH key printed as a psql table
        cell, with ``|`` borders and ``+`` continuation markers, reached the model). The whole block span becomes
        one ``CRED_NNN`` whose value is the key's canonical bytes (BEGIN … END, ``\\n``-joined), so the gateway can
        write it back to a file byte-exact. See ``keyblocks``."""
        if not text:
            return text
        text = self._replace_spans(text, find_private_keys(text))
        # v3 privacy audit: encoded keys (base64 of the PEM, URL-encoded), a key tail without its BEGIN (``tail``, a torn
        # BEGIN, the second half of a split key), markers torn by a fixed-width terminal wrap
        text = self._replace_spans(text, find_encoded_private_keys(text))
        text = self._replace_spans(text, find_key_tails(text))
        text = self._replace_spans(text, find_wrapped_private_keys(text))
        text = self._replace_spans(text, find_headerless_openssh(text))
        return self._replace_spans(text, find_bare_key_rows(text))

    def known_key_windows(self) -> Dict[str, str]:
        """16-char windows of every multi-line key value this vault holds -> its placeholder (local only)."""
        out: Dict[str, str] = {}
        if self.is_expired():
            return out
        for ph, entry in list(self._by_ph.items()):
            if entry.category is not Category.CRED:
                continue
            try:
                value = self._decrypt(entry.ciphertext)
            except Exception:  # noqa: BLE001 — an unreadable entry has no window
                continue
            if "\n" in value:
                for w in key_body_windows(value):
                    out.setdefault(w, ph)
        return out

    def register_table_secrets(self, text: str) -> str:
        """``password | value`` rows and secret-named columns of DB-client tables (psql/mysql/sqlite box output):
        the value cell only, never the name, the borders or another cell."""
        if not text:
            return text

        def accept(value: str) -> bool:
            return not is_cred_false_positive(value) and not PLACEHOLDER_ANY_RE.search(value) \
                and value.upper() != "NULL" and not re.fullmatch(r"[-+=─]+", value)

        text = self._replace_spans(text, find_table_secrets(text, accept))
        return self._replace_spans(text, find_delimited_secrets(text, accept))

    def is_private_key(self, placeholder: str) -> bool:
        """True when ``placeholder`` stands for a private-key block (local check, the value never leaves)."""
        entry = self._by_ph.get(placeholder)
        if entry is None or entry.category is not Category.CRED or self.is_expired():
            return False
        try:
            return is_private_key_value(self._decrypt(entry.ciphertext))
        except Exception:  # noqa: BLE001 — an unreadable entry is not a key
            return False

    def _b64_userpass(self, m: "re.Match") -> str:
        """A base64 blob that decodes to a printable ``user:password`` (Basic credentials outside an Authorization
        header: a config file, a log line) is a credential (round 5). Random base64 essentially never decodes to such
        a printable pair, so this does not touch hashes, ids or JWT segments."""
        tok = m.group(0)
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("ascii")
        except Exception:  # noqa: BLE001 — not base64 / not ASCII: not a Basic credential
            return tok
        if not _USERPASS_DECODED.fullmatch(dec) or PLACEHOLDER_RE.search(dec):
            return tok
        user, pw = dec.split(":", 1)
        if is_cred_false_positive(pw):
            return tok
        return self.register(tok, Category.CRED)

    def tokenize_prompt(self, text: str) -> str:
        """Tokenize a launch prompt before it ever reaches the model.

        Issue #40, section 3: `TARGET`/`CREDS`/`SCOPE`/`TOKEN` supplied on the
        command line reach the model verbatim because the gateway only acts on
        tool calls. This applies the SAME machinery to the initial prompt — no
        value is hard-coded, everything is registered through the existing
        register()/register_credentials()/tokenize() paths, so the placeholders
        are identical to the ones the gateway rehydrates during the run and
        restores into the local report.

        Order matters:
          1. credential *pairs* (`CREDS=user:pass`) -> USER + CRED, so the user
             half is not later mis-detected as a DOMAIN and the secret half is
             never left in clear;
          2. single-secret credentials (`TOKEN=`, `-p`, `key: value`) -> CRED;
          3. the general tokenizer (IP / URL / DOMAIN / PATH / EMAIL).
        """
        if not text:
            return text
        text = unwrap_cli_message(text)

        def _pair(m: "re.Match") -> str:
            # replaced by SPAN, never by str.replace (fourth mutation run): a user that also occurs in the key
            # (« auth=auth:pw », « auth=u:pw ») replaced the key and stayed in clear
            user, secret = m.group("user"), m.group("secret")
            whole, o = m.group(0), m.start()
            if user and not PLACEHOLDER_RE.fullmatch(user) and not is_cred_false_positive(user):
                user = self.register(user, Category.USER)
            if secret and not PLACEHOLDER_RE.fullmatch(secret) and not is_cred_false_positive(secret):
                secret = self.register(secret, Category.CRED)
            return (whole[:m.start("user") - o] + user + whole[m.end("user") - o:m.start("secret") - o] + secret
                    + whole[m.end("secret") - o:])

        text = _PROMPT_CRED_LIST_RE.sub(self._cred_list, text)
        text = _PROMPT_TOKEN_LIST_RE.sub(self._token_list, text)
        # The generic pair pattern now only serves the keys the list parser does
        # not own (``auth=user:pass``); re-running it over ``creds=role:USER_001:
        # CRED_001`` would register the role and a placeholder string as secrets.
        text = _PROMPT_AUTH_PAIR_RE.sub(_pair, text)
        text = self.register_credentials(text)
        text = self.tokenize(text)
        return text

    def _secret(self, value: str) -> str:
        if not value or PLACEHOLDER_RE.fullmatch(value) or is_cred_false_positive(value):
            return value
        return self.register(value, Category.CRED)

    def _user(self, value: str) -> str:
        if not value or PLACEHOLDER_RE.fullmatch(value) or is_cred_false_positive(value):
            return value
        return self.register(value, Category.USER)

    def _cred_item(self, item: str) -> str:
        """One CREDS item: 3+ fields = role:user:password (the password may contain
        ':'), 2 = user:password (or user/password), 1 = a bare secret. The role
        stays readable, the user becomes USER, the password CRED."""
        if not item:
            return item
        parts = item.split(":")
        if len(parts) == 1 and "/" in item:
            u, p = item.split("/", 1)
            return f"{self._user(u)}/{self._secret(p)}"
        if len(parts) >= 3:
            return f"{parts[0]}:{self._user(parts[1])}:{self._secret(':'.join(parts[2:]))}"
        if len(parts) == 2:
            return f"{self._user(parts[0])}:{self._secret(parts[1])}"
        return self._secret(item)

    def _cred_list(self, m: "re.Match") -> str:
        """``CREDS=role:user:pass,user:pass,secret`` (the shape build_cli_prompt and
        mask_secret_item use). P1: only the FIRST pair used to be tokenized, every
        further password reached the model in clear. E1/E2 (review 2): quoted values
        are unescaped first and a free value ends at whitespace only. The output is
        always the unquoted ``role:USER_n:CRED_n`` list the agent prompt documents."""
        if m.group("q") is not None:
            items = split_quoted_items(m.group("q"))
        else:
            items = re.split(r",\s*", m.group("val"))
            items = [x for line in items for x in re.split(r"\s*\n\s*", line)]
        return m.group("key") + ",".join(self._cred_item(i.strip()) if i.strip() else "" for i in items)

    def _token_item(self, item: str) -> str:
        sm = _SCHEME_ITEM_RE.match(item)
        if sm:
            return f"{sm.group('scheme')} {self._secret(sm.group('tok').strip())}"
        return self._secret(item)

    def _token_list(self, m: "re.Match") -> str:
        """``TOKEN=t1,t2``, ``TOKEN="Bearer x y"`` and the hand-typed ``TOKEN=Bearer
        xyz`` (P2: the scheme word used to become the secret and ``xyz`` reached the
        model)."""
        if m.group("q") is not None:
            return m.group("key") + ",".join(self._token_item(i.strip()) for i in split_quoted_items(m.group("q")))
        scheme = m.group("scheme")
        if scheme:
            # ``Bearer CRED_001,CRED_002`` (an already tokenized list, re-seen by the
            # messages.transform hook) must stay as is: each comma item is its own secret.
            toks = ",".join(self._secret(t) for t in m.group("tok").split(","))
            return f"{m.group('key')}{scheme}{m.group('sp')}{toks}"
        items = re.split(r",\s*", m.group("val"))
        return m.group("key") + ",".join(self._token_item(t) if t else t for t in items)

    def _categorize_host(self, host: str) -> Category:
        low = host.lower()
        if _is_private_ip(host):
            return Category.IP_PRIVATE
        if _is_private_ip(host) is False:
            return Category.IP_PUBLIC
        if "." not in low or low.endswith(_INTERNAL_SUFFIXES):
            return Category.HOST_INTERNAL
        return Category.DOMAIN

    # -- tokenization (real -> placeholders) ---------------------------------
    def tokenize(self, text: str) -> str:
        """Replace every real sensitive value in ``text`` with its placeholder.

        Safe to call on both LLM-bound context and on tool output. Ordering is
        important: URLs (which contain hosts) are handled before bare hosts.
        """
        if not text:
            return text
        enabled = set(self.enabled_categories)

        def sub_url(m: re.Match) -> str:
            return self.register(m.group(0), Category.URL)

        def sub_email(m: re.Match) -> str:
            # ``CRED_001@db.internal`` is the userinfo of a DSN whose secret is already tokenized, not an address: the
            # host is left to the host passes (an EMAIL holding a placeholder would never rehydrate for execution)
            if PLACEHOLDER_RE.fullmatch(m.group(0).split("@", 1)[0]):
                return m.group(0)
            return self.register(m.group(0), Category.EMAIL)

        def sub_ip(m: re.Match) -> str:
            val = m.group(0)
            base = val.split("%", 1)[0]
            # "d::" in "std::vector" is a technically valid IPv6 but almost always
            # source code, not an address. Skip a lone 1-2 hex-digit hextet + "::";
            # real link-local/global prefixes (fe80, 2001, fc00, ...) are 4 digits.
            if _SHORT_V6_ARTEFACT_RE.fullmatch(base):
                return val
            priv = _is_private_ip(val)
            cat = Category.IP_PRIVATE if priv else Category.IP_PUBLIC
            if cat not in enabled:
                return val
            return self.register(val, cat)

        def sub_domain(m: re.Match) -> str:
            val = m.group(0)
            # A filename is not a host. Tokenizing `wp-config.php` as DOMAIN_004
            # blinds the model to the very patterns it is meant to hunt for.
            if _looks_like_filename(val):
                return val
            cat = self._categorize_host(val)
            if cat not in enabled:
                return val
            return self.register(val, cat)

        def sub_path(m: re.Match) -> str:
            return self.register(m.group(0), Category.PATH)

        def sub_ldap_dn(m: re.Match) -> str:
            # An LDAP distinguished name spells the domain out component by
            # component ("DC=evilcorp,DC=local"), which the dotted-FQDN pattern
            # never matches — the domain then leaks through every LDAP/BloodHound
            # enumeration. Register the whole DC run as one DOMAIN value so the
            # model sees a placeholder and the report rehydrates the exact DN.
            return self.register(m.group(0), Category.DOMAIN)

        if Category.URL in enabled:
            text = _URL_RE.sub(sub_url, text)
        if Category.EMAIL in enabled:
            text = _EMAIL_RE.sub(sub_email, text)
        # PATH before DOMAIN: a path segment such as ``file.txt`` also matches the
        # FQDN pattern, so tokenizing paths first stops the domain pass from
        # eating a path component (and corrupting the stored path value). This
        # interaction only surfaced once DOMAIN and PATH were both enabled by
        # default — see issue #40.
        if Category.PATH in enabled:
            text = _PATH_RE.sub(sub_path, text)
        if enabled & {Category.IP_PRIVATE, Category.IP_PUBLIC}:
            # IPv6 before IPv4: an IPv4-mapped IPv6 (::ffff:192.168.1.1) embeds a
            # v4 literal, so the v6 pass must claim the whole address first.
            text = _IPV6_RE.sub(sub_ip, text)
            text = _IPV4_RE.sub(sub_ip, text)
        if enabled & {Category.HOST_INTERNAL, Category.DOMAIN}:
            # LDAP DN domain (DC=x,DC=y) before the dotted pass: it is not dotted
            # and would otherwise slip straight through to the model.
            text = _LDAP_DN_RE.sub(sub_ldap_dn, text)
            text = _DOMAIN_RE.sub(sub_domain, text)
        return text

    # -- rehydration (placeholder -> real). Local execution paths only. ------
    # Categories whose real values are NEVER restored into an executed command.
    SECRET_CATEGORIES = (Category.CRED,)

    def rehydrate(self, placeholder: str, allow_secret: bool = False) -> Optional[str]:
        """Resolve a single placeholder to its real value.

        Returns None if unknown, if the vault has expired, or if the value is a
        secret (SECRET_CATEGORIES) and ``allow_secret`` was not explicitly set —
        the only path that may pass ``allow_secret=True`` is a vetted local-only
        report renderer, never anything that flows back to the LLM.
        """
        if self.is_expired():
            return None
        entry = self._by_ph.get(placeholder)
        if entry is None:
            return None
        if entry.category in self.SECRET_CATEGORIES and not allow_secret:
            return None
        return self._decrypt(entry.ciphertext)

    def category_of(self, placeholder: str) -> Optional[Category]:
        entry = self._by_ph.get(placeholder)
        return entry.category if entry else None

    def known_placeholders(self) -> List[str]:
        return list(self._by_ph.keys())

    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for entry in self._by_ph.values():
            out[entry.category.value] = out.get(entry.category.value, 0) + 1
        return out

    def __repr__(self) -> str:  # never leak the mapping
        return (
            f"PrivacyVault(session={self.session_id!r}, entries={len(self._by_ph)}, "
            f"expired={self.is_expired()})"
        )
