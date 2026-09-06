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
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

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
_CRED_PATTERNS = (
    # -pS3cret / --password=S3cret / password: S3cret / "pass": "S3cret"
    re.compile(r"(?<![\w-])(-p|--password[=\s]|--pass[=\s]|-w\s)(?P<secret>[^\s\"',;|&]{4,})"),
    re.compile(r"(?i)[A-Za-z0-9_$.\-]{0,32}(?:passwords?|passwd|passphrase|pass|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|credentials?)\s*[:=]>?\s*[\"']?(?P<secret>[^\s\"',;|&<>]{4,})"),
    # Authorization: Bearer <token> / Basic <b64>
    re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic|token)\s+(?P<secret>[A-Za-z0-9._~+/=\-]{8,})"),
    # user:password@host inside a URI
    re.compile(r"(?<=://)[A-Za-z0-9._%\-]+:(?P<secret>[^\s@/:]{4,})(?=@)"),
    # NTLM / NT hash and long hex digests worth protecting
    re.compile(r"(?<![A-Fa-f0-9])(?P<secret>[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32})(?![A-Fa-f0-9])"),
)

# Values that match a credential pattern but carry no secret.
_CRED_FALSE_POSITIVES = frozenset({
    "none", "null", "true", "false", "changeme", "password", "redacted",
    "xxxx", "****", "<password>", "$password", "password}",
})

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
        if _HAVE_FERNET:
            import base64

            self._fernet_key = base64.urlsafe_b64encode(self._key)
            self._fernet = Fernet(self._fernet_key)
        else:  # pragma: no cover
            self._fernet = None

    # -- lifecycle -----------------------------------------------------------
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
        for pattern in _CRED_PATTERNS:
            def sub(m):
                secret = m.group("secret")
                if not secret or secret.lower() in _CRED_FALSE_POSITIVES:
                    return m.group(0)
                if PLACEHOLDER_RE.fullmatch(secret):
                    return m.group(0)  # already tokenized
                return m.group(0).replace(secret, self.register(secret, Category.CRED))

            text = pattern.sub(sub, text)
        return text

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

        def _pair(m: "re.Match") -> str:
            user, secret = m.group("user"), m.group("secret")
            out = m.group(0)
            if user and not PLACEHOLDER_RE.fullmatch(user) and user.lower() not in _CRED_FALSE_POSITIVES:
                out = out.replace(user, self.register(user, Category.USER), 1)
            if secret and not PLACEHOLDER_RE.fullmatch(secret) and secret.lower() not in _CRED_FALSE_POSITIVES:
                out = out.replace(secret, self.register(secret, Category.CRED))
            return out

        text = _PROMPT_CRED_PAIR_RE.sub(_pair, text)
        text = self.register_credentials(text)
        text = self.tokenize(text)
        return text

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
