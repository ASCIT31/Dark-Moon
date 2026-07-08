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


# A placeholder is CATEGORY_NNN. Restrict to our known prefixes so we never
# mistake an unrelated uppercase token for a placeholder.
_PREFIXES = "|".join(sorted((c.value for c in Category), key=len, reverse=True))
PLACEHOLDER_RE = re.compile(rf"\b(?P<ph>(?:{_PREFIXES})_\d{{3,}})\b")

# --- Detection patterns (ordered from most specific to least). ----------------
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`|\\]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# FQDN with at least one dot and a 2+ char TLD; label-safe.
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)
# Absolute unix paths (>=2 segments) and Windows paths. Kept conservative.
_PATH_RE = re.compile(r"(?<![\w./])(?:/[A-Za-z0-9._\-]+){2,}/?|[A-Za-z]:\\\\?(?:[^\s\"'<>|]+)")

# Internal-looking single-label hosts / suffixes are treated as HOST_INTERNAL.
_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home", ".intra", ".test")


def _is_private_ip(value: str) -> Optional[bool]:
    try:
        ip = ipaddress.ip_address(value)
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
    enabled_categories: Tuple[Category, ...] = (
        Category.URL,
        Category.EMAIL,
        Category.IP_PRIVATE,
        Category.IP_PUBLIC,
        Category.HOST_INTERNAL,
        Category.DOMAIN,
        Category.PATH,
    )
    created_at: float = field(default_factory=time.time)

    # internal state (never logged)
    _key: bytes = field(default_factory=lambda: os.urandom(32), repr=False)
    _hmac_key: bytes = field(default_factory=lambda: os.urandom(32), repr=False)
    _fernet_key: bytes = field(default=b"", repr=False)
    _by_hash: Dict[str, _Entry] = field(default_factory=dict, repr=False)
    _by_ph: Dict[str, _Entry] = field(default_factory=dict, repr=False)
    _counters: Dict[Category, int] = field(default_factory=dict, repr=False)

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
            priv = _is_private_ip(val)
            cat = Category.IP_PRIVATE if priv else Category.IP_PUBLIC
            if cat not in enabled:
                return val
            return self.register(val, cat)

        def sub_domain(m: re.Match) -> str:
            val = m.group(0)
            cat = self._categorize_host(val)
            if cat not in enabled:
                return val
            return self.register(val, cat)

        def sub_path(m: re.Match) -> str:
            return self.register(m.group(0), Category.PATH)

        if Category.URL in enabled:
            text = _URL_RE.sub(sub_url, text)
        if Category.EMAIL in enabled:
            text = _EMAIL_RE.sub(sub_email, text)
        if enabled & {Category.IP_PRIVATE, Category.IP_PUBLIC}:
            text = _IPV4_RE.sub(sub_ip, text)
        if enabled & {Category.HOST_INTERNAL, Category.DOMAIN}:
            text = _DOMAIN_RE.sub(sub_domain, text)
        if Category.PATH in enabled:
            text = _PATH_RE.sub(sub_path, text)
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
