"""Killing tests for the PERMISSIVE survivors of the v3 privacy mutation run (MUTATION-V3.md).

Each case is a key / password rendering the v3 audit suite does not exercise and that a surviving mutant of the v3
privacy code lets through to the model (or crashes on: ``server._sanitize_for_model`` is fail-OPEN, an exception
returns the raw value). Throwaway keys only, generated per module; nothing secret is printed on failure.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import shutil
import subprocess
import urllib.parse

import pytest

from src.privacy.gateway import CommandGateway
from src.privacy.vault import PrivacyVault
from tests.test_cycle3_privacy_keyblocks import term_wrap

pytestmark = pytest.mark.skipif(not (shutil.which("ssh-keygen") and shutil.which("openssl")),
                                reason="ssh-keygen and openssl are needed to generate throwaway keys")


class _Keys(dict):
    def __repr__(self):
        return f"<{len(self)} throwaway keys>"


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("mutkeys")
    out = _Keys()

    def run(*a):
        subprocess.run(a, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)

    for name, args in (("ssh-ed25519", ("-t", "ed25519")), ("ssh-rsa", ("-t", "rsa", "-b", "2048"))):
        run("ssh-keygen", "-q", "-N", "", "-C", "mut", "-f", str(d / name), *args)
        out[name] = (d / name).read_text().rstrip("\n")
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(d / "p8.pem"))
    run("openssl", "pkey", "-in", str(d / "p8.pem"), "-traditional", "-out", str(d / "rt.pem"))
    run("openssl", "pkcs8", "-topk8", "-in", str(d / "p8.pem"), "-v2", "aes-256-cbc", "-passout", "pass:throwaway",
        "-out", str(d / "pe.pem"))
    out["rsa-trad"] = (d / "rt.pem").read_text().rstrip("\n")
    out["pkcs8-enc"] = (d / "pe.pem").read_text().rstrip("\n")
    pub = base64.b64encode(secrets.token_bytes(51)).decode()
    priv = base64.b64encode(secrets.token_bytes(36)).decode()
    out["putty-ppk"] = ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: mut\nPublic-Lines: 2\n"
                        + pub[:64] + "\n" + pub[64:] + "\nPrivate-Lines: 1\n" + priv + "\nPrivate-MAC: "
                        + secrets.token_hex(32))
    return out


_B64L = re.compile(r"[A-Za-z0-9+/=]{16,}")
_HDR = set()                                            # base64 of the PEM headers: public, never counted


def _rows(k):
    ls = k.split("\n")
    if ls[0].startswith("PuTTY-User-Key-File"):
        ls = ls[next(j for j, x in enumerate(ls) if x.startswith("Private-Lines:")) + 1:]
    return [x for x in ls if _B64L.fullmatch(x)]


def _w(s, n=12):
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def _leaks(out, k, extra=()):
    ws = set().union(*(_w(r) for r in _rows(k))) | set(extra)
    return sum(1 for w in ws if w in out)


def _leaks_known(out, k):
    """``_leaks`` over the rows the generic PATH tokenizer leaves whole: a key row holding ``+/ab/cd`` is split by a
    PATH placeholder BEFORE the known-key pass and its short remainder is a separate, documented residual
    (``test_residual_known_key_row_split_by_a_path_token``)."""
    from src.privacy.vault import _PATH_RE
    ws = set().union(*(_w(r) for r in _rows(k) if not _PATH_RE.search(r)))
    return sum(1 for w in ws if w in out)


def _b64_secret_windows(k, enc):
    """12-char windows of the base64 of ``k`` that do not come from its (public) BEGIN line."""
    hdr = base64.b64encode(k.split("\n")[0].encode()).decode()
    return _w(enc) - _w(hdr[:-4])


def _san(text, v=None):
    v = v or PrivacyVault("mutkill")
    return CommandGateway().sanitize_output(text, v), v


def _tail(k, n):
    return k.split("\n")[-n:]


# ── key renderings (one per surviving PERMISSIVE mutant family; mutant ids in MUTATION-V3.md) ──────────────────

RENDER = {
    # _strip_row (#3 #4 #5 #6 #7): a key tail printed inside a box / psql cell, no header row
    "tail-box-tight": lambda k: "\n".join("|" + x + "|" for x in _tail(k, 4)) + "\n",
    "tail-box-spaced": lambda k: "\n".join("| " + x + " |" for x in _tail(k, 4)) + "\n",
    "tail-psql-cont-sp": lambda k: "\n".join("    | " + x + (" +" if i < 3 else "") for i, x in enumerate(_tail(k, 4))) + "\n",
    "tail-psql-unicode": lambda k: "\n".join("│" + x + ("↵" if i < 3 else "") + "│" for i, x in enumerate(_tail(k, 4))) + "\n",
    # find_key_tails (#29 #30 #73 #74 #76): newline-stripped tail glued to END (``tail -c … | tr -d '\n'``)
    "tail-joined": lambda k: "".join(_tail(k, 4)) + "\n",
    # find_key_tails (#32 #66): an END in prose / code / after a short word BEFORE the real tail
    "decoy-code-then-tail": lambda k: 'x = "-----END RSA PRIVATE KEY-----"\n' + "\n".join(_tail(k, 4)) + "\n",
    "decoy-else-then-tail": lambda k: "else:\n-----END RSA PRIVATE KEY-----\n" + "\n".join(_tail(k, 4)) + "\n",
    "decoy-short-then-tail": lambda k: "abcd\n-----END RSA PRIVATE KEY-----\n" + "\n".join(_tail(k, 4)) + "\n",
    # find_key_tails (#40 #41: TypeError on a 2nd tail): ``tail -n4 a b``
    "two-tails": lambda k: "==> a <==\n" + "\n".join(_tail(k, 4)) + "\n\n==> b <==\n" + "\n".join(_tail(k, 3)) + "\n",
    # find_key_tails (#60): CRLF tail
    "tail-crlf": lambda k: "\r\n".join(_tail(k, 4)) + "\r\n",
    # _dewrap / find_wrapped / find_key_tails (#44 #62 #84 #86 #87 #89 #100 #102 #104 #107)
    "wrap33-tail": lambda k: term_wrap("\n".join(_tail(k, 4)) + "\n", 33),
    "wrap16": lambda k: term_wrap(k, 16),
    "wrap20": lambda k: term_wrap(k, 20),
    "wrap18": lambda k: term_wrap(k, 18),
    "wrap33": lambda k: term_wrap(k, 33),
    "wrap-2full": lambda k: term_wrap("\n".join(_tail(k, 2)), 33),
    "wrap30-crlf": lambda k: term_wrap(k.replace("\n", "\r\n"), 30),
    "wrap33-head": lambda k: term_wrap("\n".join(k.split("\n")[:4]), 33),
}

CASES = [
    ("tail-box-tight", "rsa-trad"), ("tail-box-tight", "ssh-ed25519"), ("tail-box-spaced", "rsa-trad"),
    ("tail-psql-cont-sp", "rsa-trad"), ("tail-psql-cont-sp", "ssh-ed25519"), ("tail-psql-unicode", "rsa-trad"),
    ("tail-joined", "rsa-trad"), ("tail-joined", "ssh-ed25519"),
    ("decoy-code-then-tail", "rsa-trad"), ("decoy-else-then-tail", "rsa-trad"), ("decoy-short-then-tail", "ssh-ed25519"),
    ("two-tails", "rsa-trad"), ("two-tails", "putty-ppk"), ("tail-crlf", "rsa-trad"), ("tail-crlf", "ssh-ed25519"),
    ("wrap33-tail", "ssh-ed25519"), ("wrap33-tail", "putty-ppk"), ("wrap16", "rsa-trad"), ("wrap16", "ssh-ed25519"),
    ("wrap20", "rsa-trad"), ("wrap20", "ssh-rsa"), ("wrap33", "ssh-rsa"), ("wrap-2full", "ssh-rsa"),
    ("wrap-2full", "pkcs8-enc"), ("wrap30-crlf", "pkcs8-enc"), ("wrap33-head", "pkcs8-enc"),
    # narrow terminal wrap of a PuTTY key (_dewrap / _view_to_text survivors #101 #103 #115)
    ("wrap16", "putty-ppk"), ("wrap18", "putty-ppk"), ("wrap20", "putty-ppk"),
]


@pytest.mark.parametrize("render,name", CASES)
def test_key_rendering_never_reaches_the_model(keys, render, name):
    k = keys[name]
    for path in ("gateway", "prompt"):
        text = RENDER[render](k)
        out = _san(text)[0] if path == "gateway" else PrivacyVault("p").tokenize_prompt(text)
        assert _leaks(out, k) == 0, (render, name, path)


# ── encoded keys (find_encoded_private_keys / _b64_signatures) ────────────────────────────────────────────

def _b64(k):
    return base64.b64encode(k.encode()).decode()


ENC = {
    "b64-off1": lambda k: base64.b64encode(b"x" + k.encode()).decode() + "\n",             # #149
    "b64-two": lambda k: _b64(k) + "\nsep\n" + base64.b64encode(b"z" + k.encode()).decode() + "\n",   # #154 #155 #245 #246 #250
    "b64-w60": lambda k: "\n".join(re.findall(".{1,60}", _b64(k))) + "\n",               # #191 #193
    "b64-w76-crlf": lambda k: "\r\n".join(re.findall(".{1,76}", _b64(k))) + "\r\n",      # #199 #200
    "b64-w76-trailer": lambda k: "\n".join(re.findall(".{1,76}", _b64(k))) + "\ntail-no-eol",   # #187
    "b64-glued": lambda k: "key=" + _b64(k) + "&x=1\n",                                   # #232
    "b64-trunc-41": lambda k: _b64(k)[:41] + "\n",                                          # #231
    "b64-trunc-4n+1": lambda k: _b64(k)[: (len(_b64(k)) // 8) * 4 + 1] + "\n",            # #219 #223 #229 #231
    "url-two": lambda k: "a=" + urllib.parse.quote(k, safe="") + "&b=" + urllib.parse.quote(k, safe="") + "\n",  # #245…
}


@pytest.mark.parametrize("name", ["rsa-trad", "ssh-ed25519", "putty-ppk"])
@pytest.mark.parametrize("render", sorted(ENC))
def test_encoded_key_never_reaches_the_model(keys, render, name):
    if render.startswith("url") and name == "putty-ppk":
        pytest.skip("documented residual: a URL-encoded PPK has no encoded-marker detector")
    k = keys[name]
    text = ENC[render](k)
    extra = set()
    for r in _B64L.findall(text):
        extra |= _b64_secret_windows(k, r) if not render.startswith("url") else set()
    out, _ = _san(text)
    assert _leaks(out, k, extra) == 0, (render, name)


# ── a known key re-printed without markers ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["rsa-trad", "ssh-ed25519", "putty-ppk"])
def test_rows_reprinted_after_the_key_was_first_seen_as_a_tail(keys, name):
    """#67 #68: the canonical value of a TAIL span must keep its rows newline-separated, or known_key_windows has no
    window for it and the rows re-printed later (``sed -n``, ``> row`` quoting) go through."""
    k = keys[name]
    v = PrivacyVault("seq")
    _san("\n".join(_tail(k, 3)) + "\n", v)
    rows = _rows("\n".join(_tail(k, 3)))
    for text in ("\n".join(rows) + "\n", "\n".join("> " + r for r in rows) + "\n"):
        out, _ = _san(text, v)
        assert _leaks_known(out, k) == 0


@pytest.mark.parametrize("name", ["rsa-trad", "ssh-ed25519"])
def test_known_key_windows_skip_non_credential_entries(keys, name):
    """#392: an IP / host registered BEFORE the key must not stop known_key_windows (continue, not break)."""
    k = keys[name]
    v = PrivacyVault("seq")
    _san("host 10.1.2.3 api.example.com\n", v)
    _san(k + "\n", v)
    out, _ = _san("\n".join(k.split("\n")[2:-2]) + "\n", v)
    assert _leaks_known(out, k) == 0


# closed 18/11 (production readiness): find_bare_key_rows
def test_residual_known_key_row_split_by_a_path_token():
    rnd = base64.b64encode(secrets.token_bytes(48 * 6)).decode().replace("/", "A").replace("+", "B")
    rows = [rnd[i:i + 64] for i in range(0, len(rnd), 64)]
    r = rows[2]
    rows[2] = r[:12] + "+/ab/cd" + r[19:50] + "+" + r[51:]          # PATH eats « /ab/cd… » up to the 2nd « + »
    k = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(rows) + "\n-----END RSA PRIVATE KEY-----"
    v = PrivacyVault("seq")
    _san(k + "\n", v)
    out, _ = _san("\n".join(rows[1:4]) + "\n", v)
    assert _leaks(out, k) == 0


# ── passwords ───────────────────────────────────────────────────────────────────────────────────────────────

PW = "Qz7vKp2LmX9wRt4N"                                # synthetic

PW_CASES = {
    "csv-mismatch-then-ok": f"id,username,password\nbroken,row\n2,admin,{PW}\n",          # #298
    "csv-quoted-header": f'"id","username","password"\n1,"admin","{PW}"\n',              # #316
    "csv-single-quoted": f"id,username,password\n1,admin,'{PW}'\n",                      # #316
    "csv-two-rows": f"query ok\nid,username,password\n1,admin,{PW}\n2,bob,{PW[::-1]}\n",  # #323
    "csv-two-columns": f"user,password\nadmin,{PW}\n",                                     # #330
    "csv-password-first": f"password,user\n{PW},admin\n",                                 # #330
    # #379 #380: a tool slot holding a placeholder / a false positive must not crash the pass (fail-open middleware)
    "slot-placeholder-then-pw": f"<password>CRED_001</password>\npassword={PW}\n",
    "slot-false-positive-then-pw": f"<password>changeme</password>\npassword={PW}\n",
}


@pytest.mark.parametrize("case", sorted(PW_CASES))
def test_password_shapes_never_reach_the_model(case):
    for s in (PW, PW[::-1]):
        out, _ = _san(PW_CASES[case])
        assert not any(s[i:i + 8] in out for i in range(len(s) - 7)), case


# ── defence in depth: each v3 detector ALONE (latent survivors, masked end-to-end by an overlapping layer) ──────

from src.privacy import keyblocks as kb                                         # noqa: E402
from tests.test_cycle3_privacy_keyblocks import psql_aligned                    # noqa: E402

UNIT = [
    # (detector, rendering) pairs the detector covers on its own today
    ("find_key_tails", lambda k: "\r\n".join(_tail(k, 4)) + "\r\n"),                       # #58
    ("find_wrapped_private_keys", lambda k: "\r\n".join(_tail(k, 4)) + "\r\n"),            # #58
    ("find_wrapped_private_keys", lambda k: term_wrap(k.replace("\n", "\r\n"), 30)),       # #82
    ("find_wrapped_private_keys", lambda k: term_wrap(k, 16)),                             # #92
    ("find_wrapped_private_keys", lambda k: term_wrap(k, 17)),                             # #92
    ("find_wrapped_private_keys", lambda k: term_wrap(psql_aligned(k), 47)),               # #92
    ("find_wrapped_private_keys", lambda k: psql_aligned(k)),                              # #94 #101 #113 #115
    ("find_wrapped_private_keys", lambda k: "\n".join(_tail(k, 5)[:2]) + "\n\n\n" + "\n".join(_tail(k, 3)) + "\n"),  # #34 #52
]


@pytest.mark.parametrize("name", ["rsa-trad", "ssh-ed25519"])
@pytest.mark.parametrize("i", range(len(UNIT)))
def test_each_detector_alone_covers_its_rendering(keys, i, name):
    fn, render = UNIT[i]
    k = keys[name]
    text = render(k)
    spans = getattr(kb, fn)(text)
    masked, cur = [], 0
    for a, b, _ in sorted(spans):
        masked.append(text[cur:a] + "#")
        cur = max(cur, b)
    masked.append(text[cur:])
    masked = "".join(masked)
    if _leaks(text, k) and not spans:
        pytest.fail(f"{fn} found nothing")
    assert _leaks(masked, k) == 0, fn


def _accept(v):
    return True


@pytest.mark.parametrize("text", [f"id,username,password\n1,admin,{PW}\n", f"id\tusername\tpassword\n1\tadmin\t{PW}\n",
                                  f'"id","username","password"\n1,"admin","{PW}"\n', f"id,password\n1,'{PW}'\n"])
def test_delimited_span_is_exactly_the_value(text):
    """#288 #289 #302 #303 #315: the span is the value, to the character (no char leaked at either end)."""
    spans = kb.find_delimited_secrets(text, _accept)
    assert [(text[a:b], v) for a, b, v in spans] == [(PW, PW)]


def test_box_table_last_column_value_span():
    """#362: a unicode box whose secret column is the last one."""
    text = f"│ id │ password │\n├────┼──────────┤\n│  1 │ {PW} │\n"
    spans = kb.find_table_secrets(text, _accept)
    assert [text[a:b] for a, b, _ in spans] == [PW]


@pytest.mark.parametrize("enc", ["%0D%0A", "%0a"])
def test_url_encoded_key_span_includes_the_encoded_newline(keys, enc):
    """#236 #239: the span of a URL-encoded PEM runs past END over its encoded line break."""
    k = keys["rsa-trad"]
    q = urllib.parse.quote(k, safe="").replace("%0A", enc if enc != "%0D%0A" else "%0D%0A")
    text = "q=" + q + enc + "&n=1\n"
    spans = kb.find_encoded_private_keys(text)
    assert len(spans) == 1 and text[spans[0][1]:].startswith("&n=1")


# ── fail-closed: a crash of the sanitizer never hands the raw value to the model (#377 #381 #385) ──────────────

def test_sanitizer_crash_withholds_the_output(monkeypatch):
    from src import server
    pw = "Zr4kQ9wLm2Tx7Vb"
    raw = f"<password>{pw}</password>"

    def boom(*a, **k):
        raise RuntimeError("sanitizer bug")
    monkeypatch.setattr(server, "PRIVACY_ENABLED", True)
    monkeypatch.setattr(server._command_gateway, "sanitize_result", boom)
    monkeypatch.setattr(server, "_privacy_enabled_for", lambda sid: True)
    out = server._sanitize_for_model(raw, "s-failclosed")
    assert pw not in str(out)
    out2 = server._sanitize_for_model({"evidence": raw}, "s-failclosed")
    assert pw not in json.dumps(out2)
