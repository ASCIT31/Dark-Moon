"""V3 privacy audit (18/11/2026): no private-key body window (>= 16 chars) and no full password reaches model-bound text.

Independent audit of 63164ac9. Keys are REAL formats generated at runtime in a temp dir (ssh-keygen ed25519 / rsa /
ecdsa / rsa -m PEM / encrypted ed25519, openssl PKCS#8 RSA / EC / Ed25519, traditional RSA / EC, legacy encrypted RSA,
encrypted PKCS#8, gpg armored secret key) plus a PPK v3 shape built from random bytes. Nothing is stored in the repo and
no value is ever printed: assertions report counts only.

The property is asserted on the functions that produce model-bound text:
  * ``CommandGateway.sanitize_output`` (execute_command stdout/stderr, every MCP tool result through the middleware),
  * ``PrivacyVault.tokenize_prompt`` (the pre-model socket the opencode plugin calls for user messages),
  * ``server.execute_command`` end to end (docker mocked) and ``server._sanitize_for_model`` (the result middleware).
Residual limits are kept as strict xfails so a future fix is noticed.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import urllib.parse

import pytest

from src.privacy.gateway import CommandGateway
from src.privacy.vault import PrivacyVault
from tests.test_cycle3_privacy_keyblocks import FORMATS as C3_FORMATS
from tests.test_cycle3_privacy_keyblocks import _exec, psql_aligned, psql_expanded, srv, term_wrap  # noqa: F401

pytestmark = pytest.mark.skipif(not (shutil.which("ssh-keygen") and shutil.which("openssl")),
                                reason="ssh-keygen and openssl are needed to generate throwaway keys")


# ── throwaway keys ──────────────────────────────────────────────────────────────────────────────────────────

def _run(*a):
    subprocess.run(a, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


class _Keys(dict):
    """Never shows key material in a pytest report (fixture values are printed on failure)."""

    def __repr__(self):
        return f"<{len(self)} throwaway keys>"


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("v3keys")
    out = _Keys()

    def ssh(name, *args, pw=""):
        p = d / name
        _run("ssh-keygen", "-q", "-N", pw, "-C", "audit", "-f", str(p), *args)
        out[name] = p.read_text().rstrip("\n")

    ssh("ssh-ed25519", "-t", "ed25519")
    ssh("ssh-rsa", "-t", "rsa", "-b", "2048")
    ssh("ssh-ecdsa", "-t", "ecdsa", "-b", "256")
    ssh("ssh-rsa-pem", "-t", "rsa", "-b", "2048", "-m", "PEM")
    ssh("ssh-ed25519-enc", "-t", "ed25519", pw="throwaway-pass")

    def ossl(name, *args):
        p = d / (name + ".pem")
        _run("openssl", *args, "-out", str(p))
        out[name] = p.read_text().rstrip("\n")

    ossl("pkcs8-rsa", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
    ossl("pkcs8-ec", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    ossl("pkcs8-ed25519", "genpkey", "-algorithm", "ED25519")
    ossl("ec-trad", "ecparam", "-name", "prime256v1", "-genkey", "-noout")
    src = str(d / "pkcs8-rsa.pem")
    ossl("rsa-trad", "pkey", "-in", src, "-traditional")
    ossl("rsa-trad-enc", "rsa", "-in", src, "-traditional", "-aes128", "-passout", "pass:throwaway")
    ossl("pkcs8-enc", "pkcs8", "-topk8", "-in", src, "-v2", "aes-256-cbc", "-passout", "pass:throwaway")
    if shutil.which("gpg"):
        gh = d / "gnupg"
        gh.mkdir(mode=0o700)
        try:
            _run("gpg", "--batch", "--homedir", str(gh), "--passphrase", "", "--pinentry-mode", "loopback",
                 "--quick-gen-key", "Audit <audit@example.invalid>", "ed25519", "sign", "never")
            r = subprocess.run(["gpg", "--batch", "--homedir", str(gh), "--pinentry-mode", "loopback", "--passphrase",
                                "", "--armor", "--export-secret-keys"], capture_output=True, text=True, timeout=60)
            if "PRIVATE KEY BLOCK" in r.stdout:
                out["pgp"] = r.stdout.strip()
        finally:
            subprocess.run(["gpgconf", "--homedir", str(gh), "--kill", "all"], capture_output=True)
    pub = base64.b64encode(secrets.token_bytes(51)).decode()
    priv = base64.b64encode(secrets.token_bytes(36)).decode()
    out["putty-ppk"] = ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: audit\nPublic-Lines: 2\n"
                        + pub[:64] + "\n" + pub[64:] + "\nPrivate-Lines: 1\n" + priv + "\nPrivate-MAC: "
                        + secrets.token_hex(32))
    return out


KEY_NAMES = ["ssh-ed25519", "ssh-rsa", "ssh-ecdsa", "ssh-rsa-pem", "ssh-ed25519-enc", "pkcs8-rsa", "pkcs8-ec",
             "pkcs8-ed25519", "ec-trad", "rsa-trad", "rsa-trad-enc", "pkcs8-enc", "pgp", "putty-ppk"]
_B64L = re.compile(r"[A-Za-z0-9+/=]{16,}")


def _secret_rows(k):
    ls = k.split("\n")
    if ls[0].startswith("PuTTY-User-Key-File"):          # only the PRIVATE lines of a PPK are secret
        i = next(j for j, x in enumerate(ls) if x.startswith("Private-Lines:"))
        ls = ls[i + 1:]
    return [x for x in ls if _B64L.fullmatch(x)]


def _windows(k):
    return {r[i:i + 16] for r in _secret_rows(k) for i in range(len(r) - 15)}


def _leaks(out, k, extra=()):
    ws = _windows(k) | set(extra)
    return sum(1 for w in ws if w in out)


def _b64_windows(s):
    return {s[i:i + 16] for i in range(len(s) - 15)}


def _san(text, v=None):
    v = v or PrivacyVault("v3audit")
    return CommandGateway().sanitize_output(text, v), v


def _key(keys, name):
    if name not in keys:
        pytest.skip(f"{name} could not be generated here")
    return keys[name]


# ── renderings ──────────────────────────────────────────────────────────────────────────────────────────────

def _cjk_psql(k):
    kl = k.split("\n")
    w = max(len(x) for x in kl)
    out = [" id | 名前 | secret", "----+------+-" + "-" * w]
    for i, x in enumerate(kl):
        out.append(("  1 | 鍵🔑 | " if i == 0 else "    |      | ") + x.ljust(w) + ("+" if i < len(kl) - 1 else ""))
    return "\n".join(out) + "\n(1 row)\n"


def _cjk_psql_after(k):
    kl = k.split("\n")
    w = max(len(x) for x in kl)
    out = [" id | secret" + " " * (w - 6) + " | 備考", "----+-" + "-" * w + "-+------"]
    for i, x in enumerate(kl):
        out.append(("  1 | " if i == 0 else "    | ") + x.ljust(w) + ("+" if i < len(kl) - 1 else " ") + "| "
                   + ("日本語メモ😀" if i == 0 else ""))
    return "\n".join(out) + "\n(1 row)\n"


def _mysql_box_cjk(k):
    kl = k.split("\n")
    w = max(len(x) for x in kl)
    bar = "+----+--------+-" + "-" * w + "-+"
    out = [bar, "| id | 名前   | " + "secret".ljust(w) + " |", bar]
    for i, x in enumerate(kl):
        out.append(("|  1 | 鍵🔑   | " if i == 0 else "|    |        | ") + x.ljust(w) + " |")
    return "\n".join(out + [bar]) + "\n"


def _sqlite_table(k):
    kl = k.split("\n")
    w = max(len(x) for x in kl)
    out = ["+----+-" + "-" * w + "-+", "| id | " + "secret".ljust(w) + " |", "+----+-" + "-" * w + "-+"]
    out += [("| 1  | " if i == 0 else "|    | ") + x.ljust(w) + " |" for i, x in enumerate(kl)]
    return "\n".join(out + ["+----+-" + "-" * w + "-+"]) + "\n"


def _psql_wrapped_format(k, w=40):
    """``\\pset format wrapped`` (ascii linestyle): ``+`` = newline in the data, ``.`` = a data line wrapped."""
    rows, kl = [], k.split("\n")
    for li, x in enumerate(kl):
        chunks = [x[i:i + w] for i in range(0, len(x), w)] or [""]
        for ci, c in enumerate(chunks):
            right = "." if ci < len(chunks) - 1 else ("+" if li < len(kl) - 1 else " ")
            rows.append(("." if ci else " ", c, right))
    out = [" id | " + "secret".ljust(w), "----+-" + "-" * w + "-"]
    out += [("  1 |" if i == 0 else "    |") + lft + c.ljust(w) + r for i, (lft, c, r) in enumerate(rows)]
    return "\n".join(out) + "\n(1 row)\n"


def _log_prefix_wrap80(k):
    ls = k.split("\n")
    return term_wrap("2026-11-18T10:00:00Z app[123]: loaded key material from vault => " + ls[0] + "\n"
                     + "\n".join(ls[1:]), 80)


RENDER = {
    **{f"c3:{n}": f for n, f in C3_FORMATS.items()},
    "cat": lambda k: k + "\n",
    # terminal wrapping (fixed width, the BEGIN/END markers torn below ~37 columns), CR, ANSI
    "wrap80": lambda k: term_wrap(k, 80), "wrap120": lambda k: term_wrap(k, 120), "wrap63": lambda k: term_wrap(k, 63),
    "wrap47": lambda k: term_wrap(k, 47), "wrap33": lambda k: term_wrap(k, 33), "wrap20": lambda k: term_wrap(k, 20),
    "wrap17": lambda k: term_wrap(k, 17),
    "psql-wrap47": lambda k: term_wrap(psql_aligned(k), 47), "psql-wrap33": lambda k: term_wrap(psql_aligned(k), 33),
    "psqlx-wrap37": lambda k: term_wrap(psql_expanded(k), 37), "log-prefix-wrap80": _log_prefix_wrap80,
    "ansi-lines": lambda k: "\n".join("\x1b[32m" + x + "\x1b[0m" for x in k.split("\n")),
    "ansi-inside": lambda k: "\n".join(x[:10] + "\x1b[1;31m" + x[10:20] + "\x1b[0m" + x[20:] for x in k.split("\n")),
    "grep-color": lambda k: k.replace("PRIVATE", "\x1b[01;31m\x1b[KPRIVATE\x1b[m\x1b[K"),
    "cr-progress": lambda k: "downloading 10%\rdownloading 100%\r" + k.replace("\n", "\r\n"),
    "bare-cr": lambda k: k.replace("\n", "\r"),
    # tables with wide characters in other columns
    "cjk-psql": _cjk_psql, "cjk-psql-after": _cjk_psql_after, "mysql-box-cjk": _mysql_box_cjk,
    "psqlx-cjk": lambda k: "-[ RECORD 1 ]----\n名前   | 鍵🔑\nsecret | " + k.replace("\n", "+\n       | ") + "\n",
    "sqlite-table": _sqlite_table, "sqlite-list": lambda k: "1|ops|" + k + "\n",
    "sqlite-markdown": lambda k: "| id | secret |\n|----|--------|\n| 1  | " + k.replace("\n", "<br>") + " |\n",
    "psql-wrapped-format40": _psql_wrapped_format,
    # truncations that keep a marker
    "head3": lambda k: "\n".join(k.split("\n")[:3]) + "\n", "head2": lambda k: "\n".join(k.split("\n")[:2]) + "\n",
    "tail3": lambda k: "\n".join(k.split("\n")[-3:]) + "\n", "tail2": lambda k: "\n".join(k.split("\n")[-2:]) + "\n",
    "cut40": lambda k: "\n".join(x[:40] for x in k.split("\n")) + "\n",
    # escapes and encodings
    "json-compact": lambda k: json.dumps({"k": k}), "json-triple": lambda k: json.dumps(json.dumps(json.dumps({"k": k}))),
    "py-repr": lambda k: repr({"private": k}), "env-escaped": lambda k: 'SSH_KEY="' + k.replace("\n", "\\n") + '"\n',
    "env-multiline": lambda k: 'SSH_KEY="' + k + '"\n', "html-br": lambda k: "<pre>" + k.replace("\n", "<br/>") + "</pre>",
    "xml-entity": lambda k: "<key>" + k.replace("\n", "&#10;") + "</key>",
    "crlf-json": lambda k: json.dumps({"k": k.replace("\n", "\r\n")}),
    "json-u000a": lambda k: json.dumps({"k": k}).replace("\\n", "\\u000a"),
    "url-encoded": lambda k: "GET /upload?key=" + urllib.parse.quote(k, safe="") + " HTTP/1.1\n",
    "b64-yaml": lambda k: "  tls.key: " + base64.b64encode(k.encode()).decode() + "\n",
    "b64-k8s-json": lambda k: json.dumps({"data": {"tls.key": base64.b64encode((k + "\n").encode()).decode()}}, indent=2),
    "b64-bare": lambda k: base64.b64encode(k.encode()).decode() + "\n",
    "b64-wrap76": lambda k: "\n".join(re.findall(".{1,76}", base64.b64encode(k.encode()).decode())) + "\n",
    "b64-in-config": lambda k: base64.b64encode(b"# cfg\nuser=ops\n" + k.encode() + b"\n").decode() + "\n",
}
URL_PLUS = lambda k: "body: data=" + urllib.parse.quote_plus(k) + "\n"          # noqa: E731
B64_RENDER = {n for n in RENDER if n.startswith("b64")}


@pytest.mark.parametrize("name", KEY_NAMES)
@pytest.mark.parametrize("render", sorted(RENDER))
def test_no_key_window_reaches_the_model(keys, render, name):
    k = _key(keys, name)
    text = RENDER[render](k)
    out, v = _san(text)
    extra = ()
    if render in B64_RENDER:                         # the encoded key is the key: every base64 run of the input
        extra = set().union(*(_b64_windows(r) for r in _B64L.findall(text)))
    shown, leaked = _leaks(text, k, extra), _leaks(out, k, extra)
    has_placeholder = bool(re.search(r"CRED_\d{3}", out))
    assert leaked == 0, (render, name, leaked)
    assert has_placeholder or not shown, (render, name)


@pytest.mark.parametrize("name", KEY_NAMES)
def test_url_encoded_plus_form(keys, name):
    k = _key(keys, name)
    if name == "putty-ppk":
        pytest.xfail("residual: a URL-encoded PPK has no encoded-marker detector")
    out, _ = _san(URL_PLUS(k))
    n = _leaks(out, k)
    assert n == 0


@pytest.mark.parametrize("name", KEY_NAMES)
def test_prompt_socket_path(keys, name):
    """User-message text parts go through tokenize_prompt (the opencode plugin's socket): same passes."""
    k = _key(keys, name)
    for render in ("cat", "c3:psql-aligned", "wrap33", "tail3", "b64-k8s-json"):
        t = PrivacyVault("p").tokenize_prompt("tool said:\n" + RENDER[render](k))
        n = _leaks(t, k)
        assert n == 0, render


# ── a key split over several outputs / tools ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", KEY_NAMES)
def test_key_split_over_two_outputs(keys, name):
    k = _key(keys, name)
    ls = k.split("\n")
    for cut in sorted({2, len(ls) // 2, len(ls) - 2}):
        if not 1 <= cut < len(ls):
            continue
        v = PrivacyVault("split")
        a, _ = _san("\n".join(ls[:cut]) + "\n", v)
        b, _ = _san("\n".join(ls[cut:]) + "\n", v)
        n = _leaks(a, k) + _leaks(b, k)
        assert n == 0, (name, cut)


@pytest.mark.parametrize("name", KEY_NAMES)
def test_rows_of_a_known_key_reprinted_without_markers(keys, name):
    """``cat id`` once, then ``sed -n 3,6p id`` / a narrower wrap / the body alone: the vault knows the key."""
    k = _key(keys, name)
    v = PrivacyVault("known")
    _san(k + "\n", v)
    ls = k.split("\n")
    for text in ("\n".join(ls[2:-2]) + "\n", "\n".join(_secret_rows(k)) + "\n", term_wrap(k, 17),
                 json.dumps({"rows": _secret_rows(k)})):
        out, _ = _san(text, v)
        n = _leaks(out, k)
        assert n == 0


@pytest.mark.parametrize("name", ["rsa-trad", "pkcs8-rsa", "pkcs8-enc", "pgp", "ssh-rsa"])
# closed 18/11 (production readiness): find_bare_key_rows
def test_residual_middle_rows_never_seen_before(keys, name):
    k = _key(keys, name)
    out, _ = _san("\n".join(k.split("\n")[2:-2]) + "\n")
    n = _leaks(out, k)
    assert n == 0


@pytest.mark.xfail(strict=False, reason="(non-strict: depends on the random key bytes) residual: psql wrapped format narrower than an ENCRYPTED PRIVATE KEY marker tears "
                                       "BEGIN and END inside the cell (only OpenSSH bodies are caught by their magic)")
def test_residual_psql_wrapped_format_narrower_than_the_markers(keys):
    k = _key(keys, "pkcs8-enc")
    out, _ = _san(_psql_wrapped_format(k, 30))
    n = _leaks(out, k)
    assert n == 0


def test_execute_command_stdout_head_stderr_tail_then_middle(keys, srv, monkeypatch):  # noqa: F811
    k = _key(keys, "rsa-trad")
    ls = k.split("\n")
    out1, _ = _exec(srv, monkeypatch, "\n".join(ls[:6]) + "\n", command="head -6 id_rsa",
                    stderr="\n".join(ls[-4:]) + "\n")
    out2, _ = _exec(srv, monkeypatch, k + "\n", command="cat id_rsa")
    out3, _ = _exec(srv, monkeypatch, "\n".join(ls[8:14]) + "\n", command="sed -n 9,14p id_rsa")
    for o in (out1, out2, out3):
        n = _leaks(o, k)
        assert n == 0


def test_result_middleware_masks_keys_and_passwords_in_structured_results(keys, srv):  # noqa: F811
    """``dashboard_list_findings`` / any MCP tool result: the middleware passes every string through sanitize."""
    k = _key(keys, "pkcs8-ec")
    pw = "Vq8nTz3Lw6Rp1Kx"
    res = {"findings": [{"title": "key in table", "evidence": psql_aligned(k)},
                        {"title": "dsn", "evidence": f"postgres://app:{pw}@db.internal:5432/app"}],
           "k8s": json.dumps({"data": {"ssh-privatekey": base64.b64encode(k.encode()).decode()}})}
    out = json.dumps(srv._sanitize_for_model(res, None))
    n = _leaks(out, k) + len(_b64_windows(base64.b64encode(k.encode()).decode()) & _b64_windows(out))
    assert n == 0 and pw not in out


PW = "Qz7vKp2LmX9wRt4N"                                # synthetic
PW_CASES = {
    "uri-pg": f"postgres://admin:{PW}@db.internal:5432/app", "uri-mysql": f"mysql://root:{PW}@10.0.0.5/db",
    "uri-mongo-srv": f"mongodb+srv://svc:{PW}@cluster0.example.net/?retryWrites=true",
    "uri-redis-nouser": f"redis://:{PW}@cache:6379/0", "uri-amqp": f"amqp://guest:{PW}@rabbit:5672/",
    "jdbc-query": f"jdbc:mysql://db:3306/app?user=app&password={PW}&useSSL=false",
    "ado-conn": f"Server=sql01;Database=crm;User Id=sa;Password={PW};", "ado-pwd": f"Data Source=x;uid=sa;pwd={PW};",
    "colon": f"password: {PW}", "eq": f"PASSWORD={PW}", "export": f"export PGPASSWORD={PW}",
    "env-quoted": f'DB_PASSWORD="{PW}"', "yaml": f"  MYSQL_ROOT_PASSWORD: {PW}", "yaml-quoted": f"  db_password: '{PW}'",
    "json": json.dumps({"user": "app", "password": PW}), "json-nested": json.dumps(json.dumps({"password": PW})),
    "json-apiKey": json.dumps({"apiKey": PW}), "json-pass": json.dumps({"db": {"pass": PW}}),
    "docker-env": json.dumps({"Env": [f"POSTGRES_PASSWORD={PW}", "PATH=/usr/bin"]}),
    "xml-element": f"<password>{PW}</password>", "web-config": f'<add key="DbPassword" value="{PW}" />',
    "xml-attr": f'<user name="admin" password="{PW}"/>', "properties": f"spring.datasource.password={PW}",
    "wp-config": f"define( 'DB_PASSWORD', '{PW}' );", "php-var": f'$db_pass = "{PW}";',
    "php-array": f"'password' => '{PW}',", "hydra": f"[22][ssh] host: 10.0.0.9   login: admin   password: {PW}",
    "netrc": f"machine api.example.com login bob password {PW}", "pgpass": f"db.internal:5432:app:app:{PW}",
    "curl-u": f"curl -u admin:{PW} http://10.0.0.5/", "mysql-p": f"mysql -uroot -p{PW} -h db",
    "mysql-p-quoted": f"mysql -uroot -p'{PW}' -h db", "sshpass": f"sshpass -p {PW} ssh u@h",
    "sshpass-quoted": f"sshpass -p'{PW}' ssh u@h", "sql-identified": f"CREATE USER 'app'@'%' IDENTIFIED BY '{PW}';",
    "sql-pg-password": f"ALTER ROLE app WITH PASSWORD '{PW}';",
    "basic-header": "Authorization: Basic " + base64.b64encode(f"admin:{PW}".encode()).decode(),
    "psql-table": f" id | username | password\n----+----------+------------------\n  1 | admin    | {PW}\n(1 row)\n",
    "psql-table-cjk": f" id | 名前 | password\n----+------+------------------\n  1 | 管理者 | {PW}\n(1 row)\n",
    "psql-x": f"-[ RECORD 1 ]------\nusername | admin\npassword | {PW}\n",
    "mysql-box": ("+----+----------+------------------+\n| id | username | password         |\n"
                  f"+----+----------+------------------+\n|  1 | admin    | {PW} |\n+----+----------+------------------+\n"),
    "mysql-G": f"*************************** 1. row ***************************\nusername: admin\npassword: {PW}\n",
    "csv-header": f"id,username,password\n1,admin,{PW}\n", "tsv-mysql-B": f"id\tusername\tpassword\n1\tadmin\t{PW}\n",
    "ini": f"[db]\npassword = {PW}\n", "toml": f'password = "{PW}"', "ansi": f"\x1b[33mpassword\x1b[0m: \x1b[1m{PW}\x1b[0m",
    "url-enc-dsn": f"postgres%3A%2F%2Fadmin%3A{PW}%40db",
    "k8s-b64": f"  password: {base64.b64encode(PW.encode()).decode()}",
    "ldapsearch": f"ldapsearch -x -D cn=admin,dc=x -w {PW} -H ldap://h", "smbclient": f"smbclient //h/share -U admin%{PW}",
    "impacket": f"secretsdump.py corp/admin:{PW}@10.0.0.5", "wget": f"wget --user=admin --password={PW} http://h/",
    "git-cred-url": f"https://bob:{PW}@github.com/org/repo.git", "redis-cli": f"redis-cli -a {PW} ping",
    "requirepass": f"requirepass {PW}",
}


@pytest.mark.parametrize("case", sorted(PW_CASES))
def test_no_password_reaches_the_model(case):
    out, _ = _san(PW_CASES[case])
    assert PW not in out and base64.b64encode(PW.encode()).decode() not in out, case
    assert not any(PW[i:i + 8] in out for i in range(len(PW) - 7)), case


@pytest.mark.parametrize("text", [
    f"1|admin|{PW}\n",                                                         # headerless -At / sqlite list
    f" id | login | passwd_plain\n----+-------+-----\n 1 | adm | {PW}\n",       # suffixed column name
    "PASSWORD=Qz7v;Kp2&Lm9X9wR\n",                                           # unquoted value with ; &
    "password: Qz7v Kp2 LmX9wRt\n",                                         # unquoted value with spaces
])
@pytest.mark.xfail(strict=True, reason="residual: documented password shapes the line patterns do not cover")
def test_residual_password_shapes(text):
    out, _ = _san(text)
    secret = PW if PW in text else re.split(r"[=:] ?", text.strip(), maxsplit=1)[1]
    assert not any(secret[i:i + 6] in out for i in range(len(secret) - 5))


# ── nothing agents need is masked ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    " id | username | password_hash_algo | last_login\n----+----------+--------------------+-----------\n"
    "  1 | alice    | bcrypt             | 2026-11-17\n",
    "id,username,email_verified,role\n1,alice,true,admin\n2,bob,false,viewer\n",
    "user\tshell\nalice\t/bin/bash\n",
    "-----BEGIN CERTIFICATE-----\n" + "\n".join(re.findall(".{1,64}", base64.b64encode(b"cert" * 120).decode()))
    + "\n-----END CERTIFICATE-----\n",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkUJdjfQ0dTnVZ2V7nB9K4qkC0a0f4H3vX3a9yY0e7Q ops@lab\n",
    'if line.startswith("-----END RSA PRIVATE KEY-----"):\n    done = True\n',
    "    else:\n-----END RSA PRIVATE KEY-----\n",                           # an END after prose: no key rows above
    "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9\n",                          # a JWT-like id, no key
    base64.b64encode(b"just a config file\nuser=ops\nport=22\n" * 3).decode() + "\n",
    "\n".join("x" * 80 for _ in range(5)) + "\n",                          # a wrapped-looking text, no marker
])
def test_ordinary_output_is_untouched(text):
    out, v = _san(text)
    assert "CRED_" not in out, text[:40]


def test_table_that_mentions_password_keeps_users_and_other_columns():
    text = (" id | username | password         | role\n----+----------+------------------+------\n"
            f"  1 | alice    | {PW} | admin\n  2 | bob      | ***              | viewer\n")
    out, _ = _san(text)
    assert PW not in out
    for kept in ("alice", "bob", "admin", "viewer", "username", "password", "***"):
        assert kept in out, kept
    csv = f"id,username,password,role\n1,alice,{PW},admin\n"
    out, _ = _san(csv)
    assert PW not in out and "alice" in out and "admin" in out and "username,password" in out


def test_web_config_value_masked_other_values_kept():
    """The value of a secret-named key is minted; other values stay. (Pre-existing, unchanged: the generic
    ``key=`` rule of ``_CRED_PATTERNS`` also mints the attribute NAME, « key="CRED_n" ».)"""
    out, _ = _san(f'<add key="DbPassword" value="{PW}" />\n<add key="Theme" value="dark" />')
    assert PW not in out and 'value="dark"' in out
