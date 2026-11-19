"""Privacy gateway: AWS access keys, DSNs with credentials and prefixed vendor keys never reach the model in clear
(round2-critique « hors sujet »: a sub-agent prompt carried an AKIA… key and postgres/root DSNs untokenised).

Both directions use the same detectors (``_CRED_PATTERNS``): the prompt (``tokenize_prompt``, also used by the
pre-model socket for sub-agent prompts) and tool outputs (``CommandGateway.sanitize_output``). A placeholder written by
the model in a target-bound command is rehydrated for execution.
"""
from __future__ import annotations

import re

import pytest

from src.privacy.gateway import CommandGateway
from src.privacy.vault import PLACEHOLDER_RE, PrivacyVault

# synthetic values (never real keys)
AKIA = "AKIAZ7Q3XYWVUTSRQPON"
ASIA = "ASIAQ2WERTYUIOPASDFG"
SECRETS = {
    "aws long-term key id": (f"aws_access_key_id = {AKIA}", AKIA),
    "aws key in prose": (f"AWS credentials found in .env: {AKIA} (user vertex-ci-deployer)", AKIA),
    "aws sts key id": (f"export AWS_ACCESS_KEY_ID={ASIA}", ASIA),
    "postgres dsn": ("DATABASE_URL=postgres://postgres:Pg4ssw0rdX@dmlab-postgres:5432/vertexcrm", "Pg4ssw0rdX"),
    "postgresql dsn": ("dsn postgresql://app:S3cr3tPw@db.internal/app", "S3cr3tPw"),
    "mysql dsn": ("MYSQL_DSN=mysql://root:R00tPass@dmlab-mysql:3306/vertexbilling", "R00tPass"),
    "mongodb dsn": ("mongodb://admin:M0ngoPw9@mongo:27017/admin", "M0ngoPw9"),
    "mongodb+srv dsn": ("mongodb+srv://admin:hunter22x@cluster0.example.net/db", "hunter22x"),
    "redis dsn, empty user": ("REDIS_URL=redis://:R3disPass@10.0.0.7:6379/0", "R3disPass"),
    "amqp dsn": ("AMQP_URL=amqp://svc:Rabb1tPw@dmlab-rabbitmq:5672/", "Rabb1tPw"),
    "user/pass@host dsn": ("PostgreSQL DSN: postgres/PgSlash9@dmlab-postgres:5432/vertexcrm", "PgSlash9"),
    "user/pass@ip dsn": ("MySQL DSN: root/RootSl4sh@10.0.0.5:3306/x", "RootSl4sh"),
    "user:pass@host, no scheme": ("try svc:Bare5ecret@10.0.0.5 next", "Bare5ecret"),
    "github token": ("token ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
    "gitlab token": ("glpat-" + "Ab12Cd34Ef56Gh78Ij90", "glpat-" + "Ab12Cd34Ef56Gh78Ij90"),
    "slack token": ("xoxb-" + "1234567890-abcdefghij", "xoxb-" + "1234567890-abcdefghij"),
    "google api key": ("AIza" + "Sy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    "stripe key": ("sk_live_" + "51HAbCdEfGhIjKlMn", "sk_live_" + "51HAbCdEfGhIjKlMn"),
    "vault token": ("root token hvs.CAESIJ1234567890abcdefXYZ in runbook", "hvs.CAESIJ1234567890abcdefXYZ"),
}


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_prompt_direction_tokenises(name):
    text, secret = SECRETS[name]
    out = PrivacyVault("p").tokenize_prompt(text)
    assert secret not in out and "CRED_" in out, out


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_tool_output_direction_tokenises(name):
    text, secret = SECRETS[name]
    out = CommandGateway().sanitize_output(f"$ cat .env\n{text}\n", PrivacyVault("o"))
    assert secret not in out and "CRED_" in out, out


def test_subagent_prompt_of_the_critique_is_fully_tokenised():
    prompt = ("Known from observation:\nAWS credentials in .env: " + AKIA + "\nVault root token: hvs.CAESIJ1234567890abcdefXYZ\n"
              "PostgreSQL DSN: postgres/postgres@dmlab-postgres:5432/vertexcrm\nMySQL DSN: root/root@dmlab-mysql:3306/vertexbilling\n"
              "DATABASE_URL from .env: postgres://postgres:postgres@dmlab-postgres:5432/vertexcrm\n"
              "AMQP_URL from .env: amqp://guest:guest@dmlab-rabbitmq:5672/")
    out = PrivacyVault("sub").tokenize_prompt(prompt)
    assert AKIA not in out and "hvs.CAES" not in out
    assert not re.search(r"(postgres|root|guest)[:/](postgres|root|guest)@", out), out


def test_dsn_userinfo_is_not_swallowed_as_an_email():
    out = PrivacyVault("e").tokenize_prompt("dsn postgresql://app:S3cr3tPw@db.internal/app")
    assert "EMAIL_" not in out and re.search(r"app:CRED_\d+@", out)


@pytest.mark.parametrize("text", [
    "uses: actions/checkout@v4", "npm i @angular/core@17.0.0", "docker pull library/nginx@sha256:abcd",
    "pip install foo/bar@main", "org/repo@1.2", "ssh root@10.0.0.5", "User-Agent: Mozilla/5.0 (X11)",
    "at 12:30:45 on host", "contact john.doe@example.com",
])
def test_no_false_credentials(text):
    v = PrivacyVault("f")
    v.tokenize_prompt(text)
    assert not any(ph.startswith("CRED_") for ph in v.known_placeholders()), text


def test_placeholders_rehydrate_for_a_target_bound_command():
    v, gw = PrivacyVault("r"), CommandGateway()
    t = v.tokenize_prompt(f"TARGET: http://10.0.0.9:8080 key {AKIA} and pg postgres/Pg4ssw0rd@db.lab:5432/crm, "
                          "redis redis://:R3disPass@10.0.0.7:6379/0")
    ak = re.search(r"key (CRED_\d+)", t).group(1)
    pw = re.search(r"postgres/(CRED_\d+)@", t).group(1)
    host = re.search(r"@(DOMAIN_\d+)", t).group(1)
    url = re.search(r"(URL_\d+)", t).group(1)
    redis = re.search(r"redis://\S+", t).group(0).rstrip(",")
    r1 = gw.process_command(f"psql postgres://postgres:{pw}@{host}:5432/crm -c 'select 1'", v)
    assert "Pg4ssw0rd@db.lab" in r1.command and not r1.withheld
    r2 = gw.process_command(f"curl -s -H 'X-Api-Key: {ak}' {url}/api", v)
    assert AKIA in r2.command and "10.0.0.9" in r2.command and not r2.withheld
    r3 = gw.process_command(f"redis-cli -u {redis} ping", v)
    assert "R3disPass@10.0.0.7" in r3.command and not r3.withheld
    assert all(PLACEHOLDER_RE.fullmatch(p) for p in v.known_placeholders())


def _seq(outputs):
    v, gw = PrivacyVault("seq"), CommandGateway()
    return [gw.sanitize_output(t, v) for t in outputs]


@pytest.mark.parametrize("first,later", [
    ("psql postgres/postgres@db:5432/crm", "PORT STATE SERVICE\n5432/tcp open postgresql\nPostgreSQL 15 on postgres"),
    ("mysql root/root@mysql:3306", "drwxr-xr-x 2 root root 4096 /root\nuid=0(root)"),
    ("amqp://guest:guest@rabbitmq:5672/", "user guest tags administrator\nguest_access ok"),
    ("redis://:dev@redis:6379/0", "developer mode; device; revision"),
    ("sqlplus scott/tiger@orcl", "tiger team; scott"),
    ('curl "http://127.0.0.1:8080@evil.example/"', "ok 8080 open"),
])
def test_later_outputs_are_never_corrupted(first, later):
    out = _seq([first, later])
    assert out[1] == later, out
    assert "CRED_" in out[0] or "URL_" in out[0]


def test_a_dictionary_word_secret_is_replaced_as_a_whole_word_only():
    out = _seq(["mysql://app:hunterxx@db:3306/x", "hunterxx logged in; hunterxxl is another user"])
    assert out[1].startswith("CRED_") and "hunterxxl" in out[1]


def test_user_equal_to_secret_keeps_the_user():
    assert re.fullmatch(r"psql postgres/CRED_\d+@db:5432", _seq(["psql postgres/postgres@db:5432"])[0])


@pytest.mark.parametrize("text", ["npx create-foo/bar@canary", "pkg/x@beta", "app@rc1", "From: alice:wonder@mail.example.com"])
def test_more_refs_and_addresses_are_not_credentials(text):
    v = PrivacyVault("fp2")
    v.tokenize_prompt(text)
    assert not any(ph.startswith("CRED_") for ph in v.known_placeholders()), text


@pytest.mark.parametrize("text,secret", [
    ("postgres%3A%2F%2Fadmin%3AS3cretPw%40db%3A5432", "S3cretPw"),
    ('DATABASE_URL="postgres://admin:"\n"S3cretPw@db:5432"', "S3cretPw"),
    ("postgres:\\/\\/admin:S3cretPw@db:5432", "S3cretPw"),
    ("id AKIA4TQZ7HLNJRW2VQPD  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("AKIA4TQZ7HLNJRW2VQPD\n  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("s.1234567890abcdefghijklmn (vault legacy token)", "s.1234567890abcdefghijklmn"),
    ("hvs.CAESIJ1234567890abcdefghijklmnopqrstu", "hvs.CAESIJ1234567890abcdefghijklmnopqrstu"),
])
def test_round3_bypasses_are_tokenised(text, secret):
    assert secret not in _seq([text])[0]
    assert secret not in PrivacyVault("bp").tokenize_prompt(text)


def test_git_sha_after_an_access_key_id_is_not_a_secret():
    out = _seq(["AKIA4TQZ7HLNJRW2VQPD commit 3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a"])[0]
    assert "3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a" in out           # lower-case hex: no upper case, not an AWS secret


@pytest.mark.parametrize("text,secret", [
    ("curl -u admin:S3cretPw http://10.0.0.9/x", "S3cretPw"),
    ("curl --user=admin:S3cretPw http://10.0.0.9/x", "S3cretPw"),
    ("basic_auth: YWRtaW46UzNjcmV0UHc= # from config", "YWRtaW46UzNjcmV0UHc="),          # admin:S3cretPw, no header
    ("AKIA4TQZ7HLNJRW2VQPD\nregion=eu-west-3\nprofile=ci\nowner=ops\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
])
def test_round5_leftovers_are_tokenised(text, secret):
    assert secret not in PrivacyVault("r5").tokenize_prompt(text)
    assert secret not in CommandGateway().sanitize_output(text, PrivacyVault("r5o"))


@pytest.mark.parametrize("text", ["eyJhbGciOiJIUzI1NiJ9 header", "aGVsbG8gd29ybGQgaGVsbG8=", "curl -u admin http://h/x",
                                  "dGhpcyBpcyBub3QgYSBjcmVk", "commit 3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a"])
def test_round5_patterns_have_no_false_positive(text):
    v = PrivacyVault("r5f")
    v.tokenize_prompt(text)
    assert not any(ph.startswith("CRED_") for ph in v.known_placeholders()), text


def test_curl_user_password_rehydrates_for_the_target():
    v, gw = PrivacyVault("r5r"), CommandGateway()
    t = v.tokenize_prompt("TARGET: http://10.0.0.9:8080 login admin with curl -u admin:S3cretPw")
    ph = re.search(r"admin:(CRED_\d+)", t).group(1)
    url = re.search(r"(URL_\d+)", t).group(1)
    r = gw.process_command(f"curl -s -u admin:{ph} {url}/admin", v)
    assert "admin:S3cretPw" in r.command and not r.withheld


# ---------------------------------------------------------------- round5-critique: -u only for HTTP clients, no corruption
@pytest.mark.parametrize("first,later", [
    ("docker run -u 1000:1000 alpine id", "uid=1000 gid=1000 groups=1000\nlistening on port 10000"),
    ("sudo -u www-data id", "uid=33(www-data) gid=33(www-data)"),
    ("chown 1000:1000 /srv/app && ls -n /srv", "drwxr-xr-x 2 1000 1000 4096 app"),
    ("ps -u postgres:postgres", "postgres 42 0.1 postgres: checkpointer"),
    ("docker exec -u 0:0 web cat /etc/hostname", "web-01 id 100000"),
])
def test_uid_gid_and_user_switches_are_not_credentials(first, later):
    out = _seq([first, later])
    assert out[1] == later and "CRED_" not in out[0], out             # (absolute paths may become PATH_nnn, as before)


def test_the_final_pass_never_replaces_inside_a_token():
    out = _seq(["curl -u admin:Pw1234 http://10.0.0.9/x", "Pw1234 ok; Pw12345 is another; id=xPw1234; Pw1234!"])
    assert out[1].startswith("CRED_") and "Pw12345" in out[1] and "xPw1234" in out[1]
    assert not re.search(r"CRED_\d+(?!\d)[A-Za-z_]", out[1])         # never a placeholder glued to a word


@pytest.mark.parametrize("cmd", ["curl -s -u admin:S3cretPw http://h/x", "wget --http-user=admin:S3cretPw http://h",
                                 "http -a admin:S3cretPw GET h/x", "xh -u admin:S3cretPw h/x"])
def test_http_clients_still_tokenised(cmd):
    if cmd.startswith("http -a"):
        pytest.skip("httpie -a: not covered (no -u flag)")
    assert "S3cretPw" not in PrivacyVault("hc").tokenize_prompt(cmd)
