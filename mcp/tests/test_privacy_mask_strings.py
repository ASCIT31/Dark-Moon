"""Pure mask strings are never minted as credentials (provenance study 17/11: ``password: ***`` was minted ``CRED_012``,
the same placeholder in the evidence of 8 unrelated c6 findings — a value-matching engine could take it for a shared
value). Real secrets are still minted; uid/gid, ``docker -u 1000:1000`` and port 10000 are untouched; a mask never
becomes a value fingerprint in the provenance ledger (defence in depth)."""
from __future__ import annotations

import pytest

from src.privacy.gateway import CommandGateway
from src.privacy.vault import PrivacyVault, is_cred_false_positive, is_mask_string

MASKS = ["***", "*", "**", "****", "********", "xxx", "XXXXXXXX", "•••", "●●●●●●", "...", "###", "<redacted>",
         "[REDACTED]", "(hidden)", "<masked>", "[removed]", "redacted", "**REDACTED**"]
REAL = ["Sup3rPw-91", "hunter22x", "x7Kq9!", "***abc123", "xxxY7", "a*b*c*d", "R00tPass"]


def _out(text):
    v, gw = PrivacyVault("mask"), CommandGateway()
    return gw.sanitize_output(text, v), v


@pytest.mark.parametrize("mask", MASKS)
def test_mask_strings_are_not_minted(mask):
    for text in (f"password: {mask}", f"DB_PASSWORD={mask}", f"curl -u admin:{mask} http://10.0.0.9/x",
                 f"mysql -uroot -p{mask} -h db", f"postgres://app:{mask}@db.internal:5432/app",
                 f"Authorization: Bearer {mask}"):
        out, v = _out(text)
        assert "CRED_" not in out, (text, out)
    assert is_mask_string(mask) and is_cred_false_positive(mask)


def test_api_redaction_marker_is_a_mask():
    """The API's own marker (« «redacted:password» »): a mask in key: value form. Inside userinfo the credential
    patterns split it at its « : » (documented limit; the API never serves it to the agent)."""
    marker = "«redacted:password»"
    assert is_mask_string(marker)
    out, _ = _out(f"password: {marker}")
    assert "CRED_" not in out


def test_mask_in_launch_prompt_is_not_minted():
    v = PrivacyVault("p")
    t = v.tokenize_prompt("TARGET: http://10.0.0.9 CREDS=admin:*** TOKEN=[REDACTED] password=****")
    assert "CRED_" not in t


@pytest.mark.parametrize("secret", REAL)
def test_real_secrets_are_still_minted(secret):
    out, _ = _out(f"password: {secret}")
    assert secret not in out and "CRED_" in out
    assert not is_mask_string(secret)


def test_the_same_mask_in_two_findings_never_shares_a_placeholder():
    v, gw = PrivacyVault("two"), CommandGateway()
    a = gw.sanitize_output("finding 1 evidence: password: ***", v)
    b = gw.sanitize_output("finding 2 evidence: password=***", v)
    assert "***" in a and "***" in b and "CRED_" not in a + b


@pytest.mark.parametrize("first,later", [
    ("docker run -u 1000:1000 alpine id", "uid=1000 gid=1000 groups=1000\nlistening on port 10000"),
    ("sudo -u www-data id", "uid=33(www-data) gid=33(www-data)"),
    ("nmap -p 10000 10.0.0.9", "10000/tcp open  snet-sensor-mgmt"),
])
def test_uid_gid_and_port_unchanged(first, later):
    v, gw = PrivacyVault("nc"), CommandGateway()
    outs = [gw.sanitize_output(t, v) for t in (first, later)]
    assert outs[1] == later and "CRED_" not in outs[0]


