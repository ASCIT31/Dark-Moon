"""P2: short step impact on attack paths, never stronger than the proof (D-03, review 2 M-1)."""
import json
from pathlib import Path

import pytest

from api.attack_paths import step_impact, build_paths
from api.attack_paths_observed import _r3_host_capability

ROOT = Path(__file__).resolve().parents[1]


# ---------- step impact (D-03, D-11) ----------
def test_r3_capability_follows_proof():
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin"
    assert _r3_host_capability(passwd, "") == "system account file read on the host"
    assert _r3_host_capability(passwd + "\nuid=0(root) gid=0(root)", "cmd=x;id; cat /etc/passwd") == "command execution on the host"
    # ``id`` as a parameter value is not command position: prudent false negative (review 2, M-1)
    assert _r3_host_capability(passwd + "\nuid=0(root) gid=0(root)", "cmd=id&f=/etc/passwd") == "system account file read on the host"
    assert _r3_host_capability(passwd + "\nuid=0(root) gid=0(root)", "GET /etc/passwd") == "system account file read on the host"


def test_step_impact_closed_set():
    assert step_impact({"rule": "R1", "capability": "reused basic-auth/jwt"}, "n")["label"] == "Reused Basic credentials + JWT from an earlier step"
    assert step_impact({"rule": "R1", "capability": "reused internal-endpoint"}, "n")["label"] == "Internal URL disclosed, then used"
    assert step_impact({"rule": "R3", "capability": "mysql database read"}, "db")["label"] == "Mysql database rows read on db"
    assert step_impact({"rule": "sink", "category": "idor", "status": "confirmed"}, "n")["label"] == "Objective: Insecure direct object reference (IDOR), confirmed"
    assert step_impact({"rule": "R3", "capability": "anything else"}, "n") is None
    assert step_impact(None, "n") is None and step_impact({"rule": "declared"}, "n") is None


PASSWD = "root:x:0:0:root:/root:/bin/bash\n"


@pytest.mark.parametrize("request_text, response, expected", [
    # reviewer's false positives (review 2, M-1)
    ('{"id": 7, "name": "uid=0(root) gid=0(root)", "f": "/etc/passwd"}', PASSWD + '{"id": 7, "name": "uid=0(root) gid=0(root)"}', "file"),
    ("GET /search?file=/etc/passwd&q=id HTTP/1.1", PASSWD + "uid=33(www-data) gid=33(www-data)", "file"),
    ('GET /?f=/etc/passwd HTTP/1.1\nX-Trace: "id"', PASSWD + "uid=0(root) gid=0(root)", "file"),
    ("GET /?f=/etc/passwd HTTP/1.1\nX-Request-Id: 1", PASSWD + "uid=0(root) gid=0(root)", "file"),
    ("GET /?id=1&f=/etc/passwd HTTP/1.1", PASSWD + "uid=0(root) gid=0(root)", "file"),
    # real command injections
    ("host=127.0.0.1;id;cat /etc/passwd", PASSWD + "uid=0(root) gid=0(root) groups=0(root)", "exec"),
    ("host=127.0.0.1%3Bid%3Bcat%20/etc/passwd", PASSWD + "uid=0(root) gid=0(root)", "exec"),
    ("x=$(id)&f=/etc/passwd", PASSWD + "uid=1000(app) gid=1000(app)", "exec"),
    ("x=1 && id", PASSWD + "uid=0(root) gid=0(root)", "exec"),
    # echo: the uid string was already sent
    ("host=1;id;echo uid=0(root) gid=0(root)", PASSWD + "uid=0(root) gid=0(root)", "file"),
])
def test_m1_command_execution_needs_command_position_and_non_echoed_output(request_text, response, expected):
    want = {"file": "system account file read on the host", "exec": "command execution on the host"}[expected]
    assert _r3_host_capability(response, request_text) == want


def test_m1_uid_only_in_extracted_data_is_not_enough():
    """The uid output must be in the TARGET's raw_response, not in the agent-written extracted_data."""
    from tests.test_attack_paths import derive, infra, vuln
    req = "GET /ping?host=127.0.0.1;id;cat%20/etc/passwd HTTP/1.1"

    def rce(resp, extracted):
        return vuln("rce", category="command_injection", status="exploited",
                    evidence={"raw_request": req, "raw_response": resp, "extracted_data": extracted})
    caps = lambda v: [l["capability"] for l in derive(infra({"api": ["rce"]}), [v])["links"] if l["kind"] == "R3"]
    assert caps(rce("HTTP/1.1 200 OK\n" + PASSWD, "uid=0(root) gid=0(root)")) == ["system account file read on the host"]
    assert caps(rce("HTTP/1.1 200 OK\n" + PASSWD + "uid=0(root) gid=0(root)", "")) == ["command execution on the host"]
