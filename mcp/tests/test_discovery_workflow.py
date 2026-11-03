"""
Regression tests for the 2026-11-03 discovery-workflow fixes.

D1 (rate limiter)  — during the ALSCO campaign the engine launched
                    `naabu -top-1000 -rate 500`, the target firewall banned the
                    source IP for ~6 minutes and the run died. The cap existed
                    in the prompt; nothing enforced it. Now
                    src.rate_limiter.enforce_rate_limits() floors the rate of
                    every network tool at the docker_client choke point, so a
                    free-form command or a workflow script cannot bypass it.

D2 (cve lookup)    — the engine had NO automated CVE-discovery step: version
                    banner -> applicable CVEs relied on the model remembering
                    CVE numbers (the same failure mode as E3, the rule id cited
                    from memory). cve_lookup.search_cves()/get_cve() query the
                    public NVD 2.0 API and return a ranked, normalised
                    shortlist the agent validates with targeted nuclei.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from src.rate_limiter import describe_rate_limits, enforce_rate_limits  # noqa: E402
from src.tools.workflows.cve_lookup import CveLookupWorkflow  # noqa: E402
from src.tools.workflows.base import BaseWorkflow  # noqa: E402


# ── D1: mechanical rate limiting ──────────────────────────────────────────────

def test_missing_rate_flag_is_injected():
    """A network tool launched without its rate flag gets the cap injected."""
    out = enforce_rate_limits("naabu -top-ports 1000 -json -silent")
    assert "-rate 25" in out, f"Bug D1: naabu ran uncapped: {out}"


def test_explicit_higher_rate_is_floored_not_raised():
    """`-rate 500` must be floored to the engine cap — this exact command got
    the source IP banned during the ALSCO campaign."""
    out = enforce_rate_limits("naabu -list targets.txt -rate 500")
    assert "-rate 500" not in out, "Bug D1: -rate 500 survived the choke point"
    assert "-rate 25" in out


def test_lower_explicit_rate_is_kept():
    """A caller asking for LESS traffic keeps asking for less — the engine
    floors rates, never raises them."""
    out = enforce_rate_limits("ffuf -rate 5 -w words.txt")
    assert "-rate 5" in out and "-rate 25" not in out


def test_command_without_network_tools_is_untouched():
    plain = "cat /etc/passwd && grep root x"
    assert enforce_rate_limits(plain) == plain
    lst = ["curl", "-s", "http://x/"]
    assert enforce_rate_limits(lst) == lst


def test_list_form_is_capped_too():
    """Workflows may pass argv lists; they must be capped identically."""
    out = enforce_rate_limits(["naabu", "-top-ports", "100"])
    assert isinstance(out, list) and out[1:3] == ["-rate", "25"]


def test_composed_script_body_is_capped():
    """A `bash -c` body carrying an uncapped scanner must be capped inside
    the script — workflows compose with && so the tool is not a top token."""
    out = enforce_rate_limits(["bash", "-c", "naabu -top-ports 100 && cat out"])
    inner = out[2]
    assert "-rate 25" in inner, f"Bug D1: script body uncapped: {inner}"


def test_describe_rate_limits_is_machine_readable():
    caps = describe_rate_limits()
    assert caps["naabu"]["cap"] == 25
    assert "gau" not in caps  # passive tool, no rate knob


# ── D2: NVD parsing (offline, fixtures — no network in unit tests) ────────────

class _FakeWorkflow(CveLookupWorkflow):
    """Bypass docker: serve execute_step from a fixture."""

    def __init__(self):  # noqa: D107
        pass

    def execute_step(self, step_name, command, timeout=60, parse_json=True):
        return True, FIXTURE_NVD, ""


FIXTURE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1111",
                "published": "2024-03-01T00:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Royal CMS 2.1 allows RCE via import.php"},
                ],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                "references": [{"url": "https://example.com/advisory"}, {"url": "https://example.com/2"}],
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:royal_cms:2.1:*:*:*"}]}]}],
            }
        },
        {
            "cve": {
                "id": "CVE-2020-2222",
                "published": "2020-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Unrelated product"}],
                "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}]},
                "references": [],
                "configurations": [],
            }
        },
    ]
}


def test_search_cves_ranks_by_cvss_and_marks_version_hint():
    wf = _FakeWorkflow()
    out = wf.search_cves("royal cms", "2.1")
    assert out["count"] == 2
    assert out["cves"][0]["id"] == "CVE-2024-1111", "not ranked CVSS-descending"
    top = out["cves"][0]
    assert top["severity"] == "critical"
    assert top["version_hint_match"] is True, "version hint not surfaced"
    assert top["cvss"] == 9.8
    assert top["references"], "advisory reference dropped"


def test_search_cves_requires_product():
    wf = _FakeWorkflow()
    assert "error" in wf.search_cves("")


def test_min_severity_filters():
    wf = _FakeWorkflow()
    out = wf.search_cves("royal cms", min_severity="high")
    assert out["count"] == 1
    assert out["cves"][0]["id"] == "CVE-2024-1111"


def test_get_cve_validates_id():
    wf = _FakeWorkflow()
    assert "error" in wf.get_cve("not-a-cve")


def test_get_cve_returns_record():
    wf = _FakeWorkflow()
    out = wf.get_cve("cve-2024-1111")
    assert out["id"] == "CVE-2024-1111"


def test_cve_workflow_is_discoverable_by_registry():
    """The registry discovers workflows by glob; cve_lookup must be listed so
    run_workflow('cve_lookup', ...) works."""
    from src.tools.workflows.list_workflows import EXCLUDED_FILES
    from pathlib import Path

    wf_dir = Path(__file__).resolve().parents[1] / "src" / "tools" / "workflows"
    assert (wf_dir / "cve_lookup.py").exists()
    assert "cve_lookup.py" not in EXCLUDED_FILES
    assert issubclass(CveLookupWorkflow, BaseWorkflow)