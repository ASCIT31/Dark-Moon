"""
Regression: the DB-generated report markdown must not let finding fields (LLM
text written after reading the target) or raw evidence (HTTP requests/responses,
commands, logs captured from the target) turn into live markup.

Before the hotfix, a raw response containing ``` closed the ```http fence it was
wrapped in, and HTML in title/description/remediation was copied verbatim, so the
rendered report carried target-chosen <img>/<script>/<video> tags.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from api import json_storage, live_push  # noqa: E402
from api.live_push import _md_code, _md_fence, _md_inline, _md_prose  # noqa: E402

markdown_it = pytest.importorskip("markdown_it")


def render(md: str) -> str:
    """CommonMark + GFM tables, raw HTML allowed (the worst case for a viewer)."""
    return markdown_it.MarkdownIt("commonmark", {"html": True}).enable("table").render(md)


LIVE_TAGS = ("<img", "<script", "<svg", "<video", "<audio", "<iframe", "<source", "<a href=\"javascript")

HOSTILE_RESPONSE = (
    "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
    "```\n<img src=http://target.invalid/pixel onerror=alert(1)>\n"
    "````\n<script>alert(2)</script>\n~~~\n<video poster=http://target.invalid/v></video>"
)


def assert_inert(html: str) -> None:
    low = html.lower()
    for tag in LIVE_TAGS:
        assert tag not in low, f"live markup {tag!r} in rendered report:\n{html}"


# ── helpers ─────────────────────────────────────────────────────────────────

def test_fence_is_longer_than_any_backtick_run():
    block = _md_fence(HOSTILE_RESPONSE, "http")
    assert block.startswith("`````http\n")  # longest run inside is 4
    html = render(block)
    assert html.count("<pre>") == 1
    assert_inert(html)
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html  # shown, verbatim, as code


def test_prose_shows_html_as_text_and_keeps_markdown():
    md = _md_prose(
        "**Reflected XSS** in `q`: the payload `<script>alert(1)</script>` is echoed.\n\n"
        "<img src=x onerror=alert(1)>\n\n"
        "- step `<b>`\n- ![pixel](http://target.invalid/p)\n\n"
        "```html\n<script>alert(1)</script>\n```"
    )
    html = render(md)
    assert_inert(html)
    assert "<strong>Reflected XSS</strong>" in html
    assert "<code>&lt;script&gt;alert(1)&lt;/script&gt;</code>" in html  # inline code verbatim
    assert "&lt;img src=x onerror=alert(1)&gt;" in html                   # raw HTML shown as text
    assert '<code class="language-html">&lt;script&gt;' in html             # fenced PoC verbatim


def test_prose_closes_a_fence_left_open():
    md = _md_prose("intro\n```\n<img src=x onerror=alert(1)>")  # e.g. truncated at 200 chars
    html = render(md + "\n\nAFTER **bold**")
    assert html.count("<pre>") == 1
    assert "<strong>bold</strong>" in html  # what follows the field is no longer swallowed as code
    assert_inert(html)


def test_prose_multiline_or_escaped_backticks_escape_everything():
    for text in ("a `x\ny` <img src=x onerror=1> `z`", "\\`<img src=x onerror=1>`", "| `a | <img src=x onerror=1> | b` |"):
        assert_inert(render(_md_prose(text)))


def test_inline_and_code_cells_cannot_break_the_table():
    title = "SQLi | <img src=x onerror=alert(1)> `<b>`\nsecond line"
    ep = "http://t/a`b``c|<img src=x onerror=1>\\|"
    md = f"| T | E |\n|---|---|\n| {_md_inline(title, cell=True)} | {_md_code(ep)} |\n"
    html = render(md)
    assert_inert(html)
    assert html.count("<td>") == 2


# ── end to end: finalize → report file ─────────────────────────────────────

@pytest.fixture
def storage(tmp_path, monkeypatch):
    data = tmp_path / "data"
    dirs = {
        "DATA_DIR": data,
        "CAMPAIGNS_DIR": data / "campaigns",
        "INFRASTRUCTURE_DIR": data / "infrastructure",
        "VULNERABILITIES_DIR": data / "vulnerabilities",
        "REPORTS_DIR": data / "reports",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    for name, d in dirs.items():
        monkeypatch.setattr(json_storage, name, d, raising=False)
        if hasattr(live_push, name):
            monkeypatch.setattr(live_push, name, d, raising=False)
    monkeypatch.setattr(json_storage, "PROJECTS_FILE", data / "projects.json", raising=False)
    monkeypatch.setattr(json_storage, "TARGETS_FILE", data / "targets.json", raising=False)
    monkeypatch.setattr(live_push, "_OPENCODE_DATA_DIR", Path("/nonexistent-xyz"), raising=False)
    return dirs


def test_generated_report_is_inert(storage):
    cid = live_push.init_live_campaign(
        session_id="MCPCONST", target_host="10.0.0.5", target_ip="10.0.0.5", project_name="t"
    )["campaign_id"]
    evil = "<img src=http://target.invalid/t onerror=alert(1)>"
    json_storage.save_vulnerabilities(cid, [{
        "id": "vuln_1", "campaign_id": cid, "severity": "critical", "cvss_score": 9.1,
        "status": "exploited", "category": "xss`<svg onload=alert(1)>",
        "title": f"Stored XSS {evil} | `<script>`",
        "description": f"The page echoes {evil}.\n\n![p](http://target.invalid/md)\n\n```\nopen",
        "remediation": "<video poster=http://target.invalid/p></video> Encode output.",
        "plugin_or_component": evil, "mitre_attack_name": evil,
        "endpoint": "http://10.0.0.5/q?x=`` <img src=x onerror=1>",
        "evidence": {
            "raw_request": "GET /?q=```<img src=x onerror=1> HTTP/1.1",
            "raw_response": HOSTILE_RESPONSE,
            "commands": ["curl 'http://10.0.0.5/?q=```<svg onload=alert(1)>'"],
            "logs": ["````\n<audio src=http://target.invalid/a>"],
            "explanation": f"Explanation {evil}",
        },
    }])
    res = live_push.finalize_campaign(cid, executive_summary=f"Summary {evil}\nline 2 <script>x</script>")
    assert "error" not in res, res
    camp = json_storage.load_campaign(cid)
    body = (storage["REPORTS_DIR"] / Path(camp["report_path"]).name).read_text(encoding="utf-8")
    html = render(body)
    assert_inert(html)
    # the evidence is still all there, as text
    assert "alert(2)" in html and "Encode output." in html and "Stored XSS" in html
    assert html.count("<pre>") >= 4
