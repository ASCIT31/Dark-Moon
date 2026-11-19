"""The tool-output privacy filter fails CLOSED: a crash of the filter withholds the output, never returns it raw."""
from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

pytest.importorskip("fastmcp")
SECRET = "Zq8vLm2pXr7Tn4"


@pytest.fixture
def server(monkeypatch):
    import docker
    monkeypatch.setattr(docker, "from_env", lambda *a, **k: mock.MagicMock())
    from src import server as srv
    monkeypatch.setattr(srv, "PRIVACY_ENABLED", True)
    return srv


def _crash(*a, **k):
    raise RuntimeError("filter bug")


def test_sanitizer_crash_withholds_the_output(server, monkeypatch):
    monkeypatch.setattr(server._command_gateway, "sanitize_result", _crash)
    monkeypatch.setattr(server, "_privacy_enabled_for", lambda sid: True)
    out = server._sanitize_for_model(f"password={SECRET}", "ses_failclosed")
    assert out == server._PRIVACY_WITHHELD and SECRET not in str(out)


def test_middleware_error_withholds_every_block(server, monkeypatch):
    blocks = [SimpleNamespace(type="text", text=f"user=admin password={SECRET}"), SimpleNamespace(type="text", text="ok")]
    result = SimpleNamespace(content=blocks, structured_content={"result": SECRET})

    def boom(value, sid):
        if value == "ok":
            raise RuntimeError("loop error")
        return value  # first block passes through unfiltered before the error

    monkeypatch.setattr(server, "_sanitize_for_model", boom)
    ctx = SimpleNamespace(message=SimpleNamespace(arguments={}))

    async def call_next(_):
        return result

    from fastmcp.exceptions import ToolError
    with pytest.raises(ToolError) as e:
        asyncio.run(server._PrivacySanitizerMiddleware().on_call_tool(ctx, call_next))
    assert str(e.value) == server._PRIVACY_WITHHELD and SECRET not in str(e.value)


def test_a_crash_on_structured_content_is_a_clean_tool_error(server, monkeypatch):
    result = SimpleNamespace(content=[SimpleNamespace(type="text", text="ok")], structured_content={"result": SECRET})
    monkeypatch.setattr(server, "_sanitize_for_model",
                        lambda v, sid: server._PRIVACY_WITHHELD if isinstance(v, dict) else v)
    ctx = SimpleNamespace(message=SimpleNamespace(arguments={}))

    async def call_next(_):
        return result

    from fastmcp.exceptions import ToolError
    with pytest.raises(ToolError):
        asyncio.run(server._PrivacySanitizerMiddleware().on_call_tool(ctx, call_next))


def test_privacy_off_returns_the_value_unchanged(server, monkeypatch):
    monkeypatch.setattr(server, "PRIVACY_ENABLED", False)
    assert server._sanitize_for_model(f"password={SECRET}", "ses_off") == f"password={SECRET}"
