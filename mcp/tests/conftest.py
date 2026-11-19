"""Test session isolation: the Community data dir and the OpenCode session store default to the user's real
``~/.local/share/opencode``. Every test run gets a throw-away data dir (before any ``api`` module reads it at import
time) and a throw-away session-store path (tests that need a store still patch their own temporary directories)."""
import os
import tempfile
from pathlib import Path

import pytest

_ROOT = tempfile.mkdtemp(prefix="darkmoon-community-tests-")
os.environ["DARKMOON_DATA_DIR"] = os.path.join(_ROOT, "data")


@pytest.fixture(autouse=True, scope="session")
def _no_real_opencode_session_store():
    from api import live_push
    mp = pytest.MonkeyPatch()
    mp.setattr(live_push, "_OPENCODE_DB", Path(_ROOT) / "opencode" / "opencode-dev.db")
    yield
    mp.undo()
