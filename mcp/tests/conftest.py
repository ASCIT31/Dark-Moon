"""Test session isolation: the Community data dir defaults to the user's real ``~/.local/share/opencode``. Every
test run gets a throw-away data dir instead, before any ``api`` module reads it at import time (tests that need a
store still patch their own temporary directories)."""
import os
import tempfile

_ROOT = tempfile.mkdtemp(prefix="darkmoon-community-tests-")
os.environ["DARKMOON_DATA_DIR"] = os.path.join(_ROOT, "data")
