"""Isolated local store for the executive V2 tests: the Community data dir defaults to the user's real
``~/.local/share/opencode``, so every test patches every path of the store to a temporary directory."""
from pathlib import Path

from api import json_storage, live_push


def isolate(monkeypatch, tmp_path: Path, opencode_db: Path = None) -> Path:
    data = tmp_path / "data"
    dirs = {"DATA_DIR": data, "CAMPAIGNS_DIR": data / "campaigns", "INFRASTRUCTURE_DIR": data / "infrastructure",
            "VULNERABILITIES_DIR": data / "vulnerabilities", "REPORTS_DIR": data / "reports"}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    for name, d in dirs.items():
        monkeypatch.setattr(json_storage, name, d, raising=False)
        if hasattr(live_push, name):
            monkeypatch.setattr(live_push, name, d, raising=False)
    monkeypatch.setattr(json_storage, "PROJECTS_FILE", data / "projects.json", raising=False)
    monkeypatch.setattr(json_storage, "TARGETS_FILE", data / "targets.json", raising=False)
    monkeypatch.setattr(live_push, "_OPENCODE_DB", opencode_db or (tmp_path / "absent-opencode.db"), raising=False)
    monkeypatch.setattr(live_push, "_is_subagent_session", lambda sid: False)
    assert str(json_storage.DATA_DIR).startswith(str(tmp_path))
    return data
