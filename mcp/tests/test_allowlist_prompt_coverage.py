"""Every tool an agent prompt calls as the FIRST word of a darkmoon_execute_command must be on the executor allowlist
(17/11/2026: `ssh`, `timeout`, `printf` were refused while the same command wrapped in `bash -c` passed)."""
import glob
import re
from pathlib import Path

from src.tools.core.allowlist import EXECUTOR_ALLOWED_TOOLS

ROOT = Path(__file__).resolve().parents[2]


def test_first_word_tools_of_prompt_commands_are_allowed():
    used = set()
    for f in glob.glob(str(ROOT / "conf" / "agents" / "*.md")):
        text = open(f, newline="").read()
        for c in re.findall(r'darkmoon_execute_command\(command="([^"\\]*(?:\\.[^"\\]*)*)"', text):
            w = c.strip().split()
            if w and re.fullmatch(r"[A-Za-z0-9_.+-]+", w[0].split("/")[-1]) and w[0] != "...":
                used.add(w[0].split("/")[-1])
    assert sorted(used - set(EXECUTOR_ALLOWED_TOOLS)) == []


def test_ssh_is_allowed():
    assert {"ssh", "timeout", "printf"} <= set(EXECUTOR_ALLOWED_TOOLS)
