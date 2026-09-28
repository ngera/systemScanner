"""Minimal .env loader (no python-dotenv dependency).

Looked for, in order (earlier files win; real environment variables always win over any file):

1. ``.env`` in the current directory
2. ``.env`` next to runScan.exe (when running the packaged exe)
3. ``.env`` in the project root (when running from a source checkout / editable install)
4. ``.env`` in the sysscan home folder (``%LOCALAPPDATA%\\sysscan``); this is the one scheduled scans
   are guaranteed to find, because Task Scheduler starts them in C:\\Windows\\System32.

Supported syntax: ``KEY=value``, ``export KEY=value``, quoted values, ``# comments`` and blank lines.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from sysscan.config import default_home

_loaded: list[Path] = []


def candidate_files() -> list[Path]:
    files = [Path.cwd() / ".env"]
    if getattr(sys, "frozen", False):
        files.append(Path(sys.executable).resolve().parent / ".env")
    repo_root = Path(__file__).resolve().parents[2]
    if (repo_root / "pyproject.toml").exists():
        files.append(repo_root / ".env")
    files.append(default_home() / ".env")
    seen: set[str] = set()
    unique = []
    for f in files:
        key = os.path.normcase(str(f.resolve()) if f.exists() else str(f))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:  # inline comment on an unquoted value
            value = value.split(" #", 1)[0].rstrip()
        if key:
            values[key] = value
    return values


def load_env_files(files: list[Path] | None = None) -> list[Path]:
    """Load .env files into os.environ without overriding variables that are already set."""
    loaded = []
    for f in files if files is not None else candidate_files():
        try:
            text = f.read_text(encoding="utf-8-sig")
        except OSError:
            continue
        for key, value in parse_env(text).items():
            if value and not os.environ.get(key):
                os.environ[key] = value
        loaded.append(f)
    _loaded[:] = loaded
    return loaded


def loaded_files() -> list[Path]:
    return list(_loaded)
