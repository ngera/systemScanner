"""Small Windows helpers: PowerShell-as-JSON runner, admin check, time conversions.

Collectors shell out to Windows PowerShell 5.1 (present on every Windows 10/11 box) and ask it
to emit JSON. That keeps the Python side free of pywin32/COM dependencies, and every query is
easy to copy-paste into a terminal for debugging.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

IS_WINDOWS = sys.platform == "win32"

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


class PowerShellError(RuntimeError):
    pass


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def run_powershell(script: str, timeout: int = 180) -> Any:
    """Run a PowerShell snippet that writes JSON to stdout and return the parsed value.

    The snippet should end with ``| ConvertTo-Json -Depth 5 -Compress``. An empty result is
    returned as ``[]``; a single object is wrapped in a list so callers can always iterate.
    """
    if not IS_WINDOWS:
        raise PowerShellError("PowerShell collectors only run on Windows")
    prelude = (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    )
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", prelude + script],
        capture_output=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    out = proc.stdout.decode("utf-8", errors="replace").lstrip("\ufeff").strip()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise PowerShellError(err.splitlines()[0] if err else f"exit code {proc.returncode}")
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def run_command(args: list[str], timeout: int = 120) -> str:
    proc = subprocess.run(
        args,
        capture_output=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace").strip()[:300])
    return proc.stdout.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- time helpers


def utcnow() -> datetime:
    return datetime.now(UTC)


def filetime_to_dt(value: int) -> datetime | None:
    """Convert a Windows FILETIME (100 ns ticks since 1601-01-01 UTC) to aware UTC."""
    if not value:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def parse_iso(value: str | None) -> datetime | None:
    """Parse ISO-8601 (as produced by PowerShell ``.ToString('o')``) to aware UTC."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()  # treat naive as local time
    return dt.astimezone(UTC)


def parse_yyyymmdd(value: str | None) -> datetime | None:
    """Registry ``InstallDate`` is usually 'YYYYMMDD' in local time. Returns local midnight → UTC."""
    if not value:
        return None
    s = str(value).strip()
    if len(s) != 8 or not s.isdigit():
        return None
    try:
        local = datetime(int(s[:4]), int(s[4:6]), int(s[6:8]))
    except ValueError:
        return None
    if local.year < 1995:
        return None
    return local.astimezone().astimezone(UTC)


def to_local(dt: datetime | None) -> datetime | None:
    return dt.astimezone() if dt else None


def ps_date(dt: datetime) -> str:
    """Format a datetime for a PowerShell script. Parsing a 'Z' string yields a *local* [datetime],
    which is what Get-WinEvent's StartTime/EndTime and CIM comparisons expect."""
    return f"([datetime]::Parse('{dt.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}'))"
