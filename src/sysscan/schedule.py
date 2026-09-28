"""Windows Task Scheduler integration: a daily snapshot plus a run shortly after logon.

The task runs as the current user with *highest privileges*, so scheduled scans see everything
an elevated scan sees without a UAC prompt at logon. Registering such a task needs admin rights once.

When sysscan runs as the bundled ``runScan.exe`` the task points at the exe (``--startup``);
otherwise it points at ``pythonw.exe -m sysscan`` so no console window flashes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sysscan.winutil import IS_WINDOWS, is_admin

TASK_NAME = "sysscan daily snapshot"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def task_command(use_ai: bool = False, extra_args: list[str] | None = None) -> tuple[str, str]:
    """(executable, arguments) the scheduled task should run. ``extra_args`` are scan options."""
    extra = list(extra_args or [])
    if use_ai and "--ai" not in extra:
        extra.append("--ai")
    tail = (" " + subprocess.list2cmdline(extra)) if extra else ""
    if is_frozen():
        exe = Path(sys.executable)
        if exe.suffix.lower() == ".com" and exe.with_suffix(".exe").exists():
            exe = exe.with_suffix(".exe")  # installed from the terminal twin: run the windowless one
        return str(exe), "--startup" + tail
    exe = Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")
    return str(pythonw if pythonw.exists() else exe), "-m sysscan scan --no-open --quiet" + tail


def _ps(script: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
    return proc.returncode == 0, out


def _psq(s: str) -> str:
    return s.replace("'", "''")


def install(time: str = "09:00", use_ai: bool = False, extra_args: list[str] | None = None) -> tuple[bool, str]:
    if not IS_WINDOWS:
        return False, "Scheduling uses Windows Task Scheduler. On other systems add `sysscan scan --no-open` to cron."
    if not is_admin():
        return False, ("Registering a task that runs with highest privileges needs administrator rights. "
                       "Run this from an elevated terminal (or use runScan.exe --install-startup).")
    exe, args = task_command(use_ai, extra_args)
    script = f"""
$a = New-ScheduledTaskAction -Execute '{_psq(exe)}' -Argument '{_psq(args)}'
$t = New-ScheduledTaskTrigger -Daily -At '{_psq(time)}'
$l = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\\$env:USERNAME"
$l.Delay = 'PT10M'
$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$p = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName '{TASK_NAME}' -Description 'Daily software snapshot and change report (sysscan)' -Action $a -Trigger @($t, $l) -Settings $s -Principal $p -Force | Out-Null
"""
    ok, out = _ps(script)
    if ok:
        return True, f"Scheduled: daily at {time} and 10 minutes after you sign in.\nRuns: {exe} {args}"
    return False, f"Could not register the task: {out}"


def remove() -> tuple[bool, str]:
    if not IS_WINDOWS:
        return False, "Nothing to remove: scheduling is Windows-only."
    ok, out = _ps(f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false")
    return (True, "Scheduled task removed.") if ok else (False, f"Could not remove the task: {out}")


def status() -> tuple[bool, str]:
    if not IS_WINDOWS:
        return False, "Scheduling is Windows-only."
    ok, out = _ps(f"$t = Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction Stop; "
                  "$i = $t | Get-ScheduledTaskInfo; "
                  "\"State: $($t.State)`nLast run: $($i.LastRunTime) (result $($i.LastTaskResult))`n"
                  "Next run: $($i.NextRunTime)`nRuns: $($t.Actions[0].Execute) $($t.Actions[0].Arguments)\"")
    return (True, out) if ok else (False, "No sysscan task is registered.")
