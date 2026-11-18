"""Read the PC's current remote-access / monitoring state and its remote-session history.

Everything is gathered by read-only queries. One PowerShell run collects the current state, a second checks
code signatures for the handful of auto-start programs that need it, and a third reads session history from
event logs. Each section is wrapped separately, so one failure (for example the Security log without admin
rights, or Defender cmdlets when another antivirus is installed) never hides the rest.

All parsing lives in pure functions that take plain dicts, so it is tested on any OS with fixtures.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
from typing import Any

from sysscan.security.catalog import ACCESSIBILITY_EXES
from sysscan.winutil import IS_WINDOWS, parse_iso, run_powershell


def as_list(v: Any) -> list:
    """Normalise PowerShell JSON into a list.

    ConvertTo-Json turns one-element arrays into scalars, and Windows PowerShell 5.1 can turn an empty or
    wrapped array into ``{"value": [...], "Count": n}`` or ``{}``. All of these become a plain list.
    """
    if v is None:
        return []
    if isinstance(v, dict):
        if not v:
            return []
        if "value" in v and set(v) <= {"value", "Count", "count", "Length"}:
            return as_list(v["value"])
        return [v]
    return v if isinstance(v, list) else [v]


# ----------------------------------------------------------------------------- current state

STATE_SCRIPT = r"""
$r = [ordered]@{}
function Grab($name, [scriptblock]$sb) {
  try { $r[$name] = & $sb } catch { $r[$name + '_error'] = "$($_.Exception.Message)" }
}
Grab 'rdp' {
  $ts  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
  $tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
  $ra  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
  [pscustomobject]@{ deny = $ts.fDenyTSConnections; nla = $tcp.UserAuthentication; port = $tcp.PortNumber
                     assist = $ra.fAllowToGetHelp }
}
Grab 'services' { @(Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; start = $_.StartMode; path = $_.PathName } }) }
Grab 'processes' { @(Get-Process | ForEach-Object {
  [pscustomobject]@{ pid = $_.Id; name = $_.ProcessName; path = $(try { $_.Path } catch { $null }) } }) }
Grab 'listen_tcp' { @(Get-NetTCPConnection -State Listen | ForEach-Object {
  [pscustomobject]@{ addr = $_.LocalAddress; port = $_.LocalPort; pid = $_.OwningProcess } }) }
Grab 'listen_udp' { @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -in 500,4500,1701,1194,51820 } | ForEach-Object {
  [pscustomobject]@{ addr = $_.LocalAddress; port = $_.LocalPort; pid = $_.OwningProcess } }) }
Grab 'established' { @(Get-NetTCPConnection -State Established |
  Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' } | ForEach-Object {
  [pscustomobject]@{ remote = $_.RemoteAddress; rport = $_.RemotePort; lport = $_.LocalPort; pid = $_.OwningProcess } }) }
Grab 'adapters' { @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; desc = $_.InterfaceDescription; status = "$($_.Status)" } }) }
Grab 'sessions' {
  # qwinsta isn't included in Windows Home (which can't host Remote Desktop anyway). Sysnative covers 32-bit Python.
  $q = @("$env:windir\Sysnative\qwinsta.exe", "$env:windir\System32\qwinsta.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($q) { @(& $q 2>$null | ForEach-Object { "$_" }) } else { @() } }
Grab 'kbd_filters' { @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}' -Name UpperFilters -ErrorAction Stop).UpperFilters) }
Grab 'kbd_drivers' { @(foreach ($f in @($r['kbd_filters'])) { if ($f -and $f -ne 'kbdclass') {
  $d = Get-CimInstance Win32_SystemDriver -Filter "Name='$($f -replace "'", '')'" -ErrorAction SilentlyContinue
  $p = "$($d.PathName)" -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:windir -replace '^(?i)system32', "$env:windir\System32"
  [pscustomobject]@{ name = $f; path = $p; state = "$($d.State)"; display = "$($d.DisplayName)" } } }) }
Grab 'ifeo' { @(foreach ($exe in @(%ACCESSIBILITY%)) {
  $p = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe" -ErrorAction SilentlyContinue
  if ($p -and $p.Debugger) { [pscustomobject]@{ exe = $exe; debugger = $p.Debugger } } }) }
Grab 'accessibility' { @(foreach ($exe in @(%ACCESSIBILITY%)) {
  $f = Join-Path $env:windir "System32\$exe"
  if (Test-Path $f) { $s = Get-AuthenticodeSignature $f
    [pscustomobject]@{ exe = $exe; status = "$($s.Status)"; signer = "$($s.SignerCertificate.Subject)" } } }) }
Grab 'run_keys' { @(foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                                  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                                  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                                  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
  $item = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($item) { $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
    [pscustomobject]@{ where = $k; name = $_.Name; command = "$($_.Value)" } } } }) }
Grab 'startup_folder' { $sh = New-Object -ComObject WScript.Shell
  @(foreach ($d in (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
                   (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')) {
    Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | ForEach-Object {
      $target = if ($_.Extension -eq '.lnk') { $sh.CreateShortcut($_.FullName).TargetPath } else { $_.FullName }
      [pscustomobject]@{ where = $d; name = $_.Name; command = "$target" } } }) }
Grab 'tasks' { @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $t = $_; foreach ($a in @($t.Actions)) { if ($a.Execute) {
    [pscustomobject]@{ where = "Task Scheduler $($t.TaskPath)"; task_path = $t.TaskPath; name = $t.TaskName; command = "$($a.Execute) $($a.Arguments)".Trim() } } } }) }
Grab 'defender' { $s = Get-MpComputerStatus -ErrorAction Stop
  [pscustomobject]@{ service = $s.AMServiceEnabled; antivirus = $s.AntivirusEnabled; realtime = $s.RealTimeProtectionEnabled
                     tamper = $s.IsTamperProtected; sig_age_days = $s.AntivirusSignatureAge } }
Grab 'detections' { $names = @{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $names["$($_.ThreatID)"] = $_.ThreatName }
  @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) } | ForEach-Object {
    [pscustomobject]@{ t = $_.InitialDetectionTime.ToUniversalTime().ToString('o'); name = $names["$($_.ThreatID)"]
                       resources = "$(@($_.Resources) -join '; ')"; fixed = [bool]$_.ActionSuccess } }) }
Grab 'av_products' { @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
  ForEach-Object { "$($_.displayName)" }) }
Grab 'firewall' { @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; enabled = [bool]$_.Enabled } }) }
[pscustomobject]$r | ConvertTo-Json -Depth 5 -Compress
"""


def collect_state() -> dict[str, Any]:
    exes = ",".join(f"'{e}'" for e in ACCESSIBILITY_EXES)
    rows = run_powershell(STATE_SCRIPT.replace("%ACCESSIBILITY%", exes), timeout=300)
    return rows[0] if rows else {}


SIGNATURE_SCRIPT = r"""
$paths = @(%PATHS%)
@(foreach ($p in $paths) { if (Test-Path -LiteralPath $p) { $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{ path = $p; status = "$($s.Status)"; signer = "$($s.SignerCertificate.Subject)" } } }) |
  ConvertTo-Json -Depth 3 -Compress
"""


def check_signatures(paths: list[str]) -> dict[str, dict[str, str]]:
    if not paths:
        return {}
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    rows = run_powershell(SIGNATURE_SCRIPT.replace("%PATHS%", quoted), timeout=180)
    return {r["path"].lower(): r for r in rows if r.get("path")}


FILE_FACTS_SCRIPT = r"""
$paths = @(%PATHS%)
@(foreach ($p in $paths) {
  $o = [ordered]@{ path = $p; exists = $false }
  try {
    if (Test-Path -LiteralPath $p -PathType Leaf) {
      $i = Get-Item -LiteralPath $p -Force
      $o.exists = $true; $o.size = $i.Length
      $o.modified = $i.LastWriteTimeUtc.ToString('o'); $o.created = $i.CreationTimeUtc.ToString('o')
      $v = $i.VersionInfo
      $o.company = "$($v.CompanyName)".Trim(); $o.product = "$($v.ProductName)".Trim()
      $o.description = "$($v.FileDescription)".Trim(); $o.original_name = "$($v.OriginalFilename)".Trim()
      $o.version = "$($v.FileVersion)".Trim()
      try { $o.sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
      $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue
      $o.sig_status = "$($s.Status)"; $o.signer = "$($s.SignerCertificate.Subject)"
    } elseif (Test-Path -LiteralPath $p -PathType Container) { $o.exists = $true; $o.folder = $true }
  } catch { $o.error = "$($_.Exception.Message)" }
  [pscustomobject]$o
}) | ConvertTo-Json -Depth 3 -Compress
"""


def file_facts(paths: list[str]) -> dict[str, dict[str, Any]]:
    """Hash, signature and version info for each path (read-only). Keyed by lower-case path."""
    paths = [p for p in dict.fromkeys(paths) if p]
    if not paths:
        return {}
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    rows = run_powershell(FILE_FACTS_SCRIPT.replace("%PATHS%", quoted), timeout=300)
    out = {}
    for r in rows:
        if isinstance(r, dict) and r.get("path"):
            r["name"] = PureWindowsPath(str(r["path"])).name
            out[str(r["path"]).lower()] = r
    return out


def signer_name(subject: str) -> str:
    """'CN=AnyDesk Software GmbH, O=…' → 'AnyDesk Software GmbH'."""
    m = re.search(r"CN=(\"[^\"]+\"|[^,]+)", subject or "")
    return m.group(1).strip('"') if m else ""


_EXE_IN_COMMAND = re.compile(r'^\s*"?([^"]+?\.(?:exe|bat|cmd|ps1|vbs|js|scr|com|dll))"?', re.I)


def command_path(command: str) -> str | None:
    """Pull the program path out of a command line, expanding %VARS%."""
    m = _EXE_IN_COMMAND.match(os.path.expandvars(command or ""))
    return m.group(1) if m else None


# ----------------------------------------------------------------------------- session history

def _wevt(log: str, ids: list[int], since: datetime, xpath_extra: str = "") -> str:
    ms = max(int((datetime.now(UTC) - since).total_seconds() * 1000), 1)
    id_expr = " or ".join(f"EventID={i}" for i in ids)
    xpath = f"*[System[({id_expr}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]{xpath_extra}"
    return (f"""@(try {{ Get-WinEvent -LogName '{log}' -FilterXPath "{xpath}" -ErrorAction Stop | ForEach-Object {{
      [pscustomobject]@{{ t = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id
        props = @($_.Properties | ForEach-Object {{ "$($_.Value)" }}); msg = "$($_.Message)" }} }} }}
    catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatching*') {{ [pscustomobject]@{{ error = "$($_.Exception.Message)" }} }} }})""")


def collect_history(since: datetime) -> dict[str, Any]:
    script = "$r = [ordered]@{}\n"
    queries = {
        # RDP sign-ins: Security 4624 with LogonType 10 (needs admin).
        "rdp_logons": _wevt("Security", [4624], since, " and *[EventData[Data[@Name='LogonType']='10']]"),
        # Someone passed Remote Desktop's network authentication (has the source IP).
        "rdp_auth": _wevt("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", [1149], since),
        # Remote Desktop session logon / reconnect.
        "rdp_sessions": _wevt("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", [21, 25], since),
        # OpenSSH server sign-ins.
        "ssh": _wevt("OpenSSH/Operational", [4], since),
    }
    for key, q in queries.items():
        script += f"$r['{key}'] = {q}\n"
    script += "[pscustomobject]$r | ConvertTo-Json -Depth 5 -Compress\n"
    rows = run_powershell(script, timeout=300)
    return rows[0] if rows else {}


@dataclass
class Session:
    time: datetime | None
    method: str  # Remote Desktop | SSH | TeamViewer | AnyDesk
    who: str  # user name or remote ID
    source: str  # IP address or remote ID
    detail: str = ""
    extra: dict[str, str] = field(default_factory=dict)


_PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd|fc|::1$|127\.)", re.I)


def is_local_address(ip: str) -> bool:
    return bool(_PRIVATE.match(ip or ""))


def parse_history(h: dict[str, Any]) -> tuple[list[Session], list[str]]:
    sessions: list[Session] = []
    errors: list[str] = []
    for key, rows in h.items():
        for r in as_list(rows):
            if not isinstance(r, dict):
                continue
            if r.get("error"):
                errors.append(f"{key}: {r['error']}")
                continue
            t, props, msg = parse_iso(r.get("t")), [str(p) for p in as_list(r.get("props"))], str(r.get("msg") or "")
            if key == "rdp_logons" and len(props) > 18:
                user = f"{props[6]}\\{props[5]}" if props[6] and props[6] != "-" else props[5]
                sessions.append(Session(t, "Remote Desktop", user, props[18], "Signed in over Remote Desktop "
                                        "(Security log 4624, logon type 10)"))
            elif key == "rdp_auth" and props:
                user = f"{props[1]}\\{props[0]}" if len(props) > 1 and props[1] else props[0]
                sessions.append(Session(t, "Remote Desktop", user, props[2] if len(props) > 2 else "",
                                        "Passed Remote Desktop network sign-in (event 1149)"))
            elif key == "rdp_sessions" and props:
                addr = props[2] if len(props) > 2 else ""
                if addr.upper() in ("LOCAL", ""):
                    continue  # console sign-in at the PC itself
                verb = "connected" if r.get("id") == 21 else "reconnected"
                sessions.append(Session(t, "Remote Desktop", props[0], addr, f"Remote Desktop session {verb} (event {r.get('id')})"))
            elif key == "ssh" and "accepted" in msg.lower():
                m = re.search(r"Accepted \S+ for (\S+) from (\S+)", msg)
                sessions.append(Session(t, "SSH", m.group(1) if m else "?", m.group(2) if m else "?",
                                        "Signed in over SSH (OpenSSH log)"))
    return sessions, errors


# ----------------------------------------------------------------------------- remote tools' own logs

_TV_DATE = ("%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S")


def _parse_local(text: str, formats: tuple[str, ...]) -> datetime | None:
    for fmt in formats:
        try:
            return datetime.strptime(text.strip(), fmt).astimezone().astimezone(UTC)
        except ValueError:
            continue
    return None


def parse_teamviewer_incoming(text: str, since: datetime) -> list[Session]:
    """TeamViewer's Connections_incoming.txt: ID, name, start, end, local user, type, GUID (tab-separated)."""
    out = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 4 or not parts[0]:
            continue
        start = _parse_local(parts[2], _TV_DATE)
        if start is None or start < since:
            continue
        end = parts[3]
        kind = parts[5] if len(parts) > 5 else ""
        out.append(Session(start, "TeamViewer", parts[1] or parts[0], f"TeamViewer ID {parts[0]}",
                           f"Incoming TeamViewer {kind or 'connection'} until {end}".strip()))
    return out


_ANYDESK = re.compile(r"^\s*Incoming\s+(\d{4}-\d{2}-\d{2}),?\s+(\d{2}:\d{2}(?::\d{2})?)\s+(\S+)\s+(\d+)", re.I)


def parse_anydesk_trace(text: str, since: datetime) -> list[Session]:
    """AnyDesk's connection_trace.txt lines like 'Incoming  2026-11-17, 21:35  User  123456789  123456789'."""
    out = []
    for line in text.splitlines():
        m = _ANYDESK.match(line)
        if not m:
            continue
        stamp = f"{m.group(1)} {m.group(2) if m.group(2).count(':') == 2 else m.group(2) + ':00'}"
        t = _parse_local(stamp, ("%Y-%m-%d %H:%M:%S",))
        if t is None or t < since:
            continue
        how = m.group(3)
        if how.upper() == "REJECTED":
            detail = "Incoming AnyDesk connection that was REJECTED"
        else:
            detail = f"Incoming AnyDesk connection (accepted by: {how})"
        out.append(Session(t, "AnyDesk", m.group(4), f"AnyDesk ID {m.group(4)}", detail))
    return out


def read_tool_logs(since: datetime) -> list[Session]:
    if not IS_WINDOWS:
        return []
    env = os.environ
    candidates = [
        (Path(env.get("ProgramFiles", r"C:\Program Files")) / "TeamViewer" / "Connections_incoming.txt", parse_teamviewer_incoming),
        (Path(env.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "TeamViewer" / "Connections_incoming.txt",
         parse_teamviewer_incoming),
        (Path(env.get("ProgramData", r"C:\ProgramData")) / "AnyDesk" / "connection_trace.txt", parse_anydesk_trace),
        (Path(env.get("APPDATA", "")) / "AnyDesk" / "connection_trace.txt", parse_anydesk_trace),
    ]
    out: list[Session] = []
    for path, parser in candidates:
        try:
            out += parser(path.read_text(encoding="utf-8", errors="replace"), since)
        except OSError:
            continue
    return out


def default_since(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)
