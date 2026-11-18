"""Step-by-step fixes for security findings.

Each step is ``{"text": what and why, "cmd": an optional PowerShell command}``. Commands are shown in the
report with a copy button and are **never run by sysscan**. They target the exact services, processes, files,
registry values and tasks recorded on the finding, and are written for PowerShell run as administrator.
Destructive steps come after "check it first" steps, and registry edits are preceded by a backup.
"""

from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Any

from sysscan.known import ps_quote
from sysscan.security.analyze import ALERT, WARN, Finding

RDP_FIREWALL_GROUP = "@FirewallAPI.dll,-28752"  # the "Remote Desktop" rule group, independent of Windows' language
OFFLINE_SCAN = {"text": "Run a Microsoft Defender Offline scan. The PC restarts and scans before Windows (and any "
                        "hidden malware) loads. Save your work first.", "cmd": "Start-MpWDOScan"}
PASSWORDS = {"text": "From a different, trusted device, change the passwords you've used on this PC (email first, then "
                     "banking and work accounts), and turn on two-step sign-in where you can."}
APPS_SETTINGS = {"text": "Or uninstall it from Settings → Apps → Installed apps.", "cmd": "start ms-settings:appsfeatures"}


def step(text: str, cmd: str | None = None) -> dict[str, str]:
    return {"text": text, "cmd": cmd} if cmd else {"text": text}


def q(s: str) -> str:
    return ps_quote(s)


def _reg_ps(path: str) -> str:
    """'HKLM\\SOFTWARE\\…' or 'HKLM:\\SOFTWARE\\…' → PowerShell provider path 'HKLM:\\SOFTWARE\\…'."""
    for hive in ("HKLM", "HKCU"):
        if path.upper().startswith(hive + "\\"):
            return hive + ":" + path[len(hive):]
    return path


def _reg_native(path: str) -> str:
    """'HKLM:\\SOFTWARE\\…' → 'HKLM\\SOFTWARE\\…' (for reg.exe)."""
    return path.replace("HKLM:", "HKLM").replace("HKCU:", "HKCU")


def _stop_services(names: list[str]) -> list[dict[str, str]]:
    if not names:
        return []
    joined = ",".join(q(n) for n in names)
    return [step("Stop its service" + ("s" if len(names) > 1 else "") + " and stop " + ("them" if len(names) > 1 else "it")
                 + " from starting with Windows.",
                 f"Stop-Service -Name {joined} -Force; Set-Service -Name {joined} -StartupType Disabled")]


def _stop_processes(names: list[str], pids: list[int] | None = None) -> list[dict[str, str]]:
    if pids:
        return [step("End the running program now (this disconnects any open session).",
                     f"Stop-Process -Id {','.join(str(p) for p in pids)} -Force")]
    if names:
        return [step("End the running program now (this disconnects any open session).",
                     f"Stop-Process -Name {','.join(q(n) for n in names)} -Force")]
    return []


def _uninstall(installs: list[dict[str, str]], display: str) -> list[dict[str, str]]:
    out = []
    for e in installs:
        if e.get("uninstall"):
            out.append(step(f"Uninstall {e['name']} with its own uninstaller.", f"cmd /c --% {e['uninstall']}"))
    if not out:
        out.append(step(f"Uninstall {display}.", f"winget uninstall --name {q(display)}"))
    out.append(APPS_SETTINGS)
    return out


def _check_file(path: str) -> list[dict[str, str]]:
    return [step(f"Scan the file with Microsoft Defender: {path}",
                 f"Start-MpScan -ScanType CustomScan -ScanPath {q(path)}")]


def _block_program(path: str, name: str) -> dict[str, str]:
    return step(f"Block it from accepting connections from the network (firewall rule for {name}).",
                f"New-NetFirewallRule -DisplayName {q('sysscan: block ' + name)} -Direction Inbound "
                f"-Program {q(path)} -Action Block")


def _proc_steps(procs: list[dict[str, Any]]) -> list[dict[str, str]]:
    out = []
    for p in procs:
        name = p.get("name") or f"process {p.get('pid')}"
        if p.get("path"):
            out += _check_file(p["path"])
        out.append(step(f"Stop {name} (PID {p.get('pid')}), which is listening on {p.get('proto', 'TCP')} port "
                        f"{p.get('port')}.", f"Stop-Process -Id {p.get('pid')} -Force"))
        if p.get("path"):
            out.append(_block_program(p["path"], PureWindowsPath(p["path"]).name))
    return out


def _rdp_off() -> dict[str, str]:
    return step("Turn Remote Desktop off and close its firewall rules (or use Settings → System → Remote Desktop).",
                "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                f"-Name fDenyTSConnections -Value 1; Get-NetFirewallRule -Group {q(RDP_FIREWALL_GROUP)} | "
                "Disable-NetFirewallRule")


# ----------------------------------------------------------------------------- per finding type

def _exposure(f: Finding) -> list[dict[str, str]]:
    m, k = f.meta, f.key
    if k == "exposure:rdp":
        out = [_rdp_off()]
        if not m.get("nla"):
            out.append(step("If you need Remote Desktop, at least turn Network Level Authentication on.",
                            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\"
                            "WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"))
        out.append(step("See which accounts are allowed to sign in remotely (administrators always are).",
                        "Get-LocalGroupMember -SID S-1-5-32-555; Get-LocalGroupMember -SID S-1-5-32-544"))
        out.append(step(f"Check that your router doesn't forward port {m.get('port', 3389)} to this PC "
                        "(router admin page → Port forwarding)."))
        return out
    if k == "exposure:remote_assistance":
        return [step("Turn off Remote Assistance invitations (or System Properties → Remote → untick it).",
                     "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Remote Assistance' "
                     "-Name fAllowToGetHelp -Value 0")]
    if k == "exposure:vpn_server":
        out = []
        if m.get("rras"):
            out += _stop_services(["RemoteAccess"])
            out.append(step("Delete the \"Incoming Connections\" entry, if there is one, in Network Connections.",
                            "ncpa.cpl"))
        return out + _proc_steps([p for p in m.get("procs", []) if p.get("pid", -1) > 4])
    if k == "exposure:ssh":
        return [step("Check which keys can sign in without a password, and remove any you don't recognise.",
                     "Get-Content \"$env:ProgramData\\ssh\\administrators_authorized_keys\", "
                     "\"$env:USERPROFILE\\.ssh\\authorized_keys\" -ErrorAction SilentlyContinue"),
                *_stop_services(["sshd"]),
                step("If you never use it, remove the OpenSSH Server feature.",
                     "Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0")]
    if k == "exposure:winrm":
        return [step("Turn off remote PowerShell (on a work PC, ask IT first: they may rely on it).",
                     "Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled")]
    if k.startswith("exposure:overlay:"):
        return [*_stop_services(m.get("services", [])), *_uninstall(m.get("installs", []), m.get("tool", "it"))]
    if k.startswith(("exposure:port:", "exposure:listener:")):
        return _proc_steps(m.get("procs", []))
    return []


def _tools(f: Finding) -> list[dict[str, str]]:
    m = f.meta
    out = []
    if m.get("kind") == "monitoring":
        out.append(step("On a work or school PC, ask IT before removing it: it may be required. Otherwise:"))
    if m.get("connected"):
        out.append(step("If you didn't start this session, disconnect from the internet now (Wi-Fi off or cable out), "
                        "then continue."))
    out += _stop_processes(m.get("processes", []), m.get("pids") if m.get("connected") else None)
    out += _stop_services(m.get("services", []))
    out += _uninstall(m.get("installs", []), m.get("tool", "it"))
    if m.get("kind") == "monitoring" or m.get("connected"):
        out += [OFFLINE_SCAN, PASSWORDS]
    elif f.status in (ALERT, WARN):
        out.append(step("If you keep it, set a strong unattended-access password (or turn unattended access off) in "
                        "its settings, and check its list of trusted devices."))
    return out


def _sessions(f: Finding) -> list[dict[str, str]]:
    m = f.meta
    if f.key == "sessions:rdp_live":
        out = [step("See who is connected (look for rdp-tcp#… lines).", "qwinsta")]
        for s in m.get("sessions", []):
            if s.get("id"):
                out.append(step(f"Sign out session {s['id']}" + (f" ({s['user']})" if s.get("user") else "")
                                + " if it isn't you.", f"logoff {s['id']}"))
        return out + [_rdp_off(), PASSWORDS]
    if m.get("rejected"):
        return [step("Nothing got in. If attempts keep coming from the internet, turn the method off or "
                     "close the port on your router.")]
    method, who = m.get("method", ""), m.get("who", "")
    out = [step("If you recognise this (you, from another device of yours), mark it as trusted. If not:")]
    if method == "Remote Desktop":
        out.append(_rdp_off())
    elif method == "SSH":
        out += _stop_services(["sshd"])
    elif method in ("TeamViewer", "AnyDesk"):
        out.append(step(f"In {method}, remove this ID from trusted devices / the address book, and turn off "
                        "unattended access, or uninstall it.", "start ms-settings:appsfeatures"))
    if who and method in ("Remote Desktop", "SSH"):
        user = who.split("\\")[-1]
        out.append(step(f"Change the password of the account {who} (it will ask for the new one).",
                        f"net user {q(user)} *"))
    out.append(step("Look for accounts you don't recognise.",
                    "Get-LocalUser | Where-Object Enabled | Select-Object Name, LastLogon, Description"))
    if m.get("internet"):
        out.append(step("This came from the internet: check your router for port forwarding to this PC and remove it."))
    return out + [PASSWORDS]


def _monitoring(f: Finding) -> list[dict[str, str]]:
    m, k = f.meta, f.key
    if k.startswith("monitoring:kbd_filters:"):
        out = []
        for d in m.get("drivers", []):
            out.append(step(f"See the driver file and maker of {d}.",
                            f"Get-CimInstance Win32_SystemDriver -Filter \"Name='{d.replace(chr(39), '')}'\" | "
                            "Select-Object Name, DisplayName, State, PathName"))
        for p in f.paths:
            out += _check_file(p)
        out.append(step("If it isn't from your laptop maker or a security product you use, uninstall the program that "
                        "installed it. Don't edit the UpperFilters registry value by hand: a mistake there can leave "
                        "you without a working keyboard.", "start ms-settings:appsfeatures"))
        return out
    if k == "monitoring:accessibility_backdoor":
        out = []
        for exe in m.get("ifeo", []):
            key = f"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{exe}"
            out.append(step(f"Back up, then remove the debugger hijack on {exe}.",
                            f"reg export {q(_reg_native(key))} \"$env:USERPROFILE\\Desktop\\ifeo-{exe}.reg\" /y; "
                            f"Remove-ItemProperty -Path {q(key)} -Name Debugger"))
        if m.get("bad_files"):
            out.append(step("Restore Windows' original system files (takes a while).", "sfc /scannow"))
        return out + [OFFLINE_SCAN, PASSWORDS]
    if k.startswith("monitoring:autostart:"):
        e, exe = m.get("autostart", {}), m.get("exe", "")
        name = PureWindowsPath(exe).name
        out = _check_file(exe)
        out.append(step("Check its hash on VirusTotal (link under the file's details above) or with the AI lookup."))
        kind = e.get("kind")
        if kind == "run":
            key = _reg_ps(e.get("where", ""))
            out.append(step(f"If it's not yours: back up, then remove the \"{e.get('name')}\" auto-start entry.",
                            f"reg export {q(_reg_native(key))} \"$env:USERPROFILE\\Desktop\\run-backup.reg\" /y; "
                            f"Remove-ItemProperty -Path {q(key)} -Name {q(e.get('name', ''))}"))
        elif kind == "startup":
            item = f"{e.get('where', '')}\\{e.get('name', '')}"
            out.append(step("If it's not yours: move the shortcut out of the Startup folder (to your desktop).",
                            f"Move-Item -LiteralPath {q(item)} -Destination \"$env:USERPROFILE\\Desktop\\\""))
        elif kind == "task":
            task_path = e.get("task_path") or "\\"
            out.append(step(f"If it's not yours: disable the scheduled task \"{e.get('name')}\".",
                            f"Disable-ScheduledTask -TaskPath {q(task_path)} -TaskName {q(e.get('name', ''))}"))
        out.append(step(f"Stop it if it's running now ({name}).",
                        f"Get-Process | Where-Object Path -eq {q(exe)} | Stop-Process -Force"))
        out.append(step("Once you're sure it's unwanted, delete the file (or let Defender quarantine it).",
                        f"Remove-Item -LiteralPath {q(exe)} -Force"))
        return out
    return []


def _protection(f: Finding) -> list[dict[str, str]]:
    m, k = f.meta, f.key
    if k == "protection:defender":
        if m.get("unreadable"):
            return [step("Open Windows Security and check Virus & threat protection.", "start windowsdefender:")]
        out = []
        if m.get("realtime_off"):
            out.append(step("Turn real-time protection back on.", "Set-MpPreference -DisableRealtimeMonitoring $false"))
        if m.get("tamper_off"):
            out.append(step("Turn tamper protection on (only possible in Windows Security → Virus & threat protection "
                            "settings).", "start windowsdefender://threatsettings"))
        if m.get("stale"):
            out.append(step("Update virus definitions.", "Update-MpSignature"))
        return out
    if k == "protection:detections":
        out = [step("See each detection, the file it was in and what Defender did.",
                    "Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, Resources, ActionSuccess | "
                    "Format-List")]
        if m.get("unresolved"):
            out.append(step("Remove the threats Defender still has active.", "Remove-MpThreat"))
        out.append(step("Run a full scan.", "Start-MpScan -ScanType FullScan"))
        return out + [OFFLINE_SCAN]
    if k == "protection:firewall":
        return [step("Turn the firewall back on.",
                     f"Set-NetFirewallProfile -Profile {','.join(m.get('profiles', ['Domain', 'Private', 'Public']))} "
                     "-Enabled True")]
    return []


BUILDERS = {"exposure": _exposure, "tools": _tools, "sessions": _sessions, "monitoring": _monitoring,
            "protection": _protection}


def add_fixes(findings: list[Finding]) -> None:
    """Fill ``fix`` for every finding that needs attention (alert/warn)."""
    for f in findings:
        if f.status not in (ALERT, WARN):
            continue
        builder = BUILDERS.get(f.area)
        if f.key.startswith("tools:monitoring:"):
            builder = _tools
        try:
            f.fix = builder(f) if builder else []
        except Exception:  # never let a fix template break the check
            f.fix = []
