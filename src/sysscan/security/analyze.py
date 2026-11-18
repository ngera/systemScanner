"""Turn raw state + history into plain-language findings.

Status levels:
  alert  🔴 investigate: something is actively allowing or doing remote access/monitoring, or was tampered with
  warn   ⚠️ worth a look: legitimate in many setups, but you should know it's there
  ok     ✅ checked and fine
  info   ℹ️ context (e.g. VPN clients, which only connect outwards)

Every finding has a stable ``key`` so it can be compared with the previous check ("new since last time") and
marked as trusted by the user. Findings also carry the exact files (``paths``) and other places (``locations``:
registry values, services, scheduled tasks) involved, plus structured ``meta`` that ``remedy.py`` turns into
fix steps.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import PureWindowsPath
from typing import Any

from sysscan.security.catalog import (
    KNOWN_KEYBOARD_FILTERS,
    MONITORING,
    OVERLAY,
    PORT_NAMES,
    REMOTE,
    STANDARD_KEYBOARD_FILTERS,
    TOOLS,
    USER_WRITABLE,
    VPN_CLIENT,
    VPN_SERVER_PORTS_TCP,
    VPN_SERVER_PORTS_UDP,
    WINDOWS_APPS,
    Tool,
)
from sysscan.security.probe import Session, as_list, command_path, is_local_address

ALERT, WARN, OK, INFO = "alert", "warn", "ok", "info"
STATUS_ORDER = {ALERT: 0, WARN: 1, INFO: 2, OK: 3}

AREAS = {
    "exposure": "Ways into this PC",
    "tools": "Remote-control tools",
    "sessions": "Recent remote sessions",
    "monitoring": "Monitoring & keylogging signs",
    "protection": "Protection",
}

RDP_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY = RDP_KEY + r"\WinStations\RDP-Tcp"
RA_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"
IFEO_KEY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
KBD_CLASS_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}"


@dataclass
class Finding:
    key: str
    area: str
    status: str
    title: str
    explanation: str
    evidence: list[str] = field(default_factory=list)
    trusted: bool = False
    trust_note: str | None = None
    new: bool = False
    paths: list[str] = field(default_factory=list)  # exact files and folders involved
    locations: list[str] = field(default_factory=list)  # registry values, services, tasks …
    files: list[dict[str, Any]] = field(default_factory=list)  # file facts (+ "ai" lookup), see probe.file_facts
    fix: list[dict[str, str]] = field(default_factory=list)  # [{"text": …, "cmd": … (optional)}]
    meta: dict[str, Any] = field(default_factory=dict)  # structured context used to build ``fix``

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(**{k: d.get(k) for k in ("key", "area", "status", "title", "explanation")},
                   evidence=list(d.get("evidence") or []), trusted=bool(d.get("trusted")),
                   trust_note=d.get("trust_note"), new=bool(d.get("new")), paths=list(d.get("paths") or []),
                   locations=list(d.get("locations") or []), files=list(d.get("files") or []),
                   fix=list(d.get("fix") or []), meta=dict(d.get("meta") or {}))

    @property
    def ai_results(self) -> list[dict[str, Any]]:
        return [f["ai"] | {"file": f.get("name") or f.get("path")} for f in self.files if f.get("ai")]


def _exposed(addr: str) -> bool:
    return not (addr.startswith("127.") or addr == "::1")


def _proc_index(state: dict) -> dict[int, dict]:
    return {int(p.get("pid") or -1): p for p in as_list(state.get("processes")) if isinstance(p, dict)}


def _proc_label(p: dict | None, pid: int) -> str:
    if not p:
        return f"process {pid}"
    return f"{p.get('name') or '?'} (PID {pid}{', ' + p['path'] if p.get('path') else ''})"


def _proc_meta(p: dict | None, pid: int) -> dict[str, Any]:
    return {"pid": pid, "name": str((p or {}).get("name") or ""), "path": str((p or {}).get("path") or "")}


def _svc_exe(s: dict) -> str | None:
    """Program path of a service from its command line (PathName)."""
    return command_path(str(s.get("path") or ""))


def _uniq(items) -> list:
    out: list = []
    for i in items:
        if i and i not in out:
            out.append(i)
    return out


def _install_meta(tool: Tool, installed_info: dict[str, dict] | None) -> tuple[list[dict], list[str]]:
    """Installed-program entries matching a tool: [{name, location, uninstall}], and their folders."""
    entries = []
    for name, info in (installed_info or {}).items():
        if any(rx.search(name) for rx in tool.rx("installed")):
            entries.append({"name": name, "location": info.get("location") or "", "uninstall": info.get("uninstall") or ""})
    return entries, _uniq(e["location"] for e in entries)


# ----------------------------------------------------------------------------- exposure

def exposure_findings(state: dict, installed_info: dict[str, dict] | None = None) -> list[Finding]:
    out: list[Finding] = []
    procs = _proc_index(state)
    services = {str(s.get("name", "")).lower(): s for s in as_list(state.get("services")) if isinstance(s, dict)}
    listen = [x for x in as_list(state.get("listen_tcp")) if isinstance(x, dict)]
    listen_udp = [x for x in as_list(state.get("listen_udp")) if isinstance(x, dict)]

    def running(name: str) -> bool:
        s = services.get(name.lower())
        return bool(s) and str(s.get("state", "")).lower() == "running"

    # Remote Desktop
    rdp = state.get("rdp") or {}
    if isinstance(rdp, dict) and rdp:
        port = int(rdp.get("port") or 3389)
        on = str(rdp.get("deny")) == "0"
        listening = any(int(x.get("port") or 0) == port and _exposed(str(x.get("addr", ""))) for x in listen)
        if on:
            nla = str(rdp.get("nla")) == "1"
            out.append(Finding(
                "exposure:rdp", "exposure", WARN if nla else ALERT, "Remote Desktop is turned on",
                "Anyone who knows a password for this PC can sign in from the network and use it as if they were "
                "sitting at it." + ("" if nla else " Network Level Authentication is OFF, which makes it easier "
                                    "to attack.") + " Turn it off in Settings → System → Remote Desktop if you don't use it.",
                [f"Listening on port {port}: {'yes' if listening else 'no'}", f"Network Level Authentication: {'on' if nla else 'off'}"],
                locations=[f"{RDP_KEY} → fDenyTSConnections = 0", f"{RDP_TCP_KEY} → UserAuthentication = {rdp.get('nla')}",
                           f"{RDP_TCP_KEY} → PortNumber = {port}"],
                meta={"nla": nla, "port": port}))
        else:
            out.append(Finding("exposure:rdp", "exposure", OK, "Remote Desktop is off",
                               "Nobody can sign in to this PC with Remote Desktop."))
        if str(rdp.get("assist")) == "1":
            out.append(Finding(
                "exposure:remote_assistance", "exposure", WARN, "Remote Assistance invitations are allowed",
                "You can invite someone to view or control your screen. Nothing happens unless you send an "
                "invitation, but if you never use it, turn it off in System Properties → Remote.",
                [f"{RA_KEY}: fAllowToGetHelp = 1"], locations=[f"{RA_KEY} → fAllowToGetHelp = 1"]))

    # Inbound VPN server (Windows "Incoming connection" / RRAS or a third-party server)
    vpn_evidence, vpn_procs = [], []
    rras = running("RemoteAccess")
    if rras:
        vpn_evidence.append("Routing and Remote Access service (RemoteAccess) is running")
    for x in listen:
        port = int(x.get("port") or 0)
        if port in VPN_SERVER_PORTS_TCP and _exposed(str(x.get("addr", ""))):
            pid = int(x.get("pid") or -1)
            vpn_evidence.append(f"TCP {port} ({VPN_SERVER_PORTS_TCP[port]}) open: {_proc_label(procs.get(pid), pid)}")
            vpn_procs.append(_proc_meta(procs.get(pid), pid) | {"port": port, "proto": "TCP"})
    for x in listen_udp:
        port = int(x.get("port") or 0)
        pid = int(x.get("pid") or -1)
        p = procs.get(pid)
        name = str((p or {}).get("name", "")).lower()
        # IKE ports (500/4500) are also opened by Windows' own IPsec service for outbound VPNs.
        # Unknown owners are treated as Windows too, so standard users don't get a false alarm.
        if port in (500, 4500) and name in ("svchost", "lsass", "") and not rras:
            continue
        if port in VPN_SERVER_PORTS_UDP:
            vpn_evidence.append(f"UDP {port} ({VPN_SERVER_PORTS_UDP[port]}) open: {_proc_label(p, pid)}")
            vpn_procs.append(_proc_meta(p, pid) | {"port": port, "proto": "UDP"})
    vpn_evidence = _uniq(vpn_evidence)  # IPv4 and IPv6 sockets of the same program
    vpn_procs = list({(p["pid"], p["port"], p["proto"]): p for p in vpn_procs}.values())
    if vpn_evidence:
        out.append(Finding(
            "exposure:vpn_server", "exposure", ALERT, "This PC is accepting incoming VPN connections",
            "A VPN server lets other computers join this PC's network from elsewhere. Unless you set this up "
            "on purpose, investigate. On Windows it's configured under Network Connections → New Incoming Connection.",
            vpn_evidence, paths=_uniq(p["path"] for p in vpn_procs),
            locations=["Service: RemoteAccess (Routing and Remote Access)"] if rras else [],
            meta={"rras": rras, "procs": vpn_procs}))
    else:
        out.append(Finding("exposure:vpn_server", "exposure", OK, "No incoming VPN server",
                           "This PC isn't set up to accept incoming VPN connections."))

    # SSH server, WinRM
    if running("sshd"):
        exe = _svc_exe(services["sshd"])
        out.append(Finding("exposure:ssh", "exposure", WARN, "An SSH server is running",
                           "Anyone with an account on this PC can open a remote command line over the network.",
                           ["OpenSSH SSH Server service (sshd) is running"], paths=[exe] if exe else [],
                           locations=["Service: sshd (OpenSSH SSH Server)",
                                      r"%ProgramData%\ssh\administrators_authorized_keys",
                                      r"%USERPROFILE%\.ssh\authorized_keys"],
                           meta={"services": ["sshd"]}))
    winrm_ports = [x for x in listen if int(x.get("port") or 0) in (5985, 5986) and _exposed(str(x.get("addr", "")))]
    if running("WinRM") and winrm_ports:
        out.append(Finding("exposure:winrm", "exposure", WARN, "Remote PowerShell (WinRM) is listening",
                           "Administrators can run commands on this PC from the network. Common on work PCs; "
                           "unusual on a home PC.", [f"Port {x['port']} open" for x in winrm_ports],
                           locations=["Service: WinRM (Windows Remote Management)"], meta={"services": ["WinRM"]}))

    # Networks that make this PC reachable
    adapters = [a for a in as_list(state.get("adapters")) if isinstance(a, dict)]
    for tool in [t for t in TOOLS if t.kind in (OVERLAY, VPN_CLIENT)]:
        hits = [a for a in adapters if any(rx.search(str(a.get("desc", ""))) for rx in tool.rx("adapters"))]
        svc = [s for s in services.values() if _svc_match(tool, s)]
        if not hits and not svc:
            continue
        up = [a for a in hits if str(a.get("status", "")).lower() == "up"]
        ev = [f"Adapter: {a.get('desc')} ({a.get('status')})" for a in hits] + \
             [f"Service: {s.get('display') or s.get('name')} ({s.get('state')}, {s.get('start')})" for s in svc]
        if tool.kind == OVERLAY:
            installs, folders = _install_meta(tool, installed_info)
            out.append(Finding(
                f"exposure:overlay:{tool.id}", "exposure",
                WARN if up or any(str(s.get("state", "")).lower() == "running" for s in svc) else INFO,
                f"{tool.name} network is installed", tool.description + " Fine if it's yours; otherwise remove it.", ev,
                paths=_uniq([_svc_exe(s) for s in svc] + folders),
                locations=[f"Service: {s.get('name')} ({s.get('display') or ''})" for s in svc]
                + [f"Network adapter: {a.get('name')} ({a.get('desc')})" for a in hits],
                meta={"tool": tool.name, "services": [str(s.get("name")) for s in svc], "installs": installs}))
        else:
            out.append(Finding(f"exposure:vpn_client:{tool.id}", "exposure", INFO, f"{tool.name} (VPN client)",
                               tool.description + " It connects outwards and doesn't let others in.", ev))

    # Remote-access ports open to the network (not already covered above)
    covered = {3389, 5985, 5986, 1723, 1194}
    for x in listen:
        port = int(x.get("port") or 0)
        if port in covered or not _exposed(str(x.get("addr", ""))):
            continue
        pid = int(x.get("pid") or -1)
        p = procs.get(pid)
        path = str((p or {}).get("path") or "")
        pm = _proc_meta(p, pid) | {"port": port, "proto": "TCP"}
        if port in PORT_NAMES and port not in (445,):
            out.append(Finding(f"exposure:port:{port}", "exposure", WARN, f"Port {port} is open: {PORT_NAMES[port]}",
                               "A program is accepting connections from the network on a port normally used for "
                               "remote access.", [_proc_label(p, pid)], paths=[path] if path else [],
                               locations=[f"TCP port {port} on {x.get('addr')}"], meta={"procs": [pm]}))
            covered.add(port)
        elif path and USER_WRITABLE.search(path):
            out.append(Finding(f"exposure:listener:{PureWindowsPath(path).name.lower()}", "exposure", WARN,
                               f"{PureWindowsPath(path).name} accepts network connections",
                               "A program running from a user folder (not Program Files) is listening for "
                               "connections from the network. Check that you recognise it.",
                               [f"Port {port}: {_proc_label(p, pid)}"], paths=[path],
                               locations=[f"TCP port {port} on {x.get('addr')}"], meta={"procs": [pm]}))
    return out


def _svc_match(tool: Tool, s: dict) -> bool:
    if not tool.services:
        return False
    name, display = str(s.get("name", "")), str(s.get("display", ""))
    return any(rx.search(name) or rx.search(display) for rx in tool.rx("services"))


# ----------------------------------------------------------------------------- remote-control and monitoring tools

def tool_findings(state: dict, installed_names: list[str], installed_info: dict[str, dict] | None = None) -> list[Finding]:
    out: list[Finding] = []
    procs = [p for p in as_list(state.get("processes")) if isinstance(p, dict)]
    by_pid = _proc_index(state)
    services = [s for s in as_list(state.get("services")) if isinstance(s, dict)]
    established = [e for e in as_list(state.get("established")) if isinstance(e, dict)]
    any_remote = False

    for tool in [t for t in TOOLS if t.kind in (REMOTE, MONITORING)]:
        exe_names = {n.lower() for n in tool.processes}
        running = [p for p in procs if f"{str(p.get('name', '')).lower()}.exe" in exe_names]
        svc = [s for s in services if _svc_match(tool, s)]
        inst = [n for n in installed_names if any(rx.search(n) for rx in tool.rx("installed"))]
        if not (running or svc or inst):
            continue
        pids = {int(p.get("pid") or -1) for p in running}
        conns = [e for e in established if int(e.get("pid") or -1) in pids]
        autostart = [s for s in svc if str(s.get("start", "")).lower() in ("auto", "automatic")]
        ev = [f"Installed: {n}" for n in sorted(set(inst))] + \
             [f"Running: {_proc_label(by_pid.get(int(p['pid'])), int(p['pid']))}" for p in running] + \
             [f"Service: {s.get('display') or s.get('name')} ({s.get('state')}, starts {s.get('start')})" for s in svc] + \
             [f"Connected now to {e.get('remote')}:{e.get('rport')}" for e in conns]
        installs, folders = _install_meta(tool, installed_info)
        paths = _uniq([str(p.get("path") or "") for p in running] + [_svc_exe(s) for s in svc] + folders)
        locations = [f"Service: {s.get('name')} ({s.get('display') or ''}), starts {s.get('start')}" for s in svc] + \
                    [f"Installed program: {e['name']}" for e in installs]
        meta = {"tool": tool.name, "processes": _uniq(str(p.get("name") or "") for p in running),
                "pids": sorted(pids), "services": [str(s.get("name")) for s in svc], "installs": installs,
                "connected": bool(conns), "installed_names": sorted(set(inst))}

        if tool.kind == MONITORING:
            out.append(Finding(f"tools:monitoring:{tool.id}", "monitoring", ALERT, f"{tool.name} is on this PC",
                               tool.description + " If you (or your employer, for a work PC) didn't install it, "
                               "someone may be recording what you type and do.", ev,
                               paths=paths, locations=locations, meta=meta | {"kind": "monitoring"}))
            continue

        any_remote = True
        if conns and tool.id != "quick_assist":
            status, state_txt = ALERT, "is connected right now"
        elif tool.id == "quick_assist" and running:
            status, state_txt = WARN, "is open right now"
        elif autostart or (running and svc):
            status, state_txt = WARN, "is installed and starts automatically"
        else:
            status, state_txt = INFO, "is installed"
        explanation = tool.description + {
            ALERT: " It has an active network connection, which usually means a remote session or that it's "
                   "standing by for one. If you're not using it, disconnect and investigate.",
            WARN: " Anyone with its ID and password (or a saved login) could connect. Fine if you use it.",
            INFO: " It isn't running, so nobody can connect through it right now.",
        }[status]
        out.append(Finding(f"tools:remote:{tool.id}", "tools", status, f"{tool.name} {state_txt}", explanation, ev,
                           paths=paths, locations=locations, meta=meta | {"kind": "remote", "id": tool.id}))

    if not any_remote:
        out.append(Finding("tools:none", "tools", OK, "No known remote-control tools found",
                           "None of the remote-control apps sysscan knows about (TeamViewer, AnyDesk, VNC, "
                           "Chrome Remote Desktop …) are installed or running."))
    return out


# ----------------------------------------------------------------------------- sessions

def session_lines(state: dict) -> list[str]:
    """Active Remote Desktop sessions from `qwinsta` output."""
    out = []
    for line in as_list(state.get("sessions")):
        text = str(line)
        if re.search(r"\brdp-tcp#\d+", text, re.I):
            out.append(" ".join(text.split()))
    return out


def _live_session(line: str) -> dict[str, str]:
    """'rdp-tcp#3 bob 2 Active' → {'user': 'bob', 'id': '2'}."""
    parts = line.lstrip(">").split()
    ids = [p for p in parts[1:] if p.isdigit()]
    user = parts[1] if len(parts) > 2 and not parts[1].isdigit() else ""
    return {"user": user, "id": ids[0] if ids else ""}


def session_findings(state: dict, sessions: list[Session], since: datetime | None) -> list[Finding]:
    out: list[Finding] = []
    live = session_lines(state)
    if live:
        out.append(Finding("sessions:rdp_live", "sessions", ALERT, "Someone is connected by Remote Desktop right now",
                           "A Remote Desktop session is active. If it isn't you (from another device), "
                           "disconnect the network and change your password.", live,
                           meta={"sessions": [_live_session(x) for x in live]}))

    grouped: dict[tuple[str, str, str], list[Session]] = defaultdict(list)
    for s in sessions:
        grouped[(s.method, s.who, s.source)].append(s)
    for (method, who, source), items in sorted(grouped.items(), key=lambda kv: max(
            (x.time.timestamp() if x.time else 0) for x in kv[1]), reverse=True):
        items.sort(key=lambda x: x.time.timestamp() if x.time else 0, reverse=True)
        last = items[0].time
        local = is_local_address(source)
        rejected = all("REJECTED" in s.detail for s in items)
        status = INFO if rejected else (WARN if local or method in ("TeamViewer", "AnyDesk") else ALERT)
        internet = bool(re.match(r"^[\d.:a-f]+$", source, re.I)) and source not in ("", "-") and not local
        where = " from your local network" if local else (" from the internet" if internet else "")
        count = f"{len(items)} time{'s' if len(items) != 1 else ''}"
        last_txt = last.astimezone().strftime("%a %d %b %Y %H:%M") if last else "unknown time"
        out.append(Finding(
            f"sessions:{method.lower().replace(' ', '_')}:{who.lower()}:{source.lower()}", "sessions", status,
            f"{method}: {who or 'unknown'} connected {count}{where}",
            ("All of these attempts were rejected." if rejected else
             "Check that you recognise this. If you don't, change your passwords and turn off the method used.")
            + f" Last time: {last_txt}.",
            [f"{s.time.astimezone():%Y-%m-%d %H:%M} · {s.source} · {s.detail}" if s.time else s.detail for s in items[:10]]
            + ([f"… and {len(items) - 10} more"] if len(items) > 10 else []),
            meta={"method": method, "who": who, "source": source, "local": local, "internet": internet,
                  "rejected": rejected}))
    if not live and not sessions:
        period = f" since {since.astimezone():%d %b %Y}" if since else ""
        out.append(Finding("sessions:none", "sessions", OK, f"No remote sessions found{period}",
                           "Windows' logs (and TeamViewer/AnyDesk's own logs, where present) show no incoming "
                           "remote sessions in this period."))
    return out


# ----------------------------------------------------------------------------- monitoring signs and protection

def monitoring_findings(state: dict, signatures: dict[str, dict[str, str]]) -> list[Finding]:
    out: list[Finding] = []
    filters = [str(f) for f in as_list(state.get("kbd_filters")) if str(f).strip()]
    extra = [f for f in filters if f.lower() not in STANDARD_KEYBOARD_FILTERS]
    if extra:
        drivers = {str(d.get("name", "")).lower(): d for d in as_list(state.get("kbd_drivers")) if isinstance(d, dict)}
        found = [drivers[f.lower()] for f in extra if f.lower() in drivers]
        out.append(Finding(
            "monitoring:kbd_filters:" + ",".join(sorted(f.lower() for f in extra)), "monitoring", WARN,
            "Extra keyboard filter driver" + ("s" if len(extra) > 1 else "") + f": {', '.join(extra)}",
            "A driver sits between your keyboard and Windows and can see every key pressed. Laptop makers "
            "(for hotkeys) and some security tools install these legitimately. Search the name online if you "
            "don't recognise it.", [f"Keyboard class UpperFilters: {', '.join(filters)}"]
            + [f"Driver {d.get('name')}: {d.get('path') or '?'} ({d.get('state') or '?'})" for d in found],
            paths=_uniq(str(d.get("path") or "") for d in found),
            locations=[f"{KBD_CLASS_KEY} → UpperFilters = {' '.join(filters)}"]
            + [f"Driver service: {f}" for f in extra], meta={"drivers": extra}))
    elif "kbd_filters" in state:
        out.append(Finding("monitoring:kbd_filters", "monitoring", OK, "No extra keyboard drivers",
                           "Only Windows' own keyboard driver is attached to the keyboard."))

    ifeo = [x for x in as_list(state.get("ifeo")) if isinstance(x, dict) and x.get("exe") and x.get("debugger")]
    tamper = [f"{x.get('exe')} → debugger set to {x.get('debugger')}" for x in ifeo]
    bad_files = []
    for x in as_list(state.get("accessibility")):
        if not isinstance(x, dict) or not x.get("exe"):
            continue
        if str(x.get("status")) != "Valid" or "microsoft" not in str(x.get("signer", "")).lower():
            tamper.append(f"{x.get('exe')} is not a valid Microsoft-signed file (signature: {x.get('status')})")
            bad_files.append(str(x.get("exe")))
    if tamper:
        debuggers = [command_path(str(x.get("debugger") or "")) for x in ifeo]
        out.append(Finding("monitoring:accessibility_backdoor", "monitoring", ALERT,
                           "Sign-in screen accessibility tools have been tampered with",
                           "Replacing Sticky Keys, Ease of Access and similar tools is a classic way to get a "
                           "command prompt at the sign-in screen without a password.", tamper,
                           paths=_uniq([rf"C:\Windows\System32\{e}" for e in bad_files] + debuggers),
                           locations=[rf"{IFEO_KEY}\{x.get('exe')} → Debugger = {x.get('debugger')}" for x in ifeo],
                           meta={"ifeo": [str(x.get("exe")) for x in ifeo], "bad_files": bad_files}))
    elif "accessibility" in state:
        out.append(Finding("monitoring:accessibility_backdoor", "monitoring", OK, "Sign-in screen tools are untouched",
                           "Sticky Keys, Ease of Access and the other sign-in screen tools are Windows' genuine files."))

    suspicious = []
    for entry in autostart_entries(state):
        path = command_path(entry["command"])
        if not _needs_signature(path):
            continue
        sig = signatures.get(path.lower())
        if sig and sig.get("status") in ("Valid", "Missing"):
            continue  # signed, or the file doesn't exist (e.g. another account's task), so nothing can run
        status_txt = sig.get("status") if sig else "not checked"
        suspicious.append((entry, path, status_txt))
    for entry, path, sig_status in suspicious:
        name = PureWindowsPath(path).name
        if entry["kind"] == "task":
            loc = f"Scheduled task: {entry.get('task_path', '')}{entry['name']}"
        elif entry["kind"] == "startup":
            loc = f"Startup folder: {entry['where']}\\{entry['name']}"
        else:
            loc = f"Registry: {entry['where']} → {entry['name']}"
        out.append(Finding(
            f"monitoring:autostart:{path.lower()}", "monitoring", WARN, f"Unsigned program starts automatically: {name}",
            "It starts every time you sign in, runs from a user folder, and isn't digitally signed. That's how "
            "most keyloggers and other malware stay on a PC, but small tools and scripts do it too.",
            [f"Started by: {entry['where']} → {entry['name']}", f"Command: {entry['command']}",
             f"Signature: {sig_status}"], paths=[path], locations=[loc], meta={"autostart": entry, "exe": path}))
    if not suspicious and any(k in state for k in ("run_keys", "startup_folder", "tasks")):
        out.append(Finding("monitoring:autostart", "monitoring", OK, "No unsigned auto-start programs in user folders",
                           "Everything set to start automatically from your user folders is digitally signed."))
    return out


def autostart_entries(state: dict) -> list[dict[str, str]]:
    out = []
    for key, kind in (("run_keys", "run"), ("startup_folder", "startup"), ("tasks", "task")):
        for e in as_list(state.get(key)):
            if isinstance(e, dict) and e.get("command"):
                item = {"where": str(e.get("where", "")), "name": str(e.get("name", "")),
                        "command": str(e["command"]), "kind": kind}
                if kind == "task":
                    item["task_path"] = str(e.get("task_path") or "\\")
                out.append(item)
    return out


def _detection_paths(resources: str) -> list[str]:
    """Defender resources look like 'file:_C:\\x\\y.exe; regkey:_HKLM…'. Return the file paths."""
    out = []
    for r in str(resources or "").split(";"):
        r = r.strip()
        if r.lower().startswith(("file:_", "process:_")):
            p = r.split("_", 1)[1]
            out.append(p.split("->")[0].strip())
    return out


def protection_findings(state: dict) -> list[Finding]:
    out: list[Finding] = []
    d = state.get("defender")
    others = [p for p in as_list(state.get("av_products")) if "defender" not in str(p).lower()]
    if isinstance(d, dict) and d:
        problems = []
        if not d.get("antivirus") or not d.get("realtime"):
            problems.append("real-time protection is off")
        if d.get("tamper") is False:
            problems.append("tamper protection is off")
        age = d.get("sig_age_days")
        stale = isinstance(age, int) and age > 7
        if stale:
            problems.append(f"virus definitions are {age} days old")
        if problems and not others:
            out.append(Finding("protection:defender", "protection", ALERT if "real-time" in problems[0] else WARN,
                               "Microsoft Defender: " + ", ".join(problems),
                               "Turn it back on in Windows Security → Virus & threat protection.",
                               [f"Antivirus enabled: {d.get('antivirus')}", f"Real-time: {d.get('realtime')}",
                                f"Tamper protection: {d.get('tamper')}", f"Definitions age (days): {age}"],
                               meta={"realtime_off": not d.get("antivirus") or not d.get("realtime"),
                                     "tamper_off": d.get("tamper") is False, "stale": stale}))
        elif not problems:
            out.append(Finding("protection:defender", "protection", OK, "Microsoft Defender is on and up to date",
                               "Real-time protection and tamper protection are on, and virus definitions are current."))
    if others:
        out.append(Finding("protection:other_av", "protection", INFO, "Other antivirus: " + ", ".join(others),
                           "Another security product is registered with Windows and may be handling protection "
                           "instead of Defender."))
    if "defender" not in state and not others:
        out.append(Finding("protection:defender", "protection", WARN, "Couldn't read antivirus status",
                           "sysscan couldn't ask Defender for its status. Check Windows Security manually.",
                           [str(state.get("defender_error", ""))[:200]], meta={"unreadable": True}))

    dets = [x for x in as_list(state.get("detections")) if isinstance(x, dict)
            and (x.get("name") or x.get("resources") or x.get("t"))]
    if dets:
        unresolved = [x for x in dets if not x.get("fixed")]
        out.append(Finding(
            "protection:detections", "protection", ALERT if unresolved else WARN,
            f"Defender found {len(dets)} threat{'s' if len(dets) != 1 else ''} in the last 30 days"
            + (f" ({len(unresolved)} not fully removed)" if unresolved else ""),
            "See Windows Security → Protection history for details and actions.",
            [f"{x.get('t', '')[:16].replace('T', ' ')} · {x.get('name') or 'unknown threat'} · "
             f"{'removed' if x.get('fixed') else 'NOT removed'} · {str(x.get('resources', ''))[:160]}" for x in dets[:15]],
            paths=_uniq(p for x in (unresolved or dets) for p in _detection_paths(x.get("resources", "")))[:20],
            meta={"unresolved": len(unresolved), "threats": _uniq(str(x.get("name") or "") for x in dets)}))
    elif "detections" in state:
        out.append(Finding("protection:detections", "protection", OK, "No threats found in the last 30 days",
                           "Microsoft Defender's protection history is clean for the last 30 days."))

    fw = [x for x in as_list(state.get("firewall")) if isinstance(x, dict)]
    off = [str(x.get("name")) for x in fw if not x.get("enabled")]
    if off:
        out.append(Finding("protection:firewall", "protection", WARN, f"Firewall is off for: {', '.join(off)}",
                           "The firewall blocks unwanted incoming connections. Turn it on in Windows Security → "
                           "Firewall & network protection, unless another firewall product replaces it.",
                           meta={"profiles": off}))
    elif fw:
        out.append(Finding("protection:firewall", "protection", OK, "Windows Firewall is on",
                           "The firewall is on for all network types."))
    return out


def analyze(state: dict, sessions: list[Session], installed_names: list[str],
            signatures: dict[str, dict[str, str]], since: datetime | None,
            installed_info: dict[str, dict] | None = None) -> list[Finding]:
    findings = (exposure_findings(state, installed_info) + tool_findings(state, installed_names, installed_info)
                + session_findings(state, sessions, since) + monitoring_findings(state, signatures)
                + protection_findings(state))
    area_order = list(AREAS)
    findings.sort(key=lambda f: (area_order.index(f.area), STATUS_ORDER.get(f.status, 9), f.title.lower()))
    return findings


def _needs_signature(path: str | None) -> bool:
    return bool(path) and bool(USER_WRITABLE.search(path)) and not WINDOWS_APPS.search(path)


def paths_needing_signature(state: dict) -> list[str]:
    out = []
    for entry in autostart_entries(state):
        path = command_path(entry["command"])
        if _needs_signature(path):
            out.append(path)
    return sorted(set(out))


def refine_with_files(findings: list[Finding]) -> None:
    """Adjust findings once file facts are known: a validly signed touchpad/hotkey driver is information."""
    for f in findings:
        if not f.key.startswith("monitoring:kbd_filters:") or f.status != WARN:
            continue
        drivers = [d.lower() for d in f.meta.get("drivers", [])]
        signed = [fi for fi in f.files if fi.get("sig_status") == "Valid"]
        if drivers and all(d in KNOWN_KEYBOARD_FILTERS for d in drivers) and len(signed) >= len(drivers):
            names = ", ".join(sorted({KNOWN_KEYBOARD_FILTERS[d] for d in drivers}))
            f.status = INFO
            f.title = f"Keyboard filter driver from your laptop's hardware: {names}"
            f.explanation = ("A driver attached to the keyboard, as laptop touchpads and hotkeys normally use. Its file "
                             "is validly signed" + (f" ({', '.join(sorted({fi.get('company') for fi in signed if fi.get('company')}))})"
                                                   if any(fi.get('company') for fi in signed) else "") + ".")
