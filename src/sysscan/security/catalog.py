"""What the security check knows about: remote-control tools, monitoring/keylogging software, overlay
networks and VPN clients, plus well-known remote-access ports.

Matching is deliberately simple and transparent (process names, service names, installed-program names,
network adapter descriptions) so every finding can say exactly *why* it was raised. Contributions welcome:
a missing tool is usually a one-line addition here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    kind: str  # remote | monitoring | overlay | vpn_client
    description: str
    processes: tuple[str, ...] = ()  # lower-case executable names
    services: tuple[str, ...] = ()  # regexes on service name or display name
    installed: tuple[str, ...] = ()  # regexes on installed-program names
    adapters: tuple[str, ...] = ()  # regexes on network adapter descriptions
    ports: tuple[int, ...] = ()
    _rx: dict = field(default_factory=dict, compare=False, hash=False, repr=False)

    def rx(self, what: str) -> list[re.Pattern]:
        if what not in self._rx:
            self._rx[what] = [re.compile(p, re.I) for p in getattr(self, what)]
        return self._rx[what]


def _t(id, name, kind, description, **kw) -> Tool:
    return Tool(id=id, name=name, kind=kind, description=description, **{k: tuple(v) for k, v in kw.items()})


REMOTE = "remote"
MONITORING = "monitoring"
OVERLAY = "overlay"
VPN_CLIENT = "vpn_client"

TOOLS: list[Tool] = [
    # ---------------------------------------------------------------- remote control / screen sharing
    _t("teamviewer", "TeamViewer", REMOTE, "Remote-control app: lets someone see and control this PC.",
       processes=["teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe"],
       services=[r"^teamviewer"], installed=[r"^teamviewer"], ports=[5938]),
    _t("anydesk", "AnyDesk", REMOTE, "Remote-control app: lets someone see and control this PC.",
       processes=["anydesk.exe"], services=[r"^anydesk"], installed=[r"^anydesk"], ports=[7070]),
    _t("rustdesk", "RustDesk", REMOTE, "Open-source remote-control app.",
       processes=["rustdesk.exe"], services=[r"^rustdesk"], installed=[r"^rustdesk"],
       ports=[21115, 21116, 21117, 21118, 21119]),
    _t("chrome_remote_desktop", "Chrome Remote Desktop", REMOTE,
       "Google's remote-access host: lets this PC be controlled from another device.",
       processes=["remoting_host.exe", "remoting_desktop.exe"], services=[r"^chromoting$"],
       installed=[r"chrome remote desktop host"]),
    _t("vnc", "VNC server", REMOTE, "Screen-sharing server (TightVNC, UltraVNC, RealVNC, TigerVNC …).",
       processes=["tvnserver.exe", "winvnc.exe", "winvnc4.exe", "vncserver.exe", "vncserverui.exe"],
       services=[r"tvnserver", r"uvnc_service", r"vncserver", r"tigervnc", r"winvnc"],
       installed=[r"\bvnc\b", r"tightvnc", r"ultravnc", r"realvnc", r"tigervnc"], ports=[5900, 5901, 5902, 5800]),
    _t("splashtop", "Splashtop Streamer", REMOTE, "Remote-access app: streams and controls this PC's screen.",
       processes=["srservice.exe", "srserver.exe", "srmanager.exe"], services=[r"splashtop"],
       installed=[r"splashtop streamer"]),
    _t("screenconnect", "ScreenConnect / ConnectWise Control", REMOTE,
       "Remote-support agent often used by IT helpdesks (and by tech-support scammers).",
       processes=["screenconnect.clientservice.exe", "screenconnect.windowsclient.exe"],
       services=[r"^screenconnect client", r"connectwise control"], installed=[r"screenconnect", r"connectwise control"]),
    _t("logmein", "LogMeIn", REMOTE, "Remote-access app.",
       processes=["logmein.exe", "lmiguardiansvc.exe"], services=[r"^logmein"], installed=[r"^logmein(?! hamachi)"]),
    _t("goto_resolve", "GoTo Resolve / GoToAssist", REMOTE, "Remote-support agent.",
       processes=["gotoassist.exe", "gotoresolve.exe"], services=[r"goto\s?(resolve|assist)"],
       installed=[r"goto\s?(resolve|assist)"]),
    _t("parsec", "Parsec", REMOTE, "Low-latency remote desktop app, popular for gaming.",
       processes=["parsecd.exe"], services=[r"^parsec"], installed=[r"^parsec"]),
    _t("quick_assist", "Quick Assist", REMOTE,
       "Windows' built-in remote-help app. Only active while someone is helping you.",
       processes=["quickassist.exe"]),
    _t("meshcentral", "MeshCentral agent", REMOTE, "Remote-management agent that allows remote control.",
       processes=["meshagent.exe"], services=[r"mesh agent", r"meshagent"], installed=[r"mesh agent"]),
    _t("radmin", "Radmin Server", REMOTE, "Remote-control server.",
       processes=["rserver3.exe"], services=[r"^rserver3"], installed=[r"radmin server"]),
    _t("ammyy", "Ammyy Admin", REMOTE, "Remote-control app frequently abused by scammers.",
       processes=["aa_v3.exe", "ammyy_admin.exe"]),
    _t("supremo", "Supremo", REMOTE, "Remote-control app.",
       processes=["supremo.exe", "supremoservice.exe"], services=[r"^supremo"], installed=[r"^supremo"]),
    _t("remote_utilities", "Remote Utilities", REMOTE, "Remote-control host.",
       processes=["rutserv.exe", "rfusclient.exe"], services=[r"rmanservice"], installed=[r"remote utilities"]),
    _t("netsupport", "NetSupport Manager", REMOTE,
       "Remote-control client used in schools and offices, and also abused as a remote-access trojan.",
       processes=["client32.exe"], services=[r"^client32"], installed=[r"netsupport"]),
    _t("dwservice", "DWService agent", REMOTE, "Remote-access agent.",
       processes=["dwagsvc.exe", "dwagent.exe"], services=[r"^dwagent"], installed=[r"dwagent"]),
    _t("zoho_assist", "Zoho Assist", REMOTE, "Remote-support agent.", installed=[r"zoho assist"],
       services=[r"zoho\s?assist"]),
    _t("beyondtrust", "BeyondTrust / Bomgar", REMOTE, "Remote-support agent.",
       processes=["bomgar-scc.exe"], services=[r"bomgar", r"beyondtrust"], installed=[r"bomgar", r"beyondtrust remote"]),
    _t("atera", "Atera agent", REMOTE, "IT management agent with remote access.",
       processes=["ateraagent.exe"], services=[r"^ateraagent"], installed=[r"atera"]),
    _t("ninjarmm", "NinjaOne agent", REMOTE, "IT management agent with remote access.",
       processes=["ninjarmmagent.exe"], services=[r"ninjarmm"], installed=[r"ninjarmm", r"ninjaone"]),
    _t("action1", "Action1 agent", REMOTE, "IT management agent with remote access.",
       processes=["action1_agent.exe"], services=[r"^a1agent", r"action1"], installed=[r"action1"]),
    # ---------------------------------------------------------------- monitoring / keylogging
    _t("spyrix", "Spyrix", MONITORING, "Monitoring software that can record keystrokes and screenshots.",
       processes=["spyrix.exe", "skm.exe"], installed=[r"spyrix"]),
    _t("refog", "Refog", MONITORING, "Monitoring software / keylogger.", installed=[r"refog"]),
    _t("ardamax", "Ardamax Keylogger", MONITORING, "Keylogger.", installed=[r"ardamax"]),
    _t("kidlogger", "KidLogger", MONITORING, "Monitoring software that logs keystrokes and activity.",
       installed=[r"kidlogger"], processes=["kidlogger.exe"]),
    _t("revealer", "Revealer Keylogger", MONITORING, "Keylogger.", installed=[r"revealer keylogger"],
       processes=["rvlkl.exe"]),
    _t("elite_keylogger", "Elite / Actual / Best Free Keylogger", MONITORING, "Keylogger.",
       installed=[r"(elite|actual|best free|perfect|all in one|free)\s+keylogger", r"\bkeylogger\b"]),
    _t("spytech", "Spytech SpyAgent / Realtime-Spy", MONITORING, "Monitoring software.",
       installed=[r"spyagent", r"realtime-spy", r"spytech"]),
    _t("wolfeye", "Wolfeye", MONITORING, "Remote monitoring software.", installed=[r"wolfeye"]),
    _t("hoverwatch", "Hoverwatch", MONITORING, "Monitoring software.", installed=[r"hoverwatch"]),
    _t("teramind", "Teramind", MONITORING, "Employee-monitoring agent (records activity and keystrokes).",
       installed=[r"teramind"], services=[r"teramind"]),
    _t("activtrak", "ActivTrak", MONITORING, "Employee-monitoring agent.", installed=[r"activtrak"],
       services=[r"activtrak"]),
    _t("veriato", "Veriato / Spector", MONITORING, "Employee-monitoring software.",
       installed=[r"veriato", r"spector\s?(360|pro|cne)"]),
    _t("hubstaff", "Hubstaff", MONITORING, "Time tracker that can take screenshots and track activity.",
       installed=[r"^hubstaff"], processes=["hubstaff.exe"]),
    _t("mspy", "mSpy / FlexiSPY", MONITORING, "Spyware-style monitoring software.",
       installed=[r"\bmspy\b", r"flexispy"]),
    # ---------------------------------------------------------------- networks that make this PC reachable
    _t("tailscale", "Tailscale", OVERLAY,
       "Private network that makes this PC reachable from your other Tailscale devices.",
       services=[r"^tailscale"], adapters=[r"tailscale"], installed=[r"^tailscale"]),
    _t("zerotier", "ZeroTier", OVERLAY, "Virtual network that makes this PC reachable from others on it.",
       services=[r"zerotier"], adapters=[r"zerotier"], installed=[r"zerotier"]),
    _t("hamachi", "LogMeIn Hamachi", OVERLAY, "Virtual network that makes this PC reachable from others on it.",
       services=[r"hamachi"], adapters=[r"hamachi"], installed=[r"hamachi"]),
    _t("radmin_vpn", "Radmin VPN", OVERLAY, "Virtual network that makes this PC reachable from others on it.",
       services=[r"radmin\s?vpn", r"rvpnsrv"], adapters=[r"radmin vpn"], installed=[r"radmin vpn"]),
    _t("netbird", "NetBird", OVERLAY, "Private network that makes this PC reachable from other devices on it.",
       services=[r"netbird"], adapters=[r"netbird|wt0"], installed=[r"netbird"]),
    # ---------------------------------------------------------------- VPN clients (outbound only)
    _t("wireguard", "WireGuard", VPN_CLIENT, "VPN tunnel.", adapters=[r"wireguard"], installed=[r"^wireguard"]),
    _t("openvpn", "OpenVPN / TAP adapter", VPN_CLIENT, "VPN client adapter.",
       adapters=[r"tap-windows", r"openvpn"], installed=[r"openvpn"]),
    _t("wintun", "Wintun tunnel", VPN_CLIENT, "Tunnel driver used by many VPN apps.", adapters=[r"wintun"]),
    _t("expressvpn", "ExpressVPN", VPN_CLIENT, "Commercial VPN client.", adapters=[r"expressvpn"],
       installed=[r"expressvpn"]),
    _t("nordvpn", "NordVPN", VPN_CLIENT, "Commercial VPN client.", adapters=[r"nordlynx", r"nordvpn"],
       installed=[r"nordvpn"]),
    _t("protonvpn", "Proton VPN", VPN_CLIENT, "Commercial VPN client.", adapters=[r"proton\s?vpn"],
       installed=[r"proton\s?vpn"]),
    _t("corporate_vpn", "Corporate VPN client", VPN_CLIENT,
       "Company VPN client (Cisco AnyConnect/Secure Client, GlobalProtect, FortiClient, Pulse/Ivanti).",
       adapters=[r"anyconnect", r"cisco", r"pangp", r"globalprotect", r"fortinet", r"fortissl", r"juniper",
                 r"pulse secure", r"ivanti"],
       installed=[r"anyconnect", r"secure client", r"globalprotect", r"forticlient", r"pulse secure", r"ivanti secure"]),
]

TOOLS_BY_ID = {t.id: t for t in TOOLS}

#: Well-known inbound ports and what they mean, for listening-port findings.
PORT_NAMES: dict[int, str] = {
    22: "SSH (remote command line)",
    23: "Telnet (old, unencrypted remote command line)",
    445: "Windows file and printer sharing (SMB)",
    1194: "OpenVPN server",
    1701: "L2TP VPN server",
    1723: "PPTP VPN server",
    3389: "Remote Desktop",
    5800: "VNC (web)",
    5900: "VNC screen sharing",
    5901: "VNC screen sharing",
    5938: "TeamViewer",
    5985: "WinRM (remote PowerShell)",
    5986: "WinRM over HTTPS (remote PowerShell)",
    7070: "AnyDesk direct connections",
    21118: "RustDesk direct connections",
    51820: "WireGuard VPN server",
}

#: Inbound VPN server signatures. WireGuard's UDP 51820 is not here: WireGuard *clients* (including the VPNs
#: bundled with McAfee, Norton, etc.) bind it too, so it doesn't tell a server from a client.
VPN_SERVER_PORTS_TCP = {1723: "PPTP", 1194: "OpenVPN"}
VPN_SERVER_PORTS_UDP = {500: "IKE/IPsec", 4500: "IPsec NAT-T", 1701: "L2TP", 1194: "OpenVPN"}

#: Keyboard class upper filters that ship with Windows. Anything else is a third-party keyboard filter driver.
STANDARD_KEYBOARD_FILTERS = {"kbdclass"}

#: Laptop touchpad/hotkey filter drivers. Shown as information (not a warning) only when the driver file is
#: validly signed, since a keylogger could borrow the name.
KNOWN_KEYBOARD_FILTERS = {
    "syntp": "Synaptics touchpad driver",
    "etd": "ELAN touchpad driver",
    "apfiltr": "Alps touchpad driver",
    "apntex": "Alps touchpad driver",
    "hpqkbfiltr": "HP keyboard hotkey driver",
}

#: Store-app execution aliases (0-byte links that can't be hashed or signature-checked; Store apps are
#: signed by the Microsoft Store).
WINDOWS_APPS = re.compile(r"\\appdata\\local\\microsoft\\windowsapps\\", re.I)

#: Accessibility programs that can be launched from the sign-in screen, and are a classic backdoor target.
ACCESSIBILITY_EXES = ["sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe",
                      "AtBroker.exe"]

#: Folders any program running as you can write to: a typical home for malware that starts automatically.
USER_WRITABLE = re.compile(
    r"\\appdata\\|\\temp\\|\\downloads\\|\\users\\public\\|\\desktop\\|\\documents\\|\\programdata\\(?!microsoft\\windows\\start menu)",
    re.I,
)
