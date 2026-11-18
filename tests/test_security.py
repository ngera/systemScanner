"""Remote access & monitoring check: analysis rules, log parsers, trust list, deltas and rendering."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sysscan.report.model import Report, report_from_dict
from sysscan.report.render import render_html, render_json, render_markdown
from sysscan.security import SecurityResult, TrustList, mark_changes
from sysscan.security.analyze import (
    ALERT,
    INFO,
    OK,
    WARN,
    analyze,
    exposure_findings,
    monitoring_findings,
    paths_needing_signature,
    protection_findings,
    session_findings,
    tool_findings,
)
from sysscan.security.probe import (
    Session,
    as_list,
    command_path,
    parse_anydesk_trace,
    parse_history,
    parse_teamviewer_incoming,
)
from sysscan.store import Store

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
SINCE = NOW - timedelta(days=30)


def clean_state() -> dict:
    """What a quiet, healthy PC looks like."""
    return {
        "rdp": {"deny": 1, "nla": 1, "port": 3389, "assist": 0},
        "services": [{"name": "WinDefend", "display": "Microsoft Defender Antivirus Service", "state": "Running",
                      "start": "Auto"}],
        "processes": [{"pid": 4, "name": "System", "path": ""}],
        "listen_tcp": [{"addr": "0.0.0.0", "port": 135, "pid": 1000}],
        "listen_udp": [{"addr": "0.0.0.0", "port": 500, "pid": 1200}],
        "established": [],
        "adapters": [{"name": "Wi-Fi", "desc": "MediaTek Wi-Fi 6E MT7922", "status": "Up"}],
        "sessions": [" SESSIONNAME       USERNAME   ID  STATE", ">console          neeraj      1  Active"],
        "kbd_filters": ["kbdclass"],
        "ifeo": [],
        "accessibility": [{"exe": "sethc.exe", "status": "Valid", "signer": "CN=Microsoft Windows"}],
        "run_keys": [{"where": "HKCU Run", "name": "OneDrive",
                      "command": r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'}],
        "startup_folder": [],
        "tasks": [],
        "defender": {"antivirus": True, "realtime": True, "tamper": True, "sig_age_days": 0},
        "detections": [],
        "av_products": ["Windows Defender"],
        "firewall": [{"name": "Domain", "enabled": True}, {"name": "Private", "enabled": True},
                     {"name": "Public", "enabled": True}],
    }


def by_key(findings):
    return {f.key: f for f in findings}


def test_clean_pc_has_no_problems():
    f = analyze(clean_state(), [], [], {}, SINCE)
    assert [x for x in f if x.status in (ALERT, WARN)] == []
    keys = by_key(f)
    for k in ("exposure:rdp", "exposure:vpn_server", "tools:none", "sessions:none", "monitoring:kbd_filters",
              "monitoring:accessibility_backdoor", "monitoring:autostart", "protection:defender",
              "protection:detections", "protection:firewall"):
        assert keys[k].status == OK, k


def test_rdp_on_and_nla_off():
    s = clean_state()
    s["rdp"] = {"deny": 0, "nla": 1, "port": 3389, "assist": 1}
    k = by_key(exposure_findings(s))
    assert k["exposure:rdp"].status == WARN
    assert k["exposure:remote_assistance"].status == WARN
    s["rdp"]["nla"] = 0
    assert by_key(exposure_findings(s))["exposure:rdp"].status == ALERT


def test_vpn_server_detection_ignores_windows_ike():
    s = clean_state()
    s["processes"].append({"pid": 1200, "name": "svchost", "path": r"C:\Windows\System32\svchost.exe"})
    assert by_key(exposure_findings(s))["exposure:vpn_server"].status == OK
    s["services"].append({"name": "RemoteAccess", "display": "Routing and Remote Access", "state": "Running",
                          "start": "Auto"})
    s["listen_tcp"].append({"addr": "0.0.0.0", "port": 1723, "pid": 1300})
    f = by_key(exposure_findings(s))["exposure:vpn_server"]
    assert f.status == ALERT and any("1723" in e for e in f.evidence)


def test_overlay_network_and_vpn_client():
    s = clean_state()
    s["adapters"].append({"name": "Tailscale", "desc": "Tailscale Tunnel", "status": "Up"})
    s["adapters"].append({"name": "OpenVPN", "desc": "TAP-Windows Adapter V9", "status": "Disconnected"})
    k = by_key(exposure_findings(s))
    assert k["exposure:overlay:tailscale"].status == WARN
    assert any(key.startswith("exposure:vpn_client:") and f.status == INFO for key, f in k.items())


def test_remote_tool_states():
    s = clean_state()
    names = ["AnyDesk"]
    f = by_key(tool_findings(s, names))
    assert f["tools:remote:anydesk"].status == INFO and "tools:none" not in f
    s["processes"].append({"pid": 777, "name": "AnyDesk", "path": r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"})
    s["services"].append({"name": "AnyDesk", "display": "AnyDesk Service", "state": "Running", "start": "Auto"})
    assert by_key(tool_findings(s, names))["tools:remote:anydesk"].status == WARN
    s["established"].append({"pid": 777, "remote": "203.0.113.9", "rport": 443})
    f = by_key(tool_findings(s, names))["tools:remote:anydesk"]
    assert f.status == ALERT and "connected right now" in f.title


def test_monitoring_software_is_alert():
    f = by_key(tool_findings(clean_state(), ["Spyrix Free Keylogger 12.0"]))
    m = [x for k, x in f.items() if k.startswith("tools:monitoring:")]
    assert m and m[0].status == ALERT and m[0].area == "monitoring"


def test_live_rdp_session_and_history_grouping():
    s = clean_state()
    s["sessions"].append(" rdp-tcp#3        bob         2  Active")
    sessions = [
        Session(NOW - timedelta(days=1), "Remote Desktop", "PC\\bob", "203.0.113.5", "Signed in"),
        Session(NOW - timedelta(days=2), "Remote Desktop", "PC\\bob", "203.0.113.5", "Signed in"),
        Session(NOW - timedelta(days=3), "Remote Desktop", "PC\\neeraj", "192.168.1.20", "Signed in"),
    ]
    f = session_findings(s, sessions, SINCE)
    k = by_key(f)
    assert k["sessions:rdp_live"].status == ALERT
    internet = k["sessions:remote_desktop:pc\\bob:203.0.113.5"]
    assert internet.status == ALERT and "2 times" in internet.title and "internet" in internet.title
    assert k["sessions:remote_desktop:pc\\neeraj:192.168.1.20"].status == WARN
    assert "sessions:none" not in k


def test_keyboard_filter_accessibility_and_autostart():
    s = clean_state()
    s["kbd_filters"] = ["kbdclass", "HpqKbFiltr"]
    s["ifeo"] = [{"exe": "sethc.exe", "debugger": r"C:\Windows\System32\cmd.exe"}]
    s["run_keys"].append({"where": "HKCU Run", "name": "updater",
                          "command": r'"C:\Users\x\AppData\Roaming\svc\upd.exe" -hidden'})
    paths = paths_needing_signature(s)
    assert paths == [r"C:\Users\x\AppData\Roaming\svc\upd.exe"]
    k = by_key(monitoring_findings(s, {paths[0].lower(): {"status": "NotSigned"}}))
    assert k["monitoring:kbd_filters:hpqkbfiltr"].status == WARN
    assert k["monitoring:accessibility_backdoor"].status == ALERT
    auto = k[r"monitoring:autostart:c:\users\x\appdata\roaming\svc\upd.exe"]
    assert auto.status == WARN and "upd.exe" in auto.title
    # a signed program in a user folder is fine
    k = by_key(monitoring_findings(s, {paths[0].lower(): {"status": "Valid"}}))
    assert "monitoring:autostart" in k


def test_protection_problems():
    s = clean_state()
    s["defender"] = {"antivirus": True, "realtime": False, "tamper": True, "sig_age_days": 12}
    s["detections"] = [{"t": "2026-11-10T08:00:00", "name": "Trojan:Win32/Test", "fixed": False, "resources": "x"}]
    s["firewall"][2]["enabled"] = False
    k = by_key(protection_findings(s))
    assert k["protection:defender"].status == ALERT
    assert k["protection:detections"].status == ALERT
    assert k["protection:firewall"].status == WARN and "Public" in k["protection:firewall"].title
    s["av_products"] = ["Windows Defender", "McAfee"]
    k = by_key(protection_findings(s))
    assert "protection:defender" not in k and k["protection:other_av"].status == INFO


def test_parse_history_events():
    props = [""] * 19
    props[5], props[6], props[18] = "bob", "PC", "203.0.113.5"
    h = {"rdp_logons": [{"t": "2026-11-17T10:00:00Z", "props": props}],
         "rdp_sessions": [{"t": "2026-11-17T10:00:01Z", "id": 21, "props": ["PC\\bob", "2", "LOCAL"]},
                          {"t": "2026-11-17T10:00:02Z", "id": 25, "props": ["PC\\bob", "2", "203.0.113.5"]}],
         "ssh": [{"t": "2026-11-16T09:00:00Z", "msg": "Accepted password for admin from 10.0.0.4 port 5022 ssh2"}],
         "rdp_auth": {"error": "access denied"}}
    sessions, errors = parse_history(h)
    assert [(s.method, s.who, s.source) for s in sessions] == [
        ("Remote Desktop", "PC\\bob", "203.0.113.5"), ("Remote Desktop", "PC\\bob", "203.0.113.5"),
        ("SSH", "admin", "10.0.0.4")]
    assert errors == ["rdp_auth: access denied"]


def test_tool_log_parsers():
    since = datetime(2026, 11, 1, tzinfo=UTC)
    tv = "123456789\tAlice\t10-11-2026 14:00:00\t10-11-2026 14:30:00\tneeraj\tRemoteControl\t{guid}\n" \
         "987654321\tOld\t01-01-2025 10:00:00\t01-01-2025 10:05:00\tneeraj\tRemoteControl\t{guid}\n"
    s = parse_teamviewer_incoming(tv, since)
    assert len(s) == 1 and s[0].who == "Alice" and s[0].method == "TeamViewer"
    ad = "Incoming    2026-11-17, 21:35    User    123456789    123456789\nOutgoing    2026-11-17, 22:00  X  1  1\n"
    s = parse_anydesk_trace(ad, since)
    assert len(s) == 1 and s[0].method == "AnyDesk" and "123456789" in s[0].source


def test_helpers():
    assert as_list(None) == [] and as_list({"a": 1}) == [{"a": 1}] and as_list([1]) == [1]
    assert command_path(r'"C:\A B\x.exe" -y') == r"C:\A B\x.exe"
    assert command_path(r"C:\Users\x\run.exe /q") == r"C:\Users\x\run.exe"


def test_trust_list_roundtrip_and_prefix(tmp_path):
    t = TrustList(tmp_path / "trusted.toml")
    t.entries["tools:remote:anydesk"] = "my own AnyDesk"
    t.entries["sessions:anydesk:*"] = ""
    t.save()
    t2 = TrustList(tmp_path / "trusted.toml")
    assert t2.match("tools:remote:anydesk") == "my own AnyDesk"
    assert t2.match("sessions:anydesk:alice:anydesk id 1") == "trusted"
    assert t2.match("tools:remote:teamviewer") is None
    s = clean_state()
    s["processes"].append({"pid": 7, "name": "AnyDesk", "path": ""})
    s["services"].append({"name": "AnyDesk", "display": "AnyDesk Service", "state": "Running", "start": "Auto"})
    findings = analyze(s, [], ["AnyDesk"], {}, SINCE)
    t2.apply(findings)
    f = by_key(findings)["tools:remote:anydesk"]
    assert f.trusted and f.trust_note == "my own AnyDesk"
    res = SecurityResult(NOW, SINCE, True, findings)
    assert res.count(WARN) == 0


def test_mark_changes_new_and_resolved():
    s = clean_state()
    s["rdp"]["deny"] = 0
    findings = analyze(s, [], [], {}, SINCE)
    # first ever check: nothing is "new"
    assert mark_changes(findings, []) == [] and not any(f.new for f in findings)
    previous = [{"key": "exposure:rdp", "area": "exposure", "status": "ok", "title": "Remote Desktop is off"},
                {"key": "exposure:ssh", "area": "exposure", "status": "warn", "title": "An SSH server is running"}]
    resolved = mark_changes(findings, previous)
    assert by_key(findings)["exposure:rdp"].new
    assert [r.key for r in resolved] == ["exposure:ssh"]


def test_store_security_runs(tmp_path):
    st = Store(tmp_path / "db.sqlite")
    assert st.last_security_findings() == (None, [])
    findings = analyze(clean_state(), [], [], {}, SINCE)
    st.save_security_findings(NOW, None, [f.to_dict() for f in findings])
    at, prev = st.last_security_findings()
    assert at is not None and {p["key"] for p in prev} == {f.key for f in findings}
    st.close()


def _report(security, mode="security"):
    return Report(scan_id=1, host="PC", period_start=SINCE, period_end=NOW, generated_at=NOW, baseline_at=None,
                  is_admin=True, tool_version="test", changes=[], warnings=[], security=security, mode=mode)


@pytest.mark.parametrize("mode", ["security", "changes"])
def test_render_security(mode):
    s = clean_state()
    s["rdp"]["deny"] = 0
    s["rdp"]["nla"] = 0
    findings = analyze(s, [], ["AnyDesk"], {}, SINCE)
    previous = [{"key": "exposure:rdp", "area": "exposure", "status": "ok", "title": "Remote Desktop is off"}]
    resolved = mark_changes(findings, previous)
    sec = SecurityResult(NOW, SINCE, True, findings, previous_at=NOW - timedelta(days=1), resolved=resolved)
    rep = _report(sec, mode)
    html = render_html(rep)
    assert "Remote access &amp; monitoring" in html and "Remote Desktop is turned on" in html
    assert "NEW" in html and "sysscan trust" in html and 'class="secrow' in html
    md = render_markdown(rep)
    assert "## Remote access & monitoring" in md and "sysscan trust 'exposure:rdp'" in md
    back = report_from_dict(__import__("json").loads(render_json(rep)))
    assert back.mode == mode and back.security.count(ALERT) == sec.count(ALERT)
    assert {f.key for f in back.security.findings} == {f.key for f in findings}
