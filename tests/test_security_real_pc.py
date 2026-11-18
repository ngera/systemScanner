"""Regression tests from a real Windows 11 Home laptop (2026-11-18): false alarms that must not come back."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import sysscan.security as security
from sysscan.config import Config
from sysscan.security.analyze import ALERT, INFO, OK, WARN
from sysscan.security.probe import as_list
from sysscan.store import Store

NOW = datetime(2026, 11, 18, 21, 0, tzinfo=UTC)
SINCE = NOW - timedelta(days=30)
WG = r"C:\Program Files\McAfee\WPS\16.3.1.108\vpn\Bins\x64\win24h2\wireguard.exe"
TEAMS = r"C:\Users\njger\AppData\Local\Microsoft\WindowsApps\MSTeams_8wekyb3d8bbwe\ms-teams.exe"
ONEDRIVE = r"C:\Users\njger\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"
SYNTP = r"C:\WINDOWS\system32\drivers\SynTP.sys"


@pytest.mark.parametrize("empty", [{}, {"value": [], "Count": 0}])
def test_powershell51_empty_arrays(empty):
    assert as_list(empty) == []
    assert as_list({"value": [{"a": 1}], "Count": 1}) == [{"a": 1}]
    assert as_list({"exe": "x"}) == [{"exe": "x"}]


def home_laptop(empty) -> dict:
    return {
        "rdp": {"deny": 1, "nla": 1, "port": 3389, "assist": 1},
        "services": [], "processes": [{"pid": 25624, "name": "wireguard", "path": WG}],
        "listen_tcp": [],
        "listen_udp": [{"addr": "0.0.0.0", "port": 51820, "pid": 25624}, {"addr": "::", "port": 51820, "pid": 25624}],
        "established": [],
        "adapters": [{"name": "wg", "desc": "WireGuard Tunnel", "status": "Up"}],
        "sessions": empty,
        "kbd_filters": ["SynTP", "kbdclass"],
        "kbd_drivers": [{"name": "SynTP", "path": SYNTP, "state": "Running"}],
        "ifeo": empty,
        "accessibility": [{"exe": "sethc.exe", "status": "Valid", "signer": "CN=Microsoft Windows"}],
        "run_keys": [{"where": r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "name": "Teams",
                      "command": f'"{TEAMS}" msteams:system-initiated'}],
        "startup_folder": empty,
        "tasks": [{"where": "Task Scheduler \\", "task_path": "\\", "name": "OneDrive Standalone Update Task-S-1-5-21-1-500",
                   "command": ONEDRIVE}],
        "defender": {"antivirus": True, "realtime": True, "tamper": True, "sig_age_days": 0},
        "detections": empty, "av_products": ["McAfee"], "firewall": [{"name": "Public", "enabled": True}],
    }


@pytest.mark.parametrize("empty", [{}, {"value": [], "Count": 0}])
def test_home_laptop_has_no_false_alarms(tmp_path, monkeypatch, empty):
    monkeypatch.setattr(security, "IS_WINDOWS", True)
    monkeypatch.setattr(security, "collect_state", lambda: home_laptop(empty))
    monkeypatch.setattr(security, "collect_history", lambda since: {})
    monkeypatch.setattr(security, "read_tool_logs", lambda since: [])
    monkeypatch.setattr(security, "is_admin", lambda: True)
    asked: list[str] = []

    def facts(paths):
        asked.extend(paths)
        out = {}
        for p in paths:
            if p == ONEDRIVE:
                out[p.lower()] = {"path": p, "name": "OneDriveStandaloneUpdater.exe", "exists": False}
            elif p == SYNTP:
                out[p.lower()] = {"path": p, "name": "SynTP.sys", "exists": True, "sig_status": "Valid",
                                  "signer": "CN=Microsoft Windows Hardware Compatibility Publisher",
                                  "company": "Synaptics Incorporated"}
            else:
                out[p.lower()] = {"path": p, "name": p.rsplit("\\", 1)[-1], "exists": True, "sig_status": "NotSigned"}
        return out

    monkeypatch.setattr(security, "file_facts", facts)
    st = Store(tmp_path / "db.sqlite")
    res = security.run_security(Config(home=tmp_path), st, SINCE, [])
    st.close()
    k = {f.key: f for f in res.findings}
    problems = {f.key for f in res.findings if f.status in (ALERT, WARN)}
    assert problems == {"exposure:remote_assistance"}, problems  # the one real finding on that PC
    assert k["exposure:vpn_server"].status == OK
    assert k["monitoring:accessibility_backdoor"].status == OK
    assert k["protection:detections"].status == OK
    assert k["monitoring:kbd_filters:syntp"].status == INFO and "Synaptics" in k["monitoring:kbd_filters:syntp"].title
    assert TEAMS not in asked  # Store app alias: not signature-checked
    assert not any("autostart:" in key for key in problems)


def test_unsigned_lookalike_touchpad_driver_still_warns(tmp_path, monkeypatch):
    s = home_laptop({})
    monkeypatch.setattr(security, "IS_WINDOWS", True)
    monkeypatch.setattr(security, "collect_state", lambda: s)
    monkeypatch.setattr(security, "collect_history", lambda since: {})
    monkeypatch.setattr(security, "read_tool_logs", lambda since: [])
    monkeypatch.setattr(security, "is_admin", lambda: True)
    monkeypatch.setattr(security, "file_facts", lambda paths: {
        p.lower(): {"path": p, "name": p.rsplit("\\", 1)[-1], "exists": True, "sig_status": "NotSigned"} for p in paths})
    st = Store(tmp_path / "db.sqlite")
    res = security.run_security(Config(home=tmp_path), st, SINCE, [])
    st.close()
    f = {x.key: x for x in res.findings}["monitoring:kbd_filters:syntp"]
    assert f.status == WARN and f.fix
