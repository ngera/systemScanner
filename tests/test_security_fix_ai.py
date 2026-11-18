"""Security findings: exact paths, file facts, fix steps and the optional AI lookup."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import sysscan.security as security
from sysscan.config import Config, load_config
from sysscan.report.model import Report, report_from_dict
from sysscan.report.render import render_html, render_json, render_markdown
from sysscan.security import SecurityResult, attach_file_facts
from sysscan.security.ai_lookup import candidates, file_payload, lookup, parse_answers, redact_path
from sysscan.security.analyze import ALERT, WARN, analyze, monitoring_findings, session_findings
from sysscan.security.probe import signer_name
from sysscan.security.remedy import add_fixes
from sysscan.store import Store

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
SINCE = NOW - timedelta(days=30)
EXE = r"C:\Users\neeraj\AppData\Roaming\svc\upd.exe"


def state() -> dict:
    return {
        "rdp": {"deny": 0, "nla": 0, "port": 3389, "assist": 0},
        "services": [{"name": "AnyDesk", "display": "AnyDesk Service", "state": "Running", "start": "Auto",
                      "path": r'"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service'}],
        "processes": [{"pid": 777, "name": "AnyDesk", "path": r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"}],
        "listen_tcp": [], "listen_udp": [], "established": [{"pid": 777, "remote": "203.0.113.9", "rport": 443}],
        "adapters": [], "sessions": [" rdp-tcp#3        bob         2  Active"],
        "kbd_filters": ["kbdclass", "EvilKbd"],
        "kbd_drivers": [{"name": "EvilKbd", "path": r"C:\Windows\System32\drivers\evilkbd.sys", "state": "Running"}],
        "ifeo": [{"exe": "sethc.exe", "debugger": r"C:\Windows\System32\cmd.exe"}],
        "accessibility": [{"exe": "sethc.exe", "status": "Valid", "signer": "CN=Microsoft Windows"}],
        "run_keys": [{"where": r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "name": "updater",
                      "command": f'"{EXE}" -hidden'}],
        "startup_folder": [],
        "tasks": [{"where": r"Task Scheduler \Evil\ ", "task_path": "\\Evil\\", "name": "Sync",
                   "command": r"C:\Users\neeraj\AppData\Local\sync\s.exe"}],
        "defender": {"antivirus": True, "realtime": False, "tamper": True, "sig_age_days": 0},
        "detections": [{"t": "2026-11-10T08:00:00", "name": "Trojan:Win32/X", "fixed": False,
                        "resources": r"file:_C:\Users\neeraj\Downloads\bad.exe; regkey:_HKLM\x"}],
        "av_products": ["Windows Defender"], "firewall": [{"name": "Public", "enabled": False}],
    }


INSTALLED = {"AnyDesk": {"location": r"C:\Program Files (x86)\AnyDesk",
                         "uninstall": r'"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --uninstall'}}


def findings():
    fs = analyze(state(), [], ["AnyDesk"], {EXE.lower(): {"status": "NotSigned"}}, SINCE, INSTALLED)
    add_fixes(fs)
    return {f.key: f for f in fs}


def cmds(f) -> str:
    return "\n".join(s.get("cmd", "") for s in f.fix)


def test_paths_and_locations():
    k = findings()
    auto = k[f"monitoring:autostart:{EXE.lower()}"]
    assert auto.paths == [EXE] and "Registry:" in auto.locations[0] and "updater" in auto.locations[0]
    tool = k["tools:remote:anydesk"]
    assert r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" in tool.paths
    assert r"C:\Program Files (x86)\AnyDesk" in tool.paths
    assert k["monitoring:kbd_filters:evilkbd"].paths == [r"C:\Windows\System32\drivers\evilkbd.sys"]
    assert k["protection:detections"].paths == [r"C:\Users\neeraj\Downloads\bad.exe"]
    assert any("Image File Execution Options\\sethc.exe" in loc for loc in k["monitoring:accessibility_backdoor"].locations)


def test_fix_steps_target_exact_items():
    k = findings()
    c = cmds(k[f"monitoring:autostart:{EXE.lower()}"])
    assert "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'updater'" in c
    assert "reg export 'HKCU\\SOFTWARE" in c and f"Start-MpScan -ScanType CustomScan -ScanPath '{EXE}'" in c
    task = k[r"monitoring:autostart:c:\users\neeraj\appdata\local\sync\s.exe"]
    assert "Disable-ScheduledTask -TaskPath '\\Evil\\' -TaskName 'Sync'" in cmds(task)
    tool = cmds(k["tools:remote:anydesk"])
    assert "Stop-Process -Id 777 -Force" in tool and "Set-Service -Name 'AnyDesk' -StartupType Disabled" in tool
    assert 'cmd /c --% "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe" --uninstall' in tool
    assert "Start-MpWDOScan" in tool  # connected right now → offline scan + passwords
    rdp = cmds(k["exposure:rdp"])
    assert "fDenyTSConnections -Value 1" in rdp and "UserAuthentication -Value 1" in rdp
    assert "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution " \
           "Options\\sethc.exe' -Name Debugger" in cmds(k["monitoring:accessibility_backdoor"])
    assert "Set-MpPreference -DisableRealtimeMonitoring $false" in cmds(k["protection:defender"])
    assert "Remove-MpThreat" in cmds(k["protection:detections"])
    assert "Set-NetFirewallProfile -Profile Public -Enabled True" in cmds(k["protection:firewall"])
    assert all(not f.fix for f in k.values() if f.status not in (ALERT, WARN))


def test_session_fix_steps():
    fs = session_findings(state(), [], SINCE)
    from sysscan.security.analyze import Session

    fs += session_findings({}, [Session(NOW, "Remote Desktop", "PC\\bob", "203.0.113.5", "Signed in")], SINCE)
    add_fixes(fs)
    k = {f.key: f for f in fs}
    assert "logoff 2" in cmds(k["sessions:rdp_live"])
    s = cmds(k["sessions:remote_desktop:pc\\bob:203.0.113.5"])
    assert "net user 'bob' *" in s and "fDenyTSConnections" in s


def test_helpers():
    assert redact_path(EXE) == r"%USERPROFILE%\AppData\Roaming\svc\upd.exe"
    assert redact_path(r"D:\Users\alice\x.exe") == r"%USERPROFILE%\x.exe"
    assert redact_path(r"\\server\Users\alice\x.exe") == r"\\server\Users\<user>\x.exe"
    assert redact_path(r"C:\Users\Public\x.exe") == r"C:\Users\Public\x.exe"
    assert signer_name('CN="Evil, Inc.", O=Evil') == "Evil, Inc." and signer_name("CN=AnyDesk Software GmbH, O=x") \
        == "AnyDesk Software GmbH"
    text = 'Here: [{"id": 0, "what": "x", "verdict": "Malicious", "confidence": "high", "advice": ["a"], ' \
           '"sources": ["https://ok", "javascript:alert(1)"]}]'
    a = parse_answers(text)[0]
    assert a["verdict"] == "malicious" and a["sources"] == ["https://ok"]


def facts(path, **kw):
    name = path.rsplit("\\", 1)[-1]
    return {"path": path, "name": name, "exists": True, "sha256": "AB" * 32, "sig_status": "NotSigned",
            "signer": "", "company": "Evil Corp", **kw}


def test_payload_has_no_personal_details():
    k = findings()
    f = k[f"monitoring:autostart:{EXE.lower()}"]
    p = file_payload(facts(EXE), f)
    blob = json.dumps(p)
    assert "neeraj" not in blob and "%USERPROFILE%" in blob and p["sha256"] == "AB" * 32


class FakeOllama:
    provider = "ollama"
    model = "llama3.2"

    def __init__(self, verdict="malicious"):
        self.calls = 0
        self.verdict = verdict

    def complete(self, system, user, max_tokens=4000):
        self.calls += 1
        assert "cannot browse" in system
        items = json.loads(user)
        return json.dumps([{"id": i["id"], "what": f"{i['file']} is a dropper.", "verdict": self.verdict,
                            "confidence": "high", "why": "unsigned copy", "advice": ["Delete it"], "sources": []}
                           for i in items])


def cfg_for(tmp_path, provider="ollama", web=True) -> Config:
    cfg = Config(home=tmp_path)
    cfg.ai.provider, cfg.ai.model = provider, "test-model"
    cfg.security_ai, cfg.security_ai_web = True, web
    return cfg


def test_lookup_escalates_caches_and_skips(tmp_path):
    k = findings()
    fs = list(k.values())
    fs_by = {f.key: f for f in fs}
    attach_file_facts(fs, {EXE.lower(): facts(EXE), r"c:\users\neeraj\appdata\local\sync\s.exe":
                           facts(r"C:\Users\neeraj\AppData\Local\sync\s.exe", sha256="CD" * 32)})
    fs_by[r"monitoring:autostart:c:\users\neeraj\appdata\local\sync\s.exe"].trusted = True
    assert [file["name"] for _f, file in candidates(fs)] == ["upd.exe"]
    ms = facts(r"C:\Windows\System32\cmd.exe", sig_status="Valid", signer="CN=Microsoft Windows, O=Microsoft")
    fs_by["monitoring:accessibility_backdoor"].files = [ms]
    assert "cmd.exe" not in [file["name"] for _f, file in candidates(fs)]
    st = Store(tmp_path / "db.sqlite")
    fake = FakeOllama()
    label, notes = lookup(fs, cfg_for(tmp_path), st, describer_factory=lambda ai: fake)
    auto = fs_by[f"monitoring:autostart:{EXE.lower()}"]
    assert label.startswith("Ollama") and fake.calls == 1 and "1 file(s) checked" in notes[0]
    assert auto.ai_results[0]["verdict"] == "malicious" and auto.status == ALERT  # escalated from warn
    # second run: answered from the cache, no new request
    auto.files[0].pop("ai")
    auto.status = WARN
    lookup(fs, cfg_for(tmp_path), st, describer_factory=lambda ai: fake)
    assert fake.calls == 1 and auto.ai_results[0]["cached"] and auto.status == ALERT
    st.close()


def test_lookup_legitimate_never_lowers_status(tmp_path):
    fs = list(findings().values())
    attach_file_facts(fs, {EXE.lower(): facts(EXE)})
    lookup(fs, cfg_for(tmp_path), None, describer_factory=lambda ai: FakeOllama("legitimate"))
    f = {x.key: x for x in fs}[f"monitoring:autostart:{EXE.lower()}"]
    assert f.status == WARN and f.ai_results[0]["verdict"] == "legitimate"


def test_lookup_claude_uses_web_search(tmp_path):
    seen = {}

    def create(**kw):
        seen.update(kw)
        items = json.loads(kw["messages"][0]["content"])
        text = "Searched. " + json.dumps([{"id": i["id"], "what": "Updater", "verdict": "suspicious",
                                            "confidence": "medium", "why": "hash unknown",
                                            "sources": ["https://www.virustotal.com/x"]} for i in items])
        return SimpleNamespace(content=[SimpleNamespace(text=text)], stop_reason="end_turn",
                               usage=SimpleNamespace(server_tool_use=SimpleNamespace(web_search_requests=2)))

    claude = SimpleNamespace(provider="claude", model="m", client=SimpleNamespace(messages=SimpleNamespace(create=create)))
    fs = list(findings().values())
    attach_file_facts(fs, {EXE.lower(): facts(EXE)})
    label, notes = lookup(fs, cfg_for(tmp_path, "claude"), None, describer_factory=lambda ai: claude)
    assert label == "Claude with web search" and seen["tools"][0]["name"] == "web_search"
    assert "neeraj" not in seen["messages"][0]["content"] and "2 web search" in notes[0]


def test_run_security_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(security, "IS_WINDOWS", True)
    monkeypatch.setattr(security, "collect_state", state)
    monkeypatch.setattr(security, "collect_history", lambda since: {})
    monkeypatch.setattr(security, "read_tool_logs", lambda since: [])
    monkeypatch.setattr(security, "is_admin", lambda: True)
    asked = []

    def fake_facts(paths):
        asked.append(list(paths))
        return {p.lower(): facts(p) for p in paths if p.lower().endswith(".exe")}

    monkeypatch.setattr(security, "file_facts", fake_facts)
    cfg = cfg_for(tmp_path)
    st = Store(tmp_path / "db.sqlite")
    res = security.run_security(cfg, st, SINCE, ["AnyDesk"], installed_info=INSTALLED,
                                describer_factory=lambda ai: FakeOllama())
    st.close()
    assert EXE in asked[0]  # signatures for auto-start programs first
    k = {f.key: f for f in res.findings}
    auto = k[f"monitoring:autostart:{EXE.lower()}"]
    assert "1 file(s) checked" in res.ai_notes[0]  # both auto-start entries share one hash: one lookup
    assert auto.files[0]["sha256"] and auto.fix and auto.ai_results and res.ai.startswith("Ollama")
    rep = Report(scan_id=None, host="PC", period_start=SINCE, period_end=NOW, generated_at=NOW, baseline_at=None,
                 is_admin=True, tool_version="t", changes=[], warnings=[], security=res, mode="security")
    html = render_html(rep)
    assert "How to fix" in html and "Copy path" in html and "virustotal.com/gui/file/abab" in html
    assert "AI: Likely malicious" in html and "cmdbtn" in html and "&lt;script" not in html
    md = render_markdown(rep)
    assert f"path: `{EXE}`" in md and "**How to fix**" in md and "Likely malicious" in md
    back = report_from_dict(json.loads(render_json(rep)))
    f2 = {f.key: f for f in back.security.findings}[auto.key]
    assert f2.fix == auto.fix and f2.files[0]["sha256"] == auto.files[0]["sha256"] and back.security.ai == res.ai


def test_html_escapes_ai_text():
    fs = list(findings().values())
    attach_file_facts(fs, {EXE.lower(): facts(EXE)})
    f = {x.key: x for x in fs}[f"monitoring:autostart:{EXE.lower()}"]
    f.files[0]["ai"] = {"what": "<script>alert(1)</script>", "verdict": "unknown", "confidence": "low",
                        "sources": ["https://x/\"><b>"], "advice": []}
    rep = Report(scan_id=None, host="PC", period_start=SINCE, period_end=NOW, generated_at=NOW, baseline_at=None,
                 is_admin=True, tool_version="t", changes=[], warnings=[], security=SecurityResult(NOW, SINCE, True, fs),
                 mode="security")
    html = render_html(rep)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("value,expected", [("true", True), ("false", False)])
def test_security_ai_setting(home, monkeypatch, value, expected):
    monkeypatch.setenv("SYSSCAN_SECURITY_AI", value)
    assert load_config().security_ai is expected


def test_monitoring_kbd_without_driver_info_still_works():
    s = state()
    s.pop("kbd_drivers")
    f = {x.key: x for x in monitoring_findings(s, {})}["monitoring:kbd_filters:evilkbd"]
    assert f.paths == [] and f.status == WARN
