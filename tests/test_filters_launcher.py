import re

import pytest

from sysscan import launcher, schedule
from sysscan.demo import build_demo_report
from sysscan.models import Category
from sysscan.normalize import provider_name
from sysscan.report.render import render_html, render_markdown


@pytest.mark.parametrize(("raw", "expected"), [
    ("Microsoft Corporation", "Microsoft"),
    ("Intel(R) Corporation", "Intel"),
    ("HP Inc.", "HP"),
    ("Zoom Communications, Inc.", "Zoom Communications"),
    ("Advanced Micro Devices, Inc.", "AMD"),
    ("Foo Software Co., Ltd.", "Foo"),
    (None, "Unknown"),
])
def test_provider_name(raw, expected):
    assert provider_name(raw) == expected


def test_windows_updates_default_to_microsoft():
    assert provider_name(None, Category.WINDOWS_UPDATE) == "Microsoft"


def test_html_rows_carry_filter_data_and_columns():
    report = build_demo_report()
    html = render_html(report)
    rows = re.findall(r'<div class="row a-\w+" (data-action="[^>]+)>', html)
    assert len(rows) == len(report.changes)
    for attrs in rows:
        for key in ("data-cat=", "data-prov=", "data-d0=", "data-d1=", "data-sort="):
            assert key in attrs
    # filter controls populated from the data
    assert 'id="prov"' in html and '<option value="Microsoft">Microsoft (' in html
    assert 'data-cat="driver"' in html and 'id="from"' in html and 'id="to"' in html
    # new table columns
    assert ">Type</button>" in html and ">Provider</button>" in html
    assert '<span class="type t-driver">Driver</span>' in html


def test_between_scans_rows_span_the_window():
    report = build_demo_report()
    html = render_html(report)
    # Obsidian has an approximate time -> single day; Windows Calculator came from a snapshot but has a file time.
    m = re.search(r'data-prov="Obsidian" data-d0="([\d-]+)" data-d1="([\d-]+)"', html)
    assert m and m.group(1) == m.group(2)


def test_markdown_has_type_and_provider_columns():
    md = render_markdown(build_demo_report())
    assert "| Name | Type | Provider | Version | When | What it is |" in md
    assert "| Driver | Intel |" in md


def test_launcher_routes_cli_commands(monkeypatch):
    seen = {}
    monkeypatch.setattr("sysscan.cli.main", lambda args: seen.setdefault("args", args) and 0)
    launcher.main(["history"])
    assert seen["args"] == ["history"]


def test_launcher_startup_mode_is_silent(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher, "startup_scan", lambda ai: calls.append(ai) or 0)
    monkeypatch.setattr(launcher, "interactive_scan", lambda ai: pytest.fail("must not open UI"))
    assert launcher.main(["--startup", "--ai", "--format", "html"]) == 0
    assert calls == [["--ai", "--format", "html"]]


def test_schedule_command_points_at_python_when_not_frozen():
    _exe, args = schedule.task_command()
    assert "-m sysscan scan --no-open --quiet" in args


def test_schedule_command_points_at_exe_when_frozen(monkeypatch):
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", r"C:\Tools\runScan.exe")
    assert schedule.task_command(use_ai=True) == (r"C:\Tools\runScan.exe", "--startup --ai")


def test_split_args_separates_launcher_flags_and_time():
    scan, time = launcher.split_args(["--install-startup", "--time", "20:00", "--format", "html", "--elevated", "--ai"])
    assert scan == ["--format", "html", "--ai"] and time == "20:00"
    assert launcher.split_args(["--startup", "--time=07:30"]) == ([], "07:30")


def test_parse_scan_args_validates_without_exiting():
    from sysscan.cli import parse_scan_args

    ns = parse_scan_args(["--since", "7d", "--format", "html,json", "--skip", "npm", "--no-open"])
    assert ns.format == "html,json" and ns.skip == "npm" and ns.no_open and ns.since is not None
    for bad in (["--sinse", "7d"], ["--since", "not-a-date"]):
        with pytest.raises(ValueError):
            parse_scan_args(bad)


def test_task_command_carries_scan_options(monkeypatch):
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", r"C:\Tools\runScan.exe")
    _exe, args = schedule.task_command(use_ai=True, extra_args=["--out", r"D:\My Reports", "--format", "html"])
    assert args == '--startup --out "D:\\My Reports" --format html --ai'


def test_startup_scan_honours_options(tmp_path, home, monkeypatch):
    from conftest import item
    from sysscan import scan as scan_mod
    from sysscan.collectors.base import Collector

    class Inv(Collector):
        name = "registry"
        provides_inventory = True
        windows_only = False

        def inventory(self, ctx):
            return [item("a", "App", "1")]

    monkeypatch.setattr(scan_mod, "all_collectors", lambda: [Inv()])
    opened = []
    monkeypatch.setattr("sysscan.cli._open", lambda p: opened.append(p))
    out = tmp_path / "reports"
    assert launcher.main(["--startup", "--format", "html,json", "--out", str(out), "--no-ai"]) == 0
    assert sorted(p.suffix for p in out.iterdir()) == [".html", ".json"] and opened == []
    assert launcher.main(["--startup", "--bogus"]) == 2  # invalid options are rejected, not ignored


# ----------------------------------------------------------------------------- runScan.com (terminal) vs .exe

def test_terminal_help_prints(monkeypatch, capsys):
    monkeypatch.setattr(launcher, "no_console", lambda: False)
    assert launcher.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "USAGE" in out and "--install-startup" in out and "runScan.com" in out


def test_windowed_help_opens_a_window(monkeypatch):
    shown = []
    monkeypatch.setattr(launcher, "no_console", lambda: True)
    monkeypatch.setattr(launcher, "show_text", lambda title, text: shown.append((title, text)))
    assert launcher.main(["/?"]) == 0
    assert shown and "USAGE" in shown[0][1]


def test_terminal_without_arguments_scans_here(monkeypatch):
    calls = []
    monkeypatch.setattr(launcher, "no_console", lambda: False)
    monkeypatch.setattr("sysscan.cli.main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(launcher, "interactive_scan", lambda *_: pytest.fail("no progress window in a terminal"))
    monkeypatch.setattr(launcher, "relaunch_elevated", lambda *_: pytest.fail("no UAC relaunch in a terminal"))
    assert launcher.main([]) == 0
    assert launcher.main(["--since", "7d", "--no-open"]) == 0
    assert calls == [["scan"], ["scan", "--since", "7d", "--no-open"]]


def test_windowed_command_output_is_shown_not_lost(monkeypatch, home):
    shown = []
    monkeypatch.setattr(launcher, "no_console", lambda: True)
    monkeypatch.setattr(launcher, "show_text", lambda title, text: shown.append((title, text)))
    assert launcher.main(["tags"]) == 0
    assert "No tags yet" in shown[-1][1]
    assert launcher.main(["scan", "--help"]) == 0
    assert "--since" in shown[-1][1] and "usage: runScan.exe" in shown[-1][1]


def test_scheduled_task_uses_windowed_exe_when_installed_from_terminal(tmp_path, monkeypatch):
    com, exe = tmp_path / "runScan.com", tmp_path / "runScan.exe"
    com.write_bytes(b"")
    exe.write_bytes(b"")
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", str(com))
    assert schedule.task_command() == (str(exe), "--startup")
