import json
from typing import ClassVar

import pytest

from conftest import T0, item
from sysscan import scan as scan_mod
from sysscan.cli import main
from sysscan.collectors.base import Collector
from sysscan.config import AIConfig, Config
from sysscan.demo import build_demo_report
from sysscan.describe import DescriptionPipeline, usable_publisher_text
from sysscan.describe.ai import parse_response
from sysscan.describe.rules import describe_by_rule
from sysscan.models import Action, Category, Change, ChangeEvent, TimeConfidence
from sysscan.report.render import render_html, render_json, render_markdown, write_reports
from sysscan.store import Store


def change(name, cat=Category.DESKTOP_APP, desc=None, action=Action.INSTALLED):
    from sysscan.normalize import normalize_name

    return Change(category=cat, action=action, name=name, time=T0, confidence=TimeConfidence.EXACT,
                  description=desc, norm_name=normalize_name(name))


# ----------------------------------------------------------------------------- descriptions

def test_rules_cover_common_items():
    assert "Defender" in describe_by_rule(change("Security Intelligence Update for Microsoft Defender Antivirus"))
    assert "(KB5065426)" in describe_by_rule(change("2026-09 Cumulative Update for Windows 11 (KB5065426)"))
    assert "runtime" in describe_by_rule(change("Microsoft Visual C++ 2015-2022 Redistributable (x64)"))
    assert describe_by_rule(change("Totally Unknown Widget")) is None


def test_publisher_text_filter():
    assert usable_publisher_text("Install this update to resolve issues in Windows.") is None
    assert usable_publisher_text("https://example.com") is None
    assert usable_publisher_text("Fast, disk space efficient package manager") is not None


def test_parse_ai_response_tolerates_fences():
    text = '```json\n[{"id": 0, "description": "A thing.", "publisher": null, "confidence": "low"}]\n```'
    ans = parse_response(text)[0]
    assert (ans.description, ans.publisher, ans.confidence) == ("A thing.", None, "low")


class FakeDescriber:
    calls = 0

    def __init__(self, *_):
        pass

    def describe(self, items):
        from sysscan.describe.ai import AIAnswer

        FakeDescriber.calls += 1
        FakeDescriber.last = items
        return {it.id: AIAnswer(f"About {it.name}.", f"{it.name} Inc", "high") for it in items}


def test_pipeline_uses_ai_once_then_cache(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    store = Store(":memory:")
    FakeDescriber.calls = 0
    pipe = DescriptionPipeline(store, AIConfig(enabled=True), use_ai=True, describer_factory=FakeDescriber)
    c1 = [change("Obscure Tool"), change("Obscure Tool"), change("Git for Windows")]
    pipe.run(c1)
    assert c1[0].description == "About Obscure Tool." and c1[0].description_source == "ai"
    assert c1[2].description_source == "rule"
    assert FakeDescriber.calls == 1

    c2 = [change("Obscure Tool")]
    pipe.run(c2)
    assert c2[0].description_source == "ai" and FakeDescriber.calls == 1  # served from cache


def test_pipeline_without_ai_falls_back_to_publisher_or_none():
    store = Store(":memory:")
    cs = [change("Thing", desc="Command-line fuzzy finder"), change("Mystery")]
    DescriptionPipeline(store, AIConfig(), use_ai=False).run(cs)
    assert [c.description_source for c in cs] == ["publisher", "none"]


# ----------------------------------------------------------------------------- reports

def test_demo_report_renders_everywhere(tmp_path):
    report = build_demo_report()
    html, md, js = render_html(report), render_markdown(report), render_json(report)
    assert "What changed on DEMO-PC" in html and "FastLane VPN Client" in html
    assert "## Uninstalled (1)" in md
    data = json.loads(js)
    assert data["summary"]["uninstalled"] == 1
    assert {c["action"] for c in data["changes"]} >= {"installed", "updated", "uninstalled"}
    written = write_reports(report, tmp_path, ["html", "md", "json"])
    assert all(p.exists() for p in written.values())


def test_demo_merges_evidence_correctly():
    r = build_demo_report()
    by = {c.name: c for c in r.changes}
    vc = next(c for c in r.changes if "Visual C++ 2015-2022" in c.name)
    assert vc.action == Action.UPDATED and vc.confidence == TimeConfidence.EXACT
    assert by["Intel system devices driver"].action == Action.UPDATED
    assert by["Windows Calculator"].routine and not by["Blender"].routine


# ----------------------------------------------------------------------------- end-to-end scan

class FakeInventory(Collector):
    name = "registry"
    provides_inventory = True
    windows_only = False
    items: ClassVar[list] = []

    def inventory(self, ctx):
        return list(self.items)


class FakeHistory(Collector):
    name = "eventlog"
    provides_events = True
    windows_only = False

    def events(self, ctx, since, until):
        return [ChangeEvent(category=Category.DESKTOP_APP, action=Action.UNINSTALLED, name="Old App",
                            source="eventlog:msi", time=since + (until - since) / 2,
                            confidence=TimeConfidence.EXACT, version_from="1.0")]


class Broken(Collector):
    name = "appx"
    provides_inventory = True
    windows_only = False

    def inventory(self, ctx):
        raise RuntimeError("boom")


@pytest.fixture
def fake_collectors(monkeypatch):
    monkeypatch.setattr(scan_mod, "all_collectors", lambda: [FakeInventory(), FakeHistory(), Broken()])
    return FakeInventory


def test_two_scans_detect_uninstall_and_install(tmp_path, fake_collectors):
    cfg = Config(home=tmp_path)
    store = Store(cfg.db_path)
    fake_collectors.items = [item("a", "Old App", "1.0"), item("b", "Keeper", "2.0")]
    first = scan_mod.run_scan(cfg, scan_mod.ScanOptions(), store)
    assert any("First scan" in w for w in first.warnings)
    assert any("appx" in w for w in first.warnings)  # failed collector is reported

    fake_collectors.items = [item("b", "Keeper", "2.0"), item("c", "New App", "3.0")]
    second = scan_mod.run_scan(cfg, scan_mod.ScanOptions(), store)
    by = {c.name: c for c in second.changes}
    assert by["Old App"].action == Action.UNINSTALLED
    assert by["Old App"].confidence == TimeConfidence.EXACT  # refined by the event log
    assert by["New App"].action == Action.INSTALLED
    assert "Keeper" not in by
    assert second.baseline_at is not None
    store.close()


def test_cli_demo_and_default_command(tmp_path, home, capsys, fake_collectors):
    assert main(["demo", "--no-open", "--out", str(tmp_path / "d")]) == 0
    assert list((tmp_path / "d").glob("*.html"))
    fake_collectors.items = [item("a", "App", "1")]
    assert main(["--since", "3d", "--no-open", "--no-ai", "-q", "--out", str(tmp_path / "r")]) == 0
    assert list((tmp_path / "r").glob("*.md"))
    assert main(["history"]) == 0
    assert "#1" in capsys.readouterr().out


def test_since_before_first_snapshot_uses_snapshot_inside_period(tmp_path, fake_collectors):
    from datetime import timedelta

    from sysscan.winutil import utcnow

    cfg = Config(home=tmp_path)
    store = Store(cfg.db_path)
    fake_collectors.items = [item("a", "Old App", "1.0"), item("b", "Keeper", "2.0")]
    scan_mod.run_scan(cfg, scan_mod.ScanOptions(), store)  # first-ever snapshot

    fake_collectors.items = [item("b", "Keeper", "2.1")]
    report = scan_mod.run_scan(cfg, scan_mod.ScanOptions(since=utcnow() - timedelta(days=7)), store)
    by = {c.name: c for c in report.changes}
    assert by["Keeper"].action == Action.UPDATED and by["Keeper"].version_from == "2.0"
    assert by["Old App"].action == Action.UNINSTALLED
    assert any("Snapshots only cover this period from" in w for w in report.warnings)
    store.close()
