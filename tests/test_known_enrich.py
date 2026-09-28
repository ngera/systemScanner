import json
from datetime import timedelta

import pytest

from conftest import item
from sysscan import scan as scan_mod
from sysscan.classify import Classifier
from sysscan.cli import main
from sysscan.collectors.base import Collector
from sysscan.config import AIConfig
from sysscan.describe import DescriptionPipeline
from sysscan.describe.ai import AIAnswer
from sysscan.enrich import collapse_repeats, enrich_from_inventory, safe_path, service_hints, vendor_folder
from sysscan.known import KnownEntry, KnownSoftware, needs_tagging, tag_command
from sysscan.models import Action, Category, Change, Evidence, TimeConfidence
from sysscan.normalize import normalize_name, provider_name
from sysscan.report.render import render_html
from sysscan.store import Store
from sysscan.winutil import utcnow


def change(name, action=Action.INSTALLED, publisher=None, desc=None, cat=Category.DESKTOP_APP, t=None, ver=None):
    return Change(category=cat, action=action, name=name, time=t or utcnow(), confidence=TimeConfidence.EXACT,
                  publisher=publisher, description=desc, norm_name=normalize_name(name), version_to=ver)


# ----------------------------------------------------------------------------- known_software.toml

def test_known_software_roundtrip_and_matching(tmp_path):
    path = tmp_path / "known_software.toml"
    ks = KnownSoftware(path=path)
    ks.upsert(KnownEntry(name="PowerENGAGE", publisher="Acme", description='Says "hi"', routine=True))
    ks.upsert(KnownEntry(match=r"^mc-wps-", publisher="McAfee", category="desktop_app"))
    ks.save()

    loaded = KnownSoftware.load(path)
    assert not loaded.errors and len(loaded.entries) == 2
    assert loaded.find(change("PowerENGAGE (x64) 3.2.16")).description == 'Says "hi"'  # versions/arch ignored
    assert loaded.find(change("mc-wps-secdashboardservice (service)")).publisher == "McAfee"
    assert loaded.find(change("mc-wps-thing", cat=Category.DRIVER)) is None  # category filter

    # upsert merges instead of duplicating
    assert loaded.upsert(KnownEntry(name="powerengage", description="Better text")) is True
    assert len(loaded.entries) == 2 and loaded.entries[0].publisher == "Acme"


def test_blank_template_entries_are_ignored(tmp_path):
    path = tmp_path / "k.toml"
    path.write_text('[[software]]\nname = "X"\npublisher = ""\ndescription = ""\n')
    ks = KnownSoftware.load(path)
    assert ks.find(change("X")).publisher is None


def test_bad_regex_is_reported_not_fatal(tmp_path):
    path = tmp_path / "k.toml"
    path.write_text('[[software]]\nmatch = "(unclosed"\npublisher = "A"\n')
    ks = KnownSoftware.load(path)
    assert ks.errors and ks.entries == []


def test_tags_beat_rules_and_ai(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    calls = []

    class Fake:
        def __init__(self, *_):
            pass

        def describe(self, items, web=False):
            calls.append([i.name for i in items])
            return {}

    ks = KnownSoftware([KnownEntry(name="Git for Windows", publisher="Git project", description="Mine.")])
    c = change("Git for Windows")
    DescriptionPipeline(Store(":memory:"), AIConfig(), use_ai=True, describer_factory=Fake, known=ks).run([c])
    assert (c.description, c.description_source, c.publisher, c.publisher_source) == \
        ("Mine.", "yours", "Git project", "yours")
    assert calls == []  # nothing left to ask


def test_needs_tagging_and_tag_command():
    c = change("O'Brien Tool")
    c.description_source = "ai-low"
    assert needs_tagging(c)
    assert tag_command(c) == "sysscan tag 'O''Brien Tool' --publisher '' --description ''"
    ok = change("Known", publisher="Acme")
    ok.description_source = "rule"
    assert not needs_tagging(ok)


# ----------------------------------------------------------------------------- enrichment

def test_repeated_self_repairs_collapse_into_one_routine_row():
    t0 = utcnow()
    rows = [change("PowerENGAGE", Action.MODIFIED, t=t0 - timedelta(hours=6 * i), ver="3.2.16") for i in range(26)]
    for r in rows:
        r.evidence = [Evidence("reliability", "event 1035", r.time)]
    out = collapse_repeats([*rows, change("Other")])
    pe = next(c for c in out if c.name == "PowerENGAGE")
    assert len(out) == 2 and pe.occurrences == 26 and pe.time == t0 and len(pe.evidence) == 11
    Classifier().apply(out)
    assert pe.routine


def test_enrich_from_inventory_fills_publisher_and_hints():
    it = item("reg:x", "PowerENGAGE", "3.2.16", publisher="Example Corp")
    it.extra = {"install_location": r"C:\Program Files\Example\PowerENGAGE", "url": "https://www.example.com/support"}
    c = change("PowerENGAGE", Action.MODIFIED)
    enrich_from_inventory([c], [it])
    assert c.publisher == "Example Corp"
    assert c.hints == {"install_folder": r"C:\Program Files\Example\PowerENGAGE", "vendor_website": "example.com"}


def test_service_hints_name_the_vendor_and_hide_user_paths():
    svc = change("mc-wps-secdashboardservice (service)")
    svc.evidence = [Evidence("eventlog:service",
                             'System log 7045: service registered → "C:\\Program Files\\McAfee\\WPS\\svc.exe"')]
    user = change("updater (service)")
    user.evidence = [Evidence("eventlog:service", r"System log 7045: service registered → C:\Users\bob\app\u.exe")]
    service_hints([svc, user])
    assert svc.publisher == "McAfee" and svc.hints["executable"].endswith("svc.exe")
    assert user.publisher is None and "executable" not in user.hints
    assert vendor_folder(r"C:\Program Files\Common Files\x\y.exe") is None
    assert safe_path(r"C:\Users\bob\x.exe") is None


def test_guid_publishers_count_as_unknown():
    assert provider_name("5BD5593D-A41B-4F89-884E-B4F3E0FBAA75") == "Unknown"


# ----------------------------------------------------------------------------- web-search pass

class WebFake:
    def __init__(self):
        self.calls = []

    def factory(self, *_):
        return self

    def describe(self, items, web=False):
        self.calls.append(("web" if web else "plain", [i.name for i in items], [i.hints for i in items]))
        if web:
            return {i.id: AIAnswer("Found it online.", "Real Vendor", "high", "https://vendor.example/p") for i in items}
        return {i.id: AIAnswer("Some tool, probably.", None, "low") for i in items}


def test_web_pass_resolves_what_the_plain_pass_could_not(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    fake, store = WebFake(), Store(":memory:")
    c = change("PowerENGAGE")
    c.hints = {"vendor_website": "example.com"}
    DescriptionPipeline(store, AIConfig(web=True), use_ai=True, describer_factory=fake.factory).run([c])
    assert [k for k, *_ in fake.calls] == ["plain", "web"]
    assert fake.calls[0][2] == [{"vendor_website": "example.com"}]  # hints reach the model
    assert (c.description_source, c.publisher, c.source_url) == ("ai-web", "Real Vendor", "https://vendor.example/p")

    again = change("PowerENGAGE")
    DescriptionPipeline(store, AIConfig(web=True), use_ai=True, describer_factory=fake.factory).run([again])
    assert len(fake.calls) == 2 and again.description_source == "ai-web" and again.source_url


def test_earlier_unsure_answers_get_one_web_retry(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    fake, store = WebFake(), Store(":memory:")
    DescriptionPipeline(store, AIConfig(web=False), use_ai=True, describer_factory=fake.factory).run(
        [change("Obscure")])
    assert [k for k, *_ in fake.calls] == ["plain"]
    later = change("Obscure")
    DescriptionPipeline(store, AIConfig(web=True), use_ai=True, describer_factory=fake.factory).run([later])
    assert [k for k, *_ in fake.calls] == ["plain", "web"] and later.description_source == "ai-web"


# ----------------------------------------------------------------------------- CLI workflow

class Inv(Collector):
    name = "registry"
    provides_inventory = True
    windows_only = False

    def inventory(self, ctx):
        return [item("a", "PowerENGAGE", "3.2.16", t=utcnow() - timedelta(hours=1))]


@pytest.fixture
def one_app(monkeypatch):
    monkeypatch.setattr(scan_mod, "all_collectors", lambda: [Inv()])


def test_tag_unknowns_retag_workflow(tmp_path, home, capsys, one_app):
    out = tmp_path / "r"
    assert main(["scan", "--since", "1d", "--no-open", "--no-ai", "-q", "--out", str(out)]) == 0
    html = next(out.glob("*.html")).read_text(encoding="utf-8")
    assert 'class="tagbtn"' in html and "sysscan tag &#39;PowerENGAGE&#39;" in html

    assert main(["unknowns"]) == 0
    assert "PowerENGAGE" in capsys.readouterr().out

    assert main(["tag", "PowerENGAGE", "--publisher", "Example Corp", "--description", "Helper app."]) == 0
    assert main(["retag", "--no-open"]) == 0
    data = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
    row = next(c for c in data["changes"] if c["name"] == "PowerENGAGE")
    assert (row["publisher"], row["publisher_source"], row["description_source"]) == ("Example Corp", "yours", "yours")
    assert 'class="tagbtn"' not in next(out.glob("*.html")).read_text(encoding="utf-8")

    capsys.readouterr()
    assert main(["unknowns"]) == 0
    assert "Nothing to tag" in capsys.readouterr().out


def test_html_marks_yours_and_repeats():
    c = change("PowerENGAGE", Action.MODIFIED, publisher="Acme")
    c.publisher_source = c.description_source = "yours"
    c.description, c.occurrences = "Mine.", 26
    from sysscan.report.model import Report

    now = utcnow()
    html = render_html(Report(host="h", generated_at=now, period_start=now, period_end=now, scan_id=1,
                              is_admin=True, tool_version="t", changes=[c]))
    assert "×26" in html and 'class="src yours"' in html


def test_untag_and_tags_commands(tmp_path, home, capsys, one_app):
    out = tmp_path / "r"
    assert main(["scan", "--since", "1d", "--no-open", "--no-ai", "-q", "--out", str(out)]) == 0
    assert main(["tag", "PowerENGAGE", "--publisher", "Example Corp"]) == 0
    assert main(["tag", "^mc-wps-", "--regex", "--publisher", "McAfee"]) == 0
    capsys.readouterr()

    assert main(["tags"]) == 0
    listing = capsys.readouterr().out
    assert "PowerENGAGE" in listing and "/^mc-wps-/ (pattern)" in listing

    assert main(["untag", "powerengage (x64)"]) == 0  # same normalisation as matching
    assert main(["untag", "^mc-wps-"]) == 0  # pattern removed by its text
    assert main(["untag", "nothing-here"]) == 1
    assert KnownSoftware.load(home / "known_software.toml").entries == []

    # retag drops the removed tag's values from the existing report
    assert main(["retag", "--no-open"]) == 0
    row = next(c for c in json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))["changes"]
               if c["name"] == "PowerENGAGE")
    assert row["publisher_source"] is None
