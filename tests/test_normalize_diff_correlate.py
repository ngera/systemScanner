from datetime import timedelta

from conftest import T0, T1, item
from sysscan.correlate import correlate
from sysscan.diff import diff_snapshots
from sysscan.models import Action, Category, ChangeEvent, TimeConfidence
from sysscan.normalize import normalize_name, prettify_package_name

SRC = {"registry"}


def test_normalize_collapses_versions_and_arch():
    a = normalize_name("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810")
    b = normalize_name("Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.42.34433")
    assert a == b == "microsoft visual c++ 2015 2022 redistributable"
    assert normalize_name("Notepad++ (64-bit x64)") == "notepad++"
    assert normalize_name("Python 3.12.4 (64-bit)") == "python"
    assert "kb5065426" in normalize_name("2026-09 Cumulative Update (KB5065426)")


def test_prettify_package_name():
    assert prettify_package_name("Microsoft.WindowsCalculator") == "Windows Calculator"


def test_diff_detects_install_update_uninstall():
    old = [item("a", "App A", "1.0"), item("b", "App B", "2.0"), item("c", "App C", "1")]
    new = [item("a", "App A", "1.1", t=T0 + timedelta(days=1)), item("c", "App C", "1"), item("d", "App D", "5")]
    ev = {e.name: e for e in diff_snapshots(old, new, T0, T1, SRC, SRC)}
    assert ev["App A"].action == Action.UPDATED
    assert (ev["App A"].version_from, ev["App A"].version_to) == ("1.0", "1.1")
    assert ev["App A"].confidence == TimeConfidence.FILE  # refined from the item's own timestamp
    assert ev["App B"].action == Action.UNINSTALLED
    assert ev["App D"].action == Action.INSTALLED
    assert ev["App D"].confidence == TimeConfidence.WINDOW
    assert "App C" not in ev


def test_diff_pairs_msi_major_upgrade_as_update():
    old = [item("reg:{OLD}", "Tool (x64) - 1.2.3", "1.2.3")]
    new = [item("reg:{NEW}", "Tool (x64) - 1.3.0", "1.3.0")]
    (e,) = diff_snapshots(old, new, T0, T1, SRC, SRC)
    assert e.action == Action.UPDATED and e.version_from == "1.2.3" and e.version_to == "1.3.0"


def test_diff_ignores_sources_missing_from_either_snapshot():
    old = [item("x", "Store thing", "1", source="appx", cat=Category.STORE_APP)]
    assert diff_snapshots(old, [], T0, T1, {"appx", "registry"}, {"registry"}) == []


def _ev(action, name, t, source="eventlog:msi", **kw):
    return ChangeEvent(category=Category.DESKTOP_APP, action=action, name=name, source=source, time=t,
                       confidence=TimeConfidence.EXACT, **kw)


def test_correlate_merges_duplicate_evidence():
    t = T0 + timedelta(days=2)
    changes = correlate([
        _ev(Action.INSTALLED, "Blender", t, version_to="4.2"),
        _ev(Action.INSTALLED, "Blender", t + timedelta(seconds=40), source="reliability"),
    ])
    assert len(changes) == 1
    assert changes[0].action == Action.INSTALLED and len(changes[0].evidence) == 2


def test_correlate_turns_remove_plus_install_into_update():
    t = T0 + timedelta(days=2)
    (c,) = correlate([
        _ev(Action.UNINSTALLED, "Tool - 1.2.3", t, version_from="1.2.3"),
        _ev(Action.INSTALLED, "Tool - 1.3.0", t + timedelta(minutes=1), version_to="1.3.0"),
    ])
    assert c.action == Action.UPDATED and c.version_from == "1.2.3" and c.version_to == "1.3.0"


def test_correlate_keeps_separate_occurrences_apart():
    changes = correlate([
        _ev(Action.INSTALLED, "Trial App", T0 + timedelta(days=1)),
        _ev(Action.UNINSTALLED, "Trial App", T0 + timedelta(days=4)),
    ])
    assert sorted(c.action for c in changes) == [Action.INSTALLED, Action.UNINSTALLED]


def test_correlate_attaches_history_to_snapshot_anchor_and_uses_exact_time():
    old = [item("k", "VPN Client", "3.2")]
    anchor = diff_snapshots(old, [], T0, T1, SRC, SRC)
    exact = T0 + timedelta(days=3, hours=2)
    (c,) = correlate([*anchor, _ev(Action.UNINSTALLED, "VPN Client", exact, version_from="3.2")])
    assert c.action == Action.UNINSTALLED
    assert c.time == exact and c.confidence == TimeConfidence.EXACT
    assert c.window_start == T0


def test_driver_device_events_fold_into_provider_row():
    old = [item("drv:Intel:System:1", "Intel system devices driver", "1.0", source="drivers", cat=Category.DRIVER)]
    new = [item("drv:Intel:System:2", "Intel system devices driver", "2.0", source="drivers", cat=Category.DRIVER)]
    events = diff_snapshots(old, new, T0, T1, {"drivers"}, {"drivers"})
    t = T0 + timedelta(days=1)
    for dev in ("Intel(R) Serial IO I2C", "Intel(R) Management Engine"):
        events.append(ChangeEvent(category=Category.DRIVER, action=Action.INSTALLED, name=dev, source="setupapi",
                                  time=t, confidence=TimeConfidence.EXACT, version_to="2.0"))
    (c,) = correlate(events)
    assert c.action == Action.UPDATED and c.time == t and len(c.evidence) == 3
