"""Synthetic sample data — powers `sysscan demo`, the README screenshot and the report tests.

It runs through the real pipeline (diff → correlate → classify → describe), so it doubles as an
end-to-end check that works on any OS.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sysscan import __version__
from sysscan.classify import Classifier
from sysscan.config import AIConfig
from sysscan.correlate import correlate
from sysscan.describe import DescriptionPipeline
from sysscan.diff import diff_snapshots
from sysscan.models import (
    Action,
    Category,
    ChangeEvent,
    CollectorStatus,
    InventoryItem,
    TimeConfidence,
)
from sysscan.report.model import Report
from sysscan.store import Store


def _item(key, cat, source, name, version, publisher=None, t=None, conf=TimeConfidence.FILE, desc=None):
    return InventoryItem(key=key, category=cat, source=source, name=name, version=version,
                         publisher=publisher, install_time=t, time_confidence=conf if t else
                         TimeConfidence.UNKNOWN, description=desc)


def build_demo_report(now: datetime | None = None) -> Report:
    now = now or datetime(2026, 9, 26, 14, 0, tzinfo=UTC)
    start = now - timedelta(days=7)
    d = lambda days, h=10, m=0: (start + timedelta(days=days)).replace(hour=h, minute=m)

    R, A, P = "registry", "appx", "pip"
    old = [
        _item("reg:HKLM64:{VC-40}", Category.DESKTOP_APP, R,
              "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", "14.40.33810.0", "Microsoft Corporation"),
        _item("reg:HKLM64:Notepad++", Category.DESKTOP_APP, R, "Notepad++ (64-bit x64)", "8.6.9", "Notepad++ Team"),
        _item("reg:HKLM32:WinRAR", Category.DESKTOP_APP, R, "WinRAR 6.24 (64-bit)", "6.24.0", "win.rar GmbH"),
        _item("reg:HKLM64:{OLDVPN}", Category.DESKTOP_APP, R, "FastLane VPN Client", "3.2.1", "FastLane Networks"),
        _item("reg:user:S-1-5-21-1:Zoom", Category.DESKTOP_APP, R, "Zoom Workplace", "6.1.11", "Zoom Communications"),
        _item("appx:Microsoft.WindowsCalculator_x64_8wekyb3d8bbwe", Category.STORE_APP, A, "Windows Calculator",
              "11.2405.2.0", "Microsoft Corporation"),
        _item("appx:Microsoft.VCLibs.140.00_x64_8wekyb3d8bbwe", Category.STORE_APP, A, "Microsoft Visual C++ Runtime Package (VCLibs)",
              "14.0.33519.0", "Microsoft Corporation"),
        _item("drv:Intel:System:2406.5.5.0", Category.DRIVER, "drivers", "Intel system devices driver", "2406.5.5.0", "Intel",
              desc="Used by: Intel(R) Management Engine Interface #1, Intel(R) Serial IO I2C Host Controller and 6 more"),
        _item("pip:Python312:requests", Category.DEV_PACKAGE, P, "requests [pip · Python312]", "2.32.3", None,
              desc="Python HTTP for Humans."),
    ]
    new = [
        _item("reg:HKLM64:{VC-42}", Category.DESKTOP_APP, R,
              "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433", "14.42.34433.0",
              "Microsoft Corporation", d(2, 9, 41)),
        _item("reg:HKLM64:Notepad++", Category.DESKTOP_APP, R, "Notepad++ (64-bit x64)", "8.7.1", "Notepad++ Team",
              d(3, 18, 2), desc="Free source-code editor and Notepad replacement"),
        _item("reg:HKLM32:WinRAR", Category.DESKTOP_APP, R, "WinRAR 6.24 (64-bit)", "6.24.0", "win.rar GmbH"),
        _item("reg:HKLM64:{BLENDER}", Category.DESKTOP_APP, R, "Blender", "4.2.1", "Blender Foundation", d(5, 21, 15)),
        _item("reg:user:S-1-5-21-1:Zoom", Category.DESKTOP_APP, R, "Zoom Workplace", "6.2.5", "Zoom Communications", d(4, 8, 5)),
        _item("reg:user:S-1-5-21-1:Obsidian", Category.DESKTOP_APP, R, "Obsidian", "1.6.7", "Obsidian", d(6, 11, 30)),
        _item("appx:Microsoft.WindowsCalculator_x64_8wekyb3d8bbwe", Category.STORE_APP, A, "Windows Calculator",
              "11.2408.12.0", "Microsoft Corporation", d(1, 3, 12)),
        _item("appx:Microsoft.VCLibs.140.00_x64_8wekyb3d8bbwe", Category.STORE_APP, A, "Microsoft Visual C++ Runtime Package (VCLibs)",
              "14.0.33728.0", "Microsoft Corporation", d(1, 3, 10)),
        _item("drv:Intel:System:2409.5.63.0", Category.DRIVER, "drivers", "Intel system devices driver", "2409.5.63.0", "Intel",
              desc="Used by: Intel(R) Management Engine Interface #1, Intel(R) Serial IO I2C Host Controller and 6 more"),
        _item("pip:Python312:requests", Category.DEV_PACKAGE, P, "requests [pip · Python312]", "2.32.3", None,
              desc="Python HTTP for Humans."),
        _item("pip:Python312:httpx", Category.DEV_PACKAGE, P, "httpx [pip · Python312]", "0.27.2", None, d(2, 16, 40),
              desc="The next generation HTTP client."),
        _item("ext:Cursor:ms-python.python", Category.DEV_PACKAGE, "editor-extensions",
              "Python [Cursor extension]", "2024.14.1", "ms-python", d(2, 16, 20),
              desc="Python language support with extension access points for IntelliSense (Pylance), Debugging (Python Debugger), linting, formatting, refactoring, unit tests, and more."),
    ]
    sources = {R, A, "drivers", P, "editor-extensions"}
    events = diff_snapshots(old, new, start, now, sources, sources)

    def ev(cat, action, name, source, t, **kw):
        return ChangeEvent(category=cat, action=action, name=name, source=source, time=t,
                           confidence=TimeConfidence.EXACT, **kw)

    events += [
        ev(Category.DESKTOP_APP, Action.INSTALLED, "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433",
           "eventlog:msi", d(2, 9, 40), version_to="14.42.34433", detail="Application log, MsiInstaller event 1033"),
        ev(Category.DESKTOP_APP, Action.UNINSTALLED, "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810",
           "eventlog:msi", d(2, 9, 40), version_from="14.40.33810", detail="Application log, MsiInstaller event 1034"),
        ev(Category.DESKTOP_APP, Action.UNINSTALLED, "FastLane VPN Client", "eventlog:msi", d(4, 19, 22),
           version_from="3.2.1", detail="Application log, MsiInstaller event 1034"),
        ev(Category.DESKTOP_APP, Action.INSTALLED, "Blender", "reliability", d(5, 21, 16),
           version_to="4.2.1", detail="Reliability Monitor: event 11707"),
        ev(Category.WINDOWS_UPDATE, Action.UPDATED,
           "2026-09 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5065426)",
           "windows-update", d(1, 3, 5), version_to="KB5065426",
           detail="Windows Update history (via UpdateOrchestrator)"),
        ev(Category.WINDOWS_UPDATE, Action.UPDATED,
           "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.419.58.0)",
           "windows-update", d(3, 7, 51), version_to="KB2267602", detail="Windows Update history (via Windows Defender)"),
        ev(Category.WINDOWS_UPDATE, Action.UPDATED,
           "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.419.71.0)",
           "windows-update", d(5, 13, 2), version_to="KB2267602", detail="Windows Update history (via Windows Defender)"),
        ev(Category.WINDOWS_UPDATE, Action.UPDATED, "Windows Malicious Software Removal Tool x64 - v5.130 (KB890830)",
           "windows-update", d(1, 3, 7), version_to="KB890830", detail="Windows Update history"),
        ev(Category.DRIVER, Action.INSTALLED, "Intel(R) Serial IO I2C Host Controller - 51E8", "setupapi",
           d(1, 3, 20), version_to="2409.5.63.0", detail="setupapi.dev.log: driver installed on device (iaLPSS2_I2C_ADL.inf)"),
        ev(Category.DRIVER, Action.INSTALLED, "Intel(R) Management Engine Interface #1", "setupapi",
           d(1, 3, 21), version_to="2409.5.63.0", detail="setupapi.dev.log: driver installed on device (heci.inf)"),
        ev(Category.DESKTOP_APP, Action.INSTALLED, "BlenderSvc (service)", "eventlog:service", d(5, 21, 16),
           detail="System log 7045: service registered → C:\\Program Files\\Blender Foundation\\svc.exe"),
    ]

    changes = correlate(events)
    Classifier().apply(changes)
    store = Store(":memory:")
    DescriptionPipeline(store, AIConfig(), use_ai=False).run(changes)
    # Show what AI-written descriptions look like, without calling the API.
    for c in changes:
        if c.name == "Blender" and c.description_source == "none":
            c.description, c.description_source = (
                "Free 3D modelling, animation and rendering application.", "ai")
        if c.name == "FastLane VPN Client" and c.description_source == "none":
            c.description, c.description_source = (
                "VPN software that routes your internet traffic through a private network.", "ai-low")
        if c.name == "Obsidian" and c.description_source == "none":
            c.description, c.description_source = (
                "Note-taking app that stores notes as plain Markdown files on your PC.", "ai")
        if c.name.startswith("httpx") and not c.publisher:
            c.publisher, c.publisher_source = "Encode", "ai"
    store.close()

    return Report(
        host="DEMO-PC", generated_at=now, period_start=start, period_end=now, scan_id=None,
        is_admin=True, tool_version=__version__, changes=changes, baseline_at=start, comparison_end=now,
        collector_status=[
            CollectorStatus("registry", True, items=212, seconds=0.4),
            CollectorStatus("appx", True, items=148, seconds=6.1),
            CollectorStatus("drivers", True, items=96, events=2, seconds=4.8),
            CollectorStatus("reliability", True, events=3, seconds=9.7),
            CollectorStatus("eventlog", True, events=4, seconds=1.2),
            CollectorStatus("windows-update", True, events=4, seconds=2.3),
            CollectorStatus("pip", True, items=64, seconds=1.9),
            CollectorStatus("npm", False, message="skipped: npm not found"),
            CollectorStatus("editor-extensions", True, items=31, seconds=0.1),
            CollectorStatus("scoop-choco", True, seconds=0.0),
        ],
        warnings=[], demo=True,
    )
