from sysscan.collectors.appx import AppxCollector
from sysscan.collectors.base import Collector, ScanContext
from sysscan.collectors.devpkgs import (
    EditorExtensionsCollector,
    NpmCollector,
    PipCollector,
    ScoopChocoCollector,
)
from sysscan.collectors.drivers import DriverCollector
from sysscan.collectors.history import EventLogCollector, ReliabilityCollector, WindowsUpdateCollector
from sysscan.collectors.uninstall_registry import UninstallRegistryCollector


def all_collectors() -> list[Collector]:
    return [
        UninstallRegistryCollector(),
        AppxCollector(),
        DriverCollector(),
        ReliabilityCollector(),
        EventLogCollector(),
        WindowsUpdateCollector(),
        PipCollector(),
        NpmCollector(),
        EditorExtensionsCollector(),
        ScoopChocoCollector(),
    ]


__all__ = ["Collector", "ScanContext", "all_collectors"]
