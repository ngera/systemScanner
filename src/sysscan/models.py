"""Core data model shared by collectors, the diff engine, the correlator and the reports.

Two kinds of data flow through sysscan:

* ``InventoryItem`` — "this thing is on the machine right now" (a point-in-time snapshot row).
* ``ChangeEvent``   — "this thing changed at (roughly) this time", produced either by
  diffing two snapshots or by reading historical evidence (event logs, update history …).

The correlator merges many ``ChangeEvent`` objects that describe the same real-world
change into one ``Change``, which is what the reports display.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Category(StrEnum):
    DESKTOP_APP = "desktop_app"
    STORE_APP = "store_app"
    WINDOWS_UPDATE = "windows_update"
    DRIVER = "driver"
    DEV_PACKAGE = "dev_package"

    @property
    def label(self) -> str:
        return {
            Category.DESKTOP_APP: "Desktop apps",
            Category.STORE_APP: "Store apps",
            Category.WINDOWS_UPDATE: "Windows updates",
            Category.DRIVER: "Drivers & firmware",
            Category.DEV_PACKAGE: "Developer packages",
        }[self]

    @property
    def short_label(self) -> str:
        return {
            Category.DESKTOP_APP: "Desktop app",
            Category.STORE_APP: "Store app",
            Category.WINDOWS_UPDATE: "Windows update",
            Category.DRIVER: "Driver",
            Category.DEV_PACKAGE: "Dev package",
        }[self]


class Action(StrEnum):
    INSTALLED = "installed"
    UPDATED = "updated"
    UNINSTALLED = "uninstalled"
    #: Something changed but the evidence can't tell an install from an update
    #: (e.g. a registry InstallDate inside the period, with no earlier snapshot).
    CHANGED = "changed"
    #: MSI "reconfigured" / repaired / service registered — noteworthy but not a version change.
    MODIFIED = "modified"

    @property
    def label(self) -> str:
        return {
            Action.INSTALLED: "Installed",
            Action.UPDATED: "Updated",
            Action.UNINSTALLED: "Uninstalled",
            Action.CHANGED: "Installed or updated",
            Action.MODIFIED: "Modified / repaired",
        }[self]


class TimeConfidence(StrEnum):
    """How much to trust a timestamp. Ordered from most to least precise."""

    EXACT = "exact"  # event log / update history record
    FILE = "file"  # filesystem or registry write time — usually right, sometimes touched later
    DAY = "day"  # a date without a time (registry InstallDate)
    WINDOW = "window"  # only known to be between two snapshots
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return list(TimeConfidence).index(self)

    @property
    def label(self) -> str:
        return {
            TimeConfidence.EXACT: "exact",
            TimeConfidence.FILE: "approx.",
            TimeConfidence.DAY: "date only",
            TimeConfidence.WINDOW: "between scans",
            TimeConfidence.UNKNOWN: "unknown",
        }[self]


@dataclass
class InventoryItem:
    """One piece of software present on the machine at scan time."""

    key: str  # stable identity within its source, e.g. "reg:HKLM64:{GUID}"
    category: Category
    source: str  # collector name
    name: str
    version: str | None = None
    publisher: str | None = None
    install_time: datetime | None = None  # tz-aware UTC
    time_confidence: TimeConfidence = TimeConfidence.UNKNOWN
    scope: str = "machine"  # machine | user
    description: str | None = None  # publisher-provided description, if any
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    source: str
    detail: str
    time: datetime | None = None


@dataclass
class ChangeEvent:
    """A single piece of evidence that something changed."""

    category: Category
    action: Action
    name: str
    source: str
    time: datetime | None = None
    confidence: TimeConfidence = TimeConfidence.UNKNOWN
    #: For WINDOW confidence: the change happened in (window_start, window_end].
    window_start: datetime | None = None
    window_end: datetime | None = None
    version_from: str | None = None
    version_to: str | None = None
    publisher: str | None = None
    description: str | None = None
    detail: str = ""
    item_key: str | None = None
    #: True if this came from comparing two snapshots (authoritative for the action).
    from_snapshot: bool = False


@dataclass
class Change:
    """A merged, report-ready change."""

    category: Category
    action: Action
    name: str
    time: datetime | None
    confidence: TimeConfidence
    version_from: str | None = None
    version_to: str | None = None
    publisher: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    routine: bool = False
    description: str | None = None
    description_source: str | None = None  # rule | publisher | ai | ai-low | none
    publisher_source: str | None = None  # None = the software itself | "ai" | "yours" (known_software.toml)
    evidence: list[Evidence] = field(default_factory=list)
    norm_name: str = ""
    #: How many times this identical change happened in the period (e.g. an MSI that self-repairs every 6 h).
    occurrences: int = 1
    #: Where a web-assisted AI answer came from.
    source_url: str | None = None
    #: Extra context for identifying the software (install folder, vendor URL, service path …). Not shown.
    hints: dict[str, str] = field(default_factory=dict)

    @property
    def provider(self) -> str:
        """Publisher cleaned up for display and filtering ("Microsoft Corporation" -> "Microsoft")."""
        from sysscan.normalize import provider_name

        return provider_name(self.publisher, self.category)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["provider"] = self.provider
        for k in ("time", "window_start", "window_end"):
            d[k] = d[k].isoformat() if d[k] else None
        for ev in d["evidence"]:
            ev["time"] = ev["time"].isoformat() if ev["time"] else None
        d["category"] = str(self.category)
        d["action"] = str(self.action)
        d["confidence"] = str(self.confidence)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Change:
        """Rebuild a Change from a JSON report (used by `sysscan retag`)."""
        from sysscan.winutil import parse_iso

        return cls(
            category=Category(d["category"]), action=Action(d["action"]), name=d["name"],
            time=parse_iso(d.get("time")), confidence=TimeConfidence(d.get("confidence") or "unknown"),
            version_from=d.get("version_from"), version_to=d.get("version_to"), publisher=d.get("publisher"),
            window_start=parse_iso(d.get("window_start")), window_end=parse_iso(d.get("window_end")),
            routine=bool(d.get("routine")), description=d.get("description"),
            description_source=d.get("description_source"), publisher_source=d.get("publisher_source"),
            evidence=[Evidence(e.get("source", ""), e.get("detail", ""), parse_iso(e.get("time")))
                      for e in d.get("evidence") or []],
            norm_name=d.get("norm_name") or "", occurrences=int(d.get("occurrences") or 1),
            source_url=d.get("source_url"), hints=dict(d.get("hints") or {}),
        )


@dataclass
class CollectorStatus:
    name: str
    ok: bool
    items: int = 0
    events: int = 0
    message: str = ""
    seconds: float = 0.0
