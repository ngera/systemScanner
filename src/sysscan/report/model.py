"""Report data model — everything the renderers need, nothing they have to compute."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sysscan.models import Action, Category, Change, CollectorStatus

ACTION_ORDER = [Action.INSTALLED, Action.UPDATED, Action.UNINSTALLED, Action.CHANGED, Action.MODIFIED]
CATEGORY_ORDER = [Category.DESKTOP_APP, Category.STORE_APP, Category.WINDOWS_UPDATE, Category.DRIVER,
                  Category.DEV_PACKAGE]

ACTION_BLURB = {
    Action.INSTALLED: "New software that wasn't on this PC before.",
    Action.UPDATED: "Software that was already here and moved to a newer version.",
    Action.UNINSTALLED: "Software that was removed.",
    Action.CHANGED: "Timestamps show these changed in the period, but there's no earlier snapshot to "
                    "tell whether they were new installs or updates.",
    Action.MODIFIED: "Repaired, reconfigured or re-registered without a version change.",
}


@dataclass
class Section:
    action: Action
    blurb: str
    groups: list[tuple[Category, list[Change]]]
    routine: list[Change]

    @property
    def total(self) -> int:
        return sum(len(c) for _, c in self.groups) + len(self.routine)

    @property
    def notable(self) -> int:
        return sum(len(c) for _, c in self.groups)

    @property
    def items(self) -> list[Change]:
        """Non-routine changes as one list, newest first (the HTML report shows one table per action)."""
        return _sort([c for _, cs in self.groups for c in cs])


@dataclass
class Report:
    host: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    scan_id: int | None
    is_admin: bool
    tool_version: str
    changes: list[Change]
    baseline_at: datetime | None = None
    comparison_end: datetime | None = None
    collector_status: list[CollectorStatus] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ai_used: bool = False
    demo: bool = False

    def count(self, action: Action, include_routine: bool = True) -> int:
        return sum(1 for c in self.changes if c.action == action and (include_routine or not c.routine))

    @property
    def routine_total(self) -> int:
        return sum(1 for c in self.changes if c.routine)

    def sections(self) -> list[Section]:
        out: list[Section] = []
        for action in ACTION_ORDER:
            items = [c for c in self.changes if c.action == action]
            if not items:
                continue
            groups = []
            for cat in CATEGORY_ORDER:
                cs = [c for c in items if c.category == cat and not c.routine]
                if cs:
                    groups.append((cat, _sort(cs)))
            routine = _sort([c for c in items if c.routine])
            out.append(Section(action, ACTION_BLURB[action], groups, routine))
        return out

    def categories(self) -> list[tuple[Category, int]]:
        return [(cat, n) for cat in CATEGORY_ORDER if (n := sum(1 for c in self.changes if c.category == cat))]

    def providers(self) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for c in self.changes:
            counts[c.provider] = counts.get(c.provider, 0) + 1
        return sorted(counts.items(), key=lambda kv: (kv[0] == "Unknown", -kv[1], kv[0].lower()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "sysscan",
            "tool_version": self.tool_version,
            "host": self.host,
            "generated_at": self.generated_at.isoformat(),
            "period": {"start": self.period_start.isoformat(), "end": self.period_end.isoformat()},
            "scan_id": self.scan_id,
            "is_admin": self.is_admin,
            "baseline_at": self.baseline_at.isoformat() if self.baseline_at else None,
            "comparison_end": self.comparison_end.isoformat() if self.comparison_end else None,
            "summary": {str(a): self.count(a) for a in ACTION_ORDER} | {"routine": self.routine_total},
            "warnings": self.warnings,
            "collectors": [vars(s) for s in self.collector_status],
            "changes": [c.to_dict() for c in self.changes],
        }


def report_from_dict(d: dict[str, Any]) -> Report:
    """Rebuild a Report from its JSON form (for `sysscan retag`)."""
    from sysscan.winutil import parse_iso

    return Report(
        host=d.get("host", ""), generated_at=parse_iso(d["generated_at"]),  # type: ignore[arg-type]
        period_start=parse_iso(d["period"]["start"]), period_end=parse_iso(d["period"]["end"]),  # type: ignore[arg-type]
        scan_id=d.get("scan_id"), is_admin=bool(d.get("is_admin")), tool_version=d.get("tool_version", ""),
        changes=[Change.from_dict(c) for c in d.get("changes", [])],
        baseline_at=parse_iso(d.get("baseline_at")), comparison_end=parse_iso(d.get("comparison_end")),
        collector_status=[CollectorStatus(**c) for c in d.get("collectors", [])],
        warnings=list(d.get("warnings", [])),
    )


def _sort(changes: list[Change]) -> list[Change]:
    return sorted(changes, key=lambda c: (c.time or c.window_end or c.window_start).timestamp()
                  if (c.time or c.window_end or c.window_start) else 0, reverse=True)
