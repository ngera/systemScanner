"""Collector interface.

A collector can contribute two things:

* ``inventory()`` — what is present right now. Saved to the snapshot database and diffed
  against earlier snapshots. Only collectors with ``provides_inventory = True`` take part in
  diffs (so a failed collector can't cause phantom "uninstalls").
* ``events(since, until)`` — historical evidence of changes inside the period
  (event logs, update history, installer logs …).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sysscan.config import Config
from sysscan.models import ChangeEvent, InventoryItem
from sysscan.winutil import IS_WINDOWS


@dataclass
class ScanContext:
    config: Config
    is_admin: bool
    now: datetime


class Collector:
    name: str = "base"
    title: str = ""
    provides_inventory: bool = False
    provides_events: bool = False
    windows_only: bool = True
    needs_admin_for_full_results: bool = False

    def available(self) -> tuple[bool, str]:
        if self.windows_only and not IS_WINDOWS:
            return False, "Windows only"
        return True, ""

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        return []

    def events(self, ctx: ScanContext, since: datetime, until: datetime) -> list[ChangeEvent]:
        return []
