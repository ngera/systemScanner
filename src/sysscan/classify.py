"""Mark routine background churn so real changes stand out in the report."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sysscan.models import Action, Category, Change

# Always routine, whatever the action.
ALWAYS_ROUTINE = [
    r"security intelligence update",
    r"definition update",
    r"antimalware platform",
    r"malicious software removal tool",
    r"microsoft defender antivirus",
    r"update for microsoft defender",
    r"windows malicious software",
    r"^windows built-in driver for",  # a device plugged in and Windows used its own inbox driver
    r"^mpksl",  # Defender's scan driver, re-registered on every scan
]

# Routine when the action is an update (a fresh *install* of these is still worth showing).
ROUTINE_UPDATES = [
    r"^microsoft edge",
    r"^google chrome",
    r"^mozilla firefox",
    r"^brave",
    r"webview2",
    r"^microsoft onedrive",
    r"^microsoft teams",
    r"microsoft update health tools",
    r"^zoom",
    r"^slack",
    r"^discord",
]

# Store "framework" packages that update constantly in the background.
FRAMEWORK_PACKAGES = [
    r"vclibs",
    r"ui ?xaml",
    r"net ?native",
    r"windows ?app ?runtime",
    r"services ?store ?engagement",
    r"desktop ?app ?installer",
    r"web ?media ?extensions",
    r"(?:heif|hevc|vp9|av1|webp|raw) ?(?:image|video)? ?extension",
]


class Classifier:
    def __init__(self, extra_patterns: Iterable[str] = ()):
        self.always = [re.compile(p, re.I) for p in ALWAYS_ROUTINE]
        self.updates = [re.compile(p, re.I) for p in ROUTINE_UPDATES]
        self.frameworks = [re.compile(p, re.I) for p in FRAMEWORK_PACKAGES]
        self.extra = [re.compile(p, re.I) for p in extra_patterns]

    def is_routine(self, change: Change) -> bool:
        name = change.name
        if change.action == Action.MODIFIED and change.occurrences >= 3:
            return True  # e.g. an installer that "repairs" itself every few hours
        if any(p.search(name) for p in self.always + self.extra):
            return True
        if change.action == Action.UPDATED:
            if any(p.search(name) for p in self.updates):
                return True
            if change.category == Category.STORE_APP:
                # Store apps auto-update all the time; treat every Store *update* as routine.
                return True
        return change.category == Category.STORE_APP and any(p.search(name) for p in self.frameworks)

    def apply(self, changes: list[Change]) -> None:
        for c in changes:
            c.routine = self.is_routine(c)
