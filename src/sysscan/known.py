"""Your own identifications ("tags") for software that neither the built-in rules nor the AI got right.

Stored in ``%LOCALAPPDATA%\\sysscan\\known_software.toml`` (path configurable). Tags win over everything
else: built-in rules, cached/AI answers and the software's own metadata. They are applied on every scan,
and `sysscan retag` re-applies them to an existing report without rescanning.

    [[software]]
    name = "PowerENGAGE"            # exact product name; case, versions and (x64)/(x86) are ignored
    # match = "^PowerENGAGE\\b"     # …or a regular expression instead of `name`
    publisher = "Example Corp"
    description = "What it is, in your words."
    routine = true                  # optional: always collapse it under "routine"
    category = "desktop_app"        # optional: only apply to this type
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sysscan.models import Category, Change
from sysscan.normalize import normalize_name

HEADER = """# sysscan: your own identifications for software. They override built-in rules and AI answers.
# Add entries with `sysscan tag`, list what still needs identifying with `sysscan unknowns`, then run
# `sysscan retag` to update the latest report (future scans pick them up automatically).
#
# [[software]]
# name = "Exact product name"       # case, versions and (x64)/(x86) are ignored
# match = "^Regex\\\\b"              # alternative to name
# publisher = "Who makes it"
# description = "What it is"
# routine = true                    # optional: collapse under "routine"
# category = "desktop_app"          # optional: desktop_app | store_app | windows_update | driver | dev_package
"""


@dataclass
class KnownEntry:
    name: str | None = None
    match: str | None = None
    publisher: str | None = None
    description: str | None = None
    routine: bool | None = None
    category: str | None = None

    def __post_init__(self) -> None:
        self._norm = normalize_name(self.name) if self.name else None
        self._rx = re.compile(self.match, re.I) if self.match else None

    def matches(self, change: Change) -> bool:
        if self.category and str(change.category) != self.category:
            return False
        if self._rx is not None:
            return bool(self._rx.search(change.name))
        return bool(self._norm) and (change.norm_name or normalize_name(change.name)) == self._norm

    def to_toml(self) -> str:
        lines = ["[[software]]"]
        for key in ("name", "match", "publisher", "description", "category"):
            value = getattr(self, key)
            if value is not None:
                lines.append(f"{key} = {json.dumps(value, ensure_ascii=False)}")  # JSON strings are valid TOML
        if self.routine is not None:
            lines.append(f"routine = {'true' if self.routine else 'false'}")
        return "\n".join(lines)


class KnownSoftware:
    def __init__(self, entries: list[KnownEntry] | None = None, path: Path | None = None):
        self.entries = entries or []
        self.path = path
        self.errors: list[str] = []

    # ------------------------------------------------------------------ load / save

    @classmethod
    def load(cls, path: Path) -> KnownSoftware:
        ks = cls(path=path)
        if not path.exists():
            return ks
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            ks.errors.append(f"Could not read {path.name}: {exc}")
            return ks
        for i, raw in enumerate(data.get("software", []), 1):
            if not isinstance(raw, dict):
                continue
            clean = {k: (v.strip() if isinstance(v, str) else v) for k, v in raw.items()
                     if k in ("name", "match", "publisher", "description", "routine", "category")}
            clean = {k: v for k, v in clean.items() if v not in ("", None)}  # empty template fields = unset
            if not (clean.get("name") or clean.get("match")):
                continue
            try:
                ks.entries.append(KnownEntry(**clean))
            except re.error as exc:
                ks.errors.append(f"{path.name} entry {i}: bad regex ({exc})")
        return ks

    def save(self) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n\n".join(e.to_toml() for e in self.entries)
        self.path.write_text(HEADER + "\n" + body + ("\n" if body else ""), encoding="utf-8")

    def upsert(self, entry: KnownEntry) -> bool:
        """Add or replace (same name/match). Returns True if an existing entry was replaced."""
        key = (entry._norm, entry.match)
        for i, e in enumerate(self.entries):
            if (e._norm, e.match) == key:
                merged = KnownEntry(
                    name=entry.name or e.name, match=entry.match or e.match,
                    publisher=entry.publisher if entry.publisher is not None else e.publisher,
                    description=entry.description if entry.description is not None else e.description,
                    routine=entry.routine if entry.routine is not None else e.routine,
                    category=entry.category or e.category,
                )
                self.entries[i] = merged
                return True
        self.entries.append(entry)
        return False

    # ------------------------------------------------------------------ apply

    def find(self, change: Change) -> KnownEntry | None:
        return next((e for e in self.entries if e.matches(change)), None)

    def apply(self, changes: list[Change]) -> int:
        """Apply publisher/description/routine tags. Returns how many changes were touched."""
        n = 0
        for c in changes:
            e = self.find(c)
            if e is None:
                continue
            if e.publisher:
                c.publisher, c.publisher_source = e.publisher, "yours"
            if e.description:
                c.description, c.description_source = e.description, "yours"
            if e.routine is not None:
                c.routine = e.routine
            n += 1
        return n


def needs_tagging(change: Change) -> bool:
    """Rows worth identifying by hand: no/unsure description, or unknown provider."""
    if change.description_source == "yours" and change.publisher_source == "yours":
        return False
    return (change.description_source in (None, "none", "ai-low")
            or (change.provider == "Unknown" and change.category != Category.WINDOWS_UPDATE))


def ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def tag_command(change: Change) -> str:
    """The PowerShell command a user can paste to tag this row."""
    pub = change.publisher if change.publisher_source not in ("ai",) and change.provider != "Unknown" else ""
    return (f"sysscan tag {ps_quote(change.name)} --publisher {ps_quote(pub or '')} "
            f"--description {ps_quote('')}")
