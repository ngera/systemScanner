"""Post-correlation clean-up that makes report rows more useful and easier to identify.

* ``collapse_repeats`` — identical changes that recur (an MSI that "repairs" itself every 6 hours shows up
  as event 1035 dozens of times) become one row with an occurrence count.
* ``enrich_from_inventory`` — rows built from event logs often lack a publisher; the same program's
  uninstall-registry / Store entry usually has it, plus a vendor URL and install folder.
* ``service_hints`` — new services/kernel drivers carry their executable path; the Program Files
  folder usually names the vendor.

The "hints" collected here are passed to the AI (and shown nowhere else) so it can identify obscure
software from more than just its name. User-profile paths are never included.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import PureWindowsPath
from urllib.parse import urlparse

from sysscan.models import Action, Change, InventoryItem
from sysscan.normalize import normalize_name

_GENERIC_FOLDERS = {
    "common files", "windowsapps", "windows", "system32", "syswow64", "drivers", "program files",
    "program files (x86)", "programdata", "microsoft", "package cache", "installer", "temp", "bin",
}
_PATH_IN_TEXT = re.compile(r'"?([A-Za-z]:\\[^"\r\n]+?\.(?:exe|sys|dll))"?', re.I)


def vendor_folder(path: str | None) -> str | None:
    """'C:\\Program Files\\McAfee\\WPS\\svc.exe' -> 'McAfee'. None for generic or user-profile paths."""
    if not path:
        return None
    parts = PureWindowsPath(path.strip('"')).parts
    lowered = [p.lower() for p in parts]
    for root in ("program files", "program files (x86)", "programdata"):
        if root in lowered:
            i = lowered.index(root)
            if i + 1 < len(parts) - (1 if "." in parts[-1] else 0):
                folder = parts[i + 1]
                return None if folder.lower() in _GENERIC_FOLDERS else folder
    return None


def safe_path(path: str | None) -> str | None:
    """Drop anything under a user profile (it would reveal the user name)."""
    if not path:
        return None
    p = path.strip('"')
    return None if re.search(r"\\users\\[^\\]+\\", p, re.I) else p


def _domain(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlparse(url if "://" in url else f"https://{url}").hostname
    except ValueError:
        return None
    return host.removeprefix("www.") if host else None


def collapse_repeats(changes: list[Change]) -> list[Change]:
    groups: dict[tuple, list[Change]] = defaultdict(list)
    out: list[Change] = []
    for c in changes:
        if c.action in (Action.MODIFIED, Action.CHANGED):
            groups[(str(c.category), str(c.action), c.norm_name or normalize_name(c.name), c.version_to)].append(c)
        else:
            out.append(c)
    for group in groups.values():
        if len(group) == 1:
            out.append(group[0])
            continue
        group.sort(key=lambda c: c.time.timestamp() if c.time else 0, reverse=True)
        latest = group[0]
        latest.occurrences = sum(c.occurrences for c in group)
        evidence = [e for c in group for e in c.evidence]
        latest.evidence = evidence[:10]
        if len(evidence) > 10:
            from sysscan.models import Evidence

            latest.evidence.append(Evidence("…", f"{len(evidence) - 10} more similar records", None))
        latest.publisher = latest.publisher or next((c.publisher for c in group if c.publisher), None)
        out.append(latest)
    return out


def enrich_from_inventory(changes: list[Change], items: list[InventoryItem]) -> None:
    index: dict[tuple[str, str], InventoryItem] = {}
    for it in items:
        index.setdefault((str(it.category), normalize_name(it.name)), it)
    for c in changes:
        it = index.get((str(c.category), c.norm_name or normalize_name(c.name)))
        if it is None:
            continue
        if not c.publisher and it.publisher:
            c.publisher = it.publisher
        if not c.description and it.description:
            c.description = it.description
        loc = safe_path((it.extra or {}).get("install_location"))
        if loc:
            c.hints.setdefault("install_folder", loc)
        if domain := _domain((it.extra or {}).get("url")):
            c.hints.setdefault("vendor_website", domain)


def service_hints(changes: list[Change]) -> None:
    for c in changes:
        for ev in c.evidence:
            if not ev.source.startswith("eventlog:service"):
                continue
            m = _PATH_IN_TEXT.search(ev.detail)
            path = safe_path(m.group(1)) if m else None
            if not path:
                continue
            c.hints.setdefault("executable", path)
            vendor = vendor_folder(path)
            if vendor and not c.publisher:
                c.publisher = vendor
            break


def enrich(changes: list[Change], items: list[InventoryItem]) -> list[Change]:
    changes = collapse_repeats(changes)
    enrich_from_inventory(changes, items)
    service_hints(changes)
    return changes
