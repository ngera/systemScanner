"""Compare two inventory snapshots.

This is the most trustworthy signal sysscan has: if an item was present in the earlier snapshot
and is gone now, it *was* uninstalled — no matter which installer technology was used.

Two safety rules:

1. Only compare sources that succeeded in **both** scans. If the Store collector failed this
   time, we must not report every Store app as "uninstalled".
2. A removed key + an added key with the same normalised name in the same source is an
   **update** (MSI major upgrades change the product code, so the registry key changes).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sysscan.models import Action, ChangeEvent, InventoryItem, TimeConfidence
from sysscan.normalize import normalize_name


def _refine_time(item: InventoryItem, start: datetime, end: datetime) -> tuple[datetime | None, TimeConfidence]:
    """Use the item's own timestamp if it falls inside the snapshot window."""
    t = item.install_time
    if t and item.time_confidence in (TimeConfidence.EXACT, TimeConfidence.FILE) and start < t <= end:
        return t, item.time_confidence
    if t and item.time_confidence == TimeConfidence.DAY and start.date() <= t.date() <= end.date():
        return t, TimeConfidence.DAY
    return None, TimeConfidence.WINDOW


def _event(item: InventoryItem, action: Action, start: datetime, end: datetime, *,
           version_from: str | None = None, version_to: str | None = None, detail: str) -> ChangeEvent:
    time, conf = (None, TimeConfidence.WINDOW)
    if action != Action.UNINSTALLED:
        time, conf = _refine_time(item, start, end)
    return ChangeEvent(
        category=item.category,
        action=action,
        name=item.name,
        source=f"snapshot:{item.source}",
        time=time,
        confidence=conf,
        window_start=start,
        window_end=end,
        version_from=version_from,
        version_to=version_to,
        publisher=item.publisher,
        description=item.description,
        detail=detail,
        item_key=item.key,
        from_snapshot=True,
    )


def diff_snapshots(
    old: list[InventoryItem],
    new: list[InventoryItem],
    window_start: datetime,
    window_end: datetime,
    old_sources: set[str],
    new_sources: set[str],
) -> list[ChangeEvent]:
    common = old_sources & new_sources
    old_by_key = {i.key: i for i in old if i.source in common}
    new_by_key = {i.key: i for i in new if i.source in common}

    events: list[ChangeEvent] = []
    added = [new_by_key[k] for k in new_by_key.keys() - old_by_key.keys()]
    removed = [old_by_key[k] for k in old_by_key.keys() - new_by_key.keys()]

    for key in new_by_key.keys() & old_by_key.keys():
        a, b = old_by_key[key], new_by_key[key]
        if (a.version or "") != (b.version or ""):
            events.append(_event(b, Action.UPDATED, window_start, window_end,
                                 version_from=a.version, version_to=b.version,
                                 detail=f"version {a.version or '?'} → {b.version or '?'}"))

    # Pair removed+added with the same identity → update (e.g. MSI major upgrade).
    def ident(i: InventoryItem) -> tuple[str, str, str]:
        return (i.source, str(i.category), normalize_name(i.name))

    removed_by_ident: dict[tuple[str, str, str], list[InventoryItem]] = defaultdict(list)
    for r in removed:
        removed_by_ident[ident(r)].append(r)

    for a in sorted(added, key=lambda i: i.name):
        bucket = removed_by_ident.get(ident(a))
        if bucket:
            r = bucket.pop(0)
            events.append(_event(a, Action.UPDATED, window_start, window_end,
                                 version_from=r.version, version_to=a.version,
                                 detail=f"replaced {r.version or '?'} with {a.version or '?'}"))
        else:
            events.append(_event(a, Action.INSTALLED, window_start, window_end,
                                 version_to=a.version, detail="present now, absent in previous snapshot"))

    for bucket in removed_by_ident.values():
        for r in bucket:
            events.append(_event(r, Action.UNINSTALLED, window_start, window_end,
                                 version_from=r.version, detail="present in previous snapshot, absent now"))
    return events


def unchanged_keys(old: list[InventoryItem], new: list[InventoryItem], common_sources: set[str]) -> set[str]:
    """Keys whose version did not change between two snapshots (used to suppress timestamp noise)."""
    old_v = {i.key: i.version for i in old if i.source in common_sources}
    return {i.key for i in new if i.key in old_v and old_v[i.key] == i.version}
