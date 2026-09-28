"""Merge many pieces of evidence into one report row per real-world change.

A single MSI install can show up as: event 1033, event 11707, a Reliability Monitor record,
a new uninstall-registry key and a snapshot diff. The correlator groups evidence by
(category, normalised name), then:

1. attaches historical evidence to *snapshot* changes (authoritative about what happened),
2. clusters the remaining evidence by time, and
3. merges each group, keeping the most precise timestamp and the richest version info.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sysscan.models import Action, Category, Change, ChangeEvent, Evidence, TimeConfidence
from sysscan.normalize import normalize_name

CLUSTER_GAP = timedelta(minutes=30)
_MIN = datetime.min.replace(tzinfo=UTC)
_MAX = datetime.max.replace(tzinfo=UTC)

# Which historical actions are consistent with a snapshot-derived action.
_COMPATIBLE: dict[Action, set[Action]] = {
    Action.INSTALLED: {Action.INSTALLED, Action.CHANGED, Action.MODIFIED},
    Action.UPDATED: {Action.INSTALLED, Action.UPDATED, Action.UNINSTALLED, Action.CHANGED, Action.MODIFIED},
    Action.UNINSTALLED: {Action.UNINSTALLED},
}


def _group_key(e: ChangeEvent) -> tuple[str, str]:
    return (str(e.category), normalize_name(e.name) or e.name.lower())


def _in_window(e: ChangeEvent, anchor: ChangeEvent) -> bool:
    if e.time is None:
        return True
    start, end = anchor.window_start, anchor.window_end
    if start is None or end is None:
        return True
    if e.confidence == TimeConfidence.DAY:
        return start.date() <= e.time.date() <= end.date()
    slack = timedelta(minutes=5)
    return start - slack <= e.time <= end + slack


def _close(a: ChangeEvent, b: ChangeEvent) -> bool:
    if a.time is None or b.time is None:
        return a.time is None and b.time is None
    if TimeConfidence.DAY in (a.confidence, b.confidence):
        return a.time.date() == b.time.date()
    return abs(a.time - b.time) <= CLUSTER_GAP


def _best_time(events: list[ChangeEvent], prefer: set[Action] | None = None) -> tuple[datetime | None, TimeConfidence]:
    timed = [e for e in events if e.time is not None]
    if prefer:
        preferred = [e for e in timed if e.action in prefer]
        timed = preferred or timed
    if not timed:
        return None, TimeConfidence.WINDOW if any(e.window_start for e in events) else TimeConfidence.UNKNOWN
    best = min(timed, key=lambda e: (e.confidence.rank, e.time))
    return best.time, best.confidence


def _resolve_action(events: list[ChangeEvent]) -> Action:
    acts = {e.action for e in events}
    if Action.UPDATED in acts:
        return Action.UPDATED
    if Action.INSTALLED in acts and Action.UNINSTALLED in acts:
        # e.g. MSI major upgrade: old product removed + new product installed within minutes.
        installs = [e for e in events if e.action == Action.INSTALLED]
        removes = [e for e in events if e.action == Action.UNINSTALLED]
        vi = {e.version_to for e in installs if e.version_to}
        vr = {e.version_from for e in removes if e.version_from}
        return Action.UPDATED if (not vi or not vr or vi != vr) else Action.MODIFIED
    for a in (Action.INSTALLED, Action.UNINSTALLED, Action.CHANGED, Action.MODIFIED):
        if a in acts:
            return a
    return Action.CHANGED


def _first(values: list[str | None]) -> str | None:
    return next((v for v in values if v), None)


def _merge(events: list[ChangeEvent], anchor: ChangeEvent | None) -> Change:
    action = anchor.action if anchor else _resolve_action(events)
    ordered = ([anchor] if anchor else []) + [e for e in events if e is not anchor]

    prefer = {Action.UNINSTALLED} if action == Action.UNINSTALLED else {
        Action.INSTALLED, Action.UPDATED, Action.CHANGED}
    time, conf = _best_time(ordered, prefer)

    version_to = _first([e.version_to for e in ordered if e.action != Action.UNINSTALLED])
    version_from = _first([e.version_from for e in ordered])
    if action == Action.UPDATED and not version_from:
        version_from = _first([e.version_to for e in ordered if e.action == Action.UNINSTALLED])
    if action == Action.UNINSTALLED:
        version_from = version_from or _first([e.version_to for e in ordered])
        version_to = None

    # Prefer a human-friendly name: the longest non-snapshot name tends to be the MSI product name.
    name = (anchor.name if anchor else None) or max((e.name for e in ordered), key=len)

    return Change(
        category=ordered[0].category,
        action=action,
        name=name,
        time=time,
        confidence=conf,
        version_from=version_from,
        version_to=version_to,
        publisher=_first([e.publisher for e in ordered]),
        window_start=anchor.window_start if anchor else None,
        window_end=anchor.window_end if anchor else None,
        description=_first([e.description for e in ordered]),
        evidence=[Evidence(source=e.source, detail=e.detail, time=e.time) for e in ordered],
        norm_name=normalize_name(name),
    )


def align_driver_names(events: list[ChangeEvent]) -> None:
    """setupapi.dev.log names the *device* ("Intel(R) Serial IO I2C Host Controller"), while the
    snapshot groups drivers by provider/class. Match them up by driver version so one driver
    update becomes one row, and fold multiple devices getting the same driver into one row."""
    anchor_names: dict[str, str] = {}
    for e in events:
        if e.from_snapshot and e.category == Category.DRIVER and e.version_to:
            anchor_names.setdefault(e.version_to, e.name)
    loose_names: dict[str, str] = {}
    for e in sorted(events, key=lambda x: x.name):
        if e.from_snapshot or e.category != Category.DRIVER or not e.version_to or e.source != "setupapi":
            continue
        target = anchor_names.get(e.version_to) or loose_names.setdefault(e.version_to, e.name)
        if target != e.name:
            e.detail = f"{e.name}: {e.detail}"
            e.name = target


def correlate(events: list[ChangeEvent]) -> list[Change]:
    align_driver_names(events)
    groups: dict[tuple[str, str], list[ChangeEvent]] = defaultdict(list)
    for e in events:
        groups[_group_key(e)].append(e)

    changes: list[Change] = []
    for group in groups.values():
        anchors = [e for e in group if e.from_snapshot]
        loose = [e for e in group if not e.from_snapshot]
        attached: dict[int, list[ChangeEvent]] = {id(a): [a] for a in anchors}

        remaining: list[ChangeEvent] = []
        for e in loose:
            target = next(
                (a for a in anchors if e.action in _COMPATIBLE.get(a.action, set()) and _in_window(e, a)),
                None,
            )
            if target is not None:
                attached[id(target)].append(e)
            else:
                remaining.append(e)

        for a in anchors:
            changes.append(_merge(attached[id(a)], a))

        # Cluster whatever is left by time.
        remaining.sort(key=lambda e: (e.time is None, e.time or _MAX))
        clusters: list[list[ChangeEvent]] = []
        for e in remaining:
            if clusters and any(_close(e, x) for x in clusters[-1]):
                clusters[-1].append(e)
            else:
                clusters.append([e])
        changes.extend(_merge(c, None) for c in clusters)

    changes.sort(key=lambda c: c.time or c.window_end or _MIN, reverse=True)
    return changes
