"""Scan orchestration: collect → snapshot → diff → correlate → classify → describe → report."""

from __future__ import annotations

import logging
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sysscan import __version__
from sysscan.classify import Classifier
from sysscan.collectors import Collector, ScanContext, all_collectors
from sysscan.config import Config
from sysscan.correlate import correlate
from sysscan.describe import DescriptionPipeline
from sysscan.diff import diff_snapshots
from sysscan.enrich import enrich
from sysscan.known import KnownSoftware, needs_tagging
from sysscan.models import Action, Change, ChangeEvent, CollectorStatus, InventoryItem, TimeConfidence
from sysscan.report.model import Report
from sysscan.store import ScanRecord, Store
from sysscan.winutil import is_admin, utcnow

log = logging.getLogger(__name__)

Progress = Callable[[str], None]


@dataclass
class ScanOptions:
    since: datetime | None = None
    until: datetime | None = None
    use_ai: bool = False
    only: list[str] | None = None
    skip: list[str] | None = None


def select_collectors(cfg: Config, opts: ScanOptions) -> list[Collector]:
    chosen = []
    for c in all_collectors():
        if opts.only and c.name not in opts.only:
            continue
        if c.name in cfg.disabled_collectors or (opts.skip and c.name in opts.skip):
            continue
        chosen.append(c)
    return chosen


def inventory_time_events(items: list[InventoryItem], since: datetime, until: datetime,
                          covered_sources: set[str], covered_from: datetime | None = None) -> list[ChangeEvent]:
    """Evidence from items' own timestamps, for the parts of the period no snapshot comparison covers.

    ``covered_from``: snapshot comparison only covers the period from this moment (partial baseline);
    timestamps before it are still used for covered sources.
    """
    out = []
    for it in items:
        if it.install_time is None:
            continue
        if it.source in covered_sources and (covered_from is None or it.install_time >= covered_from):
            continue
        if it.time_confidence == TimeConfidence.DAY:
            inside = since.date() <= it.install_time.date() <= until.date()
        else:
            inside = since <= it.install_time <= until
        if not inside:
            continue
        out.append(ChangeEvent(
            category=it.category, action=Action.CHANGED, name=it.name, source=f"timestamp:{it.source}",
            time=it.install_time, confidence=it.time_confidence, version_to=it.version,
            publisher=it.publisher, description=it.description, item_key=it.key,
            detail=f"{it.source} timestamp falls inside the period (no earlier snapshot to compare)",
        ))
    return out


def _in_period(c: Change, since: datetime, until: datetime) -> bool:
    if c.time is not None:
        if c.confidence == TimeConfidence.DAY:
            return since.date() <= c.time.date() <= until.date()
        return since - timedelta(minutes=5) <= c.time <= until + timedelta(minutes=5)
    return True  # window-only snapshot changes were already bounded by the snapshot choice


def run_scan(cfg: Config, opts: ScanOptions, store: Store, progress: Progress = lambda _m: None) -> Report:
    now = utcnow()
    admin = is_admin()
    host = platform.node()
    scan_id = store.start_scan(now, host, admin, __version__)
    ctx = ScanContext(config=cfg, is_admin=admin, now=now)
    collectors = select_collectors(cfg, opts)
    statuses: dict[str, CollectorStatus] = {}
    warnings: list[str] = []

    # 1. Inventory snapshot ------------------------------------------------------------------
    items: list[InventoryItem] = []
    covered: list[str] = []
    for c in collectors:
        ok, why = c.available()
        if not ok:
            statuses[c.name] = CollectorStatus(c.name, False, message=f"skipped: {why}")
            continue
        statuses[c.name] = CollectorStatus(c.name, True)
        if not c.provides_inventory:
            continue
        progress(f"Inventory: {c.title}")
        t0 = time.perf_counter()
        try:
            found = c.inventory(ctx)
            items += found
            covered.append(c.name)
            statuses[c.name].items = len(found)
        except Exception as exc:
            log.exception("collector %s inventory failed", c.name)
            statuses[c.name].ok = False
            statuses[c.name].message = f"inventory failed: {exc}"
        statuses[c.name].seconds += time.perf_counter() - t0

    store.save_items(scan_id, items)
    store.finish_scan(scan_id, utcnow(), covered)

    # 2. Period -------------------------------------------------------------------------------
    until = opts.until or now
    previous = store.baseline_before(now, exclude=scan_id)
    if opts.since:
        since = opts.since
    elif previous:
        since = previous.started_at
    else:
        since = now - timedelta(days=cfg.first_run_days)
    if previous is None:
        warnings.append(
            "First scan on this PC: there is no earlier snapshot, so this report relies on timestamps and "
            "logs only. Uninstalls and previous versions can't be fully known yet. From the next scan on "
            "they will be."
        )

    # 3. Snapshot diff -----------------------------------------------------------------------
    events: list[ChangeEvent] = []
    baseline: ScanRecord | None = store.baseline_before(since, exclude=scan_id)
    end_scan: ScanRecord | None = store.get_scan(scan_id)
    if opts.until and until < now - timedelta(minutes=1):
        end_scan = store.first_scan_after(until) or end_scan
    partial_baseline = False
    if baseline is None and end_scan is not None:
        # No snapshot from before the period, but maybe one from inside it: diff from there, and rely on
        # logs/timestamps for the part of the period before it.
        inside = store.first_scan_after(since, exclude=scan_id)
        if inside and inside.id != end_scan.id and inside.started_at < end_scan.started_at:
            baseline, partial_baseline = inside, True
    common: set[str] = set()
    if baseline and end_scan and baseline.id != end_scan.id:
        progress("Comparing snapshots")
        common = set(baseline.collectors) & set(end_scan.collectors)
        events += diff_snapshots(store.load_items(baseline.id), store.load_items(end_scan.id),
                                 baseline.started_at, end_scan.started_at,
                                 set(baseline.collectors), set(end_scan.collectors))
        missing = set(end_scan.collectors) - set(baseline.collectors)
        if missing:
            warnings.append("No earlier snapshot for: " + ", ".join(sorted(missing))
                            + ". Changes there are based on timestamps only.")
        if partial_baseline:
            warnings.append(
                f"Snapshots only cover this period from {baseline.started_at.astimezone():%Y-%m-%d %H:%M} on. "
                f"Changes before then are based on logs and timestamps, so uninstalls and previous versions "
                f"from that part may be missing.")
    elif previous is not None:
        warnings.append(f"No snapshot exists from before {since.astimezone():%Y-%m-%d %H:%M}. "
                        "Uninstalls and previous versions inside this period may be missing.")

    # 4. Historical evidence -----------------------------------------------------------------
    for c in collectors:
        if not c.provides_events or statuses[c.name].message.startswith("skipped"):
            continue
        progress(f"History: {c.title}")
        t0 = time.perf_counter()
        try:
            found_ev = c.events(ctx, since, until)
            events += found_ev
            statuses[c.name].events = len(found_ev)
        except Exception as exc:
            log.exception("collector %s events failed", c.name)
            statuses[c.name].ok = False
            statuses[c.name].message = (statuses[c.name].message + "; " if statuses[c.name].message else "") \
                + f"history failed: {exc}"
        statuses[c.name].seconds += time.perf_counter() - t0

    period_items = items if end_scan is None or end_scan.id == scan_id else store.load_items(end_scan.id)
    events += inventory_time_events(period_items, since, until, common,
                                    covered_from=baseline.started_at if partial_baseline and baseline else None)

    # 5. Correlate, classify, describe --------------------------------------------------------
    progress("Correlating evidence")
    changes = [c for c in correlate(events) if _in_period(c, since, until)]
    changes = enrich(changes, period_items)
    Classifier(cfg.extra_routine_patterns).apply(changes)

    progress("Writing plain-language descriptions")
    known = KnownSoftware.load(cfg.known_software_path)
    warnings += known.errors
    pipeline = DescriptionPipeline(store, cfg.ai, use_ai=opts.use_ai, known=known)
    pipeline.run(changes)
    known.apply(changes)  # your tags also decide "routine"
    warnings += pipeline.messages
    todo = sum(1 for c in changes if needs_tagging(c))
    if todo:
        warnings.append(f"{todo} item(s) couldn't be fully identified. Run `sysscan unknowns` to list them, "
                        "tag them with `sysscan tag`, then `sysscan retag` to update this report.")

    if not admin:
        warnings.append("Not running as administrator: some logs and other users' installs may be missing. "
                        "Run from an elevated terminal (or the scheduled task) for full results.")
    failed = [s.name for s in statuses.values() if not s.ok and not s.message.startswith("skipped")]
    if failed:
        warnings.append("Some sources failed and were left out: " + ", ".join(failed)
                        + ". See the source table at the end.")

    return Report(
        host=host, generated_at=utcnow(), period_start=since, period_end=until, scan_id=scan_id,
        is_admin=admin, tool_version=__version__, changes=changes,
        baseline_at=baseline.started_at if baseline and end_scan and baseline.id != end_scan.id else None,
        comparison_end=end_scan.started_at if end_scan else None,
        collector_status=list(statuses.values()), warnings=warnings, ai_used=opts.use_ai,
    )


def scan_and_report(cfg: Config, opts: ScanOptions, progress: Progress = lambda _m: None,
                    formats: list[str] | None = None, out_dir=None) -> tuple[Report, dict]:
    """Run a scan and write the report files. Shared by the CLI and runScan.exe."""
    from pathlib import Path

    from sysscan.report.render import write_reports

    store = Store(cfg.db_path)
    try:
        report = run_scan(cfg, opts, store, progress)
        progress("Writing report")
        written = write_reports(report, Path(out_dir) if out_dir else cfg.reports_path, formats or cfg.formats)
        if written and report.scan_id:
            store.set_report_path(report.scan_id, str(written.get("html") or next(iter(written.values()))))
    finally:
        store.close()
    return report, written
