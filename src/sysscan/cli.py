"""Command-line interface."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path

from sysscan import __version__
from sysscan.config import Config, load_config
from sysscan.winutil import IS_WINDOWS, is_admin, utcnow


def _parse_when(value: str) -> datetime:
    """Accept '2026-09-01', '2026-09-01 14:30', '7d' (days ago) or '12h' (hours ago)."""
    v = value.strip().lower()
    if v.endswith("d") and v[:-1].isdigit():
        return utcnow() - timedelta(days=int(v[:-1]))
    if v.endswith("h") and v[:-1].isdigit():
        return utcnow() - timedelta(hours=int(v[:-1]))
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a date: {value!r} (try 2026-09-01 or 7d)") from exc
    return (dt if dt.tzinfo else dt.astimezone()).astimezone()


def _open(path: Path) -> None:
    try:
        if IS_WINDOWS:
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            webbrowser.open(path.as_uri())
    except Exception:
        pass


def _setup_logging(cfg: Config, verbose: bool) -> None:
    cfg.home.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(cfg.home / "sysscan.log", encoding="utf-8")],
    )


# ----------------------------------------------------------------------------- commands

def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.scan import scan_and_report

    if not IS_WINDOWS:
        print("note: most sources are Windows-only; on this OS only pip/npm/editor extensions are scanned.",
              file=sys.stderr)
    opts = scan_options_from_args(args, cfg)
    progress = (lambda m: None) if args.quiet else (lambda m: print(f"  · {m}", file=sys.stderr))
    report, written = scan_and_report(cfg, opts, progress,
                                      formats=args.format.split(",") if args.format else None, out_dir=args.out)

    if not args.quiet:
        from sysscan.models import Action

        print(f"\n{report.host}: {report.period_start.astimezone():%Y-%m-%d %H:%M} → "
              f"{report.period_end.astimezone():%Y-%m-%d %H:%M}")
        for a in (Action.INSTALLED, Action.UPDATED, Action.UNINSTALLED, Action.CHANGED, Action.MODIFIED):
            n, n_all = report.count(a, False), report.count(a)
            if n_all:
                print(f"  {a.label:<22} {n:>4}" + (f"  (+{n_all - n} routine)" if n_all > n else ""))
        for w in report.warnings:
            print(f"  ! {w}")
        for fmt, path in written.items():
            print(f"  {fmt:>4}: {path}")
    if "html" in written and cfg.open_report and not args.no_open:
        _open(written["html"])
    return 0


def cmd_demo(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.demo import build_demo_report
    from sysscan.report.render import write_reports

    out_dir = Path(args.out) if args.out else cfg.reports_path / "demo"
    written = write_reports(build_demo_report(), out_dir, ["html", "md", "json"])
    for fmt, path in written.items():
        print(f"{fmt:>4}: {path}")
    if not args.no_open:
        _open(written["html"])
    return 0


def cmd_history(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.store import Store

    store = Store(cfg.db_path)
    scans = store.scans()
    store.close()
    if not scans:
        print("No scans yet. Run: sysscan scan")
        return 0
    for s in scans:
        print(f"#{s.id:<4} {s.started_at.astimezone():%Y-%m-%d %H:%M}  "
              f"{'admin' if s.is_admin else 'user '}  {len(s.collectors)} sources  {s.report_path or ''}")
    return 0


def cmd_open(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.store import Store

    store = Store(cfg.db_path)
    scans = [s for s in store.scans() if s.report_path]
    store.close()
    target = next((s for s in scans if s.id == args.scan_id), None) if args.scan_id else (scans[-1] if scans else None)
    if not target or not target.report_path:
        print("No report found.")
        return 1
    _open(Path(target.report_path))
    print(target.report_path)
    return 0


def cmd_collectors(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.collectors import all_collectors

    print(f"{'name':<18} {'status':<22} what")
    for c in all_collectors():
        ok, why = c.available()
        state = "disabled (config)" if c.name in cfg.disabled_collectors else ("available" if ok else why)
        print(f"{c.name:<18} {state:<22} {c.title}")
    print(f"\nRunning as administrator: {'yes' if is_admin() else 'no'}")
    from sysscan.describe.ai import get_api_key, normalize_provider, ollama_status
    from sysscan.envfile import loaded_files

    provider = normalize_provider(cfg.ai.provider)
    if provider == "ollama":
        ok, detail = ollama_status(cfg.ai.base_url)
        print(f"AI descriptions: {'enabled' if cfg.ai.enabled else 'disabled'} "
              f"(provider ollama, model {cfg.ai.model}); {detail}")
    else:
        key = get_api_key()
        print(f"AI descriptions: {'enabled' if cfg.ai.enabled else 'disabled'} "
              f"(provider claude, model {cfg.ai.model}); "
              f"API key {'found' if key else 'not found'}")
    for f in loaded_files():
        print(f"  .env loaded: {f}")
    return 0


def cmd_set_key(args: argparse.Namespace, cfg: Config) -> int:
    try:
        from sysscan.describe.ai import set_api_key
    except ImportError:
        print('Install the AI extra first: pip install "sysscan[ai]"')
        return 1
    key = getpass.getpass("Anthropic API key (input hidden): ").strip()
    if not key:
        print("Nothing saved.")
        return 1
    set_api_key(key)
    print("Saved to Windows Credential Manager (service 'sysscan').")
    print("Enable AI descriptions with [ai] enabled = true in config.toml, or pass --ai.")
    return 0


def _latest_json(cfg: Config, scan_id: int | None = None) -> Path | None:
    from sysscan.store import Store

    store = Store(cfg.db_path)
    scans = [s for s in store.scans() if s.report_path]
    store.close()
    target = next((s for s in scans if s.id == scan_id), None) if scan_id else (scans[-1] if scans else None)
    if not target or not target.report_path:
        return None
    js = Path(target.report_path).with_suffix(".json")
    return js if js.exists() else None


def cmd_tag(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.known import KnownEntry, KnownSoftware

    if not (args.publisher or args.description or args.routine is not None):
        print("Nothing to set: give --publisher and/or --description (and optionally --routine).")
        return 1
    known = KnownSoftware.load(cfg.known_software_path)
    entry = KnownEntry(name=None if args.regex else args.name, match=args.name if args.regex else None,
                       publisher=args.publisher or None, description=args.description or None,
                       routine=args.routine, category=args.category)
    replaced = known.upsert(entry)
    known.save()
    print(f"{'Updated' if replaced else 'Added'} tag for {args.name!r} in {cfg.known_software_path}")
    print("Run `sysscan retag` to apply it to the latest report; future scans use it automatically.")
    return 0


def cmd_untag(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.known import KnownSoftware

    known = KnownSoftware.load(cfg.known_software_path)
    removed = known.remove(args.name, regex=args.regex)
    if not removed:
        print(f"No tag matches {args.name!r}. See your tags with: sysscan tags")
        return 1
    known.save()
    for e in removed:
        print(f"Removed tag: {e.match or e.name}")
    print("Run `sysscan retag` to update the latest report. The next scan uses the built-in rules or AI again.")
    return 0


def cmd_tags(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan.known import KnownSoftware

    known = KnownSoftware.load(cfg.known_software_path)
    for e in known.errors:
        print(f"! {e}")
    if not known.entries:
        print(f"No tags yet ({cfg.known_software_path}). Add one with: sysscan tag \"<name>\" --publisher ...")
        return 0
    print(f"{len(known.entries)} tag(s) in {cfg.known_software_path}:\n")
    for e in known.entries:
        print(f"  • {known.describe(e)}")
    print("\nRemove one with: sysscan untag \"<name or pattern as shown>\"")
    return 0


def cmd_unknowns(args: argparse.Namespace, cfg: Config) -> int:
    import json

    from sysscan.known import KnownEntry, KnownSoftware, needs_tagging
    from sysscan.models import Change

    js = _latest_json(cfg, args.scan_id)
    if js is None:
        print("No JSON report found. Run a scan first (JSON is on by default).")
        return 1
    known = KnownSoftware.load(cfg.known_software_path)
    rows: dict[str, Change] = {}
    for d in json.loads(js.read_text(encoding="utf-8")).get("changes", []):
        c = Change.from_dict(d)
        if needs_tagging(c) and not known.find(c):
            rows.setdefault(c.norm_name or c.name.lower(), c)
    if not rows:
        print("Everything in the latest report is identified. Nothing to tag.")
        return 0
    print(f"{len(rows)} item(s) in {js.name} need identifying:\n")
    for c in rows.values():
        why = []
        if c.description_source in (None, "none"):
            why.append("no description")
        elif c.description_source in ("ai-low", "ai-web-low"):
            why.append("AI unsure")
        if c.provider == "Unknown":
            why.append("provider unknown")
        hint = ", ".join(f"{k}: {v}" for k, v in c.hints.items())
        print(f"  • {c.name}  [{c.category.short_label}; {', '.join(why)}]" + (f"\n      {hint}" if hint else ""))
    if args.edit:
        for c in rows.values():
            known.entries.append(KnownEntry(name=c.name, publisher="" if c.provider == "Unknown" else c.provider,
                                            description=""))
        known.save()
        print(f"\nAdded {len(rows)} blank entries to {cfg.known_software_path}. Fill in publisher/description,")
        print("save, then run `sysscan retag`. Entries you leave blank are ignored.")
        _open(cfg.known_software_path)
    else:
        print("\nTag one:   sysscan tag \"<name>\" --publisher \"...\" --description \"...\"")
        print("Tag many:  sysscan unknowns --edit   (opens known_software.toml with blank entries to fill in)")
    return 0


def cmd_retag(args: argparse.Namespace, cfg: Config) -> int:
    import json

    from sysscan.known import KnownSoftware, needs_tagging
    from sysscan.report.model import report_from_dict
    from sysscan.report.render import RENDERERS

    js = _latest_json(cfg, args.scan_id)
    if js is None:
        print("No JSON report found to update.")
        return 1
    report = report_from_dict(json.loads(js.read_text(encoding="utf-8")))
    known = KnownSoftware.load(cfg.known_software_path)
    for e in known.errors:
        print(f"! {e}")
    for c in report.changes:  # forget tags that were removed since this report was made
        if not known.find(c):
            if c.description_source == "yours":
                c.description, c.description_source = None, "none"
            if c.publisher_source == "yours":
                c.publisher, c.publisher_source = None, None
    n = known.apply(report.changes)
    report.warnings = [w for w in report.warnings if "couldn't be fully identified" not in w]
    left = sum(1 for c in report.changes if needs_tagging(c))
    if left:
        report.warnings.append(f"{left} item(s) couldn't be fully identified. Run `sysscan unknowns` to list them.")
    for fmt, fn in RENDERERS.items():
        path = js.with_suffix(f".{fmt}")
        if path.exists() or fmt == "json":
            path.write_text(fn(report), encoding="utf-8")
    print(f"Applied your tags to {n} row(s) in {js.stem}; {left} still unidentified.")
    if not args.no_open and js.with_suffix(".html").exists():
        _open(js.with_suffix(".html"))
    return 0


def cmd_schedule(args: argparse.Namespace, cfg: Config) -> int:
    from sysscan import schedule

    if args.action == "status":
        ok, msg = schedule.status()
    elif args.action == "remove":
        ok, msg = schedule.remove()
    else:
        import shlex

        extra = shlex.split(args.scan_args) if args.scan_args else []
        try:
            parse_scan_args(extra, prog="sysscan schedule install --scan-args")
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
        ok, msg = schedule.install(args.time, use_ai=args.ai, extra_args=extra)
    print(msg)
    return 0 if ok else 1


# ----------------------------------------------------------------------------- parser

def add_scan_options(s: argparse.ArgumentParser) -> None:
    """Options accepted by `sysscan scan`, and by runScan.exe (--startup / --install-startup / double-click)."""
    s.add_argument("--since", type=_parse_when, help="start of period: 2026-09-01, '2026-09-01 14:00', 7d, 12h "
                   "(default: previous scan)")
    s.add_argument("--until", type=_parse_when, help="end of period (default: now)")
    s.add_argument("--ai", dest="ai", action="store_true", default=None,
                   help="use AI (Claude or Ollama) for unknown items")
    s.add_argument("--no-ai", dest="ai", action="store_false", help="never call the AI")
    s.add_argument("--format", help="comma list of html,md,json (default from config)")
    s.add_argument("--out", help="output directory for reports")
    s.add_argument("--only", help="comma list of collectors to run")
    s.add_argument("--skip", help="comma list of collectors to skip")
    s.add_argument("--no-open", action="store_true", help="don't open the HTML report")
    s.add_argument("-q", "--quiet", action="store_true", help="no console output (for scheduled runs)")


def scan_options_from_args(args: argparse.Namespace, cfg: Config):
    from sysscan.scan import ScanOptions

    return ScanOptions(
        since=args.since, until=args.until,
        use_ai=cfg.ai.enabled if args.ai is None else args.ai,
        only=args.only.split(",") if args.only else None,
        skip=args.skip.split(",") if args.skip else None,
    )


def parse_scan_args(argv: list[str], prog: str = "runScan.exe") -> argparse.Namespace:
    """Parse scan options without exiting the process; raises ValueError with a readable message."""
    parser = argparse.ArgumentParser(prog=prog, add_help=False, exit_on_error=False)
    add_scan_options(parser)
    try:
        ns, unknown = parser.parse_known_args(argv)
    except (argparse.ArgumentError, argparse.ArgumentTypeError) as exc:
        raise ValueError(str(exc)) from exc
    if unknown:
        raise ValueError("Unrecognised option(s): " + " ".join(unknown))
    return ns


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sysscan", description="Find out what got installed, updated or "
                                "uninstalled on this PC — with plain-language explanations.")
    p.add_argument("--version", action="version", version=f"sysscan {__version__}")
    p.add_argument("--config", type=Path, help="path to config.toml")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging to sysscan.log")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="take a snapshot and report changes (default command)")
    add_scan_options(s)
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("demo", help="write a sample report from synthetic data")
    d.add_argument("--out", help="output directory")
    d.add_argument("--no-open", action="store_true")
    d.set_defaults(func=cmd_demo)

    sub.add_parser("history", help="list previous scans").set_defaults(func=cmd_history)
    o = sub.add_parser("open", help="open the latest (or a given) report")
    o.add_argument("scan_id", nargs="?", type=int)
    o.set_defaults(func=cmd_open)
    sub.add_parser("collectors", help="list data sources and whether they can run here").set_defaults(
        func=cmd_collectors)
    sub.add_parser("set-key", help="store an Anthropic API key in Windows Credential Manager").set_defaults(
        func=cmd_set_key)

    t = sub.add_parser("tag", help="identify a program yourself (overrides rules and AI)")
    t.add_argument("name", help="program name as shown in the report (or a regex with --regex)")
    t.add_argument("--publisher", help="who makes it")
    t.add_argument("--description", help="what it is, in plain language")
    t.add_argument("--routine", dest="routine", action="store_true", default=None, help="always collapse as routine")
    t.add_argument("--not-routine", dest="routine", action="store_false", help="never collapse as routine")
    t.add_argument("--regex", action="store_true", help="treat NAME as a regular expression")
    t.add_argument("--category", choices=["desktop_app", "store_app", "windows_update", "driver", "dev_package"])
    t.set_defaults(func=cmd_tag)

    ut = sub.add_parser("untag", help="remove one of your tags")
    ut.add_argument("name", help="the tagged name, or the pattern text for a --regex tag")
    ut.add_argument("--regex", action="store_true", help="only remove a pattern tag with exactly this text")
    ut.set_defaults(func=cmd_untag)

    sub.add_parser("tags", help="list your tags (known_software.toml)").set_defaults(func=cmd_tags)

    u = sub.add_parser("unknowns", help="list items the latest report couldn't identify")
    u.add_argument("scan_id", nargs="?", type=int)
    u.add_argument("--edit", action="store_true", help="add blank entries to known_software.toml and open it")
    u.set_defaults(func=cmd_unknowns)

    r = sub.add_parser("retag", help="re-apply your tags to the latest (or a given) report")
    r.add_argument("scan_id", nargs="?", type=int)
    r.add_argument("--no-open", action="store_true")
    r.set_defaults(func=cmd_retag)

    sc = sub.add_parser("schedule", help="manage the daily snapshot task (Windows Task Scheduler)")
    sc.add_argument("action", choices=["install", "remove", "status"])
    sc.add_argument("--time", default="09:00", help="daily run time, HH:MM (default 09:00)")
    sc.add_argument("--ai", action="store_true", help="scheduled scans use AI descriptions")
    sc.add_argument("--scan-args", help='extra scan options for the scheduled scan, e.g. "--format html --skip npm"')
    sc.set_defaults(func=cmd_schedule)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # `sysscan` and `sysscan --since 7d` mean `sysscan scan …`: insert the default sub-command
    # after any global options.
    commands = {"scan", "demo", "history", "open", "collectors", "set-key", "schedule", "tag", "untag", "tags",
                "unknowns", "retag"}
    i = 0
    while i < len(argv) and argv[i] in ("--config", "-v", "--verbose"):
        i += 2 if argv[i] == "--config" else 1
    if not any(a in ("-h", "--help", "--version") for a in argv[:i + 1]) and (
            i >= len(argv) or argv[i] not in commands):
        argv.insert(i, "scan")
    args = parser.parse_args(argv)
    from sysscan.envfile import load_env_files

    load_env_files()  # .env values (ANTHROPIC_API_KEY, SYSSCAN_AI, …) before config is read
    cfg = load_config(args.config)
    _setup_logging(cfg, args.verbose)
    try:
        return int(args.func(args, cfg) or 0)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        logging.getLogger("sysscan").exception("command failed")
        print(f"error: {exc} (details in {cfg.home / 'sysscan.log'})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
