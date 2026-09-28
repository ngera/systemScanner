"""Render a Report to HTML, Markdown and JSON."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sysscan.models import Action, Change
from sysscan.report.model import ACTION_ORDER, Report

TEMPLATES = Path(__file__).resolve().parent / "templates"

SOURCE_LABELS = {"rule": "built-in", "publisher": "publisher", "ai": "AI", "ai-low": "AI · unsure",
                 "ai-web": "AI + web", "ai-web-low": "AI + web · unsure", "yours": "yours", "none": ""}


def fmt_dt(dt: datetime | None) -> str:
    if not dt:
        return ""
    local = dt.astimezone()
    return f"{local:%a %d %b %Y, %H:%M}"


def fmt_d(dt: datetime | None) -> str:
    return f"{dt.astimezone():%a %d %b %Y}" if dt else ""


def iso_day(dt: datetime | None) -> str:
    """Local calendar date as YYYY-MM-DD, used by the HTML date filter."""
    return f"{dt.astimezone():%Y-%m-%d}" if dt else ""


def date_span(c: Change) -> tuple[str, str]:
    """(first, last) local day the change could have happened on. Exact times give one day;
    'between scans' changes give the whole window, so a date filter matches if it overlaps."""
    if c.time:
        return iso_day(c.time), iso_day(c.time)
    if c.window_start and c.window_end:
        return iso_day(c.window_start), iso_day(c.window_end)
    return "", ""


def sort_key(c: Change) -> str:
    t = c.time or c.window_end or c.window_start
    return t.isoformat() if t else ""


def _env() -> Environment:
    # FileSystemLoader (not PackageLoader) so templates also resolve inside the PyInstaller-built runScan.exe.
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)),
                      autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)
    env.filters["dt"] = fmt_dt
    env.filters["d"] = fmt_d
    env.filters["iso_day"] = iso_day
    env.globals["source_label"] = lambda s: SOURCE_LABELS.get(s or "none", s or "")
    env.globals["date_span"] = date_span
    env.globals["sort_key"] = sort_key
    from sysscan.known import needs_tagging, tag_command

    env.globals["needs_tagging"] = needs_tagging
    env.globals["tag_command"] = tag_command
    return env


def render_html(report: Report) -> str:
    return _env().get_template("report.html.j2").render(r=report, actions=ACTION_ORDER)


# ----------------------------------------------------------------------------- Markdown

def _md_escape(s: str | None) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _md_version(c: Change) -> str:
    if c.action == Action.UPDATED and c.version_from and c.version_to:
        return f"{c.version_from} → {c.version_to}"
    if c.action == Action.UNINSTALLED:
        return c.version_from or ""
    return c.version_to or c.version_from or ""


def _md_when(c: Change) -> str:
    if c.time:
        return (fmt_d(c.time) if c.confidence.value == "day" else fmt_dt(c.time)) + f" ({c.confidence.label})"
    if c.window_start and c.window_end:
        return f"{fmt_d(c.window_start)} – {fmt_d(c.window_end)} (between scans)"
    return "unknown"


def _md_rows(changes: list[Change]) -> list[str]:
    lines = ["| Name | Type | Provider | Version | When | What it is |", "|---|---|---|---|---|---|"]
    for c in changes:
        desc = _md_escape(c.description) or "_No description available._"
        src = SOURCE_LABELS.get(c.description_source or "none", "")
        if src and c.description:
            desc += f" _({src})_"
        times = f" ×{c.occurrences}" if c.occurrences > 1 else ""
        lines.append(f"| **{_md_escape(c.name)}**{times} | {c.category.short_label} | {_md_escape(c.provider)}"
                     f"{' _(AI)_' if c.publisher_source == 'ai' else ''} | "
                     f"{_md_escape(_md_version(c))} | {_md_when(c)} | {desc} |")
    return lines


def render_markdown(report: Report) -> str:
    out = [f"# What changed on {report.host}", "",
           f"**Period:** {fmt_dt(report.period_start)} → {fmt_dt(report.period_end)}  ",
           f"**Generated:** {fmt_dt(report.generated_at)}"
           + (f" · compared with snapshot from {fmt_dt(report.baseline_at)}" if report.baseline_at else ""),
           "", "| " + " | ".join(a.label for a in ACTION_ORDER) + " |",
           "|" + "---|" * len(ACTION_ORDER),
           "| " + " | ".join(
               f"{report.count(a, False)}" + (f" (+{report.count(a) - report.count(a, False)} routine)"
                                              if report.count(a) != report.count(a, False) else "")
               for a in ACTION_ORDER) + " |", ""]
    if report.warnings:
        out += ["> **Good to know**", ">"] + [f"> - {w}" for w in report.warnings] + [""]
    sections = report.sections()
    if not sections:
        out.append("_Nothing was installed, updated or removed in this period._")
    for s in sections:
        out += [f"## {s.action.label} ({s.total})", "", f"_{s.blurb}_", ""]
        if s.items:
            out += _md_rows(s.items) + [""]
        if s.routine:
            out += [f"<details><summary>{len(s.routine)} routine items</summary>", ""]
            out += _md_rows(s.routine) + ["", "</details>", ""]
    out += ["---", "", "| Source | Status | Items | Events |", "|---|---|---|---|"]
    for st in report.collector_status:
        status = "ok" if st.ok else "not used"
        if st.message:
            status += f" — {_md_escape(st.message)}"
        out.append(f"| {st.name} | {status} | {st.items or ''} | {st.events or ''} |")
    out += ["", f"_sysscan {report.tool_version}_", ""]
    return "\n".join(out)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


RENDERERS = {"html": render_html, "md": render_markdown, "json": render_json}


def write_reports(report: Report, out_dir: Path, formats: list[str]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.astimezone().strftime("%Y-%m-%d_%H%M%S")
    written: dict[str, Path] = {}
    for fmt in formats:
        fn = RENDERERS.get(fmt)
        if fn is None:
            continue
        path = out_dir / f"sysscan_{stamp}.{fmt}"
        path.write_text(fn(report), encoding="utf-8")
        written[fmt] = path
    return written
