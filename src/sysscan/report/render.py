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
    from sysscan.known import ps_quote

    env.globals["ps_quote"] = ps_quote
    from sysscan.security.ai_lookup import VERDICT_LABEL
    from sysscan.security.probe import signer_name

    env.globals["signer_name"] = signer_name
    env.globals["verdict_label"] = lambda v: VERDICT_LABEL.get(v or "unknown", v)
    env.globals["facts_for"] = _facts_for
    return env


def render_html(report: Report) -> str:
    return _env().get_template("report.html.j2").render(r=report, actions=ACTION_ORDER)


def render_folders_html(report) -> str:
    from sysscan.foldersize import human_size

    env = _env()
    env.filters["human"] = human_size
    return env.get_template("folders.html.j2").render(
        r=report,
        total_human=human_size(report.total_bytes),
        safe_human=human_size(report.bytes_for("safe")),
        caution_human=human_size(report.bytes_for("caution")),
        keep_human=human_size(report.bytes_for("keep")),
        safety_rank={"safe": 0, "caution": 1, "unknown": 2, "keep": 3},
    )


def render_folders_markdown(report) -> str:
    from sysscan.foldersize import human_size

    total = report.total_bytes
    lines = [
        f"# Folder sizes on {report.host}",
        "",
        f"**Root:** `{report.root}` (level 1)  ",
        f"**Generated:** {fmt_dt(report.generated_at)}  ",
        f"**Total:** {human_size(total)} across {len(report.folders)} folders  ",
        f"**Safe to clear:** {human_size(report.bytes_for('safe'))} · "
        f"**Review first:** {human_size(report.bytes_for('caution'))} · "
        f"**Do not delete:** {human_size(report.bytes_for('keep'))}",
        "",
        "| Folder | Size | Share | Advice | Why |",
        "|---|---|---|---|---|",
    ]
    for f in report.folders:
        pct = f.pct_of(total)
        label = f.advice.label if f.advice else "Unknown"
        reason = f.advice.reason if f.advice else ""
        src = ""
        if f.advice and f.advice.source.startswith("ai"):
            src = " _(AI)_"
        kind = f" [{f.advice.kind}]" if f.advice and f.advice.kind else ""
        lines.append(
            f"| **{_md_escape(f.name)}** | {human_size(f.bytes)} | {pct:.1f}% "
            f"| {_md_escape(label)}{src}{kind} | {_md_escape(reason)} |"
        )
    lines += ["", f"_sysscan {report.tool_version} — advice is guidance only_", ""]
    return "\n".join(lines)


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


def _verdict(v: str | None) -> str:
    from sysscan.security.ai_lookup import VERDICT_LABEL

    return VERDICT_LABEL.get(v or "unknown", v or "unknown")


def signer_name(subject: str) -> str:
    from sysscan.security.probe import signer_name as _sn

    return _sn(subject)


def _facts_for(finding, path: str):
    for fi in finding.files:
        if str(fi.get("path", "")).lower() == str(path).lower():
            return fi
    return None


SEC_ICON = {"alert": "🔴", "warn": "⚠️", "ok": "✅", "info": "ℹ️"}


def _md_security(sec) -> list[str]:
    out = ["## Remote access & monitoring", "",
           f"Checked {fmt_dt(sec.checked_at)}" + (f", session history since {fmt_d(sec.since)}" if sec.since else "")
           + (f"; compared with the check on {fmt_dt(sec.previous_at)}" if sec.previous_at else "") + ".", "",
           f"**{sec.count('alert')}** to investigate · **{sec.count('warn')}** worth a look · "
           f"**{sec.count('ok')}** fine", ""]
    if sec.new:
        out += ["> **New since the last check**", ">"] + [f"> - {SEC_ICON.get(f.status, '')} {_md_escape(f.title)}"
                                                         for f in sec.new] + [""]
    if sec.resolved:
        out += ["**Gone since last time:** " + "; ".join(_md_escape(f.title) for f in sec.resolved), ""]
    for _area, label, items in sec.by_area():
        out += [f"### {label}", ""]
        for f in items:
            icon = "☑️" if f.trusted else SEC_ICON.get(f.status, "")
            flags = (" **NEW**" if f.new else "") + (f" _(trusted: {_md_escape(f.trust_note)})_" if f.trusted else "")
            out.append(f"- {icon} **{_md_escape(f.title)}**{flags} — {_md_escape(f.explanation)}")
            for ai in f.ai_results:
                out.append(f"  - **AI ({_md_escape(ai.get('file') or '')}): {_verdict(ai.get('verdict'))}**, "
                           f"{ai.get('confidence', '?')} confidence — {_md_escape(ai.get('what') or '')}"
                           + (f" Why: {_md_escape(ai.get('why') or '')}" if ai.get("why") else ""))
                for a in ai.get("advice") or []:
                    out.append(f"    - {_md_escape(a)}")
                if ai.get("sources"):
                    out.append("    - Sources: " + " · ".join(ai["sources"]))
            for e in f.evidence[:10]:
                out.append(f"  - {_md_escape(e)}")
            if f.status in ("alert", "warn"):
                for p in f.paths:
                    fi = _facts_for(f, p) or {}
                    bits = []
                    if fi.get("sig_status"):
                        bits.append(f"signed by {signer_name(fi.get('signer', ''))}" if fi["sig_status"] == "Valid"
                                    else f"NOT validly signed ({fi['sig_status']})")
                    if fi.get("sha256"):
                        bits.append(f"SHA-256 `{fi['sha256']}` ([VirusTotal](https://www.virustotal.com/gui/file/"
                                    f"{str(fi['sha256']).lower()}))")
                    out.append(f"  - path: `{p}`" + (f" — {'; '.join(bits)}" if bits else ""))
                for loc in f.locations:
                    out.append(f"  - where: `{loc}`")
            if f.fix and not f.trusted:
                out.append("  - **How to fix** (PowerShell as administrator; read each command first):")
                for i, st in enumerate(f.fix, 1):
                    out.append(f"    {i}. {_md_escape(st['text'])}" + (f" `{st['cmd']}`" if st.get("cmd") else ""))
            if f.status in ("alert", "warn") and not f.trusted:
                out.append(f"  - trust it: `sysscan trust '{f.key}' --note ''`")
        out.append("")
    if sec.errors:
        out += ["<details><summary>Some checks couldn't run fully</summary>", ""]
        out += [f"- {_md_escape(e)}" for e in sec.errors] + ["", "</details>", ""]
    if sec.ai or sec.ai_notes:
        out += [(f"_AI lookup: {sec.ai}. Only facts about flagged files were sent._ " if sec.ai else "")
                + " ".join(_md_escape(n) for n in sec.ai_notes), ""]
    out += ["_No tool can prove a PC is clean. If you suspect a problem, also run a Microsoft Defender Offline scan "
            "and change important passwords from another device._", ""]
    return out


def render_markdown(report: Report) -> str:
    if report.mode == "security":
        out = [f"# Remote access & monitoring check on {report.host}", ""]
        if report.security:
            out += _md_security(report.security)
        out += [f"_sysscan {report.tool_version}_", ""]
        return "\n".join(out)
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
    if report.security and report.security.count("alert"):
        out += _md_security(report.security)
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
    if report.security and not report.security.count("alert"):
        out += _md_security(report.security)
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


def write_reports(report: Report, out_dir: Path, formats: list[str], prefix: str = "sysscan") -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.astimezone().strftime("%Y-%m-%d_%H%M%S")
    written: dict[str, Path] = {}
    for fmt in formats:
        fn = RENDERERS.get(fmt)
        if fn is None:
            continue
        path = out_dir / f"{prefix}_{stamp}.{fmt}"
        path.write_text(fn(report), encoding="utf-8")
        written[fmt] = path
    return written
