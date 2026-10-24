"""Level-1 folder sizes under a configurable root (default ``C:\\``).

Walks only the immediate children of the root and reports each child's total
on-disk size (recursive). Symlinks / junctions are not followed. Permission
errors are skipped so a scan of ``C:\\`` still returns what it can.
"""

from __future__ import annotations

import json
import os
import platform
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sysscan import __version__
from sysscan.folderadvice import FolderAdvice, classify_folder
from sysscan.winutil import utcnow

DEFAULT_FOLDER_ROOT = r"C:\\"


@dataclass(frozen=True)
class FolderSize:
    path: Path
    bytes: int
    errors: int = 0  # files/dirs we couldn't read
    advice: FolderAdvice | None = None

    @property
    def name(self) -> str:
        return self.path.name or str(self.path)

    @property
    def safety(self) -> str:
        return self.advice.safety if self.advice else "unknown"

    def pct_of(self, total: int) -> float:
        return (100.0 * self.bytes / total) if total > 0 else 0.0

    def with_advice(self) -> FolderSize:
        return FolderSize(self.path, self.bytes, self.errors, classify_folder(self.path))


@dataclass
class FolderReport:
    host: str
    root: Path
    generated_at: datetime
    folders: list[FolderSize]
    tool_version: str = __version__

    @property
    def total_bytes(self) -> int:
        return sum(f.bytes for f in self.folders)

    def bytes_for(self, safety: str) -> int:
        return sum(f.bytes for f in self.folders if f.safety == safety)

    def count_for(self, safety: str) -> int:
        return sum(1 for f in self.folders if f.safety == safety)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "root": str(self.root),
            "generated_at": self.generated_at.isoformat(),
            "tool_version": self.tool_version,
            "total_bytes": self.total_bytes,
            "safe_bytes": self.bytes_for("safe"),
            "caution_bytes": self.bytes_for("caution"),
            "folders": [
                {"path": str(f.path), "name": f.name, "bytes": f.bytes,
                 "human": human_size(f.bytes), "errors": f.errors,
                 "pct": round(f.pct_of(self.total_bytes), 2),
                 "safety": f.safety,
                 "advice": f.advice.reason if f.advice else None,
                 "advice_label": f.advice.label if f.advice else None,
                 "advice_source": f.advice.source if f.advice else None,
                 "kind": f.advice.kind if f.advice else None}
                for f in self.folders
            ],
        }


def human_size(n: int) -> str:
    """Format a byte count for display (binary units)."""
    if n < 0:
        n = 0
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    size = float(n)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{n} B"


def resolve_folder_root(cli_path: str | None = None, env: dict[str, str] | None = None) -> Path:
    """CLI path wins, then ``SYSSCAN_FOLDER_ROOT``, then ``C:\\``."""
    import os as _os

    environ = env if env is not None else _os.environ
    raw = (cli_path or environ.get("SYSSCAN_FOLDER_ROOT") or DEFAULT_FOLDER_ROOT).strip().strip('"')
    return Path(raw).expanduser()


def dir_size(path: Path) -> tuple[int, int]:
    """Return ``(total_bytes, error_count)`` for ``path``, not following reparse points."""
    total = 0
    errors = 0
    try:
        for root, dirnames, filenames in os.walk(path, topdown=True, followlinks=False, onerror=lambda _e: None):
            # Drop entries we can't stat / that are reparse points so we don't descend into junctions.
            keep: list[str] = []
            for name in dirnames:
                child = Path(root) / name
                try:
                    st = child.lstat()
                except OSError:
                    errors += 1
                    continue
                if _is_reparse(st):
                    continue
                keep.append(name)
            dirnames[:] = keep
            for name in filenames:
                fp = Path(root) / name
                try:
                    st = fp.lstat()
                except OSError:
                    errors += 1
                    continue
                if _is_reparse(st):
                    continue
                total += st.st_size
    except OSError:
        errors += 1
    return total, errors


def _is_reparse(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0) or 0
    # FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    return bool(attrs & 0x400)


def level1_folder_sizes(root: Path, *, progress: Callable[[str], None] | None = None) -> list[FolderSize]:
    """Size of each immediate subdirectory of ``root`` (largest first)."""
    if not root.exists():
        raise FileNotFoundError(f"folder not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"not a folder: {root}")

    children: list[Path] = []
    try:
        with os.scandir(root) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        children.append(Path(entry.path))
                except OSError:
                    continue
    except OSError as exc:
        raise PermissionError(f"cannot list {root}: {exc}") from exc

    children.sort(key=lambda p: p.name.lower())
    out: list[FolderSize] = []
    for i, child in enumerate(children, 1):
        if progress:
            progress(f"[{i}/{len(children)}] {child}")
        nbytes, errs = dir_size(child)
        out.append(FolderSize(path=child, bytes=nbytes, errors=errs).with_advice())
    out.sort(key=lambda f: (-f.bytes, f.path.name.lower()))
    return out


def format_report(root: Path, rows: list[FolderSize]) -> str:
    if not rows:
        return f"No subfolders under {root}"
    name_w = max(len(str(r.path)) for r in rows)
    size_w = max(len(human_size(r.bytes)) for r in rows)
    lines = [f"Folder sizes under {root} (level 1)", ""]
    total = 0
    for r in rows:
        total += r.bytes
        tag = f"[{r.advice.label}] " if r.advice else ""
        note = f"  ({r.errors} access error{'s' if r.errors != 1 else ''})" if r.errors else ""
        lines.append(f"{human_size(r.bytes):>{size_w}}  {tag}{str(r.path):<{name_w}}{note}")
    lines += ["", f"{human_size(total):>{size_w}}  TOTAL ({len(rows)} folders)"]
    return "\n".join(lines)


def build_folder_report(root: Path, rows: list[FolderSize], *, host: str | None = None) -> FolderReport:
    advised = [r if r.advice else r.with_advice() for r in rows]
    return FolderReport(
        host=host or platform.node() or "localhost",
        root=root,
        generated_at=utcnow(),
        folders=advised,
    )


def write_folder_reports(report: FolderReport, out_dir: Path, formats: list[str]) -> dict[str, Path]:
    """Write folder-size report files (html / json / md). Returns format → path."""
    from sysscan.report.render import render_folders_html, render_folders_markdown

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.astimezone().strftime("%Y-%m-%d_%H%M%S")
    written: dict[str, Path] = {}
    renderers = {
        "html": render_folders_html,
        "md": render_folders_markdown,
        "json": lambda r: json.dumps(r.to_dict(), indent=2, ensure_ascii=False),
    }
    for fmt in formats:
        fn = renderers.get(fmt)
        if fn is None:
            continue
        path = out_dir / f"folders_{stamp}.{fmt}"
        path.write_text(fn(report), encoding="utf-8")
        written[fmt] = path
    return written
