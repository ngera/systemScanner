"""Developer packages that never show up in "Installed apps":
global pip packages, global npm packages, VS Code / Cursor extensions, Scoop and Chocolatey.

These collectors are cross-platform where the tool is (pip, npm, editor extensions).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sysscan.collectors.base import Collector, ScanContext
from sysscan.models import Category, InventoryItem, TimeConfidence
from sysscan.winutil import IS_WINDOWS, run_command


def created_time(path: str | Path) -> datetime | None:
    """Creation time on Windows (st_birthtime / st_ctime), mtime elsewhere."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    ts = getattr(st, "st_birthtime", None) or (st.st_ctime if IS_WINDOWS else st.st_mtime)
    return datetime.fromtimestamp(ts, UTC)


# ----------------------------------------------------------------------------- pip

def find_python_interpreters(extra: list[str]) -> list[str]:
    found: list[str] = []
    if IS_WINDOWS and shutil.which("py"):
        try:
            out = run_command(["py", "-0p"], timeout=20)
            for line in out.splitlines():
                m = re.search(r"([A-Za-z]:\\.+?python(?:w)?\.exe)\s*$", line.strip(), re.I)
                if m:
                    found.append(m.group(1))
        except Exception:
            pass
    elif not IS_WINDOWS:
        for cand in ("python3",):
            if p := shutil.which(cand):
                found.append(p)
    found += extra
    seen: set[str] = set()
    result = []
    for p in found:
        key = os.path.normcase(os.path.abspath(p))
        if key not in seen and os.path.exists(p):
            seen.add(key)
            result.append(p)
    return result


def interpreter_label(exe: str) -> str:
    """'C:\\Python312\\python.exe' -> 'Python312'; '/usr/bin/python3' -> 'python3'."""
    p = Path(exe)
    parent = p.parent.name
    if parent.lower() in ("scripts", "bin", ""):
        return p.stem
    return parent


def parse_pip_inspect(data: dict[str, Any], label: str) -> list[InventoryItem]:
    items: list[InventoryItem] = []
    for pkg in data.get("installed", []):
        meta = pkg.get("metadata", {})
        name = meta.get("name")
        if not name:
            continue
        loc = pkg.get("metadata_location")
        t = created_time(loc) if loc else None
        items.append(InventoryItem(
            key=f"pip:{label}:{name.lower()}",
            category=Category.DEV_PACKAGE,
            source="pip",
            name=f"{name} [pip · {label}]",
            version=meta.get("version"),
            publisher=meta.get("author") or None,
            install_time=t,
            time_confidence=TimeConfidence.FILE if t else TimeConfidence.UNKNOWN,
            scope="user",
            description=meta.get("summary") or None,
            extra={"package": name, "interpreter": label},
        ))
    return items


class PipCollector(Collector):
    name = "pip"
    title = "Python packages (global interpreters)"
    provides_inventory = True
    windows_only = False

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        own = os.path.normcase(os.path.abspath(sys.executable))
        for exe in find_python_interpreters(ctx.config.python_interpreters):
            if os.path.normcase(os.path.abspath(exe)) == own and exe not in ctx.config.python_interpreters:
                continue  # don't report sysscan's own environment
            try:
                out = run_command([exe, "-m", "pip", "inspect", "--disable-pip-version-check"], timeout=120)
                items += parse_pip_inspect(json.loads(out), interpreter_label(exe))
            except Exception:
                continue  # interpreter without pip, or pip < 22.2
        return items


# ----------------------------------------------------------------------------- npm -g

def parse_npm_ls(data: dict[str, Any]) -> list[InventoryItem]:
    items: list[InventoryItem] = []
    for name, info in (data.get("dependencies") or {}).items():
        path = info.get("path")
        t = created_time(path) if path else None
        items.append(InventoryItem(
            key=f"npm:{name}",
            category=Category.DEV_PACKAGE,
            source="npm",
            name=f"{name} [npm -g]",
            version=info.get("version"),
            install_time=t,
            time_confidence=TimeConfidence.FILE if t else TimeConfidence.UNKNOWN,
            scope="user",
            description=info.get("description") or None,
            extra={"package": name},
        ))
    return items


class NpmCollector(Collector):
    name = "npm"
    title = "Global npm packages"
    provides_inventory = True
    windows_only = False

    def available(self) -> tuple[bool, str]:
        return (True, "") if shutil.which("npm") else (False, "npm not found")

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        npm = shutil.which("npm")
        if not npm:
            return []
        out = run_command([npm, "ls", "-g", "--json", "--long", "--depth=0"], timeout=120)
        return parse_npm_ls(json.loads(out))


# ----------------------------------------------------------------------------- editor extensions

EDITOR_DIRS = {
    "VS Code": ".vscode/extensions",
    "VS Code Insiders": ".vscode-insiders/extensions",
    "Cursor": ".cursor/extensions",
    "Windsurf": ".windsurf/extensions",
}


def _ext_path(entry: dict[str, Any], base: Path) -> Path | None:
    loc = entry.get("location")
    if isinstance(loc, dict):
        p = loc.get("fsPath") or loc.get("path")
        if p:
            if IS_WINDOWS and re.match(r"^/[A-Za-z]:/", p):
                p = p[1:]
            return Path(p)
    if rel := entry.get("relativeLocation"):
        return base / rel
    return None


def parse_extensions(editor: str, base: Path) -> list[InventoryItem]:
    index = base / "extensions.json"
    try:
        entries = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items: list[InventoryItem] = []
    for e in entries:
        ext_id = (e.get("identifier") or {}).get("id")
        if not ext_id:
            continue
        path = _ext_path(e, base)
        display = desc = publisher = None
        if path:
            try:
                pkg = json.loads((path / "package.json").read_text(encoding="utf-8"))
                display = pkg.get("displayName")
                desc = pkg.get("description")
                publisher = pkg.get("publisher")
                if display and display.startswith("%"):
                    display = None  # localised placeholder
                if desc and desc.startswith("%"):
                    desc = None
            except (OSError, ValueError):
                pass
        ts = (e.get("metadata") or {}).get("installedTimestamp")
        t = datetime.fromtimestamp(ts / 1000, UTC) if ts else (created_time(path) if path else None)
        items.append(InventoryItem(
            key=f"ext:{editor}:{ext_id.lower()}",
            category=Category.DEV_PACKAGE,
            source="editor-extensions",
            name=f"{display or ext_id} [{editor} extension]",
            version=e.get("version"),
            publisher=publisher,
            install_time=t,
            time_confidence=TimeConfidence.FILE if t else TimeConfidence.UNKNOWN,
            scope="user",
            description=desc,
            extra={"id": ext_id, "editor": editor},
        ))
    return items


class EditorExtensionsCollector(Collector):
    name = "editor-extensions"
    title = "VS Code / Cursor / Windsurf extensions"
    provides_inventory = True
    windows_only = False

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        items: list[InventoryItem] = []
        for editor, rel in EDITOR_DIRS.items():
            base = Path.home() / rel
            if base.is_dir():
                items += parse_extensions(editor, base)
        return items


# ----------------------------------------------------------------------------- Scoop & Chocolatey

def parse_scoop_apps(apps_dir: Path, scope: str) -> list[InventoryItem]:
    items: list[InventoryItem] = []
    if not apps_dir.is_dir():
        return items
    for app in sorted(apps_dir.iterdir()):
        current = app / "current"
        manifest = current / "manifest.json"
        if app.name == "scoop" or not manifest.exists():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        version = data.get("version")
        t = created_time(app / version) if version and (app / version).exists() else created_time(manifest)
        items.append(InventoryItem(
            key=f"scoop:{scope}:{app.name}",
            category=Category.DEV_PACKAGE, source="scoop-choco", name=f"{app.name} [scoop]",
            version=version, install_time=t,
            time_confidence=TimeConfidence.FILE if t else TimeConfidence.UNKNOWN,
            scope=scope, description=data.get("description"),
        ))
    return items


def parse_choco_lib(lib_dir: Path) -> list[InventoryItem]:
    items: list[InventoryItem] = []
    if not lib_dir.is_dir():
        return items
    for pkg in sorted(lib_dir.iterdir()):
        nuspec = next(pkg.glob("*.nuspec"), None)
        if nuspec is None:
            continue
        try:
            root = ET.parse(nuspec).getroot()
        except (OSError, ET.ParseError):
            continue
        fields: dict[str, str] = {}
        for el in root.iter():
            tag = el.tag.split("}", 1)[-1]
            if tag in ("id", "version", "title", "summary", "description", "authors") and el.text:
                fields.setdefault(tag, el.text.strip())
        t = datetime.fromtimestamp(nuspec.stat().st_mtime, UTC)
        items.append(InventoryItem(
            key=f"choco:{fields.get('id', pkg.name).lower()}",
            category=Category.DEV_PACKAGE, source="scoop-choco",
            name=f"{fields.get('title') or fields.get('id') or pkg.name} [choco]",
            version=fields.get("version"), publisher=fields.get("authors"),
            install_time=t, time_confidence=TimeConfidence.FILE, scope="machine",
            description=fields.get("summary") or (fields.get("description") or "")[:300] or None,
        ))
    return items


class ScoopChocoCollector(Collector):
    name = "scoop-choco"
    title = "Scoop & Chocolatey packages"
    provides_inventory = True

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        scoop_user = Path(os.environ.get("SCOOP", Path.home() / "scoop")) / "apps"
        scoop_global = Path(os.environ.get("SCOOP_GLOBAL", r"C:\ProgramData\scoop")) / "apps"
        choco = Path(os.environ.get("ChocolateyInstall", r"C:\ProgramData\chocolatey")) / "lib"  # noqa: SIM112
        return (parse_scoop_apps(scoop_user, "user") + parse_scoop_apps(scoop_global, "machine")
                + parse_choco_lib(choco))
