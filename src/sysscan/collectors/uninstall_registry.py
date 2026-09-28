"""Desktop programs from the Windows "Uninstall" registry keys (what Settings › Apps shows).

Reads all three views — 64-bit machine, 32-bit machine (WOW6432Node) and each loaded user hive
under HKEY_USERS — and records each key's **LastWriteTime**, which is often the best timestamp
available (``InstallDate`` is date-only, frequently missing, and not always refreshed on update).
"""

from __future__ import annotations

import re
from datetime import datetime

from sysscan.collectors.base import Collector, ScanContext
from sysscan.models import Category, InventoryItem, TimeConfidence
from sysscan.winutil import filetime_to_dt, parse_yyyymmdd

UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_USER_SID = re.compile(r"^S-1-5-21-[\d-]+$")
_SKIP_RELEASE_TYPES = {"update", "hotfix", "security update", "service pack"}


def pick_install_time(install_date: str | None, last_write: datetime | None
                      ) -> tuple[datetime | None, TimeConfidence]:
    """Choose the most trustworthy timestamp from InstallDate (date only) and key LastWriteTime."""
    day = parse_yyyymmdd(install_date)
    if day and last_write:
        # Same local day → the write time is a precise version of the install date.
        if last_write.astimezone().date() == day.astimezone().date():
            return last_write, TimeConfidence.FILE
        if last_write > day:
            # Key rewritten after the recorded install date: probably an update that didn't bump
            # InstallDate. The write time is the more relevant "last changed" moment.
            return last_write, TimeConfidence.FILE
        return day, TimeConfidence.DAY
    if day:
        return day, TimeConfidence.DAY
    if last_write:
        return last_write, TimeConfidence.FILE
    return None, TimeConfidence.UNKNOWN


def parse_entry(values: dict[str, object], key_name: str, key_prefix: str, scope: str,
                last_write: datetime | None) -> InventoryItem | None:
    name = str(values.get("DisplayName") or "").strip()
    if not name:
        return None
    if str(values.get("SystemComponent", "0")) == "1":
        return None
    if values.get("ParentKeyName"):
        return None  # patches/updates of another product
    if str(values.get("ReleaseType", "")).lower() in _SKIP_RELEASE_TYPES:
        return None
    install_date = str(values.get("InstallDate") or "") or None
    t, conf = pick_install_time(install_date, last_write)
    return InventoryItem(
        key=f"{key_prefix}:{key_name}",
        category=Category.DESKTOP_APP,
        source="registry",
        name=name,
        version=str(values.get("DisplayVersion") or "").strip() or None,
        publisher=str(values.get("Publisher") or "").strip() or None,
        install_time=t,
        time_confidence=conf,
        scope=scope,
        description=str(values.get("Comments") or "").strip() or None,
        extra={
            "install_date": install_date,
            "last_write": last_write.isoformat() if last_write else None,
            "install_location": values.get("InstallLocation") or None,
            "url": values.get("URLInfoAbout") or values.get("HelpLink") or values.get("URLUpdateInfo") or None,
            "msi": str(values.get("WindowsInstaller", "0")) == "1",
            "registry_key": key_name,
        },
    )


class UninstallRegistryCollector(Collector):
    name = "registry"
    title = "Installed programs (Uninstall registry)"
    provides_inventory = True

    def _read_root(self, root, path: str, access: int, prefix: str, scope: str) -> list[InventoryItem]:
        import winreg

        items: list[InventoryItem] = []
        try:
            parent = winreg.OpenKey(root, path, 0, winreg.KEY_READ | access)
        except OSError:
            return items
        with parent:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(parent, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(parent, sub, 0, winreg.KEY_READ | access) as k:
                        _, n_values, last_mod = winreg.QueryInfoKey(k)
                        values: dict[str, object] = {}
                        for j in range(n_values):
                            try:
                                vname, vdata, _ = winreg.EnumValue(k, j)
                                values[vname] = vdata
                            except OSError:
                                continue
                except OSError:
                    continue
                item = parse_entry(values, sub, prefix, scope, filetime_to_dt(last_mod))
                if item:
                    items.append(item)
        return items

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        import winreg

        items = self._read_root(winreg.HKEY_LOCAL_MACHINE, UNINSTALL, winreg.KEY_WOW64_64KEY,
                                "reg:HKLM64", "machine")
        items += self._read_root(winreg.HKEY_LOCAL_MACHINE, UNINSTALL, winreg.KEY_WOW64_32KEY,
                                 "reg:HKLM32", "machine")
        # Per-user installs (VS Code user setup, Discord, Spotify, …) for every loaded profile.
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, "") as users:
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(users, i)
                    except OSError:
                        break
                    i += 1
                    if _USER_SID.match(sid):
                        items += self._read_root(winreg.HKEY_USERS, rf"{sid}\{UNINSTALL}", 0,
                                                 f"reg:user:{sid}", "user")
        except OSError:
            pass
        return items
