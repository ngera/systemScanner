"""Device drivers: current inventory (WMI) plus install history (setupapi.dev.log).

Drivers are grouped by (provider, device class, version) — one Intel chipset update touches
twenty devices, and the report should say that once, not twenty times.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any

from sysscan.collectors.base import Collector, ScanContext
from sysscan.models import Action, Category, ChangeEvent, InventoryItem, TimeConfidence
from sysscan.winutil import run_powershell

CLASS_LABELS = {
    "display": "graphics",
    "media": "audio/media",
    "audioendpoint": "audio endpoint",
    "net": "network",
    "bluetooth": "Bluetooth",
    "system": "system devices",
    "usb": "USB",
    "hidclass": "input devices (HID)",
    "keyboard": "keyboard",
    "mouse": "mouse/touchpad",
    "diskdrive": "disk",
    "hdc": "storage controller",
    "scsiadapter": "storage controller",
    "camera": "camera",
    "image": "camera/imaging",
    "biometric": "fingerprint/biometric",
    "firmware": "firmware",
    "monitor": "monitor",
    "printqueue": "printer",
    "printer": "printer",
    "extension": "device extension",
    "softwarecomponent": "software component",
    "securitydevices": "security (TPM)",
    "sensor": "sensor",
    "battery": "battery",
    "processor": "processor",
}

_INBOX_PROVIDERS = {"microsoft", "microsoft corporation"}


def class_label(device_class: str | None) -> str:
    c = (device_class or "").strip()
    return CLASS_LABELS.get(c.lower(), c.lower() or "other")


_VERSION_OK = re.compile(r"^\d+(?:\.\d+)+$")


def group_drivers(rows: list[dict[str, Any]]) -> list[InventoryItem]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        version = str(r.get("ver") or "").strip()
        if not _VERSION_OK.match(version):
            continue  # WMI sometimes reports junk like "2:10.0,2:6.3" for pseudo-devices
        provider = str(r.get("provider") or r.get("mfr") or "Unknown").strip()
        groups[(provider, str(r.get("cls") or ""), version)].append(r)

    items: list[InventoryItem] = []
    for (provider, cls, version), members in groups.items():
        devices = sorted({str(m.get("device") or "").strip() for m in members if m.get("device")})
        label = class_label(cls)
        infs = sorted({str(m.get("inf") or "") for m in members if m.get("inf")})
        device_ids = {str(m.get("id") or "").upper(): str(m.get("device") or "") for m in members if m.get("id")}
        preview = ", ".join(devices[:4]) + (f" and {len(devices) - 4} more" if len(devices) > 4 else "")
        items.append(InventoryItem(
            key=f"drv:{provider}:{cls}:{version}",
            category=Category.DRIVER,
            source="drivers",
            name=f"{provider} {label} driver",
            version=version,
            publisher=provider,
            scope="machine",
            description=f"Used by: {preview}" if devices else None,
            extra={"devices": devices, "inf": infs, "class": cls, "device_ids": device_ids,
                   "inbox": provider.lower() in _INBOX_PROVIDERS},
        ))
    return items


# ----------------------------------------------------------------------------- setupapi.dev.log
#
# Windows 10/11 format (abridged):
#
#   >>>  [Device Install (Hardware initiated) - USB\VID_05AC&PID_12A8&MI_00\7&10950485&0&0000]
#   >>>  Section start 2026/09/21 14:49:24.091
#        utl:      Driver Node:
#        utl:           Status         - Selected
#        utl:           Driver INF     - wpdmtp.inf (C:\WINDOWS\System32\DriverStore\...\wpdmtp.inf)
#        utl:           Driver Version - 06/21/2006,10.0.26100.8521
#        utl:           Signer Score   - Inbox (0D000003)
#   <<<  [Exit status: SUCCESS]
#
#   >>>  [Driver Install (DrvSetupInstallDriver) - C:\WINDOWS\system32\drivers\gwdrv.inf]
#        inf:           Provider       = Domotz Inc
#        inf:           Driver Version = 04/28/2026,2.1.835.0
#        idb:                     Created driver INF file object 'oem41.inf' in DRIVERS database node.
#
#   >>>  [Setup Import Driver Package - ...\prnms006.inf]
#        sto: Driver package already imported as 'oem12.inf'.        <- a no-op, ignored

_SECTION_HEAD = re.compile(r"^>>>\s+\[(?P<title>.+)\]\s*$")
_SECTION_START = re.compile(r"^>>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
_EXIT = re.compile(r"^<<<\s+\[Exit status:\s*(?P<status>[A-Z_]+)")
_KV = re.compile(r"^!*\s*\w{3}:\s+(?P<key>[A-Za-z][A-Za-z ]*?)\s*[-=]\s+(?P<value>.*?)\s*$")
_NODE = re.compile(r"Driver Node:\s*$")
_CREATED_OEM = re.compile(r"Created driver INF file object '(?P<inf>[^']+)'")
_ALREADY = re.compile(r"Driver package already imported", re.I)
_LEGACY_BRACKETS = re.compile(r"^\[(.*)\]$")  # older Windows wraps values in [ ]

#: "Device Install (...)" flavours that replace the driver on an existing device rather than set up a new one.
_UPDATE_FLAVOURS = ("windows update", "diinstalldevice", "updatedriver", "update driver")


def _version_only(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if m := _LEGACY_BRACKETS.match(v):
        v = m.group(1)
    return v.split(",")[-1].strip() or None  # "06/20/2023,22.240.0.2" -> "22.240.0.2"


def iter_setupapi_sections(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    current: dict[str, Any] | None = None
    node: dict[str, str] | None = None
    for line in lines:
        if m := _SECTION_HEAD.match(line):
            current = {"title": m.group("title"), "fields": {}, "nodes": []}
            node = None
            continue
        if current is None:
            continue
        if m := _SECTION_START.match(line):
            current["start"] = m.group(1)
        elif m := _EXIT.match(line):
            current["status"] = m.group("status")
            yield current
            current = node = None
        elif _NODE.search(line):
            node = {}
            current["nodes"].append(node)
        elif m := _CREATED_OEM.search(line):
            current["fields"]["published_inf"] = m.group("inf")
        elif _ALREADY.search(line):
            current["fields"]["already_imported"] = "1"
        elif m := _KV.match(line):
            key, value = m.group("key").strip().lower(), m.group("value").strip()
            if lm := _LEGACY_BRACKETS.match(value):
                value = lm.group(1)
            if node is not None and key in ("status", "driver inf", "driver version", "signer score",
                                            "description", "inffile", "version"):
                node.setdefault(key, value)
            else:
                current["fields"].setdefault(key, value)


def _selected_node(sec: dict[str, Any]) -> dict[str, str]:
    nodes = sec.get("nodes") or []
    return next((n for n in nodes if n.get("status", "").lower() == "selected"), nodes[0] if nodes else {})


def parse_setupapi(lines: Iterable[str], since: datetime, until: datetime,
                   device_names: dict[str, tuple[str, str]] | None = None) -> list[ChangeEvent]:
    """Driver installs from setupapi.dev.log. ``device_names`` maps DEVICE-ID -> (device name, provider)."""
    device_names = device_names or {}
    out: list[ChangeEvent] = []
    for sec in iter_setupapi_sections(lines):
        if sec.get("status") != "SUCCESS" or "start" not in sec:
            continue
        local = datetime.strptime(sec["start"], "%Y/%m/%d %H:%M:%S")
        t = local.astimezone().astimezone(UTC)  # log is in local time
        if not (since <= t <= until):
            continue
        title: str = sec["title"]
        kind, _, target = title.partition(" - ")
        f = sec["fields"]
        node = _selected_node(sec)

        if kind.startswith("Device Install"):
            def get(key: str, node: dict[str, str] = node, f: dict[str, str] = f) -> str:
                return node.get(key) or f.get(key) or ""  # older Windows logs keep these outside a node

            inf = (get("driver inf") or get("inffile")).split(" (")[0]
            inf = PureWindowsPath(inf).name if inf else ""
            version = _version_only(get("driver version") or get("version"))
            if not (inf or version or get("description")):
                continue
            inbox = "inbox" in get("signer score").lower()
            dev_name, dev_provider = device_names.get(target.upper(), ("", ""))
            provider = f.get("provider") or dev_provider or ("Microsoft" if inbox else None)
            label = dev_name or get("description") or target
            is_update = any(k in kind.lower() for k in _UPDATE_FLAVOURS)
            name = (f"Windows built-in driver for {label}" if inbox else
                    f"{provider + ' ' if provider else ''}driver for {label}")
            out.append(ChangeEvent(
                category=Category.DRIVER, action=Action.UPDATED if is_update else Action.INSTALLED,
                name=name, source="setupapi", time=t, confidence=TimeConfidence.EXACT, version_to=version,
                publisher=provider,
                detail=f"setupapi.dev.log: {kind.strip()} using {inf or 'driver'} on {target}",
            ))
        elif kind.startswith(("Driver Install", "Setup Import Driver Package", "Import Driver Package")):
            if f.get("already_imported"):
                continue  # re-import of a package that's already in the store: nothing changed
            inf = PureWindowsPath(target.replace("\\\\", "\\")).name
            provider = f.get("provider")
            version = _version_only(f.get("driver version"))
            published = f.get("published_inf")
            out.append(ChangeEvent(
                category=Category.DRIVER, action=Action.INSTALLED,
                name=f"{provider + ' ' if provider else ''}driver package {inf}",
                source="setupapi", time=t, confidence=TimeConfidence.EXACT, version_to=version, publisher=provider,
                detail="setupapi.dev.log: driver package added to the driver store"
                       + (f" as {published}" if published else "") + f" ({target})",
            ))
    return out


class DriverCollector(Collector):
    name = "drivers"
    title = "Device drivers (WMI + setupapi.dev.log)"
    provides_inventory = True
    provides_events = True

    def __init__(self) -> None:
        self._device_names: dict[str, tuple[str, str]] = {}

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        script = """
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DriverVersion } | ForEach-Object {
  [pscustomobject]@{ device = $_.DeviceName; cls = $_.DeviceClass; ver = $_.DriverVersion; id = $_.DeviceID
                     provider = $_.DriverProviderName; mfr = $_.Manufacturer; inf = $_.InfName } } |
  ConvertTo-Json -Depth 3 -Compress
"""
        items = group_drivers(run_powershell(script, timeout=300))
        # Remember device IDs -> names so setupapi events (which only name the device ID) read nicely.
        for it in items:
            for dev_id, dev_name in (it.extra.get("device_ids") or {}).items():
                self._device_names[dev_id] = (dev_name, it.publisher or "")
        return items

    def events(self, ctx: ScanContext, since: datetime, until: datetime) -> list[ChangeEvent]:
        import os

        inf_dir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF"
        out: list[ChangeEvent] = []
        for log in sorted(inf_dir.glob("setupapi.dev*.log")):
            try:
                if datetime.fromtimestamp(log.stat().st_mtime, UTC) < since:
                    continue
                with log.open("r", encoding="utf-8", errors="replace") as fh:
                    out.extend(parse_setupapi(fh, since, until, self._device_names))
            except OSError:
                continue
        return out
