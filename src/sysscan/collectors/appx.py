"""Microsoft Store / MSIX (AppX) packages for the current user."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from sysscan.collectors.base import Collector, ScanContext
from sysscan.models import Category, InventoryItem, TimeConfidence
from sysscan.normalize import prettify_package_name
from sysscan.winutil import parse_iso, run_powershell

_NS = re.compile(r"^\{[^}]+\}")


def read_manifest(install_location: str | None) -> tuple[str | None, str | None, str | None]:
    """Return (DisplayName, Description, PublisherDisplayName) from AppxManifest.xml,
    skipping ms-resource: indirections."""
    if not install_location:
        return None, None, None
    path = Path(install_location) / "AppxManifest.xml"
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None, None, None
    display = desc = pub = None
    for el in root.iter():
        tag = _NS.sub("", el.tag)
        if tag == "Properties":
            for child in el:
                ctag = _NS.sub("", child.tag)
                text = (child.text or "").strip()
                if not text or text.lower().startswith("ms-resource:"):
                    continue
                if ctag == "DisplayName":
                    display = text
                elif ctag == "Description":
                    desc = text
                elif ctag == "PublisherDisplayName":
                    pub = text
            break
    return display, desc, pub


def parse_packages(rows: list[dict[str, Any]], read_manifests: bool = True) -> list[InventoryItem]:
    items: list[InventoryItem] = []
    for r in rows:
        full = str(r.get("full") or "")
        parts = full.split("_")
        if len(parts) < 5:
            continue
        pkg_name, _version, arch, _res, pub_id = parts[:5]
        display, desc, pub_display = read_manifest(r.get("loc")) if read_manifests else (None, None, None)
        created = parse_iso(r.get("created"))
        items.append(InventoryItem(
            key=f"appx:{pkg_name}_{arch}_{pub_id}",
            category=Category.STORE_APP,
            source="appx",
            name=display or prettify_package_name(pkg_name),
            version=str(r.get("ver") or "") or None,
            publisher=pub_display or _publisher_cn(str(r.get("pub") or "")),
            install_time=created,
            time_confidence=TimeConfidence.FILE if created else TimeConfidence.UNKNOWN,
            scope="user",
            description=desc,
            extra={"package": pkg_name, "arch": arch, "framework": bool(r.get("fw")),
                   "signature": r.get("sig")},
        ))
    return items


def _publisher_cn(dn: str) -> str | None:
    m = re.search(r"(?:^|,\s*)(?:CN|O)=\"?([^\",]+)", dn)
    return m.group(1).strip() if m else (dn or None)


class AppxCollector(Collector):
    name = "appx"
    title = "Microsoft Store / MSIX apps"
    provides_inventory = True

    def inventory(self, ctx: ScanContext) -> list[InventoryItem]:
        # The install folder is version-specific, so its creation time = when this version arrived.
        script = """
Get-AppxPackage | ForEach-Object {
  $c = $null
  try { $c = (Get-Item -LiteralPath $_.InstallLocation -ErrorAction Stop).CreationTimeUtc.ToString('o') } catch {}
  [pscustomobject]@{ full = $_.PackageFullName; ver = "$($_.Version)"; pub = $_.Publisher
                     fw = [bool]$_.IsFramework; sig = "$($_.SignatureKind)"; loc = $_.InstallLocation
                     created = $c } } | ConvertTo-Json -Depth 3 -Compress
"""
        return parse_packages(run_powershell(script, timeout=300))
