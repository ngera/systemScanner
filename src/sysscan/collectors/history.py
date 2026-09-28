"""Historical evidence: Reliability Monitor, the Windows Installer event log, service
registrations and the Windows Update history.

Parsing is split from querying so the parsers can be unit-tested on any OS with captured JSON.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from sysscan.collectors.base import Collector, ScanContext
from sysscan.models import Action, Category, ChangeEvent, TimeConfidence
from sysscan.winutil import parse_iso, ps_date, run_powershell

# ----------------------------------------------------------------------------- shared MSI mapping

MSI_ACTIONS = {
    1033: Action.INSTALLED,  # "Windows Installer installed the product"
    11707: Action.INSTALLED,  # "Installation completed successfully"
    1034: Action.UNINSTALLED,  # "Windows Installer removed the product"
    11724: Action.UNINSTALLED,  # "Removal completed successfully"
    1035: Action.MODIFIED,  # "Windows Installer reconfigured the product" (repair / patch / feature change)
}
_PRODUCT_IN_MESSAGE = re.compile(r"Product:\s*(.+?)\s+--", re.I)
_PRODUCT_NAME = re.compile(r"Product Name:\s*(.+?)\.\s+Product Version", re.I)
_PRODUCT_VERSION = re.compile(r"Product Version:\s*([0-9][0-9A-Za-z.\-]*[0-9A-Za-z])", re.I)
_MANUFACTURER = re.compile(r"Manufacturer:\s*(.+?)\.\s+Installation", re.I)
_KB = re.compile(r"\b(KB\d{6,8})\b", re.I)
_TRAILING_VER = re.compile(r"\s*[-–]\s*(\d+(?:\.\d+){1,})\s*$")
_DRIVER_TITLE = re.compile(r"^[^-]{2,60} - [^-]{2,40} - \d+(?:\.\d+)+", re.I)


def _msi_from_message(message: str) -> tuple[str | None, str | None, str | None]:
    name = None
    if (m := _PRODUCT_NAME.search(message)) or (m := _PRODUCT_IN_MESSAGE.search(message)):
        name = m.group(1)
    version = m.group(1) if (m := _PRODUCT_VERSION.search(message)) else None
    maker = m.group(1) if (m := _MANUFACTURER.search(message)) else None
    return name, version, maker


# Microsoft Store updates delivered through the Windows Update agent are titled
# "<12-char Store ID>-<package family name>", e.g. "9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2".
_STORE_TITLE = re.compile(r"^(?:ApplicationSet-)?[0-9A-Z]{12}-(?P<pkg>[A-Za-z0-9][\w.\-]+)$")


def classify_update_title(title: str) -> tuple[Category, str, str | None]:
    """Return (category, display name, version) for a Windows Update history title."""
    t = title.strip()
    if m := _STORE_TITLE.match(t):
        from sysscan.normalize import prettify_package_name

        return Category.STORE_APP, prettify_package_name(m.group("pkg")), None
    if _DRIVER_TITLE.match(t) or re.search(r"\b(driver|firmware|bios|uefi)\b", t, re.I):
        version = None
        if m := _TRAILING_VER.search(t):
            version = m.group(1)
            t = t[: m.start()].strip()
        return Category.DRIVER, t, version
    kb = m.group(1).upper() if (m := _KB.search(t)) else None
    return Category.WINDOWS_UPDATE, t, kb


# ----------------------------------------------------------------------------- Reliability Monitor

def parse_reliability(rows: list[dict[str, Any]]) -> list[ChangeEvent]:
    out: list[ChangeEvent] = []
    for r in rows:
        eid = int(r.get("id") or 0)
        src = str(r.get("source") or "")
        msg = str(r.get("msg") or "")
        t = parse_iso(r.get("t"))
        product = str(r.get("product") or "").strip()
        if "WindowsUpdateClient" in src:
            if eid != 19:
                continue
            cat, name, ver = classify_update_title(product or msg)
            out.append(ChangeEvent(category=cat, action=Action.UPDATED, name=name, source="reliability",
                                   time=t, confidence=TimeConfidence.EXACT, version_to=ver,
                                   detail="Reliability Monitor: Windows Update installed successfully"))
            continue
        action = MSI_ACTIONS.get(eid)
        if action is None:
            continue
        name, version, maker = _msi_from_message(msg)
        name = product or name
        if not name:
            continue
        out.append(ChangeEvent(
            category=Category.DESKTOP_APP, action=action, name=name, source="reliability", time=t,
            confidence=TimeConfidence.EXACT,
            version_to=version if action != Action.UNINSTALLED else None,
            version_from=version if action == Action.UNINSTALLED else None,
            publisher=maker, detail=f"Reliability Monitor: event {eid}",
        ))
    return out


class ReliabilityCollector(Collector):
    name = "reliability"
    title = "Reliability Monitor records"
    provides_events = True

    def events(self, ctx: ScanContext, since: datetime, until: datetime) -> list[ChangeEvent]:
        script = f"""
$since = {ps_date(since)}; $until = {ps_date(until)}
$dmtf = [Management.ManagementDateTimeConverter]::ToDmtfDateTime($since)
Get-CimInstance -ClassName Win32_ReliabilityRecords -Filter "TimeGenerated >= '$dmtf'" |
  Where-Object {{ $_.TimeGenerated -le $until -and
                 ($_.SourceName -eq 'MsiInstaller' -or $_.SourceName -like '*WindowsUpdateClient*') }} |
  ForEach-Object {{ [pscustomobject]@{{
      t = $_.TimeGenerated.ToUniversalTime().ToString('o'); id = $_.EventIdentifier
      source = $_.SourceName; product = $_.ProductName; msg = $_.Message }} }} |
  ConvertTo-Json -Depth 3 -Compress
"""
        return parse_reliability(run_powershell(script, timeout=300))


# ----------------------------------------------------------------------------- event logs

def parse_msi_events(rows: list[dict[str, Any]]) -> list[ChangeEvent]:
    out: list[ChangeEvent] = []
    for r in rows:
        eid = int(r.get("id") or 0)
        action = MSI_ACTIONS.get(eid)
        if action is None:
            continue
        props = [str(p) for p in (r.get("props") or [])]
        msg = str(r.get("msg") or "")
        name = version = maker = None
        if eid in (1033, 1034, 1035) and len(props) >= 2:
            name, version = props[0], props[1]
            maker = props[4] if len(props) > 4 else None
            status = props[3] if len(props) > 3 else "0"
            if status not in ("0", ""):
                continue  # failed operation — nothing actually changed
        else:
            name, version, maker = _msi_from_message(" ".join(props) + " " + msg)
        if not name:
            continue
        out.append(ChangeEvent(
            category=Category.DESKTOP_APP, action=action, name=name.strip(), source="eventlog:msi",
            time=parse_iso(r.get("t")), confidence=TimeConfidence.EXACT,
            version_to=version if action != Action.UNINSTALLED else None,
            version_from=version if action == Action.UNINSTALLED else None,
            publisher=maker, detail=f"Application log, MsiInstaller event {eid}"
                                    + (f" (user {r['user']})" if r.get("user") else ""),
        ))
    return out


def parse_service_events(rows: list[dict[str, Any]]) -> list[ChangeEvent]:
    out: list[ChangeEvent] = []
    for r in rows:
        props = [str(p) for p in (r.get("props") or [])]
        if not props:
            continue
        svc = props[0]
        image = props[1] if len(props) > 1 else ""
        stype = props[2].lower() if len(props) > 2 else ""
        kernel = "kernel" in stype or "file system" in stype or image.lower().endswith(".sys")
        out.append(ChangeEvent(
            category=Category.DRIVER if kernel else Category.DESKTOP_APP,
            action=Action.INSTALLED,
            name=f"{svc} ({'kernel driver' if kernel else 'service'})",
            source="eventlog:service", time=parse_iso(r.get("t")), confidence=TimeConfidence.EXACT,
            detail=f"System log 7045: service registered → {image}",
        ))
    return out


class EventLogCollector(Collector):
    name = "eventlog"
    title = "Windows Installer & service-install events"
    provides_events = True

    def events(self, ctx: ScanContext, since: datetime, until: datetime) -> list[ChangeEvent]:
        common = f"StartTime={ps_date(since)}; EndTime={ps_date(until)}"
        body = """ | ForEach-Object { [pscustomobject]@{
      t = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id
      props = @($_.Properties | ForEach-Object { "$($_.Value)" })
      msg = $_.Message; user = "$($_.UserId)" } } | ConvertTo-Json -Depth 4 -Compress"""
        # Get-WinEvent throws "No events were found" when nothing matches; treat that as an empty result.
        def query(filter_: str) -> str:
            return ("$ev = @(); try { $ev = @(Get-WinEvent -ErrorAction Stop -FilterHashtable @{" + filter_
                    + "}) } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }; "
                    "$ev" + body)

        msi = run_powershell(query(
            f"LogName='Application'; ProviderName='MsiInstaller'; Id=1033,1034,1035,11707,11724; {common}"))
        svc = run_powershell(query(
            f"LogName='System'; ProviderName='Service Control Manager'; Id=7045; {common}"))
        return parse_msi_events(msi) + parse_service_events(svc)


# ----------------------------------------------------------------------------- Windows Update

WU_RESULT_OK = {2, 3}  # succeeded, succeeded with errors


def parse_wu_history(rows: list[dict[str, Any]], since: datetime, until: datetime) -> list[ChangeEvent]:
    out: list[ChangeEvent] = []
    for r in rows:
        title = str(r.get("title") or "").strip()
        t = parse_iso(r.get("t"))
        if not title or t is None or not (since <= t <= until):
            continue
        if int(r.get("rc") or 0) not in WU_RESULT_OK:
            continue
        op = int(r.get("op") or 1)
        cat, name, ver = classify_update_title(title)
        action = Action.UNINSTALLED if op == 2 else Action.UPDATED
        client = str(r.get("client") or "").strip()
        out.append(ChangeEvent(
            category=cat, action=action, name=name, source="windows-update", time=t,
            confidence=TimeConfidence.EXACT,
            version_to=ver if action != Action.UNINSTALLED else None,
            version_from=ver if action == Action.UNINSTALLED else None,
            description=str(r.get("desc") or "").strip() or None,
            detail="Windows Update history" + (f" (via {client})" if client else ""),
        ))
    return out


class WindowsUpdateCollector(Collector):
    name = "windows-update"
    title = "Windows Update history (incl. drivers & Defender)"
    provides_events = True

    def events(self, ctx: ScanContext, since: datetime, until: datetime) -> list[ChangeEvent]:
        script = """
$s = New-Object -ComObject Microsoft.Update.Session
$q = $s.CreateUpdateSearcher()
$n = $q.GetTotalHistoryCount()
$rows = @()
if ($n -gt 0) {
  $rows = $q.QueryHistory(0, $n) | ForEach-Object { [pscustomobject]@{
      t = ([datetime]::SpecifyKind($_.Date, 'Utc')).ToString('o'); title = $_.Title
      desc = $_.Description; op = [int]$_.Operation; rc = [int]$_.ResultCode
      client = $_.ClientApplicationID } }
}
$rows | ConvertTo-Json -Depth 3 -Compress
"""
        return parse_wu_history(run_powershell(script, timeout=300), since, until)
