"""Heuristics for whether a folder is safe to clear when reclaiming disk space.

Advice is deliberately conservative: ``safe`` means low risk of breaking Windows or
installed apps; ``caution`` means review / partial cleanup; ``keep`` means leave alone.
Unknown folders are marked ``unknown`` so the report never pretends certainty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# safety: safe | caution | keep | unknown
SAFETY_LABELS = {
    "safe": "Safe to clear",
    "caution": "Review first",
    "keep": "Do not delete",
    "unknown": "Unknown — review",
}

# Patterns match a normalised full path (lowercase, / separators, no trailing slash).
# First match wins. Prefer more specific paths before broad name-only rules.
_RULES: list[tuple[re.Pattern[str], str, str]] = [
    # --- Windows drive roots ---
    (r"(^|/)windows$", "keep",
     "Windows itself. Never delete."),
    (r"(^|/)program files( \(x86\))?$", "keep",
     "Installed programs. Uninstall via Settings → Apps, not by deleting this folder."),
    (r"(^|/)programdata$", "keep",
     "Shared app data. Do not delete the whole folder — run `sysscan folders` on it to find caches."),
    (r"(^|/)users$", "keep",
     "User profiles and documents. Never delete."),
    (r"(^|/)\$recycle\.bin$", "caution",
     "Recycle Bin. Empty it from the Recycle Bin icon; don’t delete the folder."),
    (r"(^|/)system volume information$", "keep",
     "System restore / indexing data. Leave it alone."),
    (r"(^|/)boot$", "keep",
     "Boot files. Never delete."),
    (r"(^|/)efi$", "keep",
     "Firmware boot files. Never delete."),
    (r"(^|/)recovery$", "caution",
     "OEM reset scripts and old factory logs. Clearing OEM\\Logs frees most space; "
     "deleting the whole folder can weaken HP/OEM “Reset this PC”. WinRE is on a separate partition."),
    (r"(^|/)perflogs$", "safe",
     "Performance logs. Windows recreates them as needed."),
    (r"(^|/)inetpub$", "caution",
     "IIS / web server files. Only remove if you don’t use IIS."),
    (r"(^|/)xboxgames$", "caution",
     "Xbox / PC Game Pass installs. Remove games from the Xbox app instead of deleting the folder."),
    (r"(^|/)msocache$", "safe",
     "Office installation cache. Safe to remove after Office is installed (Office may need the DVD/ISO to repair)."),
    (r"(^|/)config\.msi$", "caution",
     "Pending MSI install/uninstall data. Leave unless an install is stuck."),
    (r"(^|/)windows\.old$", "caution",
     "Previous Windows install. Removable via Disk Cleanup → “Previous Windows installation(s)” after you’re sure you won’t roll back."),
    (r"(^|/)\$windows\.~(bt|ws)$", "caution",
     "Windows upgrade leftovers. Removable via Disk Cleanup after a successful upgrade."),
    (r"(^|/)temp$", "safe",
     "Temporary files. Close apps first; skip files that are in use."),
    (r"(^|/)tmp$", "safe",
     "Temporary files. Close apps first; skip files that are in use."),
    # --- ProgramData children ---
    (r"/programdata/microsoft$", "keep",
     "Includes Defender definitions and Visual Studio caches. Do not delete. "
     "Reclaim VS space via Visual Studio Installer → Delete Installer Cache."),
    (r"/programdata/package cache$", "caution",
     "Installer caches used for Repair/Modify. Don’t wipe wholesale; reclaim via each product’s installer."),
    (r"/programdata/nvidia corporation$", "caution",
     "Often mostly Downloader (cached drivers). Clearing Downloader is usually safe after drivers are installed."),
    (r"/programdata/nvidia$", "caution",
     "NGX/DLSS cache. Usually safe to clear; games regenerate it."),
    (r"/programdata/mcafee$", "caution",
     "Leftover only if McAfee is gone — uninstall with McAfee’s removal tool first, then delete."),
    (r"/programdata/glasswire$", "keep",
     "GlassWire app data. Remove only after uninstalling GlassWire."),
    (r"/programdata/usoshared$", "caution",
     "Windows Update shared data. Logs under Logs can be cleared; keep the folder."),
    (r"/programdata/usoprivate$", "keep",
     "Windows Update private state. Leave it."),
    (r"/programdata/adobe$", "caution",
     "Adobe shared data. Only remove if Adobe apps are uninstalled."),
    (r"/programdata/(apple|apple inc|apple computer)$", "caution",
     "Apple software leftovers. Safe if iTunes/Apple apps are uninstalled."),
    (r"/programdata/riot games$", "caution",
     "Riot Games data. Safe if those games are uninstalled."),
    (r"/programdata/dockerdesktop$", "caution",
     "Docker Desktop leftovers. Safe if Docker is uninstalled."),
    (r"/programdata/temp$", "safe",
     "ProgramData temp files. Usually safe to clear."),
    # --- Common cache / temp names anywhere ---
    (r"/(temp|tmp|temporary files|temporary internet files)$", "safe",
     "Temporary files. Close apps first; skip locked files."),
    (r"/(cache|caches|code cache|gpuCACHE|shadercache)$", "safe",
     "App cache. Usually safe; the app rebuilds it."),
    (r"/crashdumps?$", "safe",
     "Crash dump files. Safe to delete."),
    (r"/downloaded installations$", "safe",
     "Cached installers. Safe after the software is installed."),
    (r"/installer cache$", "caution",
     "Installer cache. May be needed for Repair."),
    (r"/deliveryoptimization$", "caution",
     "Windows Update delivery cache. Can be cleared via Disk Cleanup / Settings."),
]


@dataclass(frozen=True)
class FolderAdvice:
    safety: str  # safe | caution | keep | unknown
    reason: str
    source: str = "rule"  # rule | ai | ai-low | unknown
    kind: str | None = None  # windows | app | cache | logs | user_data | oem | developer | other

    @property
    def label(self) -> str:
        return SAFETY_LABELS.get(self.safety, SAFETY_LABELS["unknown"])


_COMPILED = [(re.compile(p, re.I), safety, reason) for p, safety, reason in _RULES]

_UNKNOWN = FolderAdvice(
    "unknown",
    "No built-in rule for this folder. Check what created it before deleting.",
    source="unknown",
)


def _norm(path: Path) -> str:
    s = str(path).replace("\\", "/").lower().rstrip("/")
    # Collapse duplicate slashes
    while "//" in s:
        s = s.replace("//", "/")
    return s


def classify_folder(path: Path) -> FolderAdvice:
    """Return deletion/cleanup advice for a folder path."""
    n = _norm(path)
    for rx, safety, reason in _COMPILED:
        if rx.search(n):
            return FolderAdvice(safety, reason)
    return _UNKNOWN
