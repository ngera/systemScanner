"""Name normalisation so the same product matches across sources and versions.

"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810" and
"Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433" must normalise to the same
key (so a version bump reads as an *update*), while "(x64)" vs "(x86)" collapse too — they are
the same product as far as a human reader is concerned.
"""

from __future__ import annotations

import re

_PARENS_NOISE = re.compile(
    r"\((?:x64|x86|amd64|arm64|64[- ]?bit|32[- ]?bit|user|machine|per[- ]user|remove only)\)",
    re.I,
)
_TRAILING_VERSION = re.compile(r"\s+[-–]\s+v?\d+(?:\.\d+)+.*$")
_VERSION = re.compile(r"\bv?\d+(?:\.\d+){1,}[a-z0-9.+\-]*\b", re.I)
_ARCH = re.compile(r"\b(?:x64|x86|amd64|arm64|64[- ]bit|32[- ]bit|win64|win32)\b", re.I)
_NON_WORD = re.compile(r"[^a-z0-9+#]+")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")


def normalize_name(name: str) -> str:
    s = name or ""
    s = _PARENS_NOISE.sub(" ", s)
    s = _TRAILING_VERSION.sub("", s)
    s = _VERSION.sub(" ", s)
    s = _ARCH.sub(" ", s)
    s = s.lower()
    s = _NON_WORD.sub(" ", s)
    return " ".join(s.split())


def prettify_package_name(name: str) -> str:
    """'Microsoft.WindowsCalculator' -> 'Windows Calculator'; 'SpotifyAB.SpotifyMusic' -> 'Spotify Music'."""
    base = name.split(".", 1)[1] if "." in name else name
    base = base.replace(".", " ").replace("_", " ")
    base = _CAMEL.sub(" ", base)
    return " ".join(base.split()) or name


_GUID = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I)

_LEGAL_SUFFIX = re.compile(
    r"[,\s]+(?:corporation|corp\.?|incorporated|inc\.?|ltd\.?|limited|llc|l\.l\.c\.|gmbh|co\.?|"
    r"s\.?a\.?|ag|b\.?v\.?|pty|plc|foundation|team|technologies|technology|software)$",
    re.I,
)
_PROVIDER_ALIASES = {
    "microsoft windows": "Microsoft",
    "hewlett-packard": "HP",
    "hp inc": "HP",
    "hp development company, l.p.": "HP",
    "hp development company": "HP",
    "intel(r)": "Intel",
    "intel(r) corporation": "Intel",
    "advanced micro devices": "AMD",
    "realtek semiconductor": "Realtek",
    "realtek semiconductor corp": "Realtek",
    "google llc": "Google",
    "nvidia": "NVIDIA",
}


def provider_name(publisher: str | None, category: object = None) -> str:
    """Tidy a publisher string for display/filtering; fall back sensibly when it's missing."""
    p = " ".join((publisher or "").replace('"', "").split())
    if _GUID.match(p):
        p = ""  # Store packages sometimes carry a GUID as the publisher name
    if not p:
        return "Microsoft" if str(category) == "windows_update" else "Unknown"
    alias = _PROVIDER_ALIASES.get(p.lower())
    if alias:
        return alias
    prev = None
    while prev != p:  # strip stacked suffixes: "Foo Software Co., Ltd."
        prev = p
        p = _LEGAL_SUFFIX.sub("", p).strip(" ,.")
    p = p or prev or "Unknown"
    return _PROVIDER_ALIASES.get(p.lower(), p)
