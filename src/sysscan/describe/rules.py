"""Curated plain-language descriptions for common software.

Each rule is (regex, text). The text may use ``{kb}``, ``{publisher}`` and regex named groups.
Rules are checked in order; the first match wins. Contributions welcome — this list is the
cheapest, most accurate way to improve report quality.
"""

from __future__ import annotations

import re

from sysscan.models import Category, Change

RULES: list[tuple[str, str]] = [
    # --- Windows servicing -------------------------------------------------------------------
    (r"security intelligence update|definition update for (?:microsoft|windows) defender",
     "Virus-definition update for Microsoft Defender, the antivirus built into Windows. It helps "
     "Defender recognise new threats. This happens several times a day."),
    (r"antimalware platform",
     "Update to the Microsoft Defender antivirus engine itself (not just its virus definitions)."),
    (r"malicious software removal tool",
     "Microsoft's monthly malware clean-up tool. It runs once in the background, checks for "
     "common infections, then exits."),
    (r"servicing stack update",
     "Update to the part of Windows that installs other updates. Keeps Windows Update reliable."),
    (r"cumulative update for \.net framework|\.net framework .*(security|quality).*update",
     "Monthly security and reliability fixes for .NET Framework, which many older Windows programs "
     "rely on{kb_suffix}."),
    (r"cumulative update preview",
     "Optional preview of next month's Windows fixes{kb_suffix}. It contains bug fixes but no "
     "security patches."),
    (r"cumulative update",
     "Windows' regular monthly bundle of security patches and bug fixes{kb_suffix}. This is normal "
     "and important."),
    (r"feature update to windows",
     "A major Windows version upgrade with new features. These arrive about once a year."),
    (r"windows .*security update|security update for",
     "Security fix from Microsoft{kb_suffix}."),
    (r"update for windows|update for microsoft windows",
     "Non-security Windows update{kb_suffix}."),
    (r"microsoft update health tools",
     "Microsoft component that keeps Windows Update working properly. Installed automatically."),
    (r"windows subsystem for linux|^wsl\b",
     "Windows Subsystem for Linux. Lets you run a Linux environment inside Windows (a developer tool)."),
    # --- Runtimes ------------------------------------------------------------------------------
    (r"visual c\+\+ .*redistributable|vc_?redist|visual c\+\+ .*runtime",
     "Microsoft Visual C++ runtime library. Many programs and games need it to run, and other "
     "software installs it automatically. Safe to keep."),
    (r"\.net .*sdk",
     "Tools for building .NET software (a developer tool)."),
    (r"asp\.net core|\.net (?:desktop )?runtime|windows desktop runtime|microsoft \.net(?! framework)",
     "Microsoft .NET runtime. Lets programs written in .NET run. Usually installed by another app "
     "or by Windows Update."),
    (r"webview2",
     "Microsoft Edge WebView2 runtime. Lets apps show web content inside their own windows. It "
     "updates itself automatically."),
    (r"windows ?app ?runtime|windowsappruntime",
     "Windows App SDK runtime. A shared component that modern Windows apps need."),
    (r"vclibs|ui ?xaml|net ?native",
     "Shared Microsoft Store framework package. Other Store apps depend on it. Updates automatically."),
    (r"directx",
     "Microsoft DirectX. The graphics and sound technology games use."),
    (r"java\(tm\)|java \d+ update|openjdk|temurin|jdk\b|jre\b",
     "Java runtime or development kit. Needed to run (or build) Java programs."),
    # --- Browsers & common apps ---------------------------------------------------------------
    (r"^microsoft edge(?! webview)", "Microsoft Edge web browser. It updates itself automatically."),
    (r"^google chrome", "Google Chrome web browser. It updates itself automatically."),
    (r"^mozilla firefox", "Mozilla Firefox web browser."),
    (r"^brave", "Brave web browser."),
    (r"microsoft onedrive", "OneDrive. Microsoft's cloud file sync app."),
    (r"microsoft teams", "Microsoft Teams chat and video-meeting app."),
    (r"microsoft 365|microsoft office|office 16 click-to-run",
     "Microsoft Office apps (Word, Excel, PowerPoint, Outlook …)."),
    (r"^zoom", "Zoom video-meeting app."),
    (r"^slack", "Slack team chat app."),
    (r"^discord", "Discord voice and text chat app."),
    (r"^spotify", "Spotify music streaming app."),
    (r"^steam$|^steam\b", "Steam, Valve's game store and launcher."),
    (r"7-zip", "7-Zip file archiver. Opens and creates .zip, .7z and other archive files."),
    (r"notepad\+\+", "Notepad++. A free text and code editor."),
    (r"^vlc", "VLC media player."),
    (r"adobe acrobat", "Adobe Acrobat. Views and edits PDF documents."),
    # --- Developer tools ------------------------------------------------------------------------
    (r"^python \d|^python launcher", "The Python programming language."),
    (r"^node\.?js", "Node.js. Runs JavaScript outside the browser; many developer tools need it."),
    (r"^git\b|git for windows", "Git. Version-control software developers use to track code changes."),
    (r"github desktop", "GitHub Desktop. A graphical app for working with Git repositories."),
    (r"visual studio code|^vs ?code", "Visual Studio Code. Microsoft's free code editor."),
    (r"^cursor\b", "Cursor. An AI-assisted code editor based on VS Code."),
    (r"visual studio (?:community|professional|enterprise|build tools|installer)",
     "Microsoft Visual Studio. A full development environment and compilers (a developer tool)."),
    (r"docker desktop", "Docker Desktop. Runs software containers (a developer tool)."),
    (r"^powershell \d|powershell 7", "PowerShell 7. The newer, cross-platform version of the PowerShell command shell."),
    (r"windows terminal", "Windows Terminal. A tabbed command-line window."),
    (r"app installer|desktop ?app ?installer", "App Installer. Provides the `winget` command and installs .msix apps."),
    # --- Hardware vendors ----------------------------------------------------------------------
    (r"nvidia .*graphics driver|geforce", "NVIDIA graphics card driver. Controls how your GPU draws games and video."),
    (r"nvidia physx", "NVIDIA PhysX. Physics effects library some games use."),
    (r"nvidia app|geforce experience", "NVIDIA's companion app for driver updates and game settings."),
    (r"amd software|radeon", "AMD graphics driver and settings app."),
    (r"realtek .*audio", "Realtek audio driver. Makes your speakers, headphone jack and microphone work."),
    (r"intel.*management engine", "Intel Management Engine. Low-level firmware interface on Intel PCs."),
    (r"intel.*(?:graphics|arc)", "Intel graphics driver."),
    (r"intel.*(?:wireless|wi-?fi)", "Intel Wi-Fi driver."),
    (r"intel.*bluetooth", "Intel Bluetooth driver."),
    (r"omen gaming hub|omen command center", "OMEN Gaming Hub. HP's app for OMEN PC performance modes, lighting and fan control."),
    (r"hp support assistant", "HP Support Assistant. HP's tool for driver updates and diagnostics."),
    (r"dolby", "Dolby audio enhancement software."),
    (r"^bios|system firmware|uefi", "Firmware (BIOS/UEFI) update for the computer's motherboard."),
]

_COMPILED = [(re.compile(p, re.I), t) for p, t in RULES]
_KB = re.compile(r"\b(KB\d{6,8})\b", re.I)


def describe_by_rule(change: Change) -> str | None:
    name = change.name
    kb = m.group(1).upper() if (m := _KB.search(name)) else None
    for rx, text in _COMPILED:
        if rx.search(name):
            return text.format(kb_suffix=f" ({kb})" if kb else "")

    if change.category == Category.DRIVER:
        if name.endswith("(kernel driver)"):
            return ("A low-level driver was registered with Windows, usually as part of a hardware "
                    "driver, antivirus or anti-cheat installation.")
        if name.endswith(" driver"):
            what = name[: -len(" driver")]
            return f"Driver software that lets Windows talk to your hardware ({what})."
        if " - " in name:  # Windows Update driver titles: "Intel - System", "Realtek - Net"
            return f"Hardware driver delivered through Windows Update ({name.replace(' - ', ', ')})."
    if name.endswith("(service)"):
        return ("A background Windows service was registered. Services usually come with an app or "
                "driver that was installed around the same time.")
    return None
