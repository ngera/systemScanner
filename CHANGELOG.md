# Changelog

## Unreleased

- **Local Ollama AI provider.** Set `SYSSCAN_AI_PROVIDER=ollama` (and `SYSSCAN_AI_MODEL`, e.g. `llama3.2`)
  to enrich descriptions/publishers via a local Ollama daemon — no API key, nothing leaves the machine.
  Claude remains the default; web search stays Claude-only. `sysscan collectors` reports Ollama reachability.

## 0.4.0 — 2026-09-26

- **Your own tags**: `known_software.toml` holds identifications that override rules and AI.
  New commands: `sysscan tag`, `sysscan unknowns [--edit]`, and `sysscan retag` (re-applies tags to an
  existing report without rescanning). The HTML report has a **Tag it** button that copies a ready-made command.
  `sysscan tags` lists your tags and `sysscan untag` removes one.
- runScan.exe's `--startup`, `--install-startup` (plus `--time HH:MM`) and double-click launches accept all scan
  options (`--since`, `--format`, `--out`, `--only`/`--skip`, `--ai`, `--no-open` …). `--install-startup`
  stores them in the scheduled task and rejects invalid options immediately.
  `sysscan schedule install --scan-args "…"` does the same.
- **runScan now works from the terminal.** The build produces `runScan.exe` (windowed: double-click and a
  silent startup task) plus `runScan.com` (console). Typing `runScan …` runs the `.com`, so output prints in
  the terminal and the shell waits for it. With no arguments in a terminal it scans with progress shown
  there. `runScan --help` works in both; for the windowed exe, help and command output appear in a small
  window with a Copy button. The startup task always uses the windowless `.exe`.
- **Better identification before the AI is asked:** publishers are filled from the PC's own uninstall and Store
  records, Store publisher display names are read from the manifest, service vendors come from their
  Program Files folder, and GUID "publishers" are treated as unknown.
- **The AI gets hints** (vendor website, install folder, service executable) instead of just a name.
- **Optional web-search pass** (`SYSSCAN_AI_WEB=true`) for items the first pass couldn't identify, capped and
  cached. Answers are labelled "AI + web" with a source link.
- **Repeated identical changes collapse into one row** with a ×N count. For example, an MSI that re-registers
  every 6 hours is shown once and marked routine.

## 0.3.1 — 2026-09-26

Fixes found by checking real scans on a Windows 11 machine:

- **Driver installs are now detected.** The setupapi.dev.log parser was written for an old log layout, so
  on Windows 11 it missed every "Device Install" section. It now reads the selected "Driver Node" (INF,
  version, signer), provider/version from driver-package installs, and still understands the older layout.
  Device IDs are translated to device names using the driver inventory.
- "Driver package already imported" no-ops (e.g. the OneNote printer driver, re-imported every Office
  update) are no longer reported as installs.
- Store app updates recorded in Windows Update history ("9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2") are now
  Store apps with readable names and collapse as routine, instead of flooding "Windows updates".
- Devices that simply used a Windows built-in driver (plugging in a phone, etc.) are marked routine.
- The event-log source no longer fails when there are no matching events in the period.
- `--since` earlier than your first snapshot now still compares snapshots taken inside the period, and
  says which part of the period that covers.
- Junk WMI driver entries (versions like "2:10.0,2:6.3") are ignored.

## 0.3.0 — 2026-09-26

- **`.env` support** (no extra dependency): `ANTHROPIC_API_KEY`, `SYSSCAN_AI`, `SYSSCAN_AI_MODEL`,
  `SYSSCAN_AI_MAX_ITEMS`. Looked up in the current folder, next to runScan.exe, the project root and
  `%LOCALAPPDATA%\sysscan`. See `.env.example`.
- AI switch precedence: `--ai`/`--no-ai` → `SYSSCAN_AI` → `config.toml`.
- **AI now fills in missing publishers** as well as missing descriptions. It asks only for the fields that
  are missing, ignores low-confidence publishers, and marks AI-supplied values in HTML/Markdown/JSON.
- AI answers, including "unknown", are cached so nothing is sent twice (existing caches migrate automatically).
- The report says how many descriptions and publishers Claude filled in; `sysscan collectors` shows AI and key status.

## 0.2.0 — 2026-09-26

- **HTML report filters**: date range (with Last 24h / 7 days presets), provider, software type, search,
  and "show routine items". Summary cards and section counts update live, and every column is sortable.
- Report tables now have **Type** and **Provider** columns (HTML and Markdown); JSON gains `provider`.
- Publisher names are normalised into providers ("Intel(R) Corporation" → "Intel").
- **runScan.exe**: a windowed launcher built with PyInstaller. It has a progress window, a one-time UAC prompt,
  `--startup` silent mode and `--install-startup` / `--remove-startup`.
- `sysscan schedule` points at runScan.exe when running from it.
- CI builds runScan.exe, smoke-tests the built exe, and attaches it to tagged releases.

## 0.1.0 — 2026-09-26

First release.

- Collectors: Uninstall registry (all views + user hives), Store/AppX, drivers (WMI + setupapi.dev.log),
  Reliability Monitor, MSI & service-install event logs, Windows Update history, pip, npm -g,
  VS Code/Cursor/Windsurf extensions, Scoop, Chocolatey.
- SQLite snapshots with a coverage-aware diff (MSI major upgrades detected as updates).
- Evidence correlation with per-row timestamp confidence.
- Plain-language descriptions: curated rules → publisher metadata → optional Claude API, cached.
- HTML (light/dark, filter, collapsible routine items), Markdown and JSON reports.
- `sysscan schedule` for a daily Task Scheduler snapshot; `sysscan demo` for a sample report.
