# Design notes

This document explains *why* sysscan works the way it does. The problem looks simple ("list what got installed last week"). It isn't, because Windows has no single source of truth for software changes.

## The core problem

| Source | Strength | Weakness |
|---|---|---|
| Uninstall registry keys | Covers most desktop apps, including per-user installs | `InstallDate` is date-only, often missing, and not always updated on upgrade. Uninstalls leave no trace |
| MSI event log | Exact times, versions, publisher | MSI only. The log rolls over (~20 MB) |
| Reliability Monitor | Installs, removals and Windows Update in one place, ~1 year | Mostly MSI and WU. Slow to query |
| Windows Update history | Every WU package, incl. drivers and Defender | Nothing outside Windows Update |
| setupapi.dev.log | Exact driver install times | Names devices, not driver packages. Local time, unstructured text |
| Store (AppX) | Versioned install folders give reliable times | Display names are often resource indirections |
| pip / npm / editor extensions | Good metadata and descriptions | Invisible to every Windows source |

No single source answers "what changed?" So sysscan is built as **collectors + correlator**. Collectors know how to read one source. The correlator knows how to merge them.

## Two complementary signals

1. **Snapshot diff (authoritative).** Every scan stores the full inventory in SQLite. Comparing two snapshots tells you *for certain* what appeared, disappeared or changed version, whatever the installer technology. What a diff can't tell you is *when* inside the window it happened.
2. **Historical evidence (precise but partial).** Logs and histories give exact timestamps, but only for the technologies they cover and only as far back as they keep records.

The correlator uses the diff for the **action** and the history for the **time**. When there is no earlier snapshot (the first run, or a period before the first snapshot), the report falls back to history and timestamps and says so in a "Good to know" box.

## Safety rules in the diff

- **Only compare sources that succeeded in both scans.** If the Store query fails once, the diff must not report 150 Store apps as uninstalled.
- **Removed key + added key with the same normalised name = update.** MSI major upgrades change the product code (the registry key), so a naive key diff would show "uninstalled X 1.2 / installed X 1.3".
- **Timestamp noise is suppressed when a snapshot proves nothing changed.** Registry write times change for unrelated reasons, such as a Windows feature upgrade.

## Correlation

Evidence is grouped by *(category, normalised name)*. Normalisation strips versions, architecture markers and punctuation, so that `Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810` and `… - 14.42.34433` match.

Within a group:

1. Historical events attach to a compatible snapshot change whose window contains them.
2. The remaining events are clustered by time (30 min, or the same day for date-only evidence). A single product installed on Monday and removed on Thursday stays as two rows.
3. Each cluster becomes one row. It keeps the most precise timestamp, the richest version information and all the evidence, which the report shows under "Evidence".

Drivers get special handling. `setupapi.dev.log` names *devices* ("Intel(R) Serial IO I2C Host Controller"), while the inventory groups drivers by *provider + class + version*, because one chipset package touches twenty devices. Events are matched to inventory rows by driver version.

## Timestamps have confidence levels

| Label | Meaning |
|---|---|
| exact | From an event log or update history record |
| approx. | Registry key or file write time. Usually right, occasionally touched later |
| date only | Registry `InstallDate` (`YYYYMMDD`) |
| between scans | Only known to have happened between two snapshots |

Showing this is a deliberate product choice. False precision is worse than an honest "sometime between Tuesday and Friday".

## Descriptions

Order: **your tags → curated rules → cached AI answer → the software's own text → Claude → Claude with web
search → nothing.**

- **Your tags** (`known_software.toml`) always win. People often know things no automated source does.
- **Rules** are cheap, offline and accurate for the software that shows up most (runtimes, Windows
  servicing, drivers, popular apps).
- **Publisher metadata** (pip summaries, npm/extension descriptions, Store manifests, registry `Comments`)
  is used when it's usable. Boilerplate such as "Install this update to resolve issues…" is filtered out.
- **Before any AI call**, missing publishers are filled from the PC's own records (uninstall entries,
  Store manifests, a service's Program Files folder), and hints are collected: vendor website, install
  folder, executable path. Paths inside a user profile are dropped.
- **Claude** is opt-in and runs only for changed items nothing else could explain, asking only for the
  missing fields. It's batched, and every answer is cached by normalised name, including "don't know".
  The prompt tells the model to say less, not guess. Unsure publishers are never used.
- **Web search** is a separate opt-in second pass for what the first pass couldn't pin down. Each product
  is searched at most once, with a per-scan cap. Answers carry a source link.

## Routine noise

Some changes happen all the time and are rarely what the user is looking for: Defender definitions (several per day), the monthly malware removal tool, browser self-updates, Store auto-updates and framework packages. These are marked `routine` and collapsed, not hidden. The rules live in `classify.py` and can be extended from the config.

## Why PowerShell instead of pywin32

- It ships with every Windows 10/11 machine, so there are no native dependencies to install.
- Every query can be pasted into a terminal to debug a user's issue.
- WMI/CIM, COM (Windows Update) and `Get-WinEvent` are all first-class there.

The cost is about 1–10 s of process start-up and query time per collector. That's acceptable for a tool that runs once a day.

## Packaging: why runScan comes as two files

A Windows executable is built for one of two "subsystems":

- **console:** it gets a terminal. Typed commands print and the shell waits for them, but a double-click or
  a sign-in task opens a black console window.
- **windowed (GUI):** no console window ever appears, but it can't print to the terminal that started it,
  and PowerShell doesn't wait for it to finish.

runScan must be silent at startup, friendly on double-click, *and* a normal command-line tool, and no
single subsystem gives all three. So the build produces the same code twice:

| File | Subsystem | Used for |
|---|---|---|
| `runScan.exe` | windowed | double-click (progress window) and the startup task (`--startup`, silent) |
| `runScan.com` | console | typing `runScan …` in a terminal |

The `.com` is an ordinary executable with a different extension. Windows looks up names in `PATHEXT`
order, and `.COM` comes before `.EXE`, so a bare `runScan` in a terminal runs the console build while
Explorer and Task Scheduler use the `.exe`. Visual Studio ships `devenv.com` / `devenv.exe` the same
way. Details that make the pair behave:

- **Startup:** the scheduled task always points at the `.exe`, even when it was installed from the
  terminal, and passes `--startup` itself, so users never type it.
- **Elevation:** when the `.com` needs administrator rights (e.g. `--install-startup`), it relaunches the
  `.exe`, so the result shows in a message box instead of a console window that closes immediately.
- **Command output from the `.exe`** (e.g. a shortcut running `runScan.exe tags`) is captured and shown
  in a small window instead of being lost.
- **Options** for `--startup` / `--install-startup` / double-click are parsed with the same definitions
  as `sysscan scan`, and rejected up front if misspelled. Nothing is silently ignored.

Alternatives considered: a single windowed exe that attaches to the parent console prints *after* the
shell prompt returns; a single console exe that hides its own window flashes a console at every sign-in.

## Known limitations and future work

- Changelogs: not stored anywhere locally.
- Portable apps: not tracked.
- The pip collector treats an interpreter it couldn't query as "no packages". If that interpreter was queried successfully before, the diff could show false uninstalls. A per-interpreter coverage record is planned.
- A forensic-grade mode (Amcache.hve, NTFS USN journal) would add precise first-run and file-creation times at the cost of needing admin and a volume shadow copy.
