# sysscan user guide

This guide explains how to install sysscan, run it, read the report, and use every command. No
programming knowledge is needed. Commands are typed into **PowerShell** (search for "PowerShell" in the
Start menu).

**Contents**

1. [Install](#1-install)
2. [Your first scan](#2-your-first-scan)
3. [Reading the report](#3-reading-the-report)
4. [Checking a specific period](#4-checking-a-specific-period)
5. [Automatic daily snapshots](#5-automatic-daily-snapshots)
6. [AI explanations (optional)](#6-ai-explanations-optional) — Claude or local Ollama

7. [Identifying things yourself (tags)](#7-identifying-things-yourself-tags)
8. [Using runScan (no Python needed)](#8-using-runscan-no-python-needed)
9. [Command reference](#9-command-reference)
10. [Settings](#10-settings)
11. [Where sysscan keeps its files](#11-where-sysscan-keeps-its-files)
12. [Troubleshooting](#12-troubleshooting)
13. [Uninstalling](#13-uninstalling)

---

## 1. Install

Choose **one** of these options.

### Option A: runScan (easiest, no Python needed)

1. Download **`runScan.exe`** and **`runScan.com`** from the project's **Releases** page on GitHub.
2. Put **both** in the same folder, for example `C:\Tools\sysscan\`.
3. Double-click `runScan.exe`, or type `runScan` in a terminal in that folder. See
   [section 8](#8-using-runscan-no-python-needed) for everything it can do.

> Windows may show **"Windows protected your PC"** the first time, because the files aren't digitally
> signed. Click **More info → Run anyway**.

### Option B: install with Python (recommended if you're comfortable with a terminal)

You need **Python 3.11 or newer** ([python.org](https://www.python.org/downloads/)). Then, in
PowerShell:

```powershell
python -m pip install --user pipx
python -m pipx ensurepath          # then close and reopen PowerShell
pipx install "git+https://github.com/YOUR_GITHUB_USERNAME/system-scanner.git"
```

Check that it worked:

```powershell
sysscan --version
```

### Option C: from a downloaded copy of the code (for developers)

```powershell
cd C:\path\to\system-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

With this option, activate the environment (`.\.venv\Scripts\Activate.ps1`) each time you open a new
PowerShell window.

---

## 2. Your first scan

### Run PowerShell as administrator

sysscan works best with administrator rights, because some Windows logs are only readable by admins.

- Press **Win + X** and choose **Terminal (Admin)** or **Windows PowerShell (Admin)**, then click
  **Yes**.

It also works without admin rights, but some sources are skipped and the report tells you which.

### Scan

```powershell
sysscan
```

That's it. sysscan shows its progress, prints a short summary, and opens the report in your browser.

### What to expect the first time

On the very first scan there is **no earlier snapshot to compare with**, so sysscan looks back
**30 days** using Windows' own logs and timestamps. Because of that:

- Some items show as **"Installed or updated"**, because it can't yet tell which.
- Programs removed before this first scan may not show up at all.

From the **second scan on**, sysscan compares snapshots, and reports become much more accurate. That's
why the [daily snapshot](#5-automatic-daily-snapshots) is worth setting up.

### Just want to see what a report looks like?

```powershell
sysscan demo
```

This makes a sample report from made-up data. Nothing on your PC is scanned.

---

## 3. Reading the report

### The top of the page

- **Summary cards:** how many things were **Installed**, **Updated**, **Uninstalled**, **Installed or
  updated** (sysscan couldn't tell which) and **Modified / repaired**. "+ N routine" is background noise
  that's been set aside. Click a card to jump to that section.
- **"Good to know" box:** anything that limits the report, such as a first scan, not running as
  admin, a source that failed, or items that still need identifying.

### Filters

The filter bar stays at the top as you scroll.

| Filter | How to use it |
|---|---|
| **Search** | Type part of a name, maker or description |
| **Provider** | Show only software from one maker (e.g. Microsoft, Intel, HP) |
| **Type** | Click one or more: Desktop app, Store app, Windows update, Driver, Dev package |
| **Date** | Pick a from/to date, or use **Last 24h**, **7 days** or **All** |
| **Show routine items** | Expand the background-noise sections |
| **Reset filters** | Clear everything |

The summary cards and counts update to match your filters. Click a **column heading** (Name, Type,
Provider, Date) to sort.

### The columns

| Column | Meaning |
|---|---|
| **Name** | The software. **×27** means the same thing happened 27 times, e.g. a program that "repairs" itself every few hours |
| **Type** | Desktop app, Store app, Windows update, Driver or Dev package |
| **Provider** | Who makes it, tidied up (e.g. "Intel(R) Corporation" becomes "Intel") |
| **Version** | For updates: ~~old~~ → new |
| **Date** | When it happened, with a label saying how exact that is (below) |
| **What it is** | A plain-language explanation, with a label saying where it came from (below) |

**How exact is the date?**

| Label | Meaning |
|---|---|
| `exact` | Windows logged the exact time |
| `approx.` | Taken from a file or registry timestamp. Usually right, occasionally later |
| `date only` | Windows only recorded the day |
| `between scans` | It happened sometime between two snapshots |

**Where did the explanation come from?**

| Label | Meaning |
|---|---|
| `built-in` | sysscan's own list of common software |
| `publisher` | The software's own description |
| `AI` | Written by AI — Claude or Ollama (only if you turned AI on) |
| `AI · unsure` | The model wasn't confident. Worth checking |
| `AI + web` | Claude confirmed it with a web search; a **source** link shows where |
| `yours` | Your own tag (see [section 7](#7-identifying-things-yourself-tags)) |

A small **AI** or **yours** label next to the provider means the maker came from there too.

- **Evidence:** click to see exactly which Windows records support that row.
- **Tag it:** appears on rows that couldn't be fully identified; see [section 7](#7-identifying-things-yourself-tags).
- **Sources checked** (bottom of the page): what was scanned, how many items each source found, and
  whether any failed.

---

## 4. Checking a specific period

By default, a scan reports **what changed since the previous scan**. To choose the period yourself:

```powershell
sysscan scan --since 7d                              # last 7 days
sysscan scan --since 12h                             # last 12 hours
sysscan scan --since 2026-09-01                      # since a date
sysscan scan --since 2026-09-01 --until 2026-09-15   # between two dates
sysscan scan --since "2026-09-20 14:00"              # since a date and time (use quotes)
```

If the period starts before your first snapshot, the older part relies on Windows' logs only, and the
report says so.

---

## 5. Automatic daily snapshots

Snapshots are what let sysscan spot removals and old → new versions reliably. Set it up once:

```powershell
sysscan schedule install              # run in an ADMINISTRATOR PowerShell
```

This adds a Windows **Task Scheduler** task that runs a silent scan:

- **every day at 09:00**, and
- **10 minutes after you sign in.**

If the PC was off at 09:00, the scan runs as soon as it can. Each run saves a snapshot and a report.

```powershell
sysscan schedule install --time 20:30   # choose a different time
sysscan schedule install --ai           # scheduled scans also use AI explanations
sysscan schedule install --scan-args "--format html --out D:\Reports"   # any other scan options
sysscan schedule status                 # last run, next run
sysscan schedule remove                 # turn it off
sysscan history                         # list past scans
sysscan open                            # open the most recent report
```

> The task runs with full rights without asking at every sign-in. Creating it needs administrator
> rights once.

---

## 6. AI explanations (optional)

For software sysscan doesn't recognise, it can ask an AI to explain what it is and who makes it.
This is **off by default**. Two providers are supported:

| Provider | Where it runs | Needs |
|---|---|---|
| **Claude** (default) | Anthropic's cloud | An API key + (for Python installs) the AI add-on |
| **Ollama** | On your PC | [Ollama](https://ollama.com/) installed, with a model pulled |

### Claude (Anthropic)

- An Anthropic API key from [console.anthropic.com](https://console.anthropic.com/).
- The AI add-on, if you installed with Python:
  ```powershell
  pipx inject sysscan anthropic keyring      # if installed with pipx
  pip install -e ".[ai]"                      # if installed from the code
  ```
  (`runScan.exe` already includes it.)

Create a file called **`.env`** containing:

```ini
ANTHROPIC_API_KEY=sk-ant-...your key...
SYSSCAN_AI=true
# SYSSCAN_AI_PROVIDER=claude          # default; can omit
# SYSSCAN_AI_MODEL=claude-haiku-4-5
```

### Ollama (local)

Nothing about the software leaves your machine. Install [Ollama](https://ollama.com/), pull a model,
then put this in `.env`:

```ini
SYSSCAN_AI=true
SYSSCAN_AI_PROVIDER=ollama
SYSSCAN_AI_MODEL=llama3.2
# SYSSCAN_AI_BASE_URL=http://127.0.0.1:11434   # only if Ollama isn't on the default port
```

```powershell
ollama pull llama3.2
ollama serve          # usually already running after install on Windows
sysscan collectors    # should say provider ollama … reachable
sysscan scan --ai
```

No Anthropic key or `sysscan[ai]` package is needed for Ollama.

**Model tips:** any chat model Ollama can run works; set `SYSSCAN_AI_MODEL` to the exact name from
`ollama list` (for example `llama3.2`, `llama3.2:3b`, `qwen2.5`, `mistral`). Smaller models are faster on
CPU; larger ones give better descriptions. The first AI-enabled scan can take a while while the model
loads — later scans are quicker, and answers are cached so each product is only asked about once.

To switch back to Claude, set `SYSSCAN_AI_PROVIDER=claude` (or remove that line) and provide an API key.
### Where to put the `.env` file

Put it in **one** of these places:

| Location | When to use it |
|---|---|
| `%LOCALAPPDATA%\sysscan\.env` | **Best choice.** Always found, including by scheduled scans |
| Next to `runScan.exe` | If you use the exe |
| The project folder | If you run sysscan from a downloaded copy of the code |
| The folder you run the command from | For quick tests |

> ⚠️ Keep API keys private. Never share or upload your `.env` file.

Check that it's picked up:

```powershell
sysscan collectors
```

The last lines should say **AI descriptions: enabled …**, show the provider/model, and (for Claude) whether
an API key was found, or (for Ollama) whether the local daemon is reachable.

### Other ways to turn it on

```powershell
sysscan scan --ai        # AI for this scan only
sysscan scan --no-ai     # never use AI for this scan, even if it's switched on
sysscan set-key          # store a Claude API key in Windows Credential Manager instead of a file
```

If several settings disagree, the command-line option wins, then `.env`, then the
[settings file](#10-settings).

### Web search (optional second try; Claude only)

Some software is too obscure to recognise from its name. With this switched on, anything Claude was
unsure about is looked up once with a web search:

```ini
SYSSCAN_AI_WEB=true
```

Those answers are labelled **AI + web**, with a link to the page that confirmed them.
Web search is ignored when `SYSSCAN_AI_PROVIDER=ollama`.

### What it costs

- **Claude:** a fraction of a cent per scan with the default model (Haiku). Answers are saved, so each
  piece of software is only asked about once.
- **Claude web search:** about **$0.01 per search**, at most 2 searches per item and 15 items per scan
  (change the limit with `SYSSCAN_AI_WEB_MAX_ITEMS`). Each item is searched at most once, ever.
- **Ollama:** free; uses your machine's CPU/GPU. Quality depends on the model you pulled.

### What is sent

**Claude:** only facts about the software — its name, maker (if known), version and type, plus clues such
as the vendor's website domain or its folder under Program Files. Your user name, anything in your user
folder, and your computer's name are never sent.

**Ollama:** the same facts stay on your PC; the request goes to `localhost` (or whatever
`SYSSCAN_AI_BASE_URL` you set).

---

## 7. Identifying things yourself (tags)

Sometimes neither sysscan nor the AI knows what something is. If you find out (for example by searching
online), **tag** it. Your tag is used in every future report and always wins over sysscan's and the AI's
answers.

### The quick way: the "Tag it" button

1. In the report, click **Tag it** on the row. A command is copied to your clipboard, like:
   ```powershell
   sysscan tag 'PowerENGAGE' --publisher '' --description ''
   ```
2. Paste it into PowerShell and **type your answers between the empty quotes**:
   ```powershell
   sysscan tag 'PowerENGAGE' --publisher 'Example Corp' --description 'Helps Example printers stay up to date.'
   ```
3. Press Enter, then update the report you're looking at:
   ```powershell
   sysscan retag
   ```

> **Quotes:** keep the single quotes `' '`. If your text contains an apostrophe, type it twice:
> `'It''s a helper app'`.

### Tag several at once

```powershell
sysscan unknowns           # lists everything that still needs identifying
sysscan unknowns --edit    # adds a blank entry for each one and opens the file in Notepad
```

Fill in `publisher` and `description` for the ones you know, save, then run `sysscan retag`. Entries you
leave blank are ignored.

### Manage your tags

```powershell
sysscan tags                         # list all your tags
sysscan untag 'PowerENGAGE'          # remove one
sysscan retag                        # refresh the report afterwards
```

### More options

| Option | What it does |
|---|---|
| `--publisher '…'` | Who makes it |
| `--description '…'` | What it is |
| `--routine` | Always put it in the "routine" section (for noise you don't care about) |
| `--not-routine` | Never put it in the "routine" section |
| `--category driver` | Only apply to one type: `desktop_app`, `store_app`, `windows_update`, `driver`, `dev_package` |
| `--regex` | Treat the name as a pattern, to match several names with one tag |

Example of a pattern that matches both names Windows uses for the same app:

```powershell
sysscan tag '6365217CE6EB4|^Microsoft Defender$' --regex --publisher 'Microsoft' --description 'Microsoft Defender app.'
```

Tags are stored in `%LOCALAPPDATA%\sysscan\known_software.toml`, a plain text file you can also edit in
Notepad. To use the same tags on several PCs, point sysscan at a shared copy (e.g. on OneDrive); see
`known_software` in [Settings](#10-settings).

Names are matched loosely: capital letters, version numbers and "(x64)"/"(x86)" are ignored.

---

## 8. Using runScan (no Python needed)

`runScan` is the same tool packaged so Python isn't needed. It comes as **two files that belong together
in the same folder**:

| File | Used when | Behaviour |
|---|---|---|
| `runScan.exe` | You **double-click** it, or it runs **at startup** | No console window. A small progress window (or nothing at all at startup), then the report |
| `runScan.com` | You type **`runScan`** in a terminal | Prints progress and results right in the terminal, like any command-line tool |

You never pick one yourself. Windows runs `.com` before `.exe` when you type a name without an
extension, so `runScan …` in PowerShell or Command Prompt automatically uses the terminal version.
Visual Studio uses the same trick (`devenv.com` / `devenv.exe`).

### From a terminal

```powershell
cd C:\Tools\sysscan
.\runScan --help                 # everything it can do
.\runScan                        # scan: progress here, then the report opens
.\runScan --since 7d --no-open   # any scan options
.\runScan history                # every sysscan command works, output shown here
.\runScan tags
```

Add the folder to your **PATH** to type `runScan` from anywhere. Run the terminal as administrator for
complete results; `runScan` reminds you if it isn't.

### Double-click

Double-clicking `runScan.exe` asks once for administrator rights (click **No** to scan with fewer
sources), shows a small progress window, then opens the report. If you run a command from a shortcut
(e.g. `runScan.exe tags`), its output appears in a small window with a **Copy** button.

### At startup (silent)

```powershell
.\runScan --install-startup          # asks for admin once
```

This creates a Task Scheduler task that runs `runScan.exe --startup` daily at 09:00 and 10 minutes
after you sign in. It runs **completely in the background**: no window, no browser. You don't need to
type `--startup` yourself; the task adds it. Reports still appear in `%LOCALAPPDATA%\sysscan\reports`.
Use `runScan --remove-startup` to stop it.

### Options only runScan has

| Option | What it does |
|---|---|
| `--help` | Show all options (in the terminal, or in a window when double-clicked) |
| `--install-startup [--time HH:MM] [scan options]` | Set up the silent daily and sign-in scan (asks for admin once) |
| `--remove-startup` | Remove it |
| `--startup [scan options]` | Silent scan: no window, no browser (what the task runs) |
| `--no-elevate` | Double-click without asking for admin rights |

Everything else (`--since`, `--format`, `--out`, `--ai`, `tag`, `history` …) is the same as `sysscan`.

To use AI with runScan, put your `.env` file **next to the two files** or in `%LOCALAPPDATA%\sysscan\`
(Claude key and/or `SYSSCAN_AI_PROVIDER=ollama` — see [section 6](#6-ai-explanations-optional)).

### Passing options at startup

`--install-startup` stores any **scan options** you give it in the scheduled task, so every automatic
run uses them. Add `--time HH:MM` to choose the daily time (default 09:00):

```powershell
.\runScan.exe --install-startup --time 20:00 --format html,json --out "D:\Reports" --skip npm --ai
```

Run it again with different options to replace the task. To check what it will run, use
`sysscan schedule status` (the **Runs:** line), or open **Task Scheduler → Task Scheduler Library →
"sysscan daily snapshot"**.

The same options also work for a manual silent scan (`runScan.exe --startup --out D:\Reports`), and
from a desktop shortcut (right-click the exe → *Create shortcut* → *Properties* → add them to the end of
**Target**).

| Option | Example |
|---|---|
| `--since` / `--until` | `--since 7d` (default: since the previous scan) |
| `--format` | `--format html,json` |
| `--out` | `--out "D:\Reports"` (use quotes if the path has spaces) |
| `--only` / `--skip` | `--skip npm,pip` |
| `--ai` / `--no-ai` | `--ai` |
| `--no-open` | Don't open the report after a double-click scan |

If an option is misspelled, runScan.exe tells you straight away instead of silently ignoring it. For
`--startup`, the error goes to `sysscan.log`.

> Why not the Windows **Startup folder**? It works (a shortcut with `--startup` and your options), but
> programs started from there can't get administrator rights without a prompt at every sign-in, so some
> sources would be skipped. `--install-startup` uses Task Scheduler instead, which avoids that.

**Building it yourself** (on Windows, from a copy of the code):

```powershell
python -m venv .venv-build
.\.venv-build\Scripts\Activate.ps1
pip install -e ".[ai,build]"
python scripts\build_exe.py          # creates dist\runScan.exe and dist\runScan.com
```

Run these from the project folder, not from inside `scripts`. Add `--onedir` to build a folder instead
of a single file: it starts faster and antivirus programs flag it less often.

---

## 9. Command reference

Every command also accepts `--help`, e.g. `sysscan scan --help`.

### Scanning and reports

| Command | What it does |
|---|---|
| `sysscan` | Same as `sysscan scan` |
| `sysscan scan` | Take a snapshot and report changes since the last scan |
| `  --since WHEN` | Start of the period: `7d`, `12h`, `2026-09-01`, `"2026-09-01 14:00"` |
| `  --until WHEN` | End of the period (default: now) |
| `  --ai` / `--no-ai` | Force AI explanations on or off |
| `  --format html,md,json` | Which report files to write (default: all three) |
| `  --out FOLDER` | Save reports somewhere else |
| `  --no-open` | Don't open the report in the browser |
| `  -q`, `--quiet` | No output in the window |
| `  --only a,b` / `--skip a,b` | Run only, or skip, some sources (names from `sysscan collectors`) |
| `sysscan demo` | Make a sample report from made-up data |
| `sysscan history` | List past scans and their report files |
| `sysscan open [N]` | Open the latest report, or the report of scan number N |
| `sysscan collectors` | Show which sources can run on this PC, and whether AI is set up |

### Identifying software

| Command | What it does |
|---|---|
| `sysscan unknowns [N] [--edit]` | List items the latest report (or scan N) couldn't identify; `--edit` opens a file to fill in |
| `sysscan tag NAME --publisher … --description …` | Add or update your own identification (options in [section 7](#7-identifying-things-yourself-tags)) |
| `sysscan untag NAME [--regex]` | Remove a tag |
| `sysscan tags` | List your tags |
| `sysscan retag [N] [--no-open]` | Apply your current tags to the latest report (or scan N) without rescanning |

### Setup

| Command | What it does |
|---|---|
| `sysscan schedule install [--time HH:MM] [--ai] [--scan-args "…"]` | Daily + at-sign-in automatic scans (admin, once) |
| `sysscan schedule status` | When it last ran and will next run |
| `sysscan schedule remove` | Turn automatic scans off |
| `sysscan set-key` | Save a Claude (Anthropic) API key in Windows Credential Manager |

### Options for any command

| Option | What it does |
|---|---|
| `--config PATH` | Use a different settings file |
| `-v`, `--verbose` | Write extra detail to the log file (for troubleshooting) |
| `--version` | Show the version |

### Source names (for `--only` / `--skip`)

`registry` (installed programs), `appx` (Store apps), `drivers`, `reliability` (Reliability Monitor),
`eventlog`, `windows-update`, `pip`, `npm`, `editor-extensions` (VS Code/Cursor/Windsurf),
`scoop-choco`.

---

## 10. Settings

Most people never need these. There are two optional places for settings.

### `.env` file

Good for AI settings and switches (see [section 6](#6-ai-explanations-optional)):

| Setting | Meaning | Default |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude API key (Claude provider) | none |
| `SYSSCAN_AI` | `true` / `false`: use AI | `false` |
| `SYSSCAN_AI_PROVIDER` | `claude` or `ollama` | `claude` |
| `SYSSCAN_AI_MODEL` | Model name (`claude-haiku-4-5`, or e.g. `llama3.2` for Ollama) | `claude-haiku-4-5` |
| `SYSSCAN_AI_BASE_URL` | Ollama HTTP URL | `http://127.0.0.1:11434` |
| `SYSSCAN_AI_MAX_ITEMS` | Most items sent to the AI per scan | `150` |
| `SYSSCAN_AI_WEB` | `true` / `false`: web-search second try (Claude only) | `false` |
| `SYSSCAN_AI_WEB_MAX_ITEMS` | Most items web-searched per scan | `15` |
| `SYSSCAN_HOME` | Store all sysscan data in a different folder | `%LOCALAPPDATA%\sysscan` |

### `config.toml`

Save it as `%LOCALAPPDATA%\sysscan\config.toml`; a commented example is in `config.example.toml`.

```toml
[general]
report_dir = "~/Documents/sysscan-reports"   # where reports are saved
formats = ["html", "md", "json"]             # which report files to write
open_report = true                           # open the report after a scan
first_run_days = 30                          # how far the first scan looks back
known_software = "~/OneDrive/sysscan/known_software.toml"   # share your tags across PCs

[collectors]
disabled = ["npm"]                           # sources to never run
python_interpreters = ["C:/Tools/Python312/python.exe"]      # extra Pythons to check

[routine]
extra_patterns = ["^Zoom", "OneDrive"]       # extra things to always treat as routine noise

[ai]
enabled = false
provider = "claude"          # or "ollama"
model = "claude-haiku-4-5"   # e.g. "llama3.2" for Ollama
# base_url = "http://127.0.0.1:11434"
web = false
```

---

## 11. Where sysscan keeps its files

Everything is in **`%LOCALAPPDATA%\sysscan\`**. Paste that into File Explorer's address bar to open it.

| File or folder | What it is |
|---|---|
| `reports\` | Every report: `sysscan_<date>_<time>.html`, `.md` and `.json` |
| `sysscan.db` | Snapshots and saved AI answers |
| `known_software.toml` | Your tags |
| `config.toml` | Your settings (optional) |
| `.env` | AI settings (Claude key and/or Ollama provider) and other switches (optional) |
| `sysscan.log` | A log for troubleshooting |

Deleting `sysscan.db` starts fresh: the next scan behaves like a first scan.

---

## 12. Troubleshooting

**"sysscan is not recognized…"**

If you installed with pipx, close and reopen PowerShell after `pipx ensurepath`. If you're using a
copy of the code, activate its environment first (`.\.venv\Scripts\Activate.ps1`), or use
`python -m sysscan` instead of `sysscan`.

**"running scripts is disabled on this system" (when activating)**

Allow it for this window only, then activate again:
`Set-ExecutionPolicy -Scope Process Bypass`

**The report says "Not running as administrator"**

Open PowerShell as administrator (Win + X → Terminal (Admin)) and scan again. Scheduled scans always
run with full rights.

**The first report shows lots of "Installed or updated"**

This is expected on a first scan (see [section 2](#what-to-expect-the-first-time)). It improves from
the second scan on.

**Something I know changed isn't in the report**

Check the period at the top of the report. By default it only covers the time since the previous scan,
so try `sysscan scan --since 7d`. Also look at **Sources checked** at the bottom to see whether a source
failed.

**Device Manager shows a recent "Last Arrival Date" for a device, but sysscan shows no driver update**

"Last Arrival Date" is when Windows last *detected* the device (at start-up, wake from sleep or
reconnect). It doesn't mean a driver was installed. Compare **Driver Version** and **Install Date**
instead.

**AI: "no API key was found"**

Check the `.env` file's name and location with `sysscan collectors`. For scheduled scans, put it in
`%LOCALAPPDATA%\sysscan\`. (Not needed when `SYSSCAN_AI_PROVIDER=ollama`.)

**AI: "API key is invalid" (401)**

The key was mistyped or revoked. Create a new one in the Anthropic Console.

**AI: "This API key is not scoped to a workspace" (400)**

Create a key inside a workspace in the Anthropic Console and use that one.

**AI: "the Anthropic SDK is missing"**

Install the AI add-on (see [section 6](#6-ai-explanations-optional)). Only needed for Claude.

**AI: "Cannot reach Ollama…"**

Start Ollama (`ollama serve`, or open the Ollama app), check `SYSSCAN_AI_BASE_URL`, and confirm
`sysscan collectors` shows it as reachable. Pull the model named in `SYSSCAN_AI_MODEL`
(`ollama pull llama3.2`).

**Windows says "Windows protected your PC" for runScan.exe**

The file isn't digitally signed. Click **More info → Run anyway**, or install with Python instead.

**My antivirus flags runScan.exe**

This is a known false alarm for single-file Python programs. Build with `--onedir` or install with
Python instead.

**Still stuck?**

Run the command again with `-v`, then look at the end of `%LOCALAPPDATA%\sysscan\sysscan.log`. When
reporting a problem, include that part of the log, and first remove anything personal from it.

---

## 13. Uninstalling

```powershell
sysscan schedule remove                          # 1. stop automatic scans (admin PowerShell)
pipx uninstall sysscan                           # 2. remove the program (if installed with pipx)
Remove-Item -Recurse "$env:LOCALAPPDATA\sysscan" # 3. delete reports, snapshots, tags and settings
```

- **If you used runScan.exe:** run `runScan.exe --remove-startup`, then delete the exe.
- **If you saved your API key with `sysscan set-key`:** open **Credential Manager → Windows
  Credentials** and remove the entry mentioning **sysscan**.
