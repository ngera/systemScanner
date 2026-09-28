"""Entry point for ``runScan.exe``, the double-clickable Windows build of sysscan.

Behaviour
---------
runScan.exe                     Ask for admin rights (UAC; decline = scan as standard user), show a small
                                progress window, then open the HTML report.
runScan.exe --startup           Silent scan: no window, no browser. Used by the scheduled task / startup.
runScan.exe --install-startup   Register the daily + at-logon scheduled task (asks for admin once).
                                Add --time HH:MM and any scan options; they're stored in the task, e.g.
                                runScan.exe --install-startup --time 20:00 --format html,json --out D:\\Reports
runScan.exe --remove-startup    Remove it.
runScan.exe --no-elevate        On-demand scan without asking for admin rights.
runScan.exe --help              Show all of this in a window.
runScan.exe scan --since 7d     Any regular sysscan command works too (history, open, demo, …). Their text
                                output (and `<command> --help`) is shown in a window, since there's no console.

Scan options (--since, --until, --ai/--no-ai, --format, --out, --only, --skip, --no-open) work with a
double-click launch (via a shortcut), --startup and --install-startup.

The exe is built windowed (no console), so all feedback goes through message boxes, the progress
window and the report itself. Everything is also logged to %LOCALAPPDATA%\\sysscan\\sysscan.log.
"""

from __future__ import annotations

import ctypes
import logging
import queue
import subprocess
import sys
import threading
from collections.abc import Callable

from sysscan import __version__
from sysscan.config import load_config
from sysscan.winutil import IS_WINDOWS, is_admin

APP_TITLE = "sysscan"
CLI_COMMANDS = {"scan", "demo", "history", "open", "collectors", "set-key", "schedule", "tag", "untag", "tags",
                "unknowns", "retag"}

log = logging.getLogger("sysscan.launcher")

_MB_ICONERROR, _MB_ICONINFO, _MB_ICONWARNING = 0x10, 0x40, 0x30


def message(text: str, icon: int = _MB_ICONINFO) -> None:
    """Tell the user something: in the terminal for runScan.com, as a message box for runScan.exe."""
    if IS_WINDOWS and no_console():
        ctypes.windll.user32.MessageBoxW(None, text, APP_TITLE, icon)  # type: ignore[attr-defined]
    else:
        print(text, file=sys.stderr if icon == _MB_ICONERROR else sys.stdout)


def sibling_gui_exe() -> str | None:
    """Path of runScan.exe next to runScan.com (used for UAC relaunches and the scheduled task)."""
    from pathlib import Path

    exe = Path(sys.executable)
    if exe.suffix.lower() == ".com" and exe.with_suffix(".exe").exists():
        return str(exe.with_suffix(".exe"))
    return None


HELP_TEXT = """runScan {version}: find out what was installed, updated or removed on this PC.

USAGE
  runScan [options]                  scan now (in a terminal: progress shown here, then the report opens)
  runScan <command> [options]        run a sysscan command (list below)

  Two files work together: runScan.exe (double-click, startup; no console) and runScan.com (terminal).
  Typing `runScan` in a terminal runs runScan.com automatically, so output appears in the terminal.

WHEN RUN WITHOUT A COMMAND
  (no options)            Terminal: scan with progress here, then open the report.
                          Double-click: ask for admin rights once, show a progress window, open the report.
                          Reports what changed since the previous scan (first run: last 30 days).
  --no-elevate            Don't ask for administrator rights (some sources are skipped).
  --startup               Silent scan: no window, no browser (what the scheduled task runs).
  --install-startup       Scan automatically every day and 10 minutes after sign-in.
      --time HH:MM        Daily time for --install-startup (default 09:00).
                          Any scan options you add are saved in the task.
  --remove-startup        Stop the automatic scans.

SCAN OPTIONS (work with all of the above)
  --since WHEN            Start of the period: 7d, 12h, 2026-09-01, "2026-09-01 14:00"
  --until WHEN            End of the period (default: now)
  --ai / --no-ai          Turn AI explanations on or off for this run
  --format LIST           Report files to write: html,md,json
  --out FOLDER            Where to save reports (quote paths with spaces)
  --only LIST / --skip LIST
                          Run only / skip these sources: registry, appx, drivers, reliability,
                          eventlog, windows-update, pip, npm, editor-extensions, scoop-choco
  --no-open               Don't open the report afterwards

COMMANDS  (add --help after any command for its options, e.g. runScan.exe tag --help)
  scan                    Same as running without a command
  history                 List previous scans
  open [N]                Open the latest report (or scan number N)
  demo                    Make a sample report from made-up data
  collectors              Show which sources can run here, and whether AI is set up
  unknowns [--edit]       List what the latest report couldn't identify
  tag NAME ...            Record what something is (--publisher, --description, --routine, --regex)
  untag NAME              Remove one of your tags
  tags                    List your tags
  retag                   Apply your tags to the latest report without rescanning
  schedule install|remove|status

EXAMPLES
  runScan.exe --since 7d
  runScan.exe --install-startup --time 20:00 --format html,json --out "D:\\Reports"
  runScan.exe tag "PowerENGAGE" --publisher "Example Corp" --description "What it is"

FILES
  Reports, snapshots, tags and settings: %LOCALAPPDATA%\\sysscan
  Put a .env file (ANTHROPIC_API_KEY=..., SYSSCAN_AI=true) next to runScan.exe or in that folder.
"""


def no_console() -> bool:
    """True when built as a windowed exe (print() output would be lost)."""
    return sys.stdout is None or (getattr(sys, "frozen", False) and not _has_console())


def _has_console() -> bool:
    if not IS_WINDOWS:
        return True
    try:
        return bool(ctypes.windll.kernel32.GetConsoleWindow())  # type: ignore[attr-defined]
    except Exception:
        return False


def show_text(title: str, text: str) -> None:
    """Show longer text (help, command output) in a scrollable window with a Copy button."""
    text = text.rstrip() or "(no output)"
    try:
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        root = tk.Tk()
        root.title(f"{APP_TITLE}: {title}")
        lines = text.count("\n") + 1
        box = ScrolledText(root, wrap="none", font=("Consolas", 10), width=104, height=min(max(lines, 8), 40))
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=8, pady=(0, 8))

        def copy() -> None:
            root.clipboard_clear()
            root.clipboard_append(text)
            copy_btn.configure(text="Copied")

        copy_btn = ttk.Button(bar, text="Copy", command=copy)
        copy_btn.pack(side="left")
        ttk.Button(bar, text="Close", command=root.destroy).pack(side="right")
        root.bind("<Escape>", lambda _e: root.destroy())
        root.mainloop()
    except Exception:
        message(text[:3000])  # no Tk: a plain message box still shows the essentials


def run_cli_visibly(args: list[str]) -> int:
    """Run a sysscan command; in a windowed exe, show what it printed instead of losing it."""
    from sysscan.cli import main as cli_main

    if not no_console():
        return cli_main(args)
    if args and args[0] == "set-key":
        message("set-key needs a console to type the key into.\n\nPut ANTHROPIC_API_KEY=... in a .env file next "
                "to runScan.exe (or in %LOCALAPPDATA%\\sysscan) instead.", _MB_ICONINFO)
        return 1
    import contextlib
    import io

    buf = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            code = int(cli_main(args) or 0)
        except SystemExit as exc:  # argparse --help / usage errors
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
    output = buf.getvalue()
    if output.strip():
        show_text(" ".join(args[:2]), output.replace("usage: sysscan", "usage: runScan.exe"))
    return code


def relaunch_elevated(args: list[str]) -> bool:
    """Start this exe again with a UAC prompt. True if the elevated copy started (user said yes)."""
    if not IS_WINDOWS:
        return False
    params = subprocess.list2cmdline(args)
    target = sibling_gui_exe() or sys.executable
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, None, 1)  # type: ignore[attr-defined]
    return int(rc) > 32


def _setup_logging(cfg) -> None:
    cfg.home.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=[logging.FileHandler(cfg.home / "sysscan.log", encoding="utf-8")])


LAUNCHER_FLAGS = {"--startup", "--install-startup", "--remove-startup", "--no-elevate", "--elevated"}


def split_args(args: list[str]) -> tuple[list[str], str]:
    """Separate runScan.exe's own flags from scan options. Returns (scan_args, time for --install-startup)."""
    scan_args: list[str] = []
    time = "09:00"
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--time" and i + 1 < len(args):
            time = args[i + 1]
            i += 2
            continue
        if a.startswith("--time="):
            time = a.split("=", 1)[1]
        elif a not in LAUNCHER_FLAGS:
            scan_args.append(a)
        i += 1
    return scan_args, time


def _parse(scan_args: list[str]):
    """Parse scan options; show a message box and return None if they're invalid."""
    from sysscan.cli import parse_scan_args

    try:
        return parse_scan_args(scan_args)
    except ValueError as exc:
        message(f"{exc}\n\nrunScan.exe accepts the same options as `sysscan scan`, e.g.\n"
                "--since 7d   --format html,json   --out D:\\Reports   --skip npm   --ai", _MB_ICONERROR)
        return None


def _run_scan(cfg, ns, progress: Callable[[str], None]):
    from sysscan.cli import scan_options_from_args
    from sysscan.scan import scan_and_report

    return scan_and_report(cfg, scan_options_from_args(ns, cfg), progress,
                           formats=ns.format.split(",") if ns.format else None, out_dir=ns.out)


# ----------------------------------------------------------------------------- modes

def startup_scan(scan_args: list[str]) -> int:
    cfg = load_config()
    _setup_logging(cfg)
    ns = _parse_quiet(scan_args)
    if ns is None:
        return 2
    log.info("startup scan (admin=%s, options=%s)", is_admin(), scan_args)
    try:
        _run_scan(cfg, ns, lambda m: log.info(m))
        return 0
    except Exception:
        log.exception("startup scan failed")
        return 1


def _parse_quiet(scan_args: list[str]):
    """Like _parse, but for unattended runs: log instead of popping up a message box."""
    from sysscan.cli import parse_scan_args

    try:
        return parse_scan_args(scan_args)
    except ValueError as exc:
        log.error("invalid startup options %s: %s", scan_args, exc)
        return None


def interactive_scan(scan_args: list[str]) -> int:
    cfg = load_config()
    _setup_logging(cfg)
    ns = _parse(scan_args)
    if ns is None:
        return 2
    result: dict = {}

    def work(progress: Callable[[str], None]) -> None:
        try:
            result["report"], result["written"] = _run_scan(cfg, ns, progress)
        except Exception as exc:
            log.exception("scan failed")
            result["error"] = exc

    try:
        ProgressWindow(work, admin=is_admin()).run()
    except Exception:  # no Tk available: scan without a window
        log.warning("progress window unavailable; scanning headless", exc_info=True)
        work(lambda m: log.info(m))

    if "error" in result:
        message(f"The scan failed:\n\n{result['error']}\n\nDetails: {cfg.home / 'sysscan.log'}", _MB_ICONERROR)
        return 1
    written = result.get("written") or {}
    if "html" in written and not ns.no_open:
        from sysscan.cli import _open

        _open(written["html"])
    elif written:
        message("Scan finished. Reports saved to:\n" + "\n".join(str(p) for p in written.values()))
    return 0


def install_startup(scan_args: list[str], time: str) -> int:
    from sysscan import schedule

    if _parse(scan_args) is None:  # check the options now, not at 9 am tomorrow
        return 2
    if IS_WINDOWS and not is_admin():
        if relaunch_elevated(["--install-startup", "--time", time, *scan_args]):
            if not no_console():
                print("Approve the administrator prompt; the result appears in a message box.")
            return 0
        message("Administrator rights are needed to add sysscan to startup.", _MB_ICONWARNING)
        return 1
    ok, msg = schedule.install(time, extra_args=scan_args)
    message(msg, _MB_ICONINFO if ok else _MB_ICONERROR)
    return 0 if ok else 1


def remove_startup() -> int:
    from sysscan import schedule

    ok, msg = schedule.remove()
    message(msg, _MB_ICONINFO if ok else _MB_ICONERROR)
    return 0 if ok else 1


# ----------------------------------------------------------------------------- progress window

class ProgressWindow:
    """Tiny Tk window: indeterminate bar + current step, closes itself when the scan ends."""

    def __init__(self, work: Callable[[Callable[[str], None]], None], admin: bool):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.root = tk.Tk()
        self.root.title(f"{APP_TITLE} {__version__}")
        self.root.resizable(False, False)
        self.root.attributes("-topmost", True)
        frame = ttk.Frame(self.root, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Scanning this PC for software changes…", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.step = tk.StringVar(value="Starting")
        ttk.Label(frame, textvariable=self.step, width=56).pack(anchor="w", pady=(6, 10))
        bar = ttk.Progressbar(frame, mode="indeterminate", length=380)
        bar.pack(fill="x")
        bar.start(12)
        if not admin:
            ttk.Label(frame, text="Running without administrator rights: some sources will be skipped.",
                      foreground="#8a5a00").pack(anchor="w", pady=(10, 0))
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 3
        self.root.geometry(f"+{x}+{y}")
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)  # scan can't be cancelled midway safely
        # The worker thread never touches Tk directly; it posts messages that the UI thread polls.
        self.messages: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.thread = threading.Thread(target=work, args=(self.messages.put,), daemon=True)

    def _poll(self) -> None:
        latest = None
        while not self.messages.empty():
            latest = self.messages.get()
        if latest:
            self.step.set(latest)
        if self.thread.is_alive():
            self.root.after(150, self._poll)
        else:
            self.root.destroy()

    def run(self) -> None:
        self.thread.start()
        self.root.after(200, self._poll)
        self.root.mainloop()


# ----------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    from sysscan.envfile import load_env_files

    load_env_files()
    console = not no_console()
    if any(a in ("-h", "--help", "/?", "-?") for a in args) and not (args and args[0] in CLI_COMMANDS):
        help_text = HELP_TEXT.format(version=__version__)
        if console:
            print(help_text)
        else:
            show_text("help", help_text)
        return 0
    if args and (args[0] in CLI_COMMANDS or args[0] == "--version"):
        return run_cli_visibly(args)

    scan_args, time = split_args(args)
    if "--startup" in args:
        return startup_scan(scan_args)
    if "--install-startup" in args:
        return install_startup(scan_args, time)
    if "--remove-startup" in args:
        return remove_startup()

    if console:
        # Typed in a terminal (runScan.com): behave like `sysscan scan`: progress and summary right here.
        from sysscan.cli import main as cli_main

        if IS_WINDOWS and not is_admin():
            print("Tip: run this in an administrator terminal for complete results.\n")
        return cli_main(["scan", *scan_args])

    # Double-click (runScan.exe): one UAC prompt. If accepted, the elevated copy scans and this one exits.
    wants_elevation = IS_WINDOWS and not is_admin() and not {"--no-elevate", "--elevated"} & set(args)
    if wants_elevation and relaunch_elevated([*args, "--elevated"]):
        return 0
    return interactive_scan(scan_args)


if __name__ == "__main__":
    raise SystemExit(main())
