r"""Build runScan.exe with PyInstaller.

Run on Windows from the repo root, in a virtual environment:

    python -m venv .venv-build
    .\.venv-build\Scripts\Activate.ps1
    pip install -e ".[ai,build]"
    python scripts/build_exe.py            # -> dist\runScan.exe

Produces two files from the same code:
    dist\runScan.exe   windowed: double-click and the startup task (no console window ever appears)
    dist\runScan.com   console:  typing `runScan ...` in a terminal runs this one automatically
                       (Windows prefers .com over .exe), so output prints in the terminal.

Options:
    --onedir     build a folder instead of single files (starts faster, fewer antivirus false positives)
    --no-ai      leave the Anthropic SDK out (smaller; AI descriptions unavailable)
    --no-console skip runScan.com
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sysscan import __version__  # noqa: E402

VERSION_INFO = """VSVersionInfo(
  ffi=FixedFileInfo(filevers={v4}, prodvers={v4}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'sysscan (open source)'),
      StringStruct('FileDescription', 'sysscan: find what was installed, updated or uninstalled'),
      StringStruct('FileVersion', '{v}'),
      StringStruct('InternalName', 'runScan'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'runScan.exe'),
      StringStruct('ProductName', 'sysscan'),
      StringStruct('ProductVersion', '{v}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--onedir", action="store_true")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--no-console", action="store_true")
    opts = ap.parse_args()

    try:
        import PyInstaller.__main__ as pyinstaller
    except ImportError:
        print('PyInstaller is missing: pip install -e ".[build]"')
        return 1

    build = ROOT / "build" / "pyinstaller"
    build.mkdir(parents=True, exist_ok=True)
    parts = [int(p) for p in __version__.split(".")[:3] if p.isdigit()]
    v4 = tuple((parts + [0, 0, 0, 0])[:4])
    version_file = build / "version_info.txt"
    version_file.write_text(VERSION_INFO.format(v=__version__, v4=v4), encoding="utf-8")

    common = [
        str(ROOT / "packaging" / "runScan_entry.py"),
        "--onedir" if opts.onedir else "--onefile",
        "--clean", "--noconfirm",
        "--icon", str(ROOT / "packaging" / "runScan.ico"),
        "--version-file", str(version_file),
        "--paths", str(ROOT / "src"),
        "--collect-data", "sysscan",  # HTML report template
        "--specpath", str(build),
        "--exclude-module", "pytest",
    ]
    if not opts.no_ai and importlib.util.find_spec("anthropic"):
        common += ["--collect-submodules", "anthropic", "--copy-metadata", "anthropic"]
    if importlib.util.find_spec("keyring"):
        common += ["--copy-metadata", "keyring", "--hidden-import", "keyring.backends.Windows",
                   "--collect-submodules", "win32ctypes"]

    dist = ROOT / "dist"
    # 1) windowed: double-click + startup task
    pyinstaller.run([*common, "--name", "runScan", "--noconsole",
                     "--distpath", str(dist), "--workpath", str(build / "gui")])
    built = [dist / ("runScan" if opts.onedir else "runScan.exe")]

    # 2) console twin, renamed to .com so `runScan` in a terminal picks it (like devenv.com / devenv.exe)
    if not opts.no_console:
        tmp = build / "console-dist"
        pyinstaller.run([*common, "--name", "runScan", "--console",
                         "--distpath", str(tmp), "--workpath", str(build / "console")])
        if opts.onedir:
            # Both builds bundle the same runtime; the console launcher can share the windowed one's folder.
            target = dist / "runScan" / "runScan.com"
            shutil.copy2(tmp / "runScan" / "runScan.exe", target)
        else:
            target = dist / "runScan.com"
            shutil.copy2(tmp / "runScan.exe", target)
        built.append(target)

    print("\nBuilt:")
    for path in built:
        print(f"  {path}")
    print("Keep runScan.exe and runScan.com in the same folder.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
