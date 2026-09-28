# Contributing

Thanks for helping! Useful contributions, roughly in order of impact:

1. **Description rules**: add a `(regex, text)` pair to `src/sysscan/describe/rules.py` for software you
   see a lot. Keep the text short, plain and free of marketing language. Add a test if the regex is tricky.
2. **Routine patterns**: noisy auto-updaters that clutter reports belong in `src/sysscan/classify.py`.
3. **Parser fixes**: if a collector misreads your machine, capture the raw output (each collector's
   PowerShell snippet can be run directly) and add it as a test fixture. Remove anything personal first.
4. **New collectors**: subclass `Collector` in `src/sysscan/collectors/`, keep parsing in a pure
   function, and register it in `collectors/__init__.py`.

## Setup

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev,ai]"
pytest
ruff check .
```

## Building runScan (Windows)

```powershell
python -m venv .venv-build; .\.venv-build\Scripts\Activate.ps1
pip install -e ".[ai,build]"
python scripts\build_exe.py      # dist\runScan.exe (windowed) + dist\runScan.com (terminal)
```

Run it from the repository root. Test both halves: double-click `runScan.exe`, and run `.\runScan --help`
and `.\runScan --since 1d` in a terminal inside `dist`. CI builds both and smoke-tests them on every push;
tagging `v*` attaches them to a GitHub release. See "Packaging" in [docs/DESIGN.md](docs/DESIGN.md) for
why there are two files.

Never commit real scan reports or databases. They describe your machine. `.gitignore` excludes them.
