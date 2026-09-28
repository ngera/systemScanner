"""PyInstaller entry script for runScan.exe (see scripts/build_exe.py)."""

from sysscan.launcher import main

raise SystemExit(main())
