"""CI helper: fail if any collector that should run on this machine failed during a real scan."""

import json
import sys
from pathlib import Path

reports = sorted(Path(sys.argv[1]).glob("*.json"))
if not reports:
    sys.exit("no JSON report produced")
data = json.loads(reports[-1].read_text(encoding="utf-8"))
failed = [c for c in data["collectors"] if not c["ok"] and not c["message"].startswith("skipped")]
for c in data["collectors"]:
    print(f"{c['name']:<18} ok={c['ok']!s:<5} items={c['items']:<5} events={c['events']:<5} {c['message']}")
print("summary:", data["summary"])
if failed:
    sys.exit(f"collectors failed: {[c['name'] for c in failed]}")
if not any(c["items"] for c in data["collectors"] if c["name"] == "registry"):
    sys.exit("registry collector returned no programs")
