"""Remote access & monitoring check.

    result = run_security(cfg, store, since=..., installed_names=[...])

Collects the PC's current state and remote-session history, grades it into findings, applies the user's
trusted list (``trusted.toml``), and compares with the previous check so new problems stand out.
Each finding lists the exact files and places involved, file facts (hash, signer, version info) and
step-by-step fixes (``remedy.py``). Nothing here changes the PC; every query is read-only.

Findings are not sent to the AI. Only when the AI lookup is turned on (``ai_lookup.py``) are facts about the
flagged *files* (name, folder without your user name, signer, version info, hash) sent for identification.
"""

from __future__ import annotations

import json
import logging
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sysscan.security.analyze import (
    ALERT,
    AREAS,
    INFO,
    OK,
    STATUS_ORDER,
    WARN,
    Finding,
    analyze,
    paths_needing_signature,
    refine_with_files,
)
from sysscan.security.probe import (
    collect_history,
    collect_state,
    file_facts,
    parse_history,
    read_tool_logs,
)
from sysscan.security.remedy import add_fixes
from sysscan.winutil import IS_WINDOWS, is_admin, parse_iso, utcnow

log = logging.getLogger(__name__)

__all__ = ["ALERT", "AREAS", "INFO", "OK", "WARN", "Finding", "SecurityResult", "TrustList", "run_security"]


@dataclass
class SecurityResult:
    checked_at: datetime
    since: datetime | None
    is_admin: bool
    findings: list[Finding]
    previous_at: datetime | None = None
    resolved: list[Finding] = field(default_factory=list)  # problems last time that are gone now
    errors: list[str] = field(default_factory=list)
    ai: str | None = None  # provider label when the AI lookup ran, e.g. "Claude with web search"
    ai_notes: list[str] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for f in self.findings if f.status == status and not f.trusted)

    @property
    def new(self) -> list[Finding]:
        return [f for f in self.findings if f.new]

    def by_area(self) -> list[tuple[str, str, list[Finding]]]:
        return [(a, label, [f for f in self.findings if f.area == a]) for a, label in AREAS.items()
                if any(f.area == a for f in self.findings)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at.isoformat(), "since": self.since.isoformat() if self.since else None,
            "is_admin": self.is_admin, "previous_at": self.previous_at.isoformat() if self.previous_at else None,
            "summary": {s: self.count(s) for s in (ALERT, WARN, OK, INFO)},
            "findings": [f.to_dict() for f in self.findings], "resolved": [f.to_dict() for f in self.resolved],
            "errors": self.errors, "ai": self.ai, "ai_notes": self.ai_notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SecurityResult:
        return cls(checked_at=parse_iso(d["checked_at"]), since=parse_iso(d.get("since")),  # type: ignore[arg-type]
                   is_admin=bool(d.get("is_admin")), findings=[Finding.from_dict(f) for f in d.get("findings", [])],
                   previous_at=parse_iso(d.get("previous_at")),
                   resolved=[Finding.from_dict(f) for f in d.get("resolved", [])], errors=list(d.get("errors", [])),
                   ai=d.get("ai"), ai_notes=list(d.get("ai_notes", [])))


# ----------------------------------------------------------------------------- trusted list

TRUST_HEADER = """# sysscan: security findings you've checked and trust (e.g. your own AnyDesk, your Tailscale network).
# Trusted findings are shown greyed out with your note and don't count as problems.
# Manage with `sysscan trust KEY --note "…"`, `sysscan untrust KEY` and `sysscan trusted`.
"""


class TrustList:
    def __init__(self, path: Path):
        self.path = path
        self.entries: dict[str, str] = {}
        self.errors: list[str] = []
        if path.exists():
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
                for e in data.get("trusted", []):
                    if isinstance(e, dict) and e.get("key"):
                        self.entries[str(e["key"])] = str(e.get("note") or "")
            except (OSError, tomllib.TOMLDecodeError) as exc:
                self.errors.append(f"Could not read {path.name}: {exc}")

    def match(self, key: str) -> str | None:
        """Exact key, or a prefix entry ending in '*' (e.g. 'sessions:anydesk:*')."""
        if key in self.entries:
            return self.entries[key] or "trusted"
        for k, note in self.entries.items():
            if k.endswith("*") and key.startswith(k[:-1]):
                return note or "trusted"
        return None

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n\n".join(f"[[trusted]]\nkey = {json.dumps(k)}\nnote = {json.dumps(v, ensure_ascii=False)}"
                           for k, v in self.entries.items())
        self.path.write_text(TRUST_HEADER + "\n" + body + ("\n" if body else ""), encoding="utf-8")

    def apply(self, findings: list[Finding]) -> None:
        for f in findings:
            note = self.match(f.key)
            if note and f.status in (ALERT, WARN):
                f.trusted, f.trust_note = True, note


# ----------------------------------------------------------------------------- comparison with last time

def mark_changes(findings: list[Finding], previous: list[dict[str, str]]) -> list[Finding]:
    """Flag findings that are new or got worse; return previous problems that have disappeared."""
    prev = {p["key"]: p for p in previous}
    for f in findings:
        p = prev.get(f.key)
        if f.status in (ALERT, WARN) and (p is None or STATUS_ORDER.get(f.status, 9) < STATUS_ORDER.get(p["status"], 9)):
            f.new = bool(previous)  # nothing is "new" on the very first check
    current = {f.key for f in findings}
    return [Finding(p["key"], p["area"], OK, p["title"], "This was reported last time and is no longer present.")
            for p in previous if p["status"] in (ALERT, WARN) and p["key"] not in current]


# ----------------------------------------------------------------------------- run

MAX_FILE_FACTS = 80


def attach_file_facts(findings: list[Finding], facts: dict[str, dict[str, Any]]) -> None:
    for f in findings:
        f.files = [facts[p.lower()] for p in f.paths if p and p.lower() in facts]


def run_security(cfg, store, since: datetime | None, installed_names: list[str], progress=lambda _m: None,
                 scan_id: int | None = None, installed_info: dict[str, dict] | None = None,
                 use_ai: bool | None = None, describer_factory=None) -> SecurityResult:
    now = utcnow()
    errors: list[str] = []
    if not IS_WINDOWS:
        return SecurityResult(now, since, False, [], errors=["The remote access & monitoring check is Windows-only."])

    progress("Security: checking remote access and monitoring settings")
    try:
        state = collect_state()
    except Exception as exc:
        log.exception("security state failed")
        state, errors = {}, [f"Couldn't read the current state: {exc}"]
    errors += [f"{k[:-6]}: {v}" for k, v in state.items() if k.endswith("_error")]

    facts: dict[str, dict[str, Any]] = {}
    paths = paths_needing_signature(state)
    if paths:
        try:
            facts = file_facts(paths[:MAX_FILE_FACTS])
        except Exception as exc:
            errors.append(f"signature check: {exc}")
    signatures = {k: {"status": str(v.get("sig_status") or "") if v.get("exists") else "Missing"}
                  for k, v in facts.items() if not v.get("error")}

    progress("Security: reading remote-session history")
    sessions = []
    if since is not None:
        try:
            sessions, hist_errors = parse_history(collect_history(since))
            errors += hist_errors
        except Exception as exc:
            log.exception("security history failed")
            errors.append(f"session history: {exc}")
        sessions += read_tool_logs(since)

    findings = analyze(state, sessions, installed_names, signatures, since, installed_info)

    # Exact files behind everything that needs attention: hash, signer and version info.
    wanted = [p for f in findings if f.status in (ALERT, WARN) for p in f.paths if p and p.lower() not in facts]
    if wanted:
        progress("Security: checking the files involved")
        try:
            facts |= file_facts(list(dict.fromkeys(wanted))[:MAX_FILE_FACTS])
        except Exception as exc:
            errors.append(f"file details: {exc}")
    attach_file_facts(findings, facts)
    refine_with_files(findings)

    admin = is_admin()
    if not admin:
        errors.append("Not running as administrator: Remote Desktop sign-ins from the Security log and some "
                      "process details were not available.")

    trust = TrustList(cfg.trusted_path)
    errors += trust.errors
    trust.apply(findings)

    ai_label, ai_notes = None, []
    if cfg.security_ai if use_ai is None else use_ai:
        from sysscan.security.ai_lookup import lookup

        try:
            ai_label, ai_notes = lookup(findings, cfg, store, progress, describer_factory)
        except Exception as exc:
            log.exception("security AI lookup failed")
            ai_notes = [f"AI lookup failed: {exc}"]
    add_fixes(findings)

    previous_at, previous = store.last_security_findings()
    resolved = mark_changes(findings, previous)
    store.save_security_findings(now, scan_id, [f.to_dict() for f in findings])
    return SecurityResult(now, since, admin, findings, previous_at, resolved, errors, ai_label, ai_notes)
