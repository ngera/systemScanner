"""SQLite persistence: scan runs, inventory snapshots and the description cache."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sysscan.models import Category, InventoryItem, TimeConfidence
from sysscan.winutil import parse_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    host         TEXT,
    is_admin     INTEGER,
    collectors   TEXT,           -- JSON: collectors that succeeded (snapshot coverage)
    report_path  TEXT,
    tool_version TEXT
);
CREATE TABLE IF NOT EXISTS items (
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    category        TEXT NOT NULL,
    source          TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT,
    publisher       TEXT,
    install_time    TEXT,
    time_confidence TEXT,
    scope           TEXT,
    description     TEXT,
    extra           TEXT,
    PRIMARY KEY (scan_id, key)
);
CREATE TABLE IF NOT EXISTS descriptions (
    norm_key    TEXT PRIMARY KEY,
    description TEXT NOT NULL,   -- '' = asked the AI, it had no description
    source      TEXT NOT NULL,   -- ai | ai-low
    model       TEXT,
    created_at  TEXT NOT NULL,
    publisher   TEXT,            -- NULL = never asked; '' = asked, unknown
    source_url  TEXT             -- page that confirmed a web-assisted answer
);
"""


@dataclass
class CachedAnswer:
    description: str
    source: str
    publisher: str | None  # None = never asked, "" = asked but unknown
    source_url: str | None = None


@dataclass
class ScanRecord:
    id: int
    started_at: datetime
    finished_at: datetime | None
    host: str
    is_admin: bool
    collectors: list[str]
    report_path: str | None


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(descriptions)")}
        if "publisher" not in cols:  # databases created by sysscan 0.1/0.2
            self.conn.execute("ALTER TABLE descriptions ADD COLUMN publisher TEXT")
        if "source_url" not in cols:  # databases created before 0.4
            self.conn.execute("ALTER TABLE descriptions ADD COLUMN source_url TEXT")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ scans

    def start_scan(self, started_at: datetime, host: str, is_admin: bool, tool_version: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (started_at, host, is_admin, tool_version) VALUES (?, ?, ?, ?)",
            (started_at.isoformat(), host, int(is_admin), tool_version),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def finish_scan(self, scan_id: int, finished_at: datetime, collectors: list[str]) -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at = ?, collectors = ? WHERE id = ?",
            (finished_at.isoformat(), json.dumps(sorted(collectors)), scan_id),
        )
        self.conn.commit()

    def set_report_path(self, scan_id: int, path: str) -> None:
        self.conn.execute("UPDATE scans SET report_path = ? WHERE id = ?", (path, scan_id))
        self.conn.commit()

    def _scan(self, row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            id=row["id"],
            started_at=parse_iso(row["started_at"]),  # type: ignore[arg-type]
            finished_at=parse_iso(row["finished_at"]),
            host=row["host"] or "",
            is_admin=bool(row["is_admin"]),
            collectors=json.loads(row["collectors"] or "[]"),
            report_path=row["report_path"],
        )

    def scans(self) -> list[ScanRecord]:
        rows = self.conn.execute(
            "SELECT * FROM scans WHERE finished_at IS NOT NULL ORDER BY started_at"
        ).fetchall()
        return [self._scan(r) for r in rows]

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._scan(row) if row else None

    def baseline_before(self, when: datetime, exclude: int | None = None) -> ScanRecord | None:
        """Latest completed scan that started at or before ``when``."""
        candidates = [s for s in self.scans() if s.started_at <= when and s.id != exclude]
        return candidates[-1] if candidates else None

    def first_scan_after(self, when: datetime, exclude: int | None = None) -> ScanRecord | None:
        candidates = [s for s in self.scans() if s.started_at >= when and s.id != exclude]
        return candidates[0] if candidates else None

    # ------------------------------------------------------------------ items

    def save_items(self, scan_id: int, items: list[InventoryItem]) -> None:
        rows = []
        seen: set[str] = set()
        for it in items:
            if it.key in seen:
                continue
            seen.add(it.key)
            rows.append((
                scan_id, it.key, str(it.category), it.source, it.name, it.version, it.publisher,
                it.install_time.isoformat() if it.install_time else None, str(it.time_confidence),
                it.scope, it.description, json.dumps(it.extra, default=str) if it.extra else None,
            ))
        self.conn.executemany(
            "INSERT INTO items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows
        )
        self.conn.commit()

    def load_items(self, scan_id: int) -> list[InventoryItem]:
        rows = self.conn.execute("SELECT * FROM items WHERE scan_id = ?", (scan_id,)).fetchall()
        return [
            InventoryItem(
                key=r["key"],
                category=Category(r["category"]),
                source=r["source"],
                name=r["name"],
                version=r["version"],
                publisher=r["publisher"],
                install_time=parse_iso(r["install_time"]),
                time_confidence=TimeConfidence(r["time_confidence"] or "unknown"),
                scope=r["scope"] or "machine",
                description=r["description"],
                extra=json.loads(r["extra"]) if r["extra"] else {},
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ description cache

    def get_description(self, norm_key: str) -> CachedAnswer | None:
        row = self.conn.execute(
            "SELECT description, source, publisher, source_url FROM descriptions WHERE norm_key = ?", (norm_key,)
        ).fetchone()
        return CachedAnswer(row["description"] or "", row["source"], row["publisher"], row["source_url"]) if row else None

    def put_description(self, norm_key: str, text: str, source: str, model: str | None,
                        now: datetime, publisher: str | None = None, source_url: str | None = None) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO descriptions "
            "(norm_key, description, source, model, created_at, publisher, source_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (norm_key, text or "", source, model, now.isoformat(), publisher, source_url),
        )
        self.conn.commit()
