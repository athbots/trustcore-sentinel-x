"""
TrustCore Sentinel X — SQLite Persistence Layer

Async SQLite database for storing events, alerts, and system state.
Uses aiosqlite for non-blocking I/O in the FastAPI async context.
Falls back to synchronous sqlite3 if aiosqlite is not installed.
"""
import json
import sqlite3
import time
from pathlib import Path

from sentinel.config import DB_PATH
from sentinel.utils.logger import get_logger

logger = get_logger("storage.database")

# ── Schema ───────────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    threat_level TEXT DEFAULT 'SAFE',
    action_taken TEXT DEFAULT 'LOG',
    raw_event TEXT,
    analysis_result TEXT,
    explanation TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_threat ON events(threat_level);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
"""


class Database:
    """
    Synchronous SQLite wrapper. Lightweight, zero-dependency.
    All writes are serialized through a single connection.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Create DB file and tables if they don't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        logger.info(f"Database initialized at {self._db_path}")

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Events ───────────────────────────────────────────────────────────────

    def store_event(
        self,
        timestamp: float,
        source: str,
        event_type: str,
        risk_score: int = 0,
        threat_level: str = "SAFE",
        action_taken: str = "LOG",
        raw_event: dict | None = None,
        analysis_result: dict | None = None,
        explanation: dict | None = None,
    ) -> int:
        """Insert an event record. Returns the row ID."""
        if not self._conn:
            self.initialize()
        cursor = self._conn.execute(
            """INSERT INTO events
               (timestamp, source, event_type, risk_score, threat_level,
                action_taken, raw_event, analysis_result, explanation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                timestamp,
                source,
                event_type,
                risk_score,
                threat_level,
                action_taken,
                json.dumps(raw_event) if raw_event else None,
                json.dumps(analysis_result) if analysis_result else None,
                json.dumps(explanation) if explanation else None,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """Get the most recent events."""
        if not self._conn:
            self.initialize()
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_event_stats(self) -> dict:
        """Get aggregate event statistics."""
        if not self._conn:
            self.initialize()

        total = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        by_level = {}
        for row in self._conn.execute(
            "SELECT threat_level, COUNT(*) as cnt FROM events GROUP BY threat_level"
        ):
            by_level[row["threat_level"]] = row["cnt"]

        by_source = {}
        for row in self._conn.execute(
            "SELECT source, COUNT(*) as cnt FROM events GROUP BY source"
        ):
            by_source[row["source"]] = row["cnt"]

        return {
            "total_events": total,
            "by_threat_level": by_level,
            "by_source": by_source,
        }

    def prune_old_events(self, max_age_days: int = 30) -> int:
        """Delete events older than max_age_days. Returns count deleted."""
        if not self._conn:
            return 0
        cutoff = time.time() - (max_age_days * 86400)
        cursor = self._conn.execute(
            "DELETE FROM events WHERE timestamp < ?", (cutoff,)
        )
        self._conn.commit()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(f"Pruned {deleted} events older than {max_age_days} days")
        return deleted

    # ── Settings ─────────────────────────────────────────────────────────────

    def get_setting(self, key: str, default: str = "") -> str:
        if not self._conn:
            self.initialize()
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        if not self._conn:
            self.initialize()
        self._conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (key, value),
        )
        self._conn.commit()


# ── Singleton instance ───────────────────────────────────────────────────────
db = Database()
