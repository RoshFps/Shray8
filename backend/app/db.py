"""SQLite storage. One small file holds everything the collectors report."""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    hostname         TEXT PRIMARY KEY,
    department       TEXT NOT NULL,
    os               TEXT NOT NULL,
    av_enabled       INTEGER NOT NULL,
    pending_critical INTEGER NOT NULL,
    pending_security INTEGER NOT NULL,
    pending_optional INTEGER NOT NULL,
    last_seen        TEXT NOT NULL,
    forced_online    INTEGER            -- NULL = use heartbeat; 0/1 = fixed (sample data)
);
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname     TEXT NOT NULL,
    time         TEXT NOT NULL,
    process      TEXT NOT NULL,
    command_line TEXT NOT NULL,
    reason       TEXT NOT NULL,
    UNIQUE (hostname, time, command_line)
);
CREATE TABLE IF NOT EXISTS packages (
    hostname   TEXT NOT NULL,
    name       TEXT NOT NULL,
    baseline   INTEGER NOT NULL,        -- 1 = present at first check-in (trusted)
    first_seen TEXT NOT NULL,
    PRIMARY KEY (hostname, name)
);
"""


def db_path() -> str:
    return os.environ.get("DB_PATH", "esd.db")


@contextmanager
def connect():
    conn = sqlite3.connect(db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # readers don't block the collectors' writes
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def purge_old_events(days: int) -> int:
    """Delete suspicious-process events older than `days`. Returns how many were removed."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with connect() as conn:
        return conn.execute("DELETE FROM events WHERE time < ?", (cutoff,)).rowcount
