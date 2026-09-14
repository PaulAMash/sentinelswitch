"""SQLite schema and connection helpers. Documents are stored as JSON text with a few indexed columns."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (hostname TEXT PRIMARY KEY, mac TEXT, ip TEXT, vlan INTEGER, interface TEXT, role TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS unknown_devices (mac TEXT PRIMARY KEY, interface TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, department TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, ts TEXT, source TEXT, severity TEXT, status TEXT, incident_id TEXT, detection_id TEXT, device TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS detections (id TEXT PRIMARY KEY, ts TEXT, rule TEXT, severity TEXT, confidence REAL, disposition TEXT, incident_id TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, opened_at TEXT, severity TEXT, status TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews (detection_id TEXT PRIMARY KEY, opened_at TEXT, status TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS timelines (owner_id TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS containment_actions (workflow_id TEXT PRIMARY KEY, incident_id TEXT, ts TEXT, status TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_events (event_id TEXT PRIMARY KEY, ts TEXT, username TEXT, result TEXT, method TEXT, interface TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS traffic_buckets (ts TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS validation_results (scenario_id TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scenarios (id TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_events(ts);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


def reset_schema(conn: sqlite3.Connection) -> None:
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        conn.execute(f"DROP TABLE IF EXISTS {name}")
    conn.executescript(SCHEMA)
    conn.commit()


@contextmanager
def tx(conn: sqlite3.Connection):
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def loads(text: str) -> Any:
    return json.loads(text)
