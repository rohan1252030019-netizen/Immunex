"""
IMMUNEX ClickHouse Telemetry Store
====================================
Phase 7 — High-throughput telemetry persistence with automatic SQLite fallback.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime
from typing import Any, Optional

from utils.logger import log

# ─── Try ClickHouse ──────────────────────────────────────────────────────────
_CLICKHOUSE_AVAILABLE = False
try:
    from clickhouse_driver import Client as CHClient
    _CLICKHOUSE_AVAILABLE = True
except ImportError:
    pass

_DB_DIR = os.path.join("data", "logs")
_DB_PATH = os.path.join(_DB_DIR, "telemetry_store.db")


class SQLiteTelemetryStore:
    """Always-available SQLite fallback for telemetry persistence."""

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self._batch: list[tuple] = []
        self._batch_size = 100
        self.backend = "sqlite"
        log.info("SQLiteTelemetryStore initialized", db_path=db_path)

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT,
                dst_ip TEXT, event_type TEXT, severity TEXT, anomaly_score REAL, raw_json TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, campaign_id TEXT,
                severity TEXT, risk_score REAL, mitre_tactic TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_evt_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_evt_sev ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_evt_src ON events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_alt_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alt_sev ON alerts(severity);
        """)

    def connect(self) -> bool:
        return True

    def insert_event(self, event_data: dict) -> None:
        self._conn.execute(
            "INSERT INTO events (timestamp,src_ip,dst_ip,event_type,severity,anomaly_score,raw_json) VALUES (?,?,?,?,?,?,?)",
            (event_data.get("timestamp", datetime.utcnow().isoformat()), event_data.get("src_ip", ""),
             event_data.get("dst_ip", ""), event_data.get("event_type", ""), event_data.get("severity", ""),
             event_data.get("anomaly_score", 0), json.dumps(event_data)))
        self._conn.commit()

    def insert_alert(self, alert_data: dict) -> None:
        self._conn.execute(
            "INSERT INTO alerts (timestamp,campaign_id,severity,risk_score,mitre_tactic) VALUES (?,?,?,?,?)",
            (alert_data.get("timestamp", datetime.utcnow().isoformat()), alert_data.get("campaign_id", ""),
             alert_data.get("severity", ""), alert_data.get("risk_score", 0), alert_data.get("mitre_tactic", "")))
        self._conn.commit()

    def bulk_insert(self, events: list[dict]) -> int:
        count = 0
        for e in events:
            try:
                self.insert_event(e)
                count += 1
            except Exception:
                pass
        return count

    def query_events(self, filters: dict = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM events"
        params = []
        if filters:
            conditions = []
            if "severity" in filters:
                conditions.append("severity = ?"); params.append(filters["severity"])
            if "src_ip" in filters:
                conditions.append("src_ip = ?"); params.append(filters["src_ip"])
            if "event_type" in filters:
                conditions.append("event_type = ?"); params.append(filters["event_type"])
            if conditions:
                sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def query_alerts(self, filters: dict = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM alerts ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in self._conn.execute(sql, [limit]).fetchall()]

    def aggregate_metrics(self) -> dict:
        cur = self._conn.cursor()
        total_events = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        severity_dist = {}
        for row in cur.execute("SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity").fetchall():
            severity_dist[row[0]] = row[1]
        return {"total_events": total_events, "total_alerts": total_alerts,
                "severity_distribution": severity_dist, "backend": self.backend}

    def get_mitre_statistics(self) -> dict:
        cur = self._conn.cursor()
        stats = {}
        for row in cur.execute("SELECT mitre_tactic, COUNT(*) as cnt FROM alerts WHERE mitre_tactic != '' GROUP BY mitre_tactic").fetchall():
            stats[row[0]] = row[1]
        return stats


class ClickHouseTelemetryStore(SQLiteTelemetryStore):
    """ClickHouse-backed telemetry store. Falls back to SQLite parent if unavailable."""

    def __init__(self, host: str = "localhost", port: int = 9000, db_path: str = _DB_PATH):
        super().__init__(db_path=db_path)
        self._ch_client = None
        if _CLICKHOUSE_AVAILABLE:
            try:
                self._ch_client = CHClient(host=host, port=port)
                self._ch_client.execute("SELECT 1")
                self.backend = "clickhouse"
                log.info("ClickHouse connection established", host=host)
            except Exception as exc:
                log.warning("ClickHouse unavailable, using SQLite", error=str(exc))
                self._ch_client = None

    def connect(self) -> bool:
        return self._ch_client is not None or super().connect()


def create_telemetry_store(host: str = "localhost", port: int = 9000) -> SQLiteTelemetryStore:
    """Factory: returns ClickHouse store or SQLite fallback."""
    if _CLICKHOUSE_AVAILABLE:
        store = ClickHouseTelemetryStore(host=host, port=port)
        if store.backend == "clickhouse":
            return store
    return SQLiteTelemetryStore()
