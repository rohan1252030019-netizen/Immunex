import sqlite3
import json
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

class AuditStore:
    """
    SQLite-based store for recording and fetching administrative, authorization,
    and mitigation audit trails. Integrates seamlessly with immutable log formats.
    """
    def __init__(self, db_path: Path = Path("data/logs/audit.db")):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    user_identity TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    api_endpoint TEXT,
                    details TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def log_event(self, timestamp: float, user_identity: str, action_type: str, 
                  api_endpoint: Optional[str], details: Dict[str, Any], 
                  prev_hash: str, block_hash: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO audit_logs (timestamp, user_identity, action_type, api_endpoint, details, previous_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, user_identity, action_type, api_endpoint, json.dumps(details), prev_hash, block_hash))
            conn.commit()

    def get_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            logs = []
            for r in rows:
                logs.append({
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "user_identity": r["user_identity"],
                    "action_type": r["action_type"],
                    "api_endpoint": r["api_endpoint"],
                    "details": json.loads(r["details"]) if r["details"] else {},
                    "previous_hash": r["previous_hash"],
                    "block_hash": r["block_hash"]
                })
            return logs

    def get_latest_hash(self) -> str:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT block_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else "0" * 64
            
    def count_logs(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM audit_logs")
            row = cursor.fetchone()
            return row[0] if row else 0
