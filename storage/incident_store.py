import sqlite3
import json
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

class IncidentStore:
    """
    SQLite-based persistent store for tracking incident cases, investigator notes,
    timeline chains, and active mitigation decisions.
    """
    def __init__(self, db_path: Path = Path("data/logs/incidents.db")):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    campaign_id TEXT PRIMARY KEY,
                    attacker_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL,
                    stages TEXT NOT NULL,
                    assigned_analyst TEXT,
                    detected_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    notes TEXT NOT NULL DEFAULT '[]',
                    timeline TEXT NOT NULL DEFAULT '[]',
                    mitigations TEXT NOT NULL DEFAULT '[]'
                )
            """)
            conn.commit()

    def upsert_incident(self, incident: Dict[str, Any]) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO incidents (campaign_id, attacker_ip, severity, risk_score, status, stages, assigned_analyst, detected_at, updated_at, notes, timeline, mitigations)
                VALUES (:campaign_id, :attacker_ip, :severity, :risk_score, :status, :stages, :assigned_analyst, :detected_at, :updated_at, :notes, :timeline, :mitigations)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    severity = excluded.severity,
                    risk_score = excluded.risk_score,
                    status = excluded.status,
                    stages = excluded.stages,
                    assigned_analyst = COALESCE(excluded.assigned_analyst, assigned_analyst),
                    updated_at = excluded.updated_at,
                    notes = excluded.notes,
                    timeline = excluded.timeline,
                    mitigations = excluded.mitigations
            """, {
                "campaign_id": incident["campaign_id"],
                "attacker_ip": incident["attacker_ip"],
                "severity": incident["severity"],
                "risk_score": incident["risk_score"],
                "status": incident["status"],
                "stages": json.dumps(incident["stages"]),
                "assigned_analyst": incident.get("assigned_analyst"),
                "detected_at": incident["detected_at"],
                "updated_at": incident["updated_at"],
                "notes": json.dumps(incident.get("notes", [])),
                "timeline": json.dumps(incident.get("timeline", [])),
                "mitigations": json.dumps(incident.get("mitigations", []))
            })
            conn.commit()

    def get_incident(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM incidents WHERE campaign_id = ?", (campaign_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return {
                "campaign_id": r["campaign_id"],
                "attacker_ip": r["attacker_ip"],
                "severity": r["severity"],
                "risk_score": r["risk_score"],
                "status": r["status"],
                "stages": json.loads(r["stages"]),
                "assigned_analyst": r["assigned_analyst"],
                "detected_at": r["detected_at"],
                "updated_at": r["updated_at"],
                "notes": json.loads(r["notes"]),
                "timeline": json.loads(r["timeline"]),
                "mitigations": json.loads(r["mitigations"])
            }

    def list_incidents(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if status:
                cursor = conn.execute("SELECT * FROM incidents WHERE status = ? ORDER BY updated_at DESC LIMIT ?", (status, limit))
            else:
                cursor = conn.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "campaign_id": r["campaign_id"],
                    "attacker_ip": r["attacker_ip"],
                    "severity": r["severity"],
                    "risk_score": r["risk_score"],
                    "status": r["status"],
                    "stages": json.loads(r["stages"]),
                    "assigned_analyst": r["assigned_analyst"],
                    "detected_at": r["detected_at"],
                    "updated_at": r["updated_at"],
                    "notes": json.loads(r["notes"]),
                    "timeline": json.loads(r["timeline"]),
                    "mitigations": json.loads(r["mitigations"])
                })
            return results
