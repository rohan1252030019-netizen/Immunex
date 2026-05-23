import time
from typing import Dict, Any, Optional
from storage.incident_store import IncidentStore

class SOCReportingEngine:
    """
    Compiles operational SOC analytics and audit logs to structure formal summaries.
    """
    def __init__(self, store: IncidentStore) -> None:
        self._store = store

    def compile_incident_report_data(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        inc = self._store.get_incident(campaign_id)
        if not inc:
            return None
            
        return {
            "report_id": f"REP-{campaign_id[:8]}",
            "generated_at": time.time(),
            "summary": {
                "campaign_id": inc["campaign_id"],
                "attacker_ip": inc["attacker_ip"],
                "severity": inc["severity"],
                "risk_score": inc["risk_score"],
                "status": inc["status"],
                "stages": inc["stages"],
                "assigned_analyst": inc["assigned_analyst"] or "Unassigned"
            },
            "notes": inc["notes"],
            "timeline": inc["timeline"],
            "mitigations": inc["mitigations"]
        }
