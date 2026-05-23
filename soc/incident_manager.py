import time
from typing import Dict, Any, Optional
from storage.incident_store import IncidentStore

class IncidentManager:
    """
    Coordinates and persists transitions across incident lifecycles (NEW -> INVESTIGATING -> CONTAINED -> RESOLVED).
    """
    def __init__(self, store: IncidentStore) -> None:
        self._store = store

    def create_incident(self, campaign_id: str, attacker_ip: str, 
                        severity: str, risk_score: float, stages: list) -> Dict[str, Any]:
        incident = {
            "campaign_id": campaign_id,
            "attacker_ip": attacker_ip,
            "severity": severity,
            "risk_score": risk_score,
            "status": "OPEN",
            "stages": stages,
            "assigned_analyst": None,
            "detected_at": time.time(),
            "updated_at": time.time(),
            "notes": [],
            "timeline": [{"timestamp": time.time(), "action": "Incident detected and logged", "tactic": "Initial-Access"}],
            "mitigations": []
        }
        self._store.upsert_incident(incident)
        return incident

    def create_incident_case(self, campaign_id: str, attacker_ip: str, 
                             severity: str, risk_score: float, stages: list) -> Dict[str, Any]:
        return self.create_incident(campaign_id, attacker_ip, severity, risk_score, stages)

    def add_note(self, campaign_id: str, author: str, note_text: str) -> bool:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return False
        notes = incident.setdefault("notes", [])
        notes.append({
            "author": author,
            "timestamp": time.time(),
            "note": note_text
        })
        incident["updated_at"] = time.time()
        self._store.upsert_incident(incident)
        return True

    def log_timeline_event(self, campaign_id: str, action: str, tactic: str) -> bool:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return False
        timeline = incident.setdefault("timeline", [])
        timeline.append({
            "timestamp": time.time(),
            "action": action,
            "tactic": tactic
        })
        incident["updated_at"] = time.time()
        self._store.upsert_incident(incident)
        return True

    def log_mitigation_action(self, campaign_id: str, action_type: str, scope: str, result: str) -> bool:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return False
        mitigations = incident.setdefault("mitigations", [])
        mitigations.append({
            "action_type": action_type,
            "scope": scope,
            "result": result,
            "timestamp": time.time()
        })
        incident["updated_at"] = time.time()
        self._store.upsert_incident(incident)
        return True

    def update_status(self, campaign_id: str, status: str) -> bool:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return False
        incident["status"] = status
        incident["updated_at"] = time.time()
        timeline = incident.setdefault("timeline", [])
        timeline.append({
            "timestamp": time.time(),
            "action": f"Incident state updated to {status}",
            "tactic": "SOC-Operations"
        })
        self._store.upsert_incident(incident)
        return True

    def transition_state(self, campaign_id: str, next_status: str) -> Optional[Dict[str, Any]]:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return None
        
        old_status = incident["status"]
        incident["status"] = next_status
        incident["updated_at"] = time.time()
        
        # Parse timeline to make sure it's a list
        timeline = incident.setdefault("timeline", [])
        timeline.append({
            "timestamp": time.time(),
            "action": f"State transitioned from {old_status} to {next_status}",
            "tactic": "SOC-Operations"
        })
        
        self._store.upsert_incident(incident)
        return incident
