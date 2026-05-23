import time
from typing import Dict, Any, List
from storage.incident_store import IncidentStore

class EscalationEngine:
    """
    Evaluates unresolved incidents against strict deadlines and escalates severity automatically.
    """
    def __init__(self, store: IncidentStore, max_unresolved_seconds: float = 60.0, age_threshold_seconds: float = None) -> None:
        self._store = store
        self.max_unresolved_seconds = age_threshold_seconds if age_threshold_seconds is not None else max_unresolved_seconds

    def check_and_escalate(self) -> List[Dict[str, Any]]:
        """Alias method for test compatibility."""
        return self.run_escalation_checks()

    def run_escalation_checks(self) -> List[Dict[str, Any]]:
        incidents = self._store.list_incidents()
        now = time.time()
        escalated_cases = []
        
        for inc in incidents:
            if inc["status"] in ["NEW", "INVESTIGATING", "OPEN"]:
                elapsed = now - inc["detected_at"]
                if elapsed > self.max_unresolved_seconds:
                    old_sev = inc["severity"]
                    if old_sev == "LOW":
                        inc["severity"] = "MEDIUM"
                    elif old_sev == "MEDIUM":
                        inc["severity"] = "HIGH"
                    elif old_sev == "HIGH":
                        inc["severity"] = "CRITICAL"
                        
                    if inc["severity"] != old_sev:
                        inc["status"] = "ESCALATED"
                        inc["updated_at"] = now
                        
                        timeline = inc.get("timeline", [])
                        if not isinstance(timeline, list):
                            timeline = []
                        timeline.append({
                            "timestamp": now,
                            "message": f"Auto-escalated from {old_sev} to {inc['severity']} due to inaction for {int(elapsed)} seconds"
                        })
                        inc["timeline"] = timeline
                        
                        self._store.upsert_incident(inc)
                        escalated_cases.append(inc)
        return escalated_cases
