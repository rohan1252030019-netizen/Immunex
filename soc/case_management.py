import time
from typing import Dict, Any, Optional
from storage.incident_store import IncidentStore

class CaseManagement:
    """
    Facilitates collaborative analyst case notes and analyst assignations.
    """
    def __init__(self, store: IncidentStore) -> None:
        self._store = store

    def assign_case(self, campaign_id: str, analyst: str) -> Optional[Dict[str, Any]]:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return None
        incident["assigned_analyst"] = analyst
        incident["updated_at"] = time.time()
        
        timeline = incident.get("timeline", [])
        if not isinstance(timeline, list):
            timeline = []
        timeline.append({
            "timestamp": time.time(),
            "message": f"Case assigned to analyst: {analyst}"
        })
        incident["timeline"] = timeline
        
        self._store.upsert_incident(incident)
        return incident

    def add_note(self, campaign_id: str, analyst: str, note_text: str) -> Optional[Dict[str, Any]]:
        incident = self._store.get_incident(campaign_id)
        if not incident:
            return None
        
        note = {
            "timestamp": time.time(),
            "analyst": analyst,
            "content": note_text
        }
        notes_list = incident.get("notes", [])
        if not isinstance(notes_list, list):
            notes_list = []
        notes_list.append(note)
        incident["notes"] = notes_list
        incident["updated_at"] = time.time()
        
        timeline = incident.get("timeline", [])
        if not isinstance(timeline, list):
            timeline = []
        timeline.append({
            "timestamp": time.time(),
            "message": f"Note added by {analyst}"
        })
        incident["timeline"] = timeline
        
        self._store.upsert_incident(incident)
        return incident
