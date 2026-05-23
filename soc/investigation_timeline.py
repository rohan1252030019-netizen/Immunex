import time
from typing import List, Dict, Any

class InvestigationTimeline:
    """
    Autonomously tracks and displays investigation timeline trails mapping attack progression steps.
    """
    def __init__(self) -> None:
        self._timelines: Dict[str, List[Dict[str, Any]]] = {}

    def add_step(self, campaign_id: str, action: str, description: str, analyst: str = "System") -> Dict[str, Any]:
        if campaign_id not in self._timelines:
            self._timelines[campaign_id] = []
            
        step = {
            "timestamp": time.time(),
            "action": action,
            "description": description,
            "user": analyst
        }
        self._timelines[campaign_id].append(step)
        return step

    def get_timeline(self, campaign_id: str) -> List[Dict[str, Any]]:
        return self._timelines.get(campaign_id, [])
        
    def reconstruct_chronology(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort timeline events chronologically by timestamp."""
        if not events:
            return []
        return sorted(events, key=lambda x: x.get("timestamp", 0.0))

    def clear(self) -> None:
        self._timelines.clear()
