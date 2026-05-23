import time
from typing import Dict, Any, List

class AlertManager:
    """
    Deduplicates, groups, and priority-queues system alerts based on severity score.
    """
    def __init__(self) -> None:
        self._alerts: List[Dict[str, Any]] = []
        self._dedup_keys: Dict[str, float] = {}

    def ingest_alert(self, alert: Dict[str, Any]) -> bool:
        key = alert.get("campaign_id") or f"{alert.get('attacker_ip')}:{alert.get('severity')}"
        now = time.time()
        
        if key in self._dedup_keys:
            last_seen = self._dedup_keys[key]
            if now - last_seen < 10.0:
                return False
        
        self._dedup_keys[key] = now
        self._alerts.append(alert)
        self._alerts.sort(key=lambda x: x.get("risk_score", 0.0), reverse=True)
        return True

    def queue_alert(self, alert: Dict[str, Any]) -> bool:
        """Alias for ingest_alert for test compatibility."""
        return self.ingest_alert(alert)

    def get_highest_priority(self) -> List[Dict[str, Any]]:
        return self._alerts[:10]

    def list_alerts(self) -> List[Dict[str, Any]]:
        return self._alerts

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Alias for list_alerts for test compatibility."""
        return self.list_alerts()
        
    def clear(self) -> None:
        self._alerts.clear()
        self._dedup_keys.clear()
