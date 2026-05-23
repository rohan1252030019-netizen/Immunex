import time
from typing import Dict, Any, List

class RealtimeDashboard:
    """
    Manages live streaming metrics and coordinates fast refreshes.
    """
    def __init__(self) -> None:
        self.start_time = time.time()
        self._alert_history: List[Dict[str, Any]] = []

    def log_alert(self, alert: Dict[str, Any]) -> None:
        self._alert_history.append(alert)
        if len(self._alert_history) > 1000:
            self._alert_history.pop(0)

    def get_realtime_metrics(self) -> Dict[str, Any]:
        elapsed = time.time() - self.start_time
        return {
            "uptime_seconds": round(elapsed, 1),
            "total_alerts": len(self._alert_history),
            "alerts_per_hour": round(len(self._alert_history) / (elapsed / 3600.0), 2) if elapsed > 0 else 0.0,
            "recent_severity": [a.get("severity") for a in self._alert_history[-10:]]
        }
        
    def clear(self) -> None:
        self._alert_history.clear()
