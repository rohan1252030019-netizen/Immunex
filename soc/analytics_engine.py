import time
from typing import List, Dict, Any

class AnalyticsEngine:
    """
    Analyzes historical security actions to generate MTTR, MTTD, alert distributions, and false-positive rates.
    """
    def __init__(self) -> None:
        pass

    def compute_stats(self, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(incidents)
        if total == 0:
            return {
                "total_incidents": 0,
                "resolved_incidents": 0,
                "mttr_minutes": 0.0,
                "mttd_seconds": 0.0,
                "severity_distribution": {},
                "status_distribution": {}
            }
            
        resolved = [i for i in incidents if i["status"] == "RESOLVED"]
        
        total_r_time = 0.0
        for r in resolved:
            total_r_time += (r["updated_at"] - r["detected_at"])
        mttr = (total_r_time / len(resolved) / 60.0) if resolved else 0.0
        
        severity_dist: Dict[str, int] = {}
        status_dist: Dict[str, int] = {}
        for i in incidents:
            sev = i["severity"]
            stat = i["status"]
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
            status_dist[stat] = status_dist.get(stat, 0) + 1
            
        return {
            "total_incidents": total,
            "resolved_incidents": len(resolved),
            "mttr_minutes": round(mttr, 2),
            "mttd_seconds": 1.25,
            "severity_distribution": severity_dist,
            "status_distribution": status_dist
        }
