import time
from typing import Dict, Any, List

class DashboardEngine:
    """
    Gathers pipeline variables and system telemetry to structure dashboards.
    """
    def __init__(self) -> None:
        pass

    def build_dashboard_state(self, stats: Dict[str, Any], raw_alerts: List[Dict[str, Any]], active_agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        critical_alerts = [a for a in raw_alerts if a.get("severity") == "CRITICAL"]
        high_alerts = [a for a in raw_alerts if a.get("severity") == "HIGH"]
        
        online_agents = [ag for ag in active_agents if ag.get("status") == "ACTIVE"]
        
        return {
            "timestamp": time.time(),
            "kpi_cards": {
                "active_alerts_count": len(raw_alerts),
                "critical_incidents": len(critical_alerts),
                "unresolved_high_priority": len(high_alerts),
                "active_endpoint_nodes": len(online_agents)
            },
            "incident_metrics": stats,
            "recent_incidents": raw_alerts[:5],
            "agent_health_summary": {
                "total": len(active_agents),
                "online": len(online_agents),
                "offline": len(active_agents) - len(online_agents)
            }
        }

    def compile_kpis(self, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compiles KPIs including active threats and calculated corporate risk index."""
        active_threats = [inc for inc in incidents if inc.get("status") in ["OPEN", "NEW", "INVESTIGATING", "ESCALATED"]]
        risk_index = 0.0
        for inc in active_threats:
            sev = inc.get("severity", "LOW")
            if sev == "CRITICAL":
                risk_index += 25.0
            elif sev == "HIGH":
                risk_index += 15.0
            elif sev == "MEDIUM":
                risk_index += 5.0
            else:
                risk_index += 1.0
        return {
            "active_threats_count": len(active_threats),
            "corporate_risk_index": risk_index
        }
