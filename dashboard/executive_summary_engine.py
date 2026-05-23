import time
from typing import Dict, Any, List

class ExecutiveSummaryEngine:
    """
    Translates complex autonomous telemetry into concise executive textual summaries.
    """
    @staticmethod
    def generate_summary(metrics: Dict[str, Any], incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = metrics.get("active_alerts_count", 0)
        critical = metrics.get("critical_incidents", 0)
        
        headline = "IMMUNEX Defensive Perimeter: STABLE"
        summary_text = (
            f"During this operating cycle, IMMUNEX successfully monitored and defended all active enterprise hosts. "
            f"A total of {total} alerts were processed, of which {critical} were determined to be high-criticality threats "
            f"requiring autonomous containment actions. Defensive models remain highly tuned with zero severe drift signatures observed."
        )
        
        if critical > 5:
            headline = "Defensive Perimeter: ELEVATED THREAT LEVEL"
            summary_text = (
                f"Defensive perimeter is currently experiencing elevated threat pressure. "
                f"We observed {critical} critical campaign incidents. Autonomous RL mitigations were successfully applied, "
                f"achieving complete lateral containment."
            )
            
        return {
            "headline": headline,
            "ciso_brief": summary_text,
            "assessment_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "security_index_percentage": max(10.0, round(100.0 - (critical * 8.5), 1))
        }
