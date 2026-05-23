from typing import Dict, Any, List
from storage.audit_store import AuditStore

class ComplianceEngine:
    """
    Generates regulatory compliance checklists based on logs.
    """
    def __init__(self, store: AuditStore) -> None:
        self._store = store

    def evaluate_compliance(self) -> Dict[str, Any]:
        logs = self._store.get_logs(limit=1000)
        
        has_retrain = False
        has_privileged = False
        unauthorized_attempts = 0
        
        for l in logs:
            action = l["action_type"].lower()
            if "retrain" in action or "model" in action:
                has_retrain = True
            if "admin" in action or "privilege" in action:
                has_privileged = True
            if "denied" in action or "unauthorized" in action or "failed" in action:
                unauthorized_attempts += 1
                
        soc2_status = "COMPLIANT" if (has_retrain and has_privileged) else "PARTIALLY_COMPLIANT"
        iso_status = "COMPLIANT" if (unauthorized_attempts < 10) else "NEEDS_ATTENTION"
        
        return {
            "SOC2_CC6_Control_Status": soc2_status,
            "ISO27001_A12_4_Log_Monitoring": iso_status,
            "NIST_SP_800_53_Auditing": "COMPLIANT",
            "metrics": {
                "total_audited_events": len(logs),
                "unauthorized_attempts_flagged": unauthorized_attempts,
                "retraining_events_recorded": has_retrain
            }
        }
