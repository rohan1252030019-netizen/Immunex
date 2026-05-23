from typing import Dict, Any, List
from audit.compliance_engine import ComplianceEngine

class ComplianceReporter:
    """
    Orchestrates compliance analysis and prepares structural mappings
    for SOC2, ISO27001, and NIST SP 800-53 report frameworks.
    """
    def __init__(self, compliance_engine: ComplianceEngine) -> None:
        self._compliance_engine = compliance_engine

    def generate_compliance_data(self) -> Dict[str, Any]:
        """
        Compiles the evaluation metrics into structured frameworks with gap listings.
        """
        eval_result = self._compliance_engine.evaluate_compliance()
        metrics = eval_result.get("metrics", {})
        
        # Determine framework details based on compliance evaluations
        soc2_status = eval_result.get("SOC2_CC6_Control_Status", "PARTIALLY_COMPLIANT")
        iso_status = eval_result.get("ISO27001_A12_4_Log_Monitoring", "NEEDS_ATTENTION")
        nist_status = eval_result.get("NIST_SP_800_53_Auditing", "COMPLIANT")

        soc2_score = 1.0 if soc2_status == "COMPLIANT" else 0.6
        iso_score = 1.0 if iso_status == "COMPLIANT" else 0.5
        nist_score = 1.0 if nist_status == "COMPLIANT" else 0.7

        frameworks = {
            "SOC2 Type II (Security/CC6)": {
                "completed": int(soc2_score * 5),
                "total": 5,
                "score": soc2_score,
                "status": soc2_status
            },
            "ISO 27001:2022 (A.12.4 Log Monitoring)": {
                "completed": int(iso_score * 4),
                "total": 4,
                "score": iso_score,
                "status": iso_status
            },
            "NIST SP 800-53 (AU Auditing & Accountability)": {
                "completed": int(nist_score * 8),
                "total": 8,
                "score": nist_score,
                "status": nist_status
            }
        }

        gaps = []
        if soc2_status != "COMPLIANT":
            gaps.append({
                "control_id": "SOC2-CC6.3",
                "description": "Requires evidence of continuous machine learning model retraining audit trails and version check logs.",
                "recommendation": "Initiate automated ML retraining cycle or write explicit admin retraining triggers to the audit store."
            })
        if iso_status != "COMPLIANT":
            gaps.append({
                "control_id": "ISO-A.12.4.1",
                "description": "Log system recorded high levels of failed authorization or denied admin requests.",
                "recommendation": "Perform detailed RBAC entitlement review, review active session token lifespans, and investigate anomalous client IPs."
            })
            
        return {
            "compliance_summary": eval_result,
            "frameworks": frameworks,
            "gaps": gaps,
            "metrics_overview": {
                "audited_events_processed": metrics.get("total_audited_events", 0),
                "policy_violations_flagged": metrics.get("unauthorized_attempts_flagged", 0),
                "retraining_audit_trail_valid": metrics.get("retraining_events_recorded", False)
            }
        }
