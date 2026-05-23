"""
IMMUNEX Banking Fraud Behavioral Anomaly & Agentic Regulatory Compliance Engine
=============================================================================
SuRaksha Cyber Hackathon 2.0 Edition — Canara Bank Core Positioning Additive.

Implements real-time banking fraud risk classification, explainable AI risk scoring,
behavioral anomaly checks, financial document forgery flags, and the RBI Agentic
Compliance Intelligence Engine mapping Measurable Action Points (MAPs).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from utils.logger import log


# ─── Pydantic Models for Banking Risk and RBI Compliance ──────────────────────

class BankingFraudRiskEvent(BaseModel):
    """Normalized banking risk event representing transactional or session telemetry."""
    event_id: str = Field(default_factory=lambda: f"FRD-{int(datetime.utcnow().timestamp())}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    account_number: str
    session_id: str
    channel: str = "MOBILE_BANKING"  # MOBILE_BANKING, NET_BANKING, UPI, ATM
    event_type: str = "transaction_execution"  # transaction_execution, login_attempt, privilege_change, document_upload
    src_ip: str
    dst_ip: str
    src_location: str = "India"
    device_fingerprint: str
    transaction_amount: float = 0.0
    transfer_velocity: float = 0.0  # transactions per minute
    typing_speed_wpm: float = 45.0  # behavioral biometric: speed
    key_latency_ms: float = 120.0  # behavioral biometric: keystroke latency
    document_hash: Optional[str] = None
    document_metadata: Optional[Dict[str, Any]] = None
    user_role: str = "customer"  # customer, clerk, teller, administrator, admin_clerk


class ExplainableRiskScore(BaseModel):
    """Explainable AI Risk payload mapping raw anomaly factors to explicit banking logic."""
    risk_score: float  # 0 to 100
    severity: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    factors: List[str]
    explainable_reasoning: str
    recommended_mitigation: str
    mitre_tactic_mapped: str
    compliance_controls_triggered: List[str]


class MeasurableActionPoint(BaseModel):
    """Measurable Action Point (MAP) extracted from RBI master directions."""
    map_id: str
    directive_ref: str
    requirement_text: str
    assigned_department: str  # INFORMATION_SECURITY, AUDIT, IT_INFRASTRUCTURE, CORE_BANKING, OPERATIONS
    measurable_metric: str
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    validated_at: Optional[datetime] = None
    audit_trail: List[str] = Field(default_factory=list)


# ─── Risk Scoring Engine with Explainable AI ───────────────────────────────

class BankingRiskScoringEngine:
    """Computes Explainable AI risk assessments for banking transactions and session states."""

    def __init__(self):
        log.info("BankingRiskScoringEngine initialized for Canara Bank SuRaksha Console")

    def evaluate_event(self, event: BankingFraudRiskEvent) -> ExplainableRiskScore:
        """
        Evaluates a BankingFraudRiskEvent against heuristic, behavioral,
        and statistical anomaly rules.
        """
        score = 10.0  # Baseline normal login / activity score
        factors = []
        mitigations = []
        tactics = []
        controls = []

        # 1. Device and Location Anomaly Controls
        if event.src_location != "India":
            score += 40.0
            factors.append("Cross-Border Access Attempt (Outside domestic boundaries)")
            mitigations.append("Prompt out-of-band behavioral biometric confirmation.")
            tactics.append("TA0001 - Initial Access")
            controls.append("RBI-DPS-3.1 (Logical Access boundaries)")

        if "suspicious" in event.device_fingerprint.lower() or "emulator" in event.device_fingerprint.lower():
            score += 30.0
            factors.append("Anomalous Device Fingerprint / Mobile Emulator Detected")
            mitigations.append("Block execution on emulator platforms.")
            tactics.append("TA0001 - Initial Access")
            controls.append("RBI-DPS-4.2 (Device Fingerprint bindings)")

        # 2. Transaction Amount and Velocity Anomalies
        if event.transaction_amount > 500000.0:  # High transaction threshold
            score += 20.0
            factors.append("Abnormal Transaction Volume (Single transfer > 5 Lakhs)")
            mitigations.append("Require Multi-Factor Out-of-Band transaction signature authorization.")
            tactics.append("TA0011 - Impact (Financial Drain)")
            controls.append("RBI-DPS-5.6 (Transaction authorization controls)")

        if event.transfer_velocity > 5.0:  # Velocity limit (5 transfers per minute)
            score += 30.0
            factors.append("Suspicious High-Frequency Transaction Velocity (Velocity threshold breached)")
            mitigations.append("Throttling active session execution for 10 minutes.")
            tactics.append("TA0011 - Impact (Automated Drain)")
            controls.append("RBI-DPS-5.7 (Rate limits & velocity caps)")

        # 3. Behavioral Authentication checks (Keystroke Dynamics)
        if event.event_type == "login_attempt" or event.event_type == "transaction_execution":
            if event.typing_speed_wpm > 120.0 or event.typing_speed_wpm < 15.0 or event.key_latency_ms > 250.0:
                score += 25.0
                factors.append("Behavioral Biometric Inconsistency (Keystroke dynamics model deviation)")
                mitigations.append("Enforce behavioral secondary challenges (Face/Pattern Matching).")
                tactics.append("TA0006 - Credential Access (Account Takeover)")
                controls.append("RBI-DPS-6.1 (Continuous Behavioral Authentication)")

        # 4. Insider Threat Detection (Privilege escalation & data export)
        if event.user_role in ["clerk", "teller", "admin_clerk"]:
            if event.event_type == "privilege_change" or event.transaction_amount > 1000000.0:
                score += 55.0
                factors.append("Internal Administrator/Clerk Escalation Behavior (Insider Threat Signal)")
                mitigations.append("Lock administrative account session and trigger concurrent manager peer review.")
                tactics.append("TA0004 - Privilege Escalation")
                controls.append("RBI-DPS-7.3 (Dual-control Authorization / Four-Eyes principle)")

        # 5. Financial Document Forgery & PDF Tampering Checks
        if event.event_type == "document_upload" and event.document_metadata:
            meta = event.document_metadata
            if meta.get("altered_metadata", False) or meta.get("ocr_mismatch", False):
                score += 50.0
                factors.append("Financial Statement Alteration detected (Metadata inconsistency/OCR mismatch)")
                mitigations.append("Flag document for automated manual fraud-clerk review.")
                tactics.append("TA0005 - Defense Evasion (Document Tampering)")
                controls.append("RBI-DPS-8.2 (Regulatory document integrity verification)")

        # Clamp score to 100.0
        final_score = min(score, 100.0)

        # Determine Severity Labels
        if final_score < 25.0:
            severity = "SAFE"
            reasoning = "All evaluated behavioural biometrics and transaction limits reside inside historical baseline envelopes."
            mitigation = "Continue active baseline tracking."
        elif final_score < 50.0:
            severity = "LOW"
            reasoning = "Minor anomaly detected in device profile or transaction latency parameters. Low-risk rating."
            mitigation = mitigations[0] if mitigations else "Increase active log collection."
        elif final_score < 75.0:
            severity = "MEDIUM"
            reasoning = "Multi-factor deviations (location, velocity, or keystroke rhythms) suggest potential account takeover attempt."
            mitigation = "; ".join(mitigations[:2])
        elif final_score < 90.0:
            severity = "HIGH"
            reasoning = "Critical security alert. Multiple high-level transactional anomalies paired with atypical authentication signals."
            mitigation = "; ".join(mitigations[:2])
        else:
            severity = "CRITICAL"
            reasoning = "Severe risk incident. Highly anomalous insider escalation behaviors or forged document uploads paired with transaction anomalies."
            mitigation = "IMMEDIATE RESPONSE: " + ("; ".join(mitigations) if mitigations else "Revoke active token.")

        return ExplainableRiskScore(
            risk_score=final_score,
            severity=severity,
            factors=factors if factors else ["Standard operational patterns observed"],
            explainable_reasoning=reasoning,
            recommended_mitigation=mitigation,
            mitre_tactic_mapped=tactics[0] if tactics else "TA0009 - Execution",
            compliance_controls_triggered=controls if controls else ["RBI-DPS-1.1"]
        )


# ─── Agentic Compliance Intelligence Engine (RBI Guidelines) ────────────────

class AIComplianceIntelligenceEngine:
    """
    Autonomous Compliance Engine that ingests RBI circular directives,
    extracts Measurable Action Points (MAPs), maps departments, and validation metrics.
    """

    def __init__(self):
        self.maps: Dict[str, MeasurableActionPoint] = {}
        self._load_rbi_directives_database()
        log.info("Agentic Compliance Intelligence Engine pre-seeded with RBI Guidelines")

    def _load_rbi_directives_database(self):
        """Pre-seeds the compliance database with explicit Canara Bank/RBI requirements."""
        directives = [
            ("RBI-2021-01", "Sec. 3.2", "Implement multi-factor authentication (MFA) with dynamic OTP bindings for all internet banking transfers exceeding INR 10,000.", "CORE_BANKING", "Presence of SMS/Email OTP transaction signature tokens"),
            ("RBI-2021-02", "Sec. 4.5", "Enforce device fingerprinting and binding to prevent parallel login sessions across distinct geographic coordinates.", "IT_INFRASTRUCTURE", "Validate unique active session token count per device hash"),
            ("RBI-2021-03", "Sec. 6.1", "Deploy continuous behavioral biometrics (keystroke timing, typing speeds) to identify non-human robotic session execution (automated API scraping).", "INFORMATION_SECURITY", "Compute standard keyboard latency anomaly flags"),
            ("RBI-2021-04", "Sec. 7.2", "Verify identity transitions and enforce the four-eyes dual-clerk approval rule for teller actions exceeding 25 Lakhs.", "OPERATIONS", "Clerk-Manager workflow token presence"),
            ("RBI-2021-05", "Sec. 8.4", "Check metadata integrity and conduct automated signature integrity tests on uploaded land and collateral documents.", "AUDIT", "Calculate OCR-metadata integrity flag on loan-document file system uploads"),
        ]

        for i, (dir_ref, section, text, dept, metric) in enumerate(directives, 1):
            map_id = f"MAP-{i:03d}"
            self.maps[map_id] = MeasurableActionPoint(
                map_id=map_id,
                directive_ref=f"{dir_ref} ({section})",
                requirement_text=text,
                assigned_department=dept,
                measurable_metric=metric,
                audit_trail=[f"[{datetime.utcnow().isoformat()}] Directive ingested and classified into {dept} operational workflow."]
            )

    def ingest_new_regulatory_policy(self, text: str) -> List[MeasurableActionPoint]:
        """
        Parses raw RBI policy text using regex and heuristics to extract MAPs dynamically.
        (Air-gapped semantic NLP mapping).
        """
        extracted = []
        # Find paragraphs mentioning 'shall', 'must', 'implement', or 'enforce'
        sentences = re.split(r'\.|\n', text)
        for i, sentence in enumerate(sentences):
            sentence = sentence.strip()
            if any(keyword in sentence.lower() for keyword in ["shall", "must", "implement", "enforce", "require"]):
                map_id = f"MAP-EXT-{int(datetime.utcnow().timestamp())}-{i}"
                
                # Determine department heuristically
                dept = "INFORMATION_SECURITY"
                if "transaction" in sentence.lower() or "banking" in sentence.lower():
                    dept = "CORE_BANKING"
                elif "device" in sentence.lower() or "server" in sentence.lower():
                    dept = "IT_INFRASTRUCTURE"
                elif "audit" in sentence.lower() or "log" in sentence.lower():
                    dept = "AUDIT"

                new_map = MeasurableActionPoint(
                    map_id=map_id,
                    directive_ref=f"Ingested-RBI-Circular-S{i}",
                    requirement_text=sentence,
                    assigned_department=dept,
                    measurable_metric="Autonomous verification indicator",
                    audit_trail=[f"[{datetime.utcnow().isoformat()}] Agentic NLP parser identified measurable requirement. Department allocated: {dept}"]
                )
                self.maps[map_id] = new_map
                extracted.append(new_map)

        return extracted

    def validate_action_point(self, map_id: str, system_state: Dict[str, Any]) -> bool:
        """
        Autonomously validates compliance status by querying system states.
        e.g., checking if MFA or Device Bindings are active.
        """
        if map_id not in self.maps:
            return False

        action = self.maps[map_id]
        success = False

        if "MFA" in action.requirement_text and system_state.get("mfa_active", False):
            success = True
        elif "device" in action.requirement_text.lower() and system_state.get("device_binding_active", False):
            success = True
        elif "behavioral" in action.requirement_text.lower() and system_state.get("behavioral_analytics_enabled", False):
            success = True
        elif "four-eyes" in action.requirement_text.lower() and system_state.get("dual_control_token_present", False):
            success = True
        elif "integrity" in action.requirement_text.lower() and system_state.get("document_integrity_verified", False):
            success = True

        if success:
            action.status = "COMPLETED"
            action.validated_at = datetime.utcnow()
            action.audit_trail.append(f"[{datetime.utcnow().isoformat()}] Autonomous verification complete: system state matches '{action.measurable_metric}'.")
        else:
            action.status = "FAILED"
            action.audit_trail.append(f"[{datetime.utcnow().isoformat()}] Autonomous check failed: system state is missing required security flag.")

        return success

    def calculate_regulatory_compliance_score(self) -> float:
        """Calculates dynamic compliance score (0-100) based on completed MAP validations."""
        if not self.maps:
            return 100.0
        completed = sum(1 for m in self.maps.values() if m.status == "COMPLETED")
        return round(100.0 * (completed / len(self.maps)), 1)


# ─── Integrated Banking Copilot Triage Flow ──────────────────────────────────

class CanaraSuRakshaOrchestrator:
    """Co-ordinating pipeline orchestrating Fraud detection and Agentic Compliance."""

    def __init__(self):
        self.risk_engine = BankingRiskScoringEngine()
        self.compliance_engine = AIComplianceIntelligenceEngine()

    def process_incident(self, event: BankingFraudRiskEvent) -> Dict[str, Any]:
        """Runs the entire pipeline from transaction detection to RBI compliance audits."""
        risk = self.risk_engine.evaluate_event(event)
        
        # Build systemic state from incident triggers to evaluate Canara regulatory checklist
        sys_state = {
            "mfa_active": event.transaction_amount < 500000.0,  # Fails high value without MFA signature
            "device_binding_active": "emulator" not in event.device_fingerprint.lower(),
            "behavioral_analytics_enabled": event.typing_speed_wpm >= 30.0 and event.typing_speed_wpm <= 100.0,
            "dual_control_token_present": event.user_role == "customer" or event.transaction_amount < 1000000.0,
            "document_integrity_verified": not (event.document_metadata or {}).get("altered_metadata", False)
        }

        # Run autonomous agentic validations across all RBI requirements
        for map_id in self.compliance_engine.maps.keys():
            self.compliance_engine.validate_action_point(map_id, sys_state)

        comp_score = self.compliance_engine.calculate_regulatory_compliance_score()

        return {
            "incident_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "account": event.account_number,
            "risk_assessment": risk.model_dump(),
            "rbi_compliance_score": comp_score,
            "action_points_status": {
                m.map_id: m.status for m in self.compliance_engine.maps.values()
            }
        }
