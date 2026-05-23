"""
IMMUNEX Canara SuRaksha Compliance & Fraud Engine Test Suite
============================================================
Validates Explainable Risk scoring, document tampering, keystroke dynamics,
and RBI agentic compliance map extractions.
"""

from __future__ import annotations

import sys
import os
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from compliance_engine import (
    BankingFraudRiskEvent,
    BankingRiskScoringEngine,
    AIComplianceIntelligenceEngine,
    CanaraSuRakshaOrchestrator
)


@pytest.fixture
def normal_event():
    return BankingFraudRiskEvent(
        account_number="CANARA-1252030019",
        session_id="SESS-001",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_location="India",
        device_fingerprint="CanaraSecure-Web-Client-v4.1",
        transaction_amount=5000.0,
        transfer_velocity=1.0,
        typing_speed_wpm=45.0,
        key_latency_ms=120.0,
        user_role="customer"
    )


@pytest.fixture
def malicious_insider_event():
    return BankingFraudRiskEvent(
        account_number="CANARA-SYSTEM-ADMIN",
        session_id="SESS-ADMIN-99",
        src_ip="10.0.0.100",
        dst_ip="10.0.0.2",
        src_location="India",
        device_fingerprint="Clerk-Workstation-Terminal-3",
        event_type="privilege_change",
        transaction_amount=2500000.0,
        transfer_velocity=0.0,
        typing_speed_wpm=130.0,  # Abnormal behavioral timing
        key_latency_ms=50.0,
        user_role="clerk"
    )


@pytest.fixture
def document_forgery_event():
    return BankingFraudRiskEvent(
        account_number="CANARA-LOAN-992",
        session_id="SESS-LOAN-01",
        src_ip="182.15.20.30",
        dst_ip="10.0.0.1",
        src_location="India",
        device_fingerprint="Consumer-Chrome-Android",
        event_type="document_upload",
        document_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        document_metadata={
            "altered_metadata": True,
            "ocr_mismatch": True,
            "filename": "Canara_Bank_Statement_May_2026.pdf"
        },
        user_role="customer"
    )


# ─── Testing Risk Scoring Engine ──────────────────────────────────────────────

class TestBankingRiskScoring:

    def test_normal_activity_is_safe(self, normal_event):
        engine = BankingRiskScoringEngine()
        result = engine.evaluate_event(normal_event)
        assert result.risk_score == 10.0
        assert result.severity == "SAFE"
        assert len(result.factors) == 1
        assert "Standard" in result.factors[0]

    def test_cross_border_emulator_breaches(self, normal_event):
        engine = BankingRiskScoringEngine()
        normal_event.src_location = "USA"
        normal_event.device_fingerprint = "Android_Emulator_Nexus_5"
        normal_event.transaction_amount = 600000.0  # Threshold breached

        result = engine.evaluate_event(normal_event)
        assert result.risk_score >= 80.0
        assert result.severity in ["HIGH", "CRITICAL"]
        assert any("Cross-Border" in f for f in result.factors)
        assert any("Device Fingerprint" in f for f in result.factors)

    def test_insider_threat_escalation(self, malicious_insider_event):
        engine = BankingRiskScoringEngine()
        result = engine.evaluate_event(malicious_insider_event)
        assert result.risk_score >= 80.0
        assert result.severity in ["HIGH", "CRITICAL"]
        assert any("Insider Threat Signal" in f for f in result.factors)

    def test_document_forgery_flag(self, document_forgery_event):
        engine = BankingRiskScoringEngine()
        result = engine.evaluate_event(document_forgery_event)
        assert result.risk_score >= 50.0
        assert any("Financial Statement Alteration" in f for f in result.factors)


# ─── Testing RBI Agentic Compliance Engine ───────────────────────────────────

class TestComplianceIntelligence:

    def test_database_initialization(self):
        engine = AIComplianceIntelligenceEngine()
        assert len(engine.maps) >= 5
        assert "MAP-001" in engine.maps
        assert "RBI-2021-01" in engine.maps["MAP-001"].directive_ref

    def test_regulatory_circular_nlp_ingestion(self):
        engine = AIComplianceIntelligenceEngine()
        circular_text = "Under Directive RBI-2026, all schedules banks shall implement device binding. Also, IT staff must audit databases weekly."
        extracted = engine.ingest_new_regulatory_policy(circular_text)
        assert len(extracted) >= 1
        assert any("device" in m.requirement_text for m in extracted)
        assert any("audit" in m.requirement_text for m in extracted)

    def test_autonomous_compliance_validation(self):
        engine = AIComplianceIntelligenceEngine()
        # Initial status is PENDING
        assert engine.maps["MAP-001"].status == "PENDING"

        # System state matches MAP-001 (MFA required)
        sys_state = {"mfa_active": True}
        assert engine.validate_action_point("MAP-001", sys_state) is True
        assert engine.maps["MAP-001"].status == "COMPLETED"
        assert engine.maps["MAP-001"].validated_at is not None

        # System state fails MAP-002 (device binding missing)
        sys_state_fail = {"device_binding_active": False}
        assert engine.validate_action_point("MAP-002", sys_state_fail) is False
        assert engine.maps["MAP-002"].status == "FAILED"


# ─── Testing End-To-End Orchestrator ──────────────────────────────────────────

class TestCanaraOrchestrator:

    def test_orchestration_flow(self, normal_event):
        orch = CanaraSuRakshaOrchestrator()
        result = orch.process_incident(normal_event)
        assert result["incident_id"].startswith("FRD-")
        assert result["account"] == "CANARA-1252030019"
        assert result["risk_assessment"]["risk_score"] == 10.0
        assert result["rbi_compliance_score"] > 0.0
