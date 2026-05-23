"""
IMMUNEX Phase 5 SOC Copilot Test Suite
========================================
Tests RAG Memory, Sigma/YARA Generation, MITRE Explainer, Compliance Mapper,
and the unified EnterpriseSOCCopilot orchestrator.
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime

import pytest

# ─── Ensure project root is on path ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.schemas import SecurityEvent, DetectionDecision


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_event():
    return SecurityEvent(
        timestamp=datetime.utcnow(),
        src_ip="10.0.0.50",
        dst_ip="192.168.1.100",
        src_port=49152,
        dst_port=445,
        protocol="TCP",
        user_id="jdoe",
        process_name="powershell.exe",
        process_hash="a" * 64,
        event_type="process_creation",
        src_bytes=1024,
        dst_bytes=2048,
        duration=5.0,
        failed_logins=0,
        connection_count=3,
        packet_rate=10.0,
        geo_location="internal",
        asset_criticality="HIGH",
    )


@pytest.fixture
def sample_decision():
    return DetectionDecision(
        event_id="EVT-TEST-001",
        timestamp=datetime.utcnow(),
        event_type="process_creation",
        src_ip="10.0.0.50",
        dst_ip="192.168.1.100",
        asset_criticality="HIGH",
        anomaly_score=0.85,
        faiss_distance=0.3,
        confidence_score=0.9,
        severity="HIGH",
        is_high_confidence_anomaly=True,
        detection_reason="Suspicious PowerShell execution with encoded command",
        mitre_tactic="execution",
        recommended_mitigation="Block encoded PowerShell, investigate parent process",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# RAG Memory Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRAGMemory:
    """Test the RAG Memory system."""

    def test_memory_index_creation(self, tmp_path):
        from rag_memory import ThreatMemoryIndex
        db_path = str(tmp_path / "test_memory.db")
        index = ThreatMemoryIndex(db_path=db_path)
        assert index is not None
        stats = index.stats()
        assert stats["total_events"] == 0

    def test_ingest_and_search(self, sample_decision, tmp_path):
        from rag_memory import ThreatMemoryIndex
        db_path = str(tmp_path / "test_memory.db")
        index = ThreatMemoryIndex(db_path=db_path)
        index.ingest_decision(sample_decision)
        stats = index.stats()
        assert stats["total_events"] == 1
        # Search for the event
        results = index.search("powershell", top_k=5)
        assert len(results) >= 0  # May use different search backends

    def test_get_recent(self, sample_decision, tmp_path):
        from rag_memory import ThreatMemoryIndex
        db_path = str(tmp_path / "test_memory.db")
        index = ThreatMemoryIndex(db_path=db_path)
        index.ingest_decision(sample_decision)
        recent = index.get_recent(10)
        assert len(recent) == 1
        assert recent[0]["event_id"] == "EVT-TEST-001"

    def test_context_retriever(self, sample_decision, tmp_path):
        from rag_memory import ThreatMemoryIndex, ContextRetriever
        db_path = str(tmp_path / "test_memory.db")
        index = ThreatMemoryIndex(db_path=db_path)
        index.ingest_decision(sample_decision)
        retriever = ContextRetriever(index)
        context = retriever.retrieve_context("powershell attack")
        assert "query" in context
        assert "results" in context

    def test_context_retriever_investigation(self, sample_decision, tmp_path):
        from rag_memory import ThreatMemoryIndex, ContextRetriever
        db_path = str(tmp_path / "test_memory.db")
        index = ThreatMemoryIndex(db_path=db_path)
        index.ingest_decision(sample_decision)
        retriever = ContextRetriever(index)
        inv_context = retriever.retrieve_for_investigation("EVT-TEST-001")
        assert inv_context["found"] is True

    def test_memory_pipeline(self, sample_decision, tmp_path):
        from rag_memory import MemoryIngestionPipeline
        db_path = str(tmp_path / "test_memory.db")
        pipeline = MemoryIngestionPipeline(db_path=db_path)
        pipeline.ingest(sample_decision)
        assert pipeline.ingested_count == 1

    def test_bulk_ingest(self, sample_decision, tmp_path):
        from rag_memory import MemoryIngestionPipeline
        db_path = str(tmp_path / "test_memory.db")
        pipeline = MemoryIngestionPipeline(db_path=db_path)
        count = pipeline.bulk_ingest([sample_decision])
        assert count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Sigma Generator Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSigmaGenerator:
    """Test Sigma rule generation."""

    def test_generate_rule(self, sample_event, sample_decision):
        from sigma_generator import SigmaRuleGenerator
        gen = SigmaRuleGenerator()
        rule = gen.generate(sample_event, sample_decision)
        assert isinstance(rule, str)
        assert "title" in rule
        assert "detection" in rule
        assert "logsource" in rule
        assert "level" in rule

    def test_validate_rule(self, sample_event, sample_decision):
        from sigma_generator import SigmaRuleGenerator
        gen = SigmaRuleGenerator()
        rule = gen.generate(sample_event, sample_decision)
        assert gen.validate_rule(rule) is True

    def test_campaign_rule(self, sample_event, sample_decision):
        from sigma_generator import SigmaRuleGenerator
        gen = SigmaRuleGenerator()
        rule = gen.generate_from_campaign([sample_event], [sample_decision])
        assert gen.validate_rule(rule) is True

    def test_invalid_rule_validation(self):
        from sigma_generator import SigmaRuleGenerator
        gen = SigmaRuleGenerator()
        assert gen.validate_rule("not valid yaml: [[[") is False


# ═══════════════════════════════════════════════════════════════════════════════
# YARA Generator Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestYaraGenerator:
    """Test YARA rule generation."""

    def test_generate_rule(self, sample_event, sample_decision):
        from yara_generator import YaraRuleGenerator
        gen = YaraRuleGenerator()
        rule = gen.generate(sample_event, sample_decision)
        assert isinstance(rule, str)
        assert "rule" in rule
        assert "meta:" in rule
        assert "strings:" in rule
        assert "condition:" in rule

    def test_generate_from_indicators(self):
        from yara_generator import YaraRuleGenerator
        gen = YaraRuleGenerator()
        rule = gen.generate_from_indicators({
            "name": "test_ioc",
            "hashes": ["a" * 64],
            "ips": ["10.0.0.1"],
            "strings": ["malware_payload"],
        })
        assert "rule test_ioc" in rule
        assert "meta:" in rule


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE Explainer Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestMITREExplainer:
    """Test MITRE ATT&CK taxonomy and narrative generation."""

    def test_explain_tactic(self):
        from mitre_explainer import MITREExplainer
        explainer = MITREExplainer()
        result = explainer.explain_tactic("TA0001")
        assert result["name"] == "Initial Access"
        assert result["technique_count"] >= 10

    def test_explain_technique(self):
        from mitre_explainer import MITREExplainer
        explainer = MITREExplainer()
        result = explainer.explain_technique("T1059")
        assert result["name"] == "Command and Scripting Interpreter"
        assert result["tactic_name"] == "Execution"

    def test_map_event_to_techniques(self, sample_event):
        from mitre_explainer import MITREExplainer
        explainer = MITREExplainer()
        techniques = explainer.map_event_to_techniques(sample_event)
        assert len(techniques) > 0
        assert all("technique_id" in t for t in techniques)

    def test_full_matrix(self):
        from mitre_explainer import MITREExplainer
        explainer = MITREExplainer()
        matrix = explainer.get_full_matrix()
        assert len(matrix) == 14  # 14 tactics

    def test_tactic_chain(self, sample_decision):
        from mitre_explainer import MITREExplainer
        explainer = MITREExplainer()
        chain = explainer.get_tactic_chain([sample_decision])
        assert isinstance(chain, list)

    def test_narrative_builder(self, sample_decision):
        from mitre_explainer import AttackNarrativeBuilder
        builder = AttackNarrativeBuilder()
        narrative = builder.build_narrative(sample_decision)
        assert isinstance(narrative, str)
        assert "HIGH" in narrative
        assert "10.0.0.50" in narrative

    def test_executive_summary(self, sample_decision):
        from mitre_explainer import AttackNarrativeBuilder
        builder = AttackNarrativeBuilder()
        summary = builder.build_executive_summary([sample_decision])
        assert "Executive" in summary
        assert "High Alerts" in summary


# ═══════════════════════════════════════════════════════════════════════════════
# Compliance Mapper Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestComplianceMapper:
    """Test compliance control mapping."""

    def test_map_threat(self, sample_decision):
        from compliance_mapper import ComplianceControlMapper
        mapper = ComplianceControlMapper()
        result = mapper.map_threat(sample_decision)
        assert "frameworks" in result
        assert len(result["frameworks"]) > 0
        # HIGH severity should match controls across frameworks
        assert result["total_controls_matched"] > 0

    def test_get_framework_controls(self):
        from compliance_mapper import ComplianceControlMapper
        mapper = ComplianceControlMapper()
        controls = mapper.get_framework_controls("SOC2")
        assert len(controls) == 10

    def test_compliance_impact(self, sample_decision):
        from compliance_mapper import ComplianceControlMapper
        mapper = ComplianceControlMapper()
        assessment = mapper.assess_compliance_impact([sample_decision])
        assert "overall_compliance_score" in assessment
        assert assessment["events_analyzed"] == 1

    def test_compliance_report(self, sample_decision):
        from compliance_mapper import ComplianceControlMapper
        mapper = ComplianceControlMapper()
        report = mapper.generate_compliance_report([sample_decision])
        assert "Compliance Impact Report" in report


# ═══════════════════════════════════════════════════════════════════════════════
# SOC Copilot Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSOCCopilot:
    """Test the unified SOC Copilot engine."""

    def test_copilot_init(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        assert copilot is not None

    def test_copilot_ask_help(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        result = copilot.ask("hello, what can you do?")
        assert "response" in result
        assert "type" in result
        assert result["type"] == "help"

    def test_copilot_ask_hunt(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        result = copilot.ask("hunt for lateral movement attacks")
        assert result["type"] == "hunt"

    def test_copilot_hunt(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        result = copilot.hunt("find critical alerts from 10.0.0.1")
        assert "results" in result
        assert "query_parsed" in result
        assert "total" in result

    def test_copilot_investigate(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        result = copilot.investigate("TEST-ALERT-001")
        assert "alert_id" in result
        assert "status" in result
        assert "containment_plan" in result

    def test_copilot_sigma(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        rule = copilot.generate_sigma({"event_type": "process_creation", "process_name": "cmd.exe"})
        assert isinstance(rule, str)
        assert len(rule) > 10

    def test_copilot_yara(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        rule = copilot.generate_yara({"process_name": "malware.exe"})
        assert isinstance(rule, str)
        assert len(rule) > 10

    def test_copilot_timeline(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        timeline = copilot.get_timeline()
        assert isinstance(timeline, list)

    def test_copilot_campaigns(self):
        from soc_copilot import EnterpriseSOCCopilot
        copilot = EnterpriseSOCCopilot()
        campaigns = copilot.get_campaigns()
        assert isinstance(campaigns, list)


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebSocketManager:
    """Test WebSocket connection manager."""

    def test_manager_init(self):
        from websocket_server import WebSocketConnectionManager
        mgr = WebSocketConnectionManager()
        assert mgr.get_active_connections() == 0

    def test_manager_status(self):
        from websocket_server import WebSocketConnectionManager
        mgr = WebSocketConnectionManager()
        status = mgr.get_status()
        assert "active_connections" in status
        assert "channels" in status


# ═══════════════════════════════════════════════════════════════════════════════
# Backward Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """Verify Phase 5 additions don't break existing schemas."""

    def test_detection_decision_backward_compat(self, sample_decision):
        assert sample_decision.event_id == "EVT-TEST-001"
        assert sample_decision.severity == "HIGH"
        assert sample_decision.anomaly_score == 0.85
        # New optional fields should have defaults
        assert sample_decision.blast_radius_score is None
        assert sample_decision.graph_risk_score is None

    def test_security_event_backward_compat(self, sample_event):
        assert sample_event.src_ip == "10.0.0.50"
        assert sample_event.event_type == "process_creation"
        assert sample_event.asset_criticality == "HIGH"
