"""
Tests for IMMUNEX Layer 3 — PlaybookEngine

Tests cover:
  - Playbook generation with all 15 sections present
  - IOC list construction
  - Attack timeline generation
  - Affected asset listing
  - MITRE ATT&CK mapping
  - Command set embedding
  - JSON serialisability
  - Offline (no Ollama) deterministic fallback
  - Playbook ID format
"""

from __future__ import annotations

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core.playbook_engine import PlaybookEngine
from core.ollama_orchestrator import OllamaOrchestrator
from core.response_models import (
    ActionType,
    IncidentPlaybook,
    PolicyDecision,
    PolicyVerdict,
    RLDecision,
)


# ─── Fakes ────────────────────────────────────────────────────────────────────


class FakeThreatReport:
    campaign_id = "CAMP-ABCDEF12"
    attacker_ip = "192.168.1.200"
    target_ips = ["10.0.0.50", "10.0.0.51", "10.0.0.52"]
    stages_observed = ["Reconnaissance", "Credential_Access", "Lateral_Movement"]
    predicted_next_stage = "Persistence"
    severity = "HIGH"
    risk_score = 0.78
    prediction_confidence = 0.85
    narrative = {"threat_paragraph": "Attacker performed multi-stage intrusion."}
    formatted_report = "Multi-stage attack: Reconnaissance → Credential_Access → Lateral_Movement"


def _make_rl_decision() -> RLDecision:
    from datetime import datetime
    return RLDecision(
        action_index=5,
        optimal_action=ActionType.MICRO_SEGMENTATION.value,
        reward_score=0.75,
        confidence_level=0.82,
        mitigation_reasoning="Micro-segmentation applied to contain lateral spread.",
        risk_reduction_score=0.68,
        q_values={a: 0.1 for a in [
            "Log_Event", "Revoke_Token", "Isolate_Host", "Block_IP",
            "Trigger_Shadow_Honeypot", "Micro_Segmentation",
            "Suspend_Process", "Disable_Lateral_Communications", "Force_MFA_Reset"
        ]},
        state_vector=[0.78, 0.75, 0.66, 0.75, 0.50, 0.85, 0.75, 1.0],
        evaluated_at=datetime.utcnow(),
    )


def _make_policy_decision() -> PolicyDecision:
    from datetime import datetime
    return PolicyDecision(
        action_id="ACT-TEST-001",
        original_action=ActionType.MICRO_SEGMENTATION.value,
        approved_action=ActionType.MICRO_SEGMENTATION.value,
        rejected_action=None,
        verdict=PolicyVerdict.APPROVED.value,
        policy_reason="All policy rules passed — action approved.",
        risk_score=0.55,
        business_impact_score=0.12,
        downgrade_mapping={},
        rules_evaluated=["R01", "R02", "R03", "R04", "R05", "R06", "R07", "R00_DEFAULT_APPROVAL"],
        validation_timestamp=datetime.utcnow(),
    )


@pytest.fixture(scope="module")
def engine():
    """Playbook engine with offline (no Ollama) orchestrator."""
    orch = OllamaOrchestrator()   # probe will fail gracefully → fallback mode
    return PlaybookEngine(orchestrator=orch)


@pytest.fixture(scope="module")
def playbook(engine):
    report = FakeThreatReport()
    rl = _make_rl_decision()
    policy = _make_policy_decision()
    return engine.generate(
        report=report,
        rl_decision=rl,
        policy_decision=policy,
        attacker_ip=report.attacker_ip,
        target_ips=report.target_ips,
        process_name="mimikatz.exe",
        user_id="jdoe",
    )


# ─── Structure validation ─────────────────────────────────────────────────────


class TestPlaybookStructure:
    def test_returns_incident_playbook(self, playbook):
        assert isinstance(playbook, IncidentPlaybook)

    def test_playbook_id_format(self, playbook):
        assert playbook.playbook_id.startswith("PB-")

    def test_campaign_id_preserved(self, playbook):
        assert playbook.campaign_id == "CAMP-ABCDEF12"

    def test_generated_at_set(self, playbook):
        assert playbook.generated_at is not None

    # ── Section 1: Executive Summary ──────────────────────────────────────────
    def test_executive_summary_non_empty(self, playbook):
        assert len(playbook.executive_summary) > 10

    # ── Section 2: Threat Severity ─────────────────────────────────────────────
    def test_threat_severity_set(self, playbook):
        assert playbook.threat_severity in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_severity_justification_non_empty(self, playbook):
        assert len(playbook.severity_justification) > 0

    # ── Section 3: MITRE ATT&CK ─────────────────────────────────────────────────
    def test_mitre_techniques_present(self, playbook):
        assert isinstance(playbook.mitre_techniques, list)
        assert len(playbook.mitre_techniques) > 0

    def test_mitre_techniques_have_required_keys(self, playbook):
        for t in playbook.mitre_techniques:
            assert "id" in t
            assert "name" in t
            assert "tactic" in t

    # ── Section 4: Root Cause Analysis ──────────────────────────────────────────
    def test_root_cause_analysis_non_empty(self, playbook):
        assert len(playbook.root_cause_analysis) > 0

    def test_initial_access_vector_non_empty(self, playbook):
        assert len(playbook.initial_access_vector) > 0

    # ── Section 5: Attack Timeline ───────────────────────────────────────────────
    def test_attack_timeline_has_entries(self, playbook):
        assert len(playbook.attack_timeline) >= len(FakeThreatReport.stages_observed)

    def test_timeline_entries_have_required_fields(self, playbook):
        for entry in playbook.attack_timeline:
            assert entry.timestamp != ""
            assert entry.stage != ""
            assert entry.src_ip == FakeThreatReport.attacker_ip

    # ── Section 6: IOC List ───────────────────────────────────────────────────────
    def test_ioc_list_non_empty(self, playbook):
        assert len(playbook.ioc_list) > 0

    def test_attacker_ip_in_iocs(self, playbook):
        ip_iocs = [i for i in playbook.ioc_list if i.ioc_type == "IP"]
        assert any(i.value == FakeThreatReport.attacker_ip for i in ip_iocs)

    def test_ioc_confidence_bounded(self, playbook):
        for ioc in playbook.ioc_list:
            assert 0.0 <= ioc.confidence <= 1.0

    # ── Section 7: Affected Assets ────────────────────────────────────────────────
    def test_affected_assets_non_empty(self, playbook):
        assert len(playbook.affected_assets) > 0

    def test_affected_assets_match_targets(self, playbook):
        asset_ips = {a.ip for a in playbook.affected_assets}
        for tip in FakeThreatReport.target_ips:
            assert tip in asset_ips

    # ── Section 8: Threat Actor ───────────────────────────────────────────────────
    def test_threat_actor_summary_non_empty(self, playbook):
        assert len(playbook.threat_actor_summary) > 0

    def test_ttp_summary_non_empty(self, playbook):
        assert len(playbook.ttp_summary) > 0

    # ── Section 9 & 10: Mitigation Commands ──────────────────────────────────────
    def test_linux_commands_present(self, playbook):
        assert len(playbook.mitigation_commands.linux_commands) > 0

    def test_windows_commands_present(self, playbook):
        assert len(playbook.mitigation_commands.windows_commands) > 0

    def test_verification_commands_present(self, playbook):
        assert len(playbook.mitigation_commands.verification_commands) > 0

    def test_rollback_commands_present(self, playbook):
        assert len(playbook.mitigation_commands.rollback_commands) > 0

    # ── Section 11: Containment Strategy ─────────────────────────────────────────
    def test_containment_strategy_non_empty(self, playbook):
        assert len(playbook.containment_strategy) > 0

    def test_containment_steps_list(self, playbook):
        assert isinstance(playbook.containment_steps, list)
        assert len(playbook.containment_steps) > 0

    # ── Section 12: Recovery Plan ─────────────────────────────────────────────────
    def test_recovery_plan_non_empty(self, playbook):
        assert len(playbook.recovery_plan) > 0

    def test_recovery_steps_list(self, playbook):
        assert isinstance(playbook.recovery_steps, list)
        assert len(playbook.recovery_steps) > 0

    # ── Section 13: Hardening ─────────────────────────────────────────────────────
    def test_hardening_recommendations_non_empty(self, playbook):
        assert len(playbook.hardening_recommendations) > 0

    # ── Section 14: Compliance ────────────────────────────────────────────────────
    def test_compliance_frameworks_listed(self, playbook):
        assert isinstance(playbook.compliance_frameworks, list)
        assert len(playbook.compliance_frameworks) > 0

    def test_compliance_impact_non_empty(self, playbook):
        assert len(playbook.compliance_impact) > 0

    # ── Section 15: Blast Radius ──────────────────────────────────────────────────
    def test_blast_radius_hosts(self, playbook):
        assert playbook.blast_radius_hosts == len(FakeThreatReport.target_ips)

    def test_blast_radius_subnets_listed(self, playbook):
        assert isinstance(playbook.blast_radius_subnets, list)
        assert len(playbook.blast_radius_subnets) > 0

    def test_blast_radius_description_non_empty(self, playbook):
        assert len(playbook.blast_radius_description) > 0

    def test_potential_data_exposure_non_empty(self, playbook):
        assert len(playbook.potential_data_exposure) > 0


# ─── JSON serialisability ─────────────────────────────────────────────────────


class TestPlaybookSerialisability:
    def test_to_dict_returns_dict(self, playbook):
        d = playbook.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_json_serialisable(self, playbook):
        d = playbook.to_dict()
        serialised = json.dumps(d)
        assert len(serialised) > 100

    def test_model_dump_json(self, playbook):
        raw = playbook.model_dump_json()
        parsed = json.loads(raw)
        assert "executive_summary" in parsed
        assert "mitigation_commands" in parsed

    def test_all_15_sections_in_dict(self, playbook):
        d = playbook.to_dict()
        required_keys = [
            "executive_summary",
            "threat_severity",
            "mitre_techniques",
            "root_cause_analysis",
            "attack_timeline",
            "ioc_list",
            "affected_assets",
            "threat_actor_summary",
            "mitigation_commands",
            "containment_strategy",
            "recovery_plan",
            "hardening_recommendations",
            "compliance_frameworks",
            "blast_radius_hosts",
            "blast_radius_description",
        ]
        for key in required_keys:
            assert key in d, f"Missing key: {key}"
