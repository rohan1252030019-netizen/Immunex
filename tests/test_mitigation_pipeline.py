"""
Tests for IMMUNEX Layer 3 — Full Mitigation Pipeline Integration

Tests cover:
  - ImmuneResponseEngine end-to-end pipeline
  - ImmunityResponse schema validation
  - RL → Policy → Playbook chain integrity
  - Telemetry / stats output
  - Offline operation (no Ollama)
  - Command generation for all action types
  - Subnet inference
  - Pipeline error recovery
"""

from __future__ import annotations

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core.immune_response import ImmuneResponseEngine
from core.mitigation_actions import (
    block_ip,
    isolate_host,
    revoke_token,
    suspend_process,
    micro_segmentation,
    disable_lateral_comms,
    force_mfa_reset,
    trigger_honeypot,
    log_event_only,
    isolate_network_traffic,
    generate_commands,
    CommandSet,
)
from core.response_models import ActionType, ImmunityResponse, PolicyVerdict


# ─── Fake ThreatReport ────────────────────────────────────────────────────────


class FakeThreatReport:
    campaign_id        = "CAMP-TEST9999"
    attacker_ip        = "203.0.113.50"
    target_ips         = ["10.1.0.10", "10.1.0.11"]
    stages_observed    = ["Reconnaissance", "Credential_Access", "Lateral_Movement"]
    predicted_next_stage = "Persistence"
    severity           = "HIGH"
    risk_score         = 0.80
    prediction_confidence = 0.88
    narrative          = {}
    formatted_report   = "Recon → Credential → Lateral"


@pytest.fixture(scope="module")
def layer3():
    return ImmuneResponseEngine()


@pytest.fixture(scope="module")
def response(layer3):
    return layer3.process(
        report=FakeThreatReport(),
        process_name="mimikatz.exe",
        user_id="test_user",
    )


# ─── ImmuneResponseEngine ─────────────────────────────────────────────────────


class TestImmuneResponseEngine:
    def test_returns_immunity_response(self, response):
        assert isinstance(response, ImmunityResponse)

    def test_response_id_format(self, response):
        assert response.response_id.startswith("IR-")

    def test_campaign_id_preserved(self, response):
        assert response.campaign_id == FakeThreatReport.campaign_id

    def test_rl_decision_present(self, response):
        assert response.rl_decision is not None
        assert 0.0 <= response.rl_decision.reward_score <= 1.0

    def test_policy_decision_present(self, response):
        assert response.policy_decision is not None
        assert response.policy_decision.verdict in (
            PolicyVerdict.APPROVED.value,
            PolicyVerdict.DOWNGRADED.value,
            PolicyVerdict.REJECTED.value,
        )

    def test_final_action_non_empty(self, response):
        assert isinstance(response.final_action, str)
        assert len(response.final_action) > 0

    def test_playbook_present(self, response):
        assert response.playbook is not None

    def test_latency_ms_positive(self, response):
        assert response.total_latency_ms > 0.0
        assert response.rl_latency_ms >= 0.0
        assert response.policy_latency_ms >= 0.0
        assert response.playbook_latency_ms >= 0.0

    def test_containment_confidence_bounded(self, response):
        assert 0.0 <= response.containment_confidence <= 1.0

    def test_generated_at_set(self, response):
        assert response.generated_at is not None

    def test_to_dict_json_serialisable(self, response):
        d = response.to_dict()
        raw = json.dumps(d)
        assert len(raw) > 50

    def test_summary_method(self, response):
        summary = response.summary()
        assert "Layer3" in summary
        assert response.campaign_id[:8] in summary

    def test_policy_final_action_consistency(self, response):
        """final_action must equal policy_decision.approved_action."""
        assert response.final_action == response.policy_decision.approved_action


# ─── Stats / telemetry ────────────────────────────────────────────────────────


class TestImmuneResponseStats:
    def test_stats_returns_dict(self, layer3):
        stats = layer3.stats()
        assert isinstance(stats, dict)

    def test_stats_has_required_keys(self, layer3):
        stats = layer3.stats()
        required = [
            "total_processed", "total_approved", "total_downgraded",
            "total_rejected", "uptime_seconds", "ollama_available", "ollama_model"
        ]
        for key in required:
            assert key in stats, f"Missing key: {key}"

    def test_stats_total_processed_positive(self, layer3, response):
        stats = layer3.stats()
        assert stats["total_processed"] >= 1

    def test_stats_verdict_counts_sum(self, layer3):
        stats = layer3.stats()
        total_verdicts = (
            stats["total_approved"]
            + stats["total_downgraded"]
            + stats["total_rejected"]
        )
        assert total_verdicts <= stats["total_processed"]


# ─── Error recovery ───────────────────────────────────────────────────────────


class TestPipelineErrorRecovery:
    def test_none_returned_for_malformed_report(self, layer3):
        """Engine must not raise on completely empty report-like object."""
        class EmptyReport:
            pass

        result = layer3.process(report=EmptyReport())
        # Must return None (graceful error) rather than raising
        assert result is None or isinstance(result, ImmunityResponse)

    def test_missing_attacker_ip_handled(self, layer3):
        class PartialReport:
            campaign_id = "PARTIAL-001"
            attacker_ip = ""
            target_ips = []
            stages_observed = ["Unknown"]
            severity = "LOW"
            risk_score = 0.1
            prediction_confidence = 0.3
            predicted_next_stage = "Unknown"
            narrative = {}
            formatted_report = ""

        result = layer3.process(report=PartialReport())
        assert result is None or isinstance(result, ImmunityResponse)


# ─── Mitigation command generation ───────────────────────────────────────────


class TestCommandGeneration:
    ATTACKER = "203.0.113.50"
    TARGET   = "10.0.0.100"
    SUBNET   = "10.0.0.0/24"

    def _check_cmd_set(self, cs: CommandSet):
        assert isinstance(cs.linux_commands, list)
        assert isinstance(cs.windows_commands, list)
        assert len(cs.linux_commands) > 0
        assert len(cs.windows_commands) > 0

    def test_block_ip_commands(self):
        cs = block_ip(self.ATTACKER)
        self._check_cmd_set(cs)
        assert any(self.ATTACKER in c for c in cs.linux_commands)
        assert any(self.ATTACKER in c for c in cs.windows_commands)

    def test_isolate_host_commands(self):
        cs = isolate_host(self.TARGET)
        self._check_cmd_set(cs)
        assert any(self.TARGET in c for c in cs.linux_commands)

    def test_revoke_token_commands(self):
        cs = revoke_token("testuser")
        self._check_cmd_set(cs)
        assert any("testuser" in c for c in cs.linux_commands)

    def test_suspend_process_commands(self):
        cs = suspend_process("mimikatz.exe")
        self._check_cmd_set(cs)
        assert any("mimikatz" in c for c in cs.linux_commands)
        assert any("mimikatz" in c for c in cs.windows_commands)

    def test_micro_segmentation_commands(self):
        cs = micro_segmentation(self.SUBNET, self.ATTACKER)
        self._check_cmd_set(cs)

    def test_disable_lateral_comms_commands(self):
        cs = disable_lateral_comms(self.SUBNET)
        self._check_cmd_set(cs)

    def test_force_mfa_reset_commands(self):
        cs = force_mfa_reset("jdoe")
        self._check_cmd_set(cs)

    def test_trigger_honeypot_commands(self):
        cs = trigger_honeypot(self.ATTACKER)
        self._check_cmd_set(cs)
        assert any(self.ATTACKER in c for c in cs.linux_commands)

    def test_log_event_commands(self):
        cs = log_event_only("Threat detected", "CAMP-001")
        assert len(cs.linux_commands) > 0
        assert len(cs.windows_commands) > 0

    def test_isolate_network_traffic_commands(self):
        cs = isolate_network_traffic(self.TARGET)
        self._check_cmd_set(cs)

    def test_commands_have_rollback(self):
        for fn, kwargs in [
            (block_ip,             {"attacker_ip": self.ATTACKER}),
            (isolate_host,         {"target_ip": self.TARGET}),
            (micro_segmentation,   {"target_subnet": self.SUBNET, "attacker_ip": self.ATTACKER}),
            (disable_lateral_comms, {"target_subnet": self.SUBNET}),
            (trigger_honeypot,     {"attacker_ip": self.ATTACKER}),
        ]:
            cs = fn(**kwargs)
            assert isinstance(cs.rollback_commands, list), f"{fn.__name__} missing rollback"

    def test_generate_commands_dispatcher_all_actions(self):
        """generate_commands dispatcher must handle all 10 action types."""
        actions = [
            ActionType.LOG_EVENT.value,
            ActionType.REVOKE_TOKEN.value,
            ActionType.ISOLATE_HOST.value,
            ActionType.BLOCK_IP.value,
            ActionType.TRIGGER_HONEYPOT.value,
            ActionType.MICRO_SEGMENTATION.value,
            ActionType.SUSPEND_PROCESS.value,
            ActionType.DISABLE_LATERAL_COMMS.value,
            ActionType.FORCE_MFA_RESET.value,
            ActionType.ISOLATE_NETWORK_TRAFFIC.value,
        ]
        for action in actions:
            cs = generate_commands(
                action_type=action,
                attacker_ip=self.ATTACKER,
                target_ip=self.TARGET,
                process_name="test_proc.exe",
                user_id="test_user",
                target_subnet=self.SUBNET,
                campaign_id="TEST-001",
            )
            assert isinstance(cs, CommandSet), f"Failed for action: {action}"
            assert len(cs.linux_commands) > 0, f"No linux commands for: {action}"

    def test_generate_commands_unknown_action_fallback(self):
        """Unknown action type must fall back to log_event gracefully."""
        cs = generate_commands(
            action_type="Unknown_Action_XYZ",
            attacker_ip=self.ATTACKER,
            target_ip=self.TARGET,
        )
        assert isinstance(cs, CommandSet)
        assert len(cs.linux_commands) > 0

    def test_commands_contain_immunex_tag(self):
        """Production commands must include IMMUNEX attribution in comments."""
        cs = block_ip(self.ATTACKER)
        assert any("IMMUNEX" in c for c in cs.linux_commands)
        assert any("IMMUNEX" in c for c in cs.windows_commands)
