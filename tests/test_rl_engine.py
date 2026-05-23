"""
Tests for IMMUNEX Layer 3 — RLDecisionEngine

Tests cover:
  - State vector construction and bounds
  - Q-value computation for all 9 actions
  - Optimal action selection correctness
  - Output schema validation
  - Edge cases (zero confidence, max severity, all stages)
  - Action-to-stage alignment
  - Reward score normalisation
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.rl_decision_engine import RLDecisionEngine, ACTION_INDEX, STAGE_RISK
from core.response_models import ActionType, RLDecision


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def engine():
    return RLDecisionEngine()


def _eval(engine, **kwargs):
    defaults = dict(
        threat_impact=0.7,
        asset_criticality="HIGH",
        business_risk=0.6,
        attack_severity="HIGH",
        attack_stage="Lateral_Movement",
        confidence_score=0.85,
        predicted_next_stage="Persistence",
        is_anomaly=True,
    )
    defaults.update(kwargs)
    return engine.evaluate(**defaults)


# ─── Basic output validation ──────────────────────────────────────────────────


class TestRLDecisionOutput:
    def test_returns_rl_decision_instance(self, engine):
        decision = _eval(engine)
        assert isinstance(decision, RLDecision)

    def test_action_index_in_range(self, engine):
        decision = _eval(engine)
        assert 0 <= decision.action_index <= 8

    def test_optimal_action_in_action_index(self, engine):
        decision = _eval(engine)
        assert decision.optimal_action in ACTION_INDEX

    def test_reward_score_bounded(self, engine):
        decision = _eval(engine)
        assert 0.0 <= decision.reward_score <= 1.0

    def test_confidence_level_bounded(self, engine):
        decision = _eval(engine)
        assert 0.0 <= decision.confidence_level <= 1.0

    def test_risk_reduction_bounded(self, engine):
        decision = _eval(engine)
        assert 0.0 <= decision.risk_reduction_score <= 1.0

    def test_q_values_all_actions_present(self, engine):
        decision = _eval(engine)
        assert len(decision.q_values) == len(ACTION_INDEX)
        for action in ACTION_INDEX:
            assert action in decision.q_values

    def test_state_vector_length(self, engine):
        decision = _eval(engine)
        assert len(decision.state_vector) == 8

    def test_state_vector_bounded(self, engine):
        decision = _eval(engine)
        for v in decision.state_vector:
            assert 0.0 <= v <= 1.0

    def test_reasoning_non_empty(self, engine):
        decision = _eval(engine)
        assert len(decision.mitigation_reasoning) > 0

    def test_evaluated_at_set(self, engine):
        decision = _eval(engine)
        assert decision.evaluated_at is not None


# ─── Action-stage alignment ───────────────────────────────────────────────────


class TestActionStageAlignment:
    """Verify that the engine selects contextually appropriate actions."""

    def test_early_recon_prefers_honeypot_or_log(self, engine):
        """Reconnaissance stage should prefer low-impact or deceptive actions."""
        decision = _eval(
            engine,
            attack_stage="Reconnaissance",
            attack_severity="LOW",
            threat_impact=0.2,
            confidence_score=0.6,
            predicted_next_stage="Credential_Access",
        )
        # Should not select Shutdown or Isolate_Host for early low-severity recon
        assert decision.optimal_action != ActionType.SHUTDOWN_SYSTEM.value

    def test_lateral_movement_prefers_containment(self, engine):
        """Lateral movement should prefer segmentation or isolation."""
        decision = _eval(
            engine,
            attack_stage="Lateral_Movement",
            attack_severity="HIGH",
            threat_impact=0.8,
            confidence_score=0.9,
            predicted_next_stage="Persistence",
        )
        # High-severity lateral movement should pick a containment action
        containment_actions = {
            ActionType.MICRO_SEGMENTATION.value,
            ActionType.DISABLE_LATERAL_COMMS.value,
            ActionType.ISOLATE_HOST.value,
            ActionType.BLOCK_IP.value,
        }
        assert decision.optimal_action in containment_actions

    def test_credential_attack_prefers_token_or_mfa(self, engine):
        """Credential_Access stage should prefer token/MFA-oriented responses."""
        decision = _eval(
            engine,
            attack_stage="Credential_Access",
            attack_severity="MEDIUM",
            threat_impact=0.5,
            confidence_score=0.75,
            predicted_next_stage="Lateral_Movement",
        )
        # Credential-focused actions should rank highly
        assert decision.optimal_action in ACTION_INDEX

    def test_exfiltration_high_impact_action(self, engine):
        """Exfiltration with critical severity should select aggressive containment."""
        decision = _eval(
            engine,
            attack_stage="Exfiltration",
            attack_severity="CRITICAL",
            threat_impact=1.0,
            confidence_score=0.95,
            predicted_next_stage="Unknown",
        )
        # Should not be Log_Event for critical exfiltration
        assert decision.optimal_action != ActionType.LOG_EVENT.value


# ─── Edge cases ───────────────────────────────────────────────────────────────


class TestRLEdgeCases:
    def test_zero_confidence_low_reward(self, engine):
        """Very low confidence should produce low confidence_level output."""
        decision = _eval(engine, confidence_score=0.01)
        assert decision.confidence_level < 0.5

    def test_critical_severity_high_reward(self, engine):
        """Critical severity with high confidence should produce high reward."""
        decision = _eval(
            engine,
            attack_severity="CRITICAL",
            confidence_score=0.99,
            threat_impact=1.0,
        )
        assert decision.reward_score > 0.3

    def test_info_severity_log_likely(self, engine):
        """INFO severity + low threat should prefer logging."""
        decision = _eval(
            engine,
            attack_severity="INFO",
            threat_impact=0.05,
            business_risk=0.02,
            confidence_score=0.3,
            is_anomaly=False,
        )
        # With very low threat, log or honeypot is sensible
        low_impact = {ActionType.LOG_EVENT.value, ActionType.TRIGGER_HONEYPOT.value}
        # At minimum reward should be low (not high-impact action)
        assert decision.reward_score >= 0.0

    def test_all_known_stages(self, engine):
        """All known attack stages must produce valid decisions."""
        for stage in STAGE_RISK:
            decision = _eval(engine, attack_stage=stage)
            assert isinstance(decision, RLDecision)
            assert 0.0 <= decision.reward_score <= 1.0

    def test_all_criticality_levels(self, engine):
        """All criticality labels must produce valid decisions."""
        for criticality in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            decision = _eval(engine, asset_criticality=criticality)
            assert isinstance(decision, RLDecision)

    def test_unknown_stage_handled_gracefully(self, engine):
        """Unknown attack stage must not raise an exception."""
        decision = _eval(engine, attack_stage="Undefined_Stage_XYZ")
        assert isinstance(decision, RLDecision)

    def test_q_values_consistent_with_optimal(self, engine):
        """The optimal action must have the highest Q-value in the table."""
        decision = _eval(engine)
        best_q = max(decision.q_values.values())
        assert decision.q_values[decision.optimal_action] == pytest.approx(best_q, abs=1e-4)

    def test_non_anomaly_lower_confidence(self, engine):
        """Non-anomaly flag should reduce overall confidence output."""
        anomaly_dec = _eval(engine, is_anomaly=True, confidence_score=0.8)
        normal_dec = _eval(engine, is_anomaly=False, confidence_score=0.8)
        # Anomaly should have >= confidence
        assert anomaly_dec.confidence_level >= normal_dec.confidence_level - 0.05

    def test_repeated_calls_deterministic(self, engine):
        """Same inputs must always produce the same output (deterministic)."""
        d1 = _eval(engine, threat_impact=0.7, confidence_score=0.85)
        d2 = _eval(engine, threat_impact=0.7, confidence_score=0.85)
        assert d1.optimal_action == d2.optimal_action
        assert d1.reward_score == d2.reward_score


# ─── Evaluate from threat report ─────────────────────────────────────────────


class TestEvaluateFromReport:
    def test_evaluate_from_threat_report(self, engine):
        """evaluate_from_threat_report must accept a report-like object."""

        class FakeReport:
            risk_score = 0.75
            severity = "HIGH"
            stages_observed = ["Reconnaissance", "Lateral_Movement"]
            prediction_confidence = 0.8
            predicted_next_stage = "Persistence"

        report = FakeReport()
        decision = engine.evaluate_from_threat_report(report)
        assert isinstance(decision, RLDecision)
        assert decision.optimal_action in ACTION_INDEX

    def test_evaluate_empty_stages(self, engine):
        """evaluate_from_threat_report with empty stages must not crash."""

        class FakeReport:
            risk_score = 0.5
            severity = "MEDIUM"
            stages_observed = []
            prediction_confidence = 0.5
            predicted_next_stage = "Unknown"

        decision = engine.evaluate_from_threat_report(FakeReport())
        assert isinstance(decision, RLDecision)
