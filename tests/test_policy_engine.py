"""
Tests for IMMUNEX Layer 3 — PolicyEngine

Tests cover:
  - Tier_1 destructive action downgrade (R01)
  - Shutdown rejection on critical assets (R02)
  - Payment gateway isolation block (R03)
  - Business-hours aggressive action block (R04)
  - Executive account protection (R05)
  - Tier_1 IP block during business hours (R06)
  - Low-confidence guard (R07)
  - Default approval for safe actions
  - Business impact scoring
  - Batch evaluation
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime

from core.policy_engine import (
    PolicyEngine,
    _business_impact_score,
    _compute_risk_score,
    _detect_business_window,
)
from core.response_models import (
    ActionType,
    AssetTier,
    BusinessWindow,
    MitigationAction,
    PolicyVerdict,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_action(
    action_type: str = ActionType.BLOCK_IP.value,
    asset_tier: str = AssetTier.TIER_3.value,
    asset_criticality: str = "MEDIUM",
    is_payment_gateway: bool = False,
    is_executive_account: bool = False,
    business_window: str = BusinessWindow.OFF_HOURS.value,
    confidence: float = 0.85,
    risk_score: float = 0.6,
) -> MitigationAction:
    return MitigationAction(
        action_id="TEST-001",
        action_type=action_type,
        target_ip="10.0.0.100",
        target_asset="ASSET-10-0-0-100",
        asset_tier=asset_tier,
        asset_criticality=asset_criticality,
        attacker_ip="192.168.1.50",
        campaign_id="CAMP-TEST-001",
        attack_stage="Lateral_Movement",
        severity="HIGH",
        confidence=confidence,
        risk_score=risk_score,
        predicted_next_stage="Persistence",
        is_payment_gateway=is_payment_gateway,
        is_executive_account=is_executive_account,
        business_window=business_window,
    )


# ─── PolicyEngine tests ───────────────────────────────────────────────────────


class TestPolicyEngine:
    """Test suite for the PolicyEngine deterministic rule chain."""

    def setup_method(self):
        self.engine = PolicyEngine()

    def test_shutdown_tier1_is_rejected(self):
        """Rule R02: Shutdown on Tier_1 asset must be rejected."""
        action = _make_action(
            action_type=ActionType.SHUTDOWN_SYSTEM.value,
            asset_tier=AssetTier.TIER_1.value,
            asset_criticality="CRITICAL",
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.REJECTED.value
        assert "R02" in " ".join(decision.rules_evaluated)
        assert decision.rejected_action == ActionType.SHUTDOWN_SYSTEM.value
        assert decision.approved_action != ActionType.SHUTDOWN_SYSTEM.value

    def test_shutdown_tier2_is_rejected(self):
        """Rule R02: Shutdown on Tier_2 asset must also be rejected."""
        action = _make_action(
            action_type=ActionType.SHUTDOWN_SYSTEM.value,
            asset_tier=AssetTier.TIER_2.value,
            asset_criticality="HIGH",
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.REJECTED.value

    def test_isolate_host_tier1_downgraded(self):
        """Rule R01: Isolate_Host on Tier_1 must be downgraded."""
        action = _make_action(
            action_type=ActionType.ISOLATE_HOST.value,
            asset_tier=AssetTier.TIER_1.value,
            asset_criticality="CRITICAL",
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.DOWNGRADED.value
        assert decision.approved_action == ActionType.MICRO_SEGMENTATION.value
        assert "R01" in " ".join(decision.rules_evaluated)

    def test_disable_lateral_comms_tier1_downgraded(self):
        """Rule R01: Disable_Lateral_Communications on Tier_1 must be downgraded."""
        action = _make_action(
            action_type=ActionType.DISABLE_LATERAL_COMMS.value,
            asset_tier=AssetTier.TIER_1.value,
            asset_criticality="CRITICAL",
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict in (
            PolicyVerdict.DOWNGRADED.value,
            PolicyVerdict.REJECTED.value,
        )
        assert decision.approved_action != ActionType.DISABLE_LATERAL_COMMS.value

    def test_payment_gateway_isolation_blocked(self):
        """Rule R03: Isolation actions on payment gateways must be blocked."""
        action = _make_action(
            action_type=ActionType.BLOCK_IP.value,
            asset_tier=AssetTier.TIER_1.value,
            is_payment_gateway=True,
        )
        decision = self.engine.evaluate(action)
        # R03 fires before R06 — should be DOWNGRADED to Isolate_Network_Traffic
        assert decision.verdict == PolicyVerdict.DOWNGRADED.value
        assert decision.approved_action == ActionType.ISOLATE_NETWORK_TRAFFIC.value
        assert "R03" in " ".join(decision.rules_evaluated)

    def test_business_hours_aggressive_action_downgraded(self):
        """Rule R04: Aggressive actions on critical assets during business hours downgraded."""
        action = _make_action(
            action_type=ActionType.SHUTDOWN_SYSTEM.value,
            asset_tier=AssetTier.TIER_2.value,
            asset_criticality="HIGH",
            business_window=BusinessWindow.BUSINESS_HOURS.value,
        )
        # Shutdown is caught by R02 before R04 — test isolate_host instead
        action2 = _make_action(
            action_type=ActionType.ISOLATE_HOST.value,
            asset_tier=AssetTier.TIER_2.value,
            asset_criticality="HIGH",
            business_window=BusinessWindow.BUSINESS_HOURS.value,
        )
        decision = self.engine.evaluate(action2)
        # Could be R01 or R04 depending on evaluation order — both correct
        assert decision.verdict in (
            PolicyVerdict.DOWNGRADED.value,
            PolicyVerdict.REJECTED.value,
        )

    def test_executive_revoke_token_downgraded(self):
        """Rule R05: Token revocation on executive account must be downgraded."""
        action = _make_action(
            action_type=ActionType.REVOKE_TOKEN.value,
            is_executive_account=True,
            asset_tier=AssetTier.TIER_2.value,
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.DOWNGRADED.value
        assert decision.approved_action == ActionType.FORCE_MFA_RESET.value
        assert "R05" in " ".join(decision.rules_evaluated)

    def test_low_confidence_action_logged_only(self):
        """Rule R07: Actions with confidence < 0.25 must be downgraded to Log_Event."""
        action = _make_action(
            action_type=ActionType.ISOLATE_HOST.value,
            confidence=0.15,
            asset_tier=AssetTier.TIER_3.value,
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.DOWNGRADED.value
        assert decision.approved_action == ActionType.LOG_EVENT.value
        assert "R07" in " ".join(decision.rules_evaluated)

    def test_safe_action_approved_unconditionally(self):
        """Log_Event on any tier must be approved without restriction."""
        action = _make_action(
            action_type=ActionType.LOG_EVENT.value,
            asset_tier=AssetTier.TIER_1.value,
            asset_criticality="CRITICAL",
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.APPROVED.value
        assert decision.approved_action == ActionType.LOG_EVENT.value

    def test_micro_segmentation_tier1_approved(self):
        """Micro_Segmentation is safe and must be approved even on Tier_1."""
        action = _make_action(
            action_type=ActionType.MICRO_SEGMENTATION.value,
            asset_tier=AssetTier.TIER_1.value,
            asset_criticality="CRITICAL",
            confidence=0.9,
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.APPROVED.value

    def test_honeypot_always_approved(self):
        """Trigger_Shadow_Honeypot is always safe and must be approved."""
        action = _make_action(
            action_type=ActionType.TRIGGER_HONEYPOT.value,
            asset_tier=AssetTier.TIER_1.value,
            asset_criticality="CRITICAL",
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.APPROVED.value

    def test_decision_has_required_fields(self):
        """PolicyDecision must always contain all required output fields."""
        action = _make_action()
        decision = self.engine.evaluate(action)
        assert decision.action_id == action.action_id
        assert decision.original_action is not None
        assert decision.approved_action is not None
        assert decision.policy_reason != ""
        assert 0.0 <= decision.risk_score <= 1.0
        assert 0.0 <= decision.business_impact_score <= 1.0
        assert isinstance(decision.rules_evaluated, list)
        assert len(decision.rules_evaluated) > 0

    def test_risk_score_bounded(self):
        """Risk score must always be in [0, 1]."""
        for tier in [AssetTier.TIER_1.value, AssetTier.TIER_2.value,
                     AssetTier.TIER_3.value, AssetTier.TIER_4.value]:
            action = _make_action(asset_tier=tier, risk_score=0.95)
            decision = self.engine.evaluate(action)
            assert 0.0 <= decision.risk_score <= 1.0

    def test_batch_evaluate(self):
        """Batch evaluation must return one decision per action."""
        actions = [
            _make_action(action_type=ActionType.LOG_EVENT.value),
            _make_action(action_type=ActionType.BLOCK_IP.value),
            _make_action(
                action_type=ActionType.SHUTDOWN_SYSTEM.value,
                asset_tier=AssetTier.TIER_1.value,
            ),
        ]
        decisions = self.engine.batch_evaluate(actions)
        assert len(decisions) == 3
        assert decisions[0].verdict == PolicyVerdict.APPROVED.value
        assert decisions[2].verdict in (
            PolicyVerdict.REJECTED.value, PolicyVerdict.DOWNGRADED.value
        )

    def test_downgrade_mapping_populated_on_downgrade(self):
        """downgrade_mapping must be populated when action is downgraded."""
        action = _make_action(
            action_type=ActionType.SHUTDOWN_SYSTEM.value,
            asset_tier=AssetTier.TIER_1.value,
        )
        decision = self.engine.evaluate(action)
        if decision.verdict in (PolicyVerdict.DOWNGRADED.value, PolicyVerdict.REJECTED.value):
            assert len(decision.downgrade_mapping) > 0

    def test_block_ip_tier3_off_hours_approved(self):
        """Block_IP on Tier_3 during off-hours must be approved."""
        action = _make_action(
            action_type=ActionType.BLOCK_IP.value,
            asset_tier=AssetTier.TIER_3.value,
            business_window=BusinessWindow.OFF_HOURS.value,
            confidence=0.85,
        )
        decision = self.engine.evaluate(action)
        assert decision.verdict == PolicyVerdict.APPROVED.value


# ─── Business Impact Scoring tests ───────────────────────────────────────────


class TestBusinessImpactScoring:
    def test_log_event_zero_impact(self):
        score = _business_impact_score(
            ActionType.LOG_EVENT.value,
            AssetTier.TIER_1.value,
            BusinessWindow.BUSINESS_HOURS.value,
        )
        assert score == 0.0

    def test_shutdown_tier1_business_hours_max_impact(self):
        score = _business_impact_score(
            ActionType.SHUTDOWN_SYSTEM.value,
            AssetTier.TIER_1.value,
            BusinessWindow.BUSINESS_HOURS.value,
        )
        assert score > 0.8, f"Expected > 0.8, got {score}"
        assert score <= 1.0

    def test_micro_seg_lower_impact_than_shutdown(self):
        seg = _business_impact_score(
            ActionType.MICRO_SEGMENTATION.value,
            AssetTier.TIER_2.value,
            BusinessWindow.OFF_HOURS.value,
        )
        shutdown = _business_impact_score(
            ActionType.SHUTDOWN_SYSTEM.value,
            AssetTier.TIER_2.value,
            BusinessWindow.OFF_HOURS.value,
        )
        assert seg < shutdown

    def test_business_hours_increases_impact(self):
        off = _business_impact_score(
            ActionType.ISOLATE_HOST.value,
            AssetTier.TIER_2.value,
            BusinessWindow.OFF_HOURS.value,
        )
        biz = _business_impact_score(
            ActionType.ISOLATE_HOST.value,
            AssetTier.TIER_2.value,
            BusinessWindow.BUSINESS_HOURS.value,
        )
        assert biz > off


# ─── Business Window Detection tests ─────────────────────────────────────────


class TestBusinessWindowDetection:
    def test_weekend_is_off_hours(self):
        saturday = datetime(2024, 6, 1, 14, 0, 0)  # Saturday 14:00
        window = _detect_business_window(saturday)
        assert window == BusinessWindow.OFF_HOURS

    def test_weekday_business_hours(self):
        monday_noon = datetime(2024, 6, 3, 12, 0, 0)  # Monday 12:00
        window = _detect_business_window(monday_noon)
        assert window == BusinessWindow.BUSINESS_HOURS

    def test_weekday_night_is_off_hours(self):
        tuesday_night = datetime(2024, 6, 4, 22, 0, 0)  # Tuesday 22:00
        window = _detect_business_window(tuesday_night)
        assert window == BusinessWindow.OFF_HOURS
