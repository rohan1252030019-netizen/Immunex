"""
IMMUNEX Layer 3 — Policy Engine
=================================
Deterministic safety validation layer that sits between the RL Decision Engine
and actual mitigation execution.

Every proposed mitigation action MUST pass through this engine before it is
approved.  The engine evaluates a comprehensive rule set to:

1. Prevent destructive actions on Tier_1 / critical banking assets
2. Enforce business-continuity safeguards during operational windows
3. Verify containment safety (blast-radius awareness)
4. Perform automated action downgrade when hard restrictions apply
5. Block unsafe credential revocation for executive accounts

Rule evaluation is deterministic — the same inputs always produce the same
output.  No ML / probabilistic components are used.

Output:
  PolicyDecision  (see response_models.py)
    .verdict        → APPROVED | DOWNGRADED | REJECTED
    .approved_action
    .rejected_action
    .policy_reason
    .risk_score
    .business_impact_score
    .downgrade_mapping
    .rules_evaluated
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Optional

from utils.logger import log
from core.response_models import (
    ActionType,
    AssetTier,
    BusinessWindow,
    MitigationAction,
    PolicyDecision,
    PolicyVerdict,
)


# ─── Business Window Detection ────────────────────────────────────────────────


def _detect_business_window(now: Optional[datetime] = None) -> BusinessWindow:
    """
    Classify the current time into a business window category.
    Uses UTC; in production override with local timezone.
    """
    if now is None:
        now = datetime.utcnow()
    hour = now.hour
    day = now.weekday()  # 0=Monday … 6=Sunday

    # Weekends → off-hours
    if day >= 5:
        return BusinessWindow.OFF_HOURS
    # Business hours: Monday–Friday 09:00–17:00 UTC
    if 9 <= hour < 17:
        return BusinessWindow.BUSINESS_HOURS
    return BusinessWindow.OFF_HOURS


# ─── Downgrade Table ──────────────────────────────────────────────────────────

# Maps unsafe actions to their safer replacements
DOWNGRADE_MAP: dict[str, str] = {
    ActionType.SHUTDOWN_SYSTEM.value: ActionType.MICRO_SEGMENTATION.value,
    ActionType.ISOLATE_HOST.value: ActionType.MICRO_SEGMENTATION.value,
    ActionType.DISABLE_LATERAL_COMMS.value: ActionType.MICRO_SEGMENTATION.value,
    ActionType.REVOKE_TOKEN.value: ActionType.FORCE_MFA_RESET.value,
    ActionType.BLOCK_IP.value: ActionType.LOG_EVENT.value,
}

# Actions that are always safe regardless of asset tier
ALWAYS_SAFE_ACTIONS: set[str] = {
    ActionType.LOG_EVENT.value,
    ActionType.TRIGGER_HONEYPOT.value,
    ActionType.FORCE_MFA_RESET.value,
    ActionType.MICRO_SEGMENTATION.value,
    ActionType.ISOLATE_NETWORK_TRAFFIC.value,
}

# Actions that require Tier_3 / Tier_4 minimum (forbidden on Tier_1 / Tier_2)
DESTRUCTIVE_ACTIONS: set[str] = {
    ActionType.SHUTDOWN_SYSTEM.value,
    ActionType.ISOLATE_HOST.value,
    ActionType.DISABLE_LATERAL_COMMS.value,
}

# Actions blocked on payment-gateway assets
PAYMENT_GATEWAY_FORBIDDEN: set[str] = {
    ActionType.SHUTDOWN_SYSTEM.value,
    ActionType.ISOLATE_HOST.value,
    ActionType.BLOCK_IP.value,
    ActionType.DISABLE_LATERAL_COMMS.value,
}

# Actions blocked during business-critical windows
BUSINESS_WINDOW_AGGRESSIVE_ACTIONS: set[str] = {
    ActionType.SHUTDOWN_SYSTEM.value,
    ActionType.ISOLATE_HOST.value,
    ActionType.DISABLE_LATERAL_COMMS.value,
    ActionType.SUSPEND_PROCESS.value,
}

# Actions forbidden for executive accounts
EXECUTIVE_FORBIDDEN_ACTIONS: set[str] = {
    ActionType.REVOKE_TOKEN.value,
    ActionType.SHUTDOWN_SYSTEM.value,
    ActionType.SUSPEND_PROCESS.value,
    ActionType.ISOLATE_HOST.value,
}


# ─── Business Impact Scoring ──────────────────────────────────────────────────


def _business_impact_score(action: str, asset_tier: str, business_window: str) -> float:
    """
    Estimate the business impact score [0.0, 1.0] for a given action/asset pair.
    Higher = more disruptive.
    """
    action_disruption: dict[str, float] = {
        ActionType.LOG_EVENT.value: 0.0,
        ActionType.TRIGGER_HONEYPOT.value: 0.02,
        ActionType.FORCE_MFA_RESET.value: 0.05,
        ActionType.MICRO_SEGMENTATION.value: 0.1,
        ActionType.ISOLATE_NETWORK_TRAFFIC.value: 0.15,
        ActionType.BLOCK_IP.value: 0.2,
        ActionType.REVOKE_TOKEN.value: 0.25,
        ActionType.SUSPEND_PROCESS.value: 0.35,
        ActionType.DISABLE_LATERAL_COMMS.value: 0.45,
        ActionType.ISOLATE_HOST.value: 0.65,
        ActionType.SHUTDOWN_SYSTEM.value: 0.90,
    }
    tier_multiplier: dict[str, float] = {
        AssetTier.TIER_1.value: 2.0,
        AssetTier.TIER_2.value: 1.4,
        AssetTier.TIER_3.value: 1.0,
        AssetTier.TIER_4.value: 0.5,
    }
    window_multiplier: float = (
        1.5 if business_window == BusinessWindow.BUSINESS_HOURS.value else 1.0
    )

    base = action_disruption.get(action, 0.3)
    tm = tier_multiplier.get(asset_tier, 1.0)
    return min(base * tm * window_multiplier, 1.0)


# ─── Risk Score ───────────────────────────────────────────────────────────────


def _compute_risk_score(action: MitigationAction) -> float:
    """
    Compute a risk score [0.0, 1.0] that balances threat severity against
    action disruption potential.
    Higher score = safer mitigation choice (low risk of excessive disruption).
    """
    # Raw threat risk
    threat_risk = action.risk_score

    # Disruption penalty
    disruption = _business_impact_score(
        action.action_type,
        action.asset_tier,
        action.business_window,
    )

    # Net risk score = threat_risk penalised by collateral disruption
    net = threat_risk * (1.0 - 0.4 * disruption)
    return round(min(max(net, 0.0), 1.0), 4)


# ─── Policy Engine ────────────────────────────────────────────────────────────


class PolicyEngine:
    """
    Deterministic policy engine that enforces safety constraints on proposed
    mitigation actions.

    Usage::

        engine = PolicyEngine()
        decision = engine.evaluate(action)
        if decision.verdict == "APPROVED":
            execute(decision.approved_action)
    """

    def __init__(self) -> None:
        log.info("PolicyEngine initialised — deterministic safety validation active")

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(self, action: MitigationAction) -> PolicyDecision:
        """
        Run the full policy rule chain against a proposed MitigationAction.

        Rules are evaluated in priority order; the first hard-block or
        downgrade that fires wins.  If no rule blocks the action, it is APPROVED.

        Returns:
            PolicyDecision with verdict, reason, and scoring.
        """
        t0 = time.perf_counter()
        rules_evaluated: list[str] = []
        proposed = action.action_type

        # Normalise window — respect action's pre-set business_window field;
        # fall back to real-time detection if not set.
        if action.business_window and action.business_window != "":
            try:
                window = BusinessWindow(action.business_window)
            except ValueError:
                window = _detect_business_window()
        else:
            window = _detect_business_window()

        # ── Rule 2: Shutdown on ANY Tier_1 / Tier_2 (evaluated first) ────
        rules_evaluated.append("R02_SHUTDOWN_CRITICAL_ASSET")
        if (
            proposed == ActionType.SHUTDOWN_SYSTEM.value
            and action.asset_tier in (AssetTier.TIER_1.value, AssetTier.TIER_2.value)
        ):
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.REJECTED,
                approved=ActionType.MICRO_SEGMENTATION.value,
                rejected=proposed,
                reason=(
                    f"Rule R02: System shutdown is categorically rejected for "
                    f"{action.asset_tier} asset '{action.target_asset}'. "
                    "Mitigation escalated to Micro_Segmentation."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── Rule 1: Tier_1 asset + other destructive actions ─────────────
        rules_evaluated.append("R01_TIER1_DESTRUCTIVE_ACTION")
        _destructive_non_shutdown = DESTRUCTIVE_ACTIONS - {ActionType.SHUTDOWN_SYSTEM.value}
        if (
            action.asset_tier == AssetTier.TIER_1.value
            and proposed in _destructive_non_shutdown
        ):
            downgraded = DOWNGRADE_MAP.get(proposed, ActionType.MICRO_SEGMENTATION.value)
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.DOWNGRADED,
                approved=downgraded,
                rejected=proposed,
                reason=(
                    f"Rule R01: Action '{proposed}' is destructive on a Tier_1 asset "
                    f"({action.target_asset}). Auto-downgraded to '{downgraded}' "
                    "to preserve business continuity."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── Rule 3: Payment gateway — subnet/host isolation forbidden ─────
        rules_evaluated.append("R03_PAYMENT_GATEWAY_ISOLATION")
        if action.is_payment_gateway and proposed in PAYMENT_GATEWAY_FORBIDDEN:
            downgraded = ActionType.ISOLATE_NETWORK_TRAFFIC.value
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.DOWNGRADED,
                approved=downgraded,
                rejected=proposed,
                reason=(
                    f"Rule R03: Action '{proposed}' is forbidden on payment-gateway "
                    f"asset '{action.target_asset}'. Full isolation would disrupt "
                    "payment processing. Downgraded to Isolate_Network_Traffic."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── Rule 4: Aggressive actions during business hours ──────────────
        rules_evaluated.append("R04_BUSINESS_WINDOW_BLOCK")
        if (
            window == BusinessWindow.BUSINESS_HOURS
            and proposed in BUSINESS_WINDOW_AGGRESSIVE_ACTIONS
            and action.asset_tier in (AssetTier.TIER_1.value, AssetTier.TIER_2.value)
        ):
            downgraded = ActionType.MICRO_SEGMENTATION.value
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.DOWNGRADED,
                approved=downgraded,
                rejected=proposed,
                reason=(
                    f"Rule R04: Aggressive action '{proposed}' blocked during "
                    "business-critical window (09:00–17:00 UTC) on a critical asset. "
                    "Downgraded to non-disruptive Micro_Segmentation."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── Rule 5: Executive account — credential revocation forbidden ───
        rules_evaluated.append("R05_EXECUTIVE_CREDENTIAL_PROTECTION")
        if action.is_executive_account and proposed in EXECUTIVE_FORBIDDEN_ACTIONS:
            downgraded = ActionType.FORCE_MFA_RESET.value
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.DOWNGRADED,
                approved=downgraded,
                rejected=proposed,
                reason=(
                    f"Rule R05: Unsafe automated action '{proposed}' is forbidden for "
                    "executive accounts without manual authorisation. "
                    "Downgraded to Force_MFA_Reset pending approval."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── Rule 6: Tier_1 — block IP during business hours ──────────────
        rules_evaluated.append("R06_TIER1_BLOCK_IP_BUSINESS_HOURS")
        if (
            action.asset_tier == AssetTier.TIER_1.value
            and proposed == ActionType.BLOCK_IP.value
            and window == BusinessWindow.BUSINESS_HOURS
        ):
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.DOWNGRADED,
                approved=ActionType.TRIGGER_HONEYPOT.value,
                rejected=proposed,
                reason=(
                    "Rule R06: Blocking source IP on a Tier_1 asset during business "
                    "hours risks disrupting legitimate traffic. Redirecting attacker "
                    "to Shadow Honeypot for continued intelligence collection."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── Rule 7: Zero-confidence actions must be logged only ───────────
        rules_evaluated.append("R07_LOW_CONFIDENCE_GUARD")
        if action.confidence < 0.25 and proposed not in ALWAYS_SAFE_ACTIONS:
            return self._build_decision(
                action=action,
                verdict=PolicyVerdict.DOWNGRADED,
                approved=ActionType.LOG_EVENT.value,
                rejected=proposed,
                reason=(
                    f"Rule R07: Action confidence {action.confidence:.2f} is below "
                    "safe execution threshold (0.25). Downgraded to Log_Event "
                    "to prevent false-positive-driven disruption."
                ),
                rules=rules_evaluated,
                window=window,
            )

        # ── All rules passed: APPROVED ────────────────────────────────────
        rules_evaluated.append("R00_DEFAULT_APPROVAL")
        return self._build_decision(
            action=action,
            verdict=PolicyVerdict.APPROVED,
            approved=proposed,
            rejected=None,
            reason=(
                f"Action '{proposed}' passed all {len(rules_evaluated)} policy "
                "rules and is approved for execution."
            ),
            rules=rules_evaluated,
            window=window,
        )

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _build_decision(
        self,
        *,
        action: MitigationAction,
        verdict: PolicyVerdict,
        approved: str,
        rejected: Optional[str],
        reason: str,
        rules: list[str],
        window: BusinessWindow,
    ) -> PolicyDecision:
        risk = _compute_risk_score(action)
        biz_impact = _business_impact_score(
            approved, action.asset_tier, window.value
        )

        decision = PolicyDecision(
            action_id=action.action_id,
            original_action=action.action_type,
            approved_action=approved,
            rejected_action=rejected,
            verdict=verdict.value,
            policy_reason=reason,
            risk_score=risk,
            business_impact_score=round(biz_impact, 4),
            downgrade_mapping=(
                {action.action_type: approved}
                if verdict != PolicyVerdict.APPROVED
                else {}
            ),
            rules_evaluated=rules,
        )

        log.info(
            "PolicyEngine decision",
            verdict=verdict.value,
            approved=approved,
            rejected=rejected,
            asset=action.target_asset,
            tier=action.asset_tier,
            risk=risk,
        )
        return decision

    def batch_evaluate(
        self, actions: list[MitigationAction]
    ) -> list[PolicyDecision]:
        """Evaluate a list of proposed actions through the policy rule chain."""
        return [self.evaluate(a) for a in actions]
