"""
IMMUNEX Layer 3 — RL Decision Engine
======================================
Production-style Reinforcement Learning–inspired response evaluator.

Simulates DQN-style decision optimisation without requiring a trained neural
network.  The engine uses a deterministic, weight-based Q-value computation
that reflects domain expertise about threat/action interactions.

Design rationale:
  A full DQN would require labelled replay data and GPU training infrastructure
  that conflicts with the CPU-only / air-gapped deployment constraint.
  Instead we model the Q-function analytically:
    Q(s, a) = Σ wᵢ · φᵢ(s, a)
  where φᵢ are domain-specific feature projections and wᵢ are expert-tuned
  weights.  This produces interpretable, auditable reward scores.

State Vector (8 dimensions):
  [0] threat_impact      — normalised [0, 1]
  [1] asset_criticality  — normalised [0, 1]  (CRITICAL=1, LOW=0.25)
  [2] business_risk      — normalised [0, 1]
  [3] attack_severity    — normalised [0, 1]
  [4] attack_stage_idx   — normalised [0, 1]  (Exfiltration=1, Recon=0)
  [5] confidence_score   — normalised [0, 1]
  [6] next_stage_risk    — normalised [0, 1]
  [7] is_anomaly         — 0 or 1

Actions (9):
  0 → Log_Event
  1 → Revoke_Token
  2 → Isolate_Host
  3 → Block_IP
  4 → Trigger_Shadow_Honeypot
  5 → Micro_Segmentation
  6 → Suspend_Process
  7 → Disable_Lateral_Communications
  8 → Force_MFA_Reset

Output:
  RLDecision (see response_models.py)
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from utils.logger import log
from core.response_models import ActionType, RLDecision


# ─── Constants ────────────────────────────────────────────────────────────────

# Map attack stage names → normalised position in kill-chain [0..1]
STAGE_RISK: dict[str, float] = {
    "Reconnaissance": 0.10,
    "Credential_Access": 0.30,
    "Lateral_Movement": 0.50,
    "Execution": 0.65,
    "Persistence": 0.75,
    "Privilege_Escalation": 0.85,
    "Exfiltration": 1.00,
    "Unknown": 0.20,
}

# Map severity label → normalised score
SEVERITY_SCORE: dict[str, float] = {
    "INFO": 0.05,
    "LOW": 0.20,
    "MEDIUM": 0.45,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}

# Map asset_criticality → normalised score
CRITICALITY_SCORE: dict[str, float] = {
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}

# Action index → ActionType string
ACTION_INDEX: list[str] = [
    ActionType.LOG_EVENT.value,            # 0
    ActionType.REVOKE_TOKEN.value,         # 1
    ActionType.ISOLATE_HOST.value,         # 2
    ActionType.BLOCK_IP.value,             # 3
    ActionType.TRIGGER_HONEYPOT.value,     # 4
    ActionType.MICRO_SEGMENTATION.value,   # 5
    ActionType.SUSPEND_PROCESS.value,      # 6
    ActionType.DISABLE_LATERAL_COMMS.value, # 7
    ActionType.FORCE_MFA_RESET.value,      # 8
]

# ─── Q-Value Weight Matrices ─────────────────────────────────────────────────
#
# Each row = action, each column = state feature.
# Values are expert-tuned weights representing how strongly each state
# dimension increases the reward for a given action.
#
# State features:
#   [0]=threat_impact  [1]=asset_crit  [2]=business_risk
#   [3]=severity       [4]=stage_idx   [5]=confidence
#   [6]=next_stage_risk [7]=is_anomaly
#
# Negative weights → action is penalised when that feature is high.

Q_WEIGHTS: list[list[float]] = [
    # Action 0: Log_Event   — always safe but low impact
    [0.0,  0.0,  0.0,  0.0,  0.0,  0.1,  0.0,  0.05],
    # Action 1: Revoke_Token — good for credential attacks
    [0.3,  0.2,  0.1,  0.3,  0.2,  0.25, 0.2,  0.2],
    # Action 2: Isolate_Host — high impact containment
    [0.5,  0.3,  -0.2, 0.5,  0.4,  0.3,  0.4,  0.3],
    # Action 3: Block_IP    — good early, risky late
    [0.35, 0.15, 0.0,  0.3,  -0.1, 0.25, 0.1,  0.25],
    # Action 4: Honeypot    — best for early recon stages
    [0.2,  0.0,  0.1,  0.15, -0.2, 0.3,  -0.1, 0.2],
    # Action 5: Micro_Segmentation — balanced containment
    [0.4,  0.35, 0.15, 0.4,  0.3,  0.35, 0.35, 0.3],
    # Action 6: Suspend_Process — targeted process control
    [0.35, 0.2,  0.05, 0.35, 0.35, 0.3,  0.3,  0.25],
    # Action 7: Disable_Lateral — critical for lateral movement
    [0.45, 0.4,  -0.1, 0.45, 0.5,  0.35, 0.5,  0.3],
    # Action 8: Force_MFA_Reset — credential hygiene
    [0.25, 0.2,  0.2,  0.25, 0.15, 0.3,  0.15, 0.2],
]

# Bias terms per action (domain knowledge baseline preference)
Q_BIAS: list[float] = [
    0.05,   # Log_Event always has a small base reward
    0.10,   # Revoke_Token
    0.05,   # Isolate_Host — careful
    0.10,   # Block_IP
    0.15,   # Honeypot — generally good early choice
    0.20,   # Micro_Segmentation — safest high-impact choice
    0.08,   # Suspend_Process
    0.05,   # Disable_Lateral — aggressive
    0.12,   # Force_MFA_Reset
]

# ─── Reasoning Templates ─────────────────────────────────────────────────────

REASONING_TEMPLATES: dict[str, str] = {
    ActionType.LOG_EVENT.value: (
        "Threat confidence is insufficient for active response. "
        "Logging the event for further analysis and pattern correlation."
    ),
    ActionType.REVOKE_TOKEN.value: (
        "Credential-based attack detected. Revoking authentication tokens "
        "for affected accounts to break the attacker's access path."
    ),
    ActionType.ISOLATE_HOST.value: (
        "High-severity compromise detected. Full host isolation prevents "
        "lateral spread while preserving forensic evidence on disk."
    ),
    ActionType.BLOCK_IP.value: (
        "Source IP identified as malicious with sufficient confidence. "
        "Network-layer block applied at perimeter and internal chokepoints."
    ),
    ActionType.TRIGGER_HONEYPOT.value: (
        "Early-stage attack detected. Redirecting attacker to shadow honeypot "
        "to collect TTPs and intelligence before active containment."
    ),
    ActionType.MICRO_SEGMENTATION.value: (
        "Multi-stage attack detected. Applying micro-segmentation to limit "
        "blast radius without disrupting business-critical workloads."
    ),
    ActionType.SUSPEND_PROCESS.value: (
        "Malicious process execution confirmed. Targeted suspension of "
        "identified process chain with parent-child tree termination."
    ),
    ActionType.DISABLE_LATERAL_COMMS.value: (
        "Lateral movement pattern confirmed. Disabling east-west communication "
        "between affected segments to contain the active campaign."
    ),
    ActionType.FORCE_MFA_RESET.value: (
        "Credential compromise or privilege escalation suspected. Forcing "
        "MFA re-enrollment for all affected accounts to reset trust chain."
    ),
}


# ─── RL Decision Engine ───────────────────────────────────────────────────────


class RLDecisionEngine:
    """
    DQN-inspired Q-value scoring engine for autonomous mitigation selection.

    The engine:
    1. Constructs a normalised state vector from threat context inputs.
    2. Computes Q(s, a) for all 9 candidate actions via weighted dot product.
    3. Selects the action with the highest Q-value as the optimal response.
    4. Returns a fully populated RLDecision with audit trail.

    Usage::

        engine = RLDecisionEngine()
        decision = engine.evaluate(
            threat_impact=0.8,
            asset_criticality="HIGH",
            business_risk=0.6,
            attack_severity="CRITICAL",
            attack_stage="Lateral_Movement",
            confidence_score=0.9,
            predicted_next_stage="Persistence",
        )
    """

    def __init__(self) -> None:
        log.info(
            "RLDecisionEngine initialised",
            actions=len(ACTION_INDEX),
            state_dim=8,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(
        self,
        threat_impact: float,
        asset_criticality: str,
        business_risk: float,
        attack_severity: str,
        attack_stage: str,
        confidence_score: float,
        predicted_next_stage: str = "Unknown",
        is_anomaly: bool = True,
    ) -> RLDecision:
        """
        Compute Q-values for all candidate actions and return the optimal choice.

        Args:
            threat_impact:         Raw threat impact score [0, 1].
            asset_criticality:     Asset criticality label (LOW/MEDIUM/HIGH/CRITICAL).
            business_risk:         Business risk score [0, 1].
            attack_severity:       Severity label (INFO/LOW/MEDIUM/HIGH/CRITICAL).
            attack_stage:          Current attack kill-chain stage name.
            confidence_score:      Detection confidence [0, 1].
            predicted_next_stage:  Markov-predicted next stage.
            is_anomaly:            Whether the event was flagged as anomalous.

        Returns:
            RLDecision with optimal action and full Q-value audit table.
        """
        t0 = time.perf_counter()

        # Build state vector
        state = self._build_state_vector(
            threat_impact=threat_impact,
            asset_criticality=asset_criticality,
            business_risk=business_risk,
            attack_severity=attack_severity,
            attack_stage=attack_stage,
            confidence_score=confidence_score,
            predicted_next_stage=predicted_next_stage,
            is_anomaly=is_anomaly,
        )

        # Compute Q-values
        q_values = self._compute_q_values(state)

        # Select best action
        best_idx = max(range(len(q_values)), key=lambda i: q_values[i])
        best_action = ACTION_INDEX[best_idx]
        best_q = q_values[best_idx]

        # Normalise reward to [0, 1]
        q_min = min(q_values)
        q_max = max(q_values)
        q_range = q_max - q_min if q_max != q_min else 1.0
        reward_score = round((best_q - q_min) / q_range, 4)

        # Risk reduction: proportional to Q-value gap between best and second-best
        sorted_q = sorted(q_values, reverse=True)
        gap = sorted_q[0] - sorted_q[1] if len(sorted_q) > 1 else sorted_q[0]
        risk_reduction = round(min(gap / (q_max + 1e-8), 1.0), 4)

        # Confidence = confidence_score adjusted for Q-value margin
        confidence_level = round(
            min(confidence_score * (0.7 + 0.3 * reward_score), 1.0), 4
        )

        decision = RLDecision(
            action_index=best_idx,
            optimal_action=best_action,
            reward_score=reward_score,
            confidence_level=confidence_level,
            mitigation_reasoning=REASONING_TEMPLATES.get(best_action, ""),
            risk_reduction_score=risk_reduction,
            q_values={ACTION_INDEX[i]: round(q_values[i], 4) for i in range(len(ACTION_INDEX))},
            state_vector=[round(v, 4) for v in state],
            evaluated_at=datetime.utcnow(),
        )

        elapsed = (time.perf_counter() - t0) * 1000
        log.info(
            "RLDecisionEngine evaluation",
            optimal_action=best_action,
            reward_score=reward_score,
            confidence=confidence_level,
            latency_ms=round(elapsed, 2),
        )

        return decision

    def evaluate_from_threat_report(self, report: Any) -> RLDecision:
        """
        Convenience wrapper that accepts a ThreatReport from AdaptiveIntelligenceLayer.

        Args:
            report: ThreatReport (from core.adaptive_intelligence).

        Returns:
            RLDecision
        """
        return self.evaluate(
            threat_impact=float(report.risk_score),
            asset_criticality="HIGH",       # default; refined by policy engine
            business_risk=float(report.risk_score) * 0.8,
            attack_severity=report.severity,
            attack_stage=(
                report.stages_observed[-1]
                if report.stages_observed
                else "Unknown"
            ),
            confidence_score=float(report.prediction_confidence),
            predicted_next_stage=report.predicted_next_stage,
            is_anomaly=True,
        )

    # ── Private ───────────────────────────────────────────────────────────────

    def _build_state_vector(
        self,
        threat_impact: float,
        asset_criticality: str,
        business_risk: float,
        attack_severity: str,
        attack_stage: str,
        confidence_score: float,
        predicted_next_stage: str,
        is_anomaly: bool,
    ) -> list[float]:
        """Build the normalised 8-dimensional state vector."""
        return [
            float(min(max(threat_impact, 0.0), 1.0)),
            CRITICALITY_SCORE.get(asset_criticality.upper(), 0.5),
            float(min(max(business_risk, 0.0), 1.0)),
            SEVERITY_SCORE.get(attack_severity.upper(), 0.5),
            STAGE_RISK.get(attack_stage, 0.2),
            float(min(max(confidence_score, 0.0), 1.0)),
            STAGE_RISK.get(predicted_next_stage, 0.2),
            1.0 if is_anomaly else 0.0,
        ]

    def _compute_q_values(self, state: list[float]) -> list[float]:
        """
        Compute Q(s, a) for all actions via dot product with weight matrix plus bias.
        Q(s, a) = bias[a] + Σ Q_WEIGHTS[a][i] * state[i]
        """
        q_values = []
        for action_idx in range(len(ACTION_INDEX)):
            weights = Q_WEIGHTS[action_idx]
            bias = Q_BIAS[action_idx]
            q = bias + sum(weights[i] * state[i] for i in range(len(state)))
            q_values.append(q)
        return q_values
