"""
IMMUNEX Layer 3 — Response Models
===================================
Pydantic v2 schemas for all Layer 3 data structures flowing through the
Immune Response & Safe Decision Engine.

Models:
  MitigationAction     – single candidate response action
  PolicyDecision       – output of PolicyEngine validation
  RLDecision           – output of RLDecisionEngine scoring
  PlaybookSection      – individual section within an incident playbook
  IncidentPlaybook     – complete structured incident response playbook
  ImmunityResponse     – full Layer 3 pipeline output (wraps all sub-outputs)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─── Enumerations ─────────────────────────────────────────────────────────────


class ActionType(str, Enum):
    LOG_EVENT = "Log_Event"
    REVOKE_TOKEN = "Revoke_Token"
    ISOLATE_HOST = "Isolate_Host"
    BLOCK_IP = "Block_IP"
    TRIGGER_HONEYPOT = "Trigger_Shadow_Honeypot"
    MICRO_SEGMENTATION = "Micro_Segmentation"
    SUSPEND_PROCESS = "Suspend_Process"
    DISABLE_LATERAL_COMMS = "Disable_Lateral_Communications"
    FORCE_MFA_RESET = "Force_MFA_Reset"
    ISOLATE_NETWORK_TRAFFIC = "Isolate_Network_Traffic"
    SHUTDOWN_SYSTEM = "Shutdown_System"


class AssetTier(str, Enum):
    TIER_1 = "Tier_1"      # Payment gateways, core banking, exec systems
    TIER_2 = "Tier_2"      # Internal business-critical services
    TIER_3 = "Tier_3"      # Standard enterprise assets
    TIER_4 = "Tier_4"      # Development / test / non-critical


class PolicyVerdict(str, Enum):
    APPROVED = "APPROVED"
    DOWNGRADED = "DOWNGRADED"
    REJECTED = "REJECTED"


class BusinessWindow(str, Enum):
    BUSINESS_HOURS = "BUSINESS_HOURS"          # 09:00–17:00 local
    OFF_HOURS = "OFF_HOURS"
    MAINTENANCE_WINDOW = "MAINTENANCE_WINDOW"
    CRITICAL_PERIOD = "CRITICAL_PERIOD"        # Month-end, quarter-close, etc.


# ─── Core Action Model ────────────────────────────────────────────────────────


class MitigationAction(BaseModel):
    """Represents a single candidate mitigation action with full context."""

    action_id: str = Field(description="Unique identifier for this action instance")
    action_type: ActionType
    target_ip: str
    target_asset: str
    asset_tier: AssetTier
    asset_criticality: str                       # Raw from DetectionDecision
    attacker_ip: str
    campaign_id: str
    attack_stage: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    predicted_next_stage: str = ""
    is_payment_gateway: bool = False
    is_executive_account: bool = False
    business_window: BusinessWindow = BusinessWindow.OFF_HOURS
    proposed_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


# ─── Policy Engine Output ─────────────────────────────────────────────────────


class PolicyDecision(BaseModel):
    """Output produced by the PolicyEngine after validating a MitigationAction."""

    action_id: str
    original_action: str
    approved_action: str
    rejected_action: Optional[str] = None
    verdict: PolicyVerdict
    policy_reason: str
    risk_score: float = Field(ge=0.0, le=1.0)
    business_impact_score: float = Field(ge=0.0, le=1.0)
    downgrade_mapping: dict[str, str] = Field(default_factory=dict)
    rules_evaluated: list[str] = Field(default_factory=list)
    validation_timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


# ─── RL Decision Engine Output ────────────────────────────────────────────────


class RLDecision(BaseModel):
    """
    Output produced by the RLDecisionEngine.
    Mirrors DQN Q-value output — highest reward_score action is chosen.
    """

    action_index: int = Field(ge=0, le=8)
    optimal_action: str
    reward_score: float = Field(ge=0.0, le=1.0)
    confidence_level: float = Field(ge=0.0, le=1.0)
    mitigation_reasoning: str
    risk_reduction_score: float = Field(ge=0.0, le=1.0)
    q_values: dict[str, float] = Field(
        default_factory=dict,
        description="Full Q-value table for all candidate actions",
    )
    state_vector: list[float] = Field(
        default_factory=list,
        description="Input state used for scoring",
    )
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Playbook Structures ──────────────────────────────────────────────────────


class MitigationCommands(BaseModel):
    """Executable OS-specific mitigation commands."""

    linux_commands: list[str] = Field(default_factory=list)
    windows_commands: list[str] = Field(default_factory=list)
    verification_commands: list[str] = Field(default_factory=list)
    rollback_commands: list[str] = Field(default_factory=list)


class AttackTimelineEntry(BaseModel):
    """Single entry in the attack timeline."""

    timestamp: str
    stage: str
    event_type: str
    src_ip: str
    dst_ip: str
    description: str


class IOCEntry(BaseModel):
    """Indicator of Compromise entry."""

    ioc_type: str          # IP, Hash, Domain, Process, etc.
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    context: str = ""


class AffectedAsset(BaseModel):
    """Asset affected by the detected campaign."""

    ip: str
    asset_name: str
    asset_tier: str
    criticality: str
    compromise_stage: str
    first_seen: str
    last_seen: str


class IncidentPlaybook(BaseModel):
    """
    Complete structured incident response playbook.
    Generated by the PlaybookEngine via Ollama orchestration.
    Strict JSON-serialisable output consumed by SOAR/SIEM platforms.
    """

    # Identity
    playbook_id: str
    campaign_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by_model: str = ""

    # 1. Executive Summary
    executive_summary: str

    # 2. Threat Severity
    threat_severity: str
    severity_justification: str

    # 3. MITRE ATT&CK Mapping
    mitre_techniques: list[dict[str, str]] = Field(default_factory=list)

    # 4. Root Cause Analysis
    root_cause_analysis: str
    initial_access_vector: str

    # 5. Attack Timeline
    attack_timeline: list[AttackTimelineEntry] = Field(default_factory=list)

    # 6. IOC List
    ioc_list: list[IOCEntry] = Field(default_factory=list)

    # 7. Affected Assets
    affected_assets: list[AffectedAsset] = Field(default_factory=list)

    # 8. Threat Actor Behavior Summary
    threat_actor_summary: str
    ttp_summary: str

    # 9 & 10. Mitigation Commands
    mitigation_commands: MitigationCommands = Field(
        default_factory=MitigationCommands
    )

    # 11. Containment Strategy
    containment_strategy: str
    containment_steps: list[str] = Field(default_factory=list)

    # 12. Recovery Plan
    recovery_plan: str
    recovery_steps: list[str] = Field(default_factory=list)

    # 13. Long-Term Hardening
    hardening_recommendations: list[str] = Field(default_factory=list)

    # 14. Compliance Impact
    compliance_frameworks: list[str] = Field(default_factory=list)
    compliance_impact: str

    # 15. Estimated Blast Radius
    blast_radius_hosts: int = 0
    blast_radius_subnets: list[str] = Field(default_factory=list)
    blast_radius_description: str
    potential_data_exposure: str

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")


# ─── Full Layer 3 Response ────────────────────────────────────────────────────


class ImmunityResponse(BaseModel):
    """
    Complete Layer 3 pipeline output for a single threat campaign.

    Contains:
    - RL optimal action recommendation
    - Policy validation result
    - Final approved mitigation action
    - Generated incident response playbook
    - Observability metrics
    """

    response_id: str
    campaign_id: str

    # Sub-layer outputs
    rl_decision: RLDecision
    policy_decision: PolicyDecision
    final_action: str
    playbook: Optional[IncidentPlaybook] = None

    # Observability
    total_latency_ms: float = 0.0
    rl_latency_ms: float = 0.0
    policy_latency_ms: float = 0.0
    playbook_latency_ms: float = 0.0
    ollama_model_used: str = ""

    # Containment confidence
    containment_confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    generated_at: datetime = Field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    def summary(self) -> str:
        """One-line terminal summary for dashboard rendering."""
        return (
            f"[Layer3] campaign={self.campaign_id[:12]} "
            f"action={self.final_action} "
            f"policy={self.policy_decision.verdict} "
            f"reward={self.rl_decision.reward_score:.3f} "
            f"containment={self.containment_confidence:.0%} "
            f"latency={self.total_latency_ms:.0f}ms"
        )
