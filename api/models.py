"""
IMMUNEX API Models
===================
Pydantic v2 request/response models for the FastAPI orchestration layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ─── Generic Responses ────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status:     Literal["healthy", "degraded", "unhealthy"]
    version:    str = "4.0.0-LAYER4"
    uptime_s:   float
    components: dict[str, str]
    timestamp:  datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    error:   str
    detail:  Optional[str] = None
    code:    int
    path:    str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ─── Stream / Events ──────────────────────────────────────────────────────────

class StreamStatusResponse(BaseModel):
    events_per_second: float
    total_events:      int
    total_alerts:      int
    total_responses:   int
    alert_rate_pct:    float
    uptime_s:          float


# ─── Alerts ───────────────────────────────────────────────────────────────────

class AlertSummary(BaseModel):
    campaign_id:    str
    attacker_ip:    str
    severity:       str
    stages:         list[str]
    risk_score:     float
    predicted_next: str
    confidence:     float
    detected_at:    datetime


class AlertsResponse(BaseModel):
    total:  int
    alerts: list[AlertSummary]


# ─── Graph ────────────────────────────────────────────────────────────────────

class GraphStatsResponse(BaseModel):
    n_nodes:     int
    n_edges:     int
    n_campaigns: int
    top_attackers: list[dict[str, Any]]


# ─── Playbook ─────────────────────────────────────────────────────────────────

class PlaybookRequest(BaseModel):
    campaign_id: str
    severity:    Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    attacker_ip: str = "0.0.0.0"
    stages:      list[str] = Field(default_factory=list)
    target_ips:  list[str] = Field(default_factory=list)


class PlaybookResponse(BaseModel):
    campaign_id: str
    playbook:    dict[str, Any]
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Mitigation ───────────────────────────────────────────────────────────────

class MitigationResponse(BaseModel):
    campaign_id:    str
    final_action:   str
    verdict:        str
    reward_score:   float
    containment_confidence: float
    commands:       list[str]
    latency_ms:     float


# ─── Retrain ──────────────────────────────────────────────────────────────────

class RetrainRequest(BaseModel):
    triggered_by: Literal["manual", "scheduled", "drift", "blind_spot"] = "manual"
    force:        bool = False


class RetrainResponse(BaseModel):
    session_id:             str
    triggered_by:           str
    success:                bool
    rolled_back:            bool
    pre_blind_spot_score:   float
    post_blind_spot_score:  float
    improvement:            float
    model_version:          str
    latency_ms:             float
    completed_at:           datetime


# ─── Metrics ──────────────────────────────────────────────────────────────────

class MetricsResponse(BaseModel):
    uptime_seconds:      float
    layer4_stats:        dict[str, Any]
    scheduler_metrics:   dict[str, Any]
    model_version:       Optional[str] = None
    last_drift_score:    Optional[float] = None
    last_blind_spot_score: Optional[float] = None


# ─── Threat Memory ────────────────────────────────────────────────────────────

class ThreatMemoryEntry(BaseModel):
    entry_id:      str
    campaign_id:   str
    attacker_ip:   str
    attack_family: str
    severity:      str
    seen_at:       str
    seen_count:    int


class ThreatMemoryResponse(BaseModel):
    total_entries:  int
    attack_families: dict[str, int]
    recent:         list[ThreatMemoryEntry]


class ThreatCorrelateRequest(BaseModel):
    campaign_id:    str
    attacker_ip:    str = "0.0.0.0"
    feature_vector: list[float] = Field(default_factory=lambda: [0.0] * 10)
    stages:         list[str]   = Field(default_factory=list)


class ThreatCorrelateResponse(BaseModel):
    query_campaign_id:            str
    recurring_threat_score:       float
    historical_match_probability: float
    known_attack_family:          str
    closest_match_id:             Optional[str]
    closest_similarity:           float
    n_similar_incidents:          int
    time_since_last_seen:         Optional[str]
    recommendation:               str
    correlated_at:                datetime


# ─── Layer 5: Enterprise SOC / Auth / Audit / Agents ──────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    role:         str


class CaseNote(BaseModel):
    author:    str
    timestamp: float
    note:      str


class CaseResponse(BaseModel):
    campaign_id:      str
    attacker_ip:      str
    severity:         str
    risk_score:       float
    status:           str
    stages:           list[str]
    assigned_analyst: str
    notes:            list[CaseNote]
    timeline:         list[dict[str, Any]]
    mitigations:      list[dict[str, Any]]


class AddNoteRequest(BaseModel):
    note: str


class AssignAnalystRequest(BaseModel):
    analyst: str


class CaseUpdateRequest(BaseModel):
    status: str


class AgentRegistrationRequest(BaseModel):
    host_id:     str
    hostname:    str
    ip_address:  str
    os_platform: str


class AgentHeartbeatRequest(BaseModel):
    host_id:         str
    status:          str = "ONLINE"
    load_percentage: float = 0.0


class AgentTelemetryRequest(BaseModel):
    host_id:    str
    event_type: str
    payload:    dict[str, Any]


class AgentResponse(BaseModel):
    success: bool
    message: str


class DashboardRealtimeResponse(BaseModel):
    uptime_seconds:  float
    total_alerts:    int
    alerts_per_hour: float
    recent_severity: list[Optional[str]]


class MitreHeatmapResponse(BaseModel):
    tactic_heat:             dict[str, int]
    technique_heat:          dict[str, int]
    total_techniques_mapped: int


class AuditLogEntry(BaseModel):
    id:            int
    timestamp:     float
    user_identity: str
    action_type:   str
    api_endpoint:  str
    details:       str
    block_hash:    str
    previous_hash: str


class AuditLogsResponse(BaseModel):
    logs:            list[AuditLogEntry]
    integrity_valid: bool


class GenerateReportRequest(BaseModel):
    campaign_id: Optional[str] = None
    format:      Literal["pdf", "markdown"] = "pdf"
    report_type: Literal["incident", "compliance"] = "incident"


class GenerateReportResponse(BaseModel):
    success:   bool
    report_id: str
    file_path: str
    content:   Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5/6/7 — Copilot, Graph, MITRE, Cluster API Models (Additive Only)
# ═══════════════════════════════════════════════════════════════════════════════

class CopilotAskRequest(BaseModel):
    question: str


class CopilotAskResponse(BaseModel):
    response:      str
    response_type: str
    data:          Optional[dict] = None
    latency_ms:    float


class CopilotHuntRequest(BaseModel):
    query: str


class CopilotHuntResponse(BaseModel):
    results:      list[dict]
    query_parsed: dict
    total:        int
    latency_ms:   float


class CopilotInvestigateRequest(BaseModel):
    alert_id: str


class CopilotInvestigateResponse(BaseModel):
    investigation: dict
    sigma_rule:    Optional[str] = None
    yara_rule:     Optional[str] = None
    narrative:     str
    latency_ms:    float


class SigmaGenerateRequest(BaseModel):
    event_type:   str
    process_name: str = ""
    src_ip:       str = ""
    severity:     str = "MEDIUM"


class SigmaGenerateResponse(BaseModel):
    rule:   str
    format: str = "yaml"


class YaraGenerateRequest(BaseModel):
    process_name: str
    process_hash: str = ""
    severity:     str = "MEDIUM"


class YaraGenerateResponse(BaseModel):
    rule:   str
    format: str = "yara"


class GraphLiveResponse(BaseModel):
    nodes: list[dict]
    edges: list[dict]
    stats: dict


class MitreMatrixResponse(BaseModel):
    tactics:          list[dict]
    technique_counts: dict[str, int]
    total_detections: int


class TimelineResponse(BaseModel):
    events: list[dict]
    total:  int


class CampaignSummaryResponse(BaseModel):
    campaigns: list[dict]
    total:     int


class ClusterStatusResponse(BaseModel):
    status:  str
    nodes:   list[dict]
    metrics: dict

