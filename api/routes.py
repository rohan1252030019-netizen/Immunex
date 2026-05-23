"""
IMMUNEX API Routes
===================
FastAPI route definitions for Layer 4 and Layer 5 endpoints.
Fully protected by Zero-Trust RBAC and Immutable Auditing.
"""

from __future__ import annotations

import time
import os
from pathlib import Path
from typing import Any, Optional, List, Dict

import numpy as np
from fastapi import APIRouter, HTTPException, Request, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from api.models import (
    # Existing models
    AlertSummary,
    AlertsResponse,
    GraphStatsResponse,
    HealthResponse,
    MetricsResponse,
    MitigationResponse,
    PlaybookRequest,
    PlaybookResponse,
    RetrainRequest,
    RetrainResponse,
    StreamStatusResponse,
    ThreatCorrelateRequest,
    ThreatCorrelateResponse,
    ThreatMemoryEntry,
    ThreatMemoryResponse,
    # New models
    LoginRequest,
    TokenResponse,
    CaseResponse,
    CaseNote,
    AddNoteRequest,
    CaseUpdateRequest,
    AssignAnalystRequest,
    AgentRegistrationRequest,
    AgentHeartbeatRequest,
    AgentTelemetryRequest,
    AgentResponse,
    DashboardRealtimeResponse,
    MitreHeatmapResponse,
    AuditLogsResponse,
    AuditLogEntry,
    GenerateReportRequest,
    GenerateReportResponse,
    # Phase 5/6/7 models
    CopilotAskRequest,
    CopilotAskResponse,
    CopilotHuntRequest,
    CopilotHuntResponse,
    CopilotInvestigateRequest,
    CopilotInvestigateResponse,
    SigmaGenerateRequest,
    SigmaGenerateResponse,
    YaraGenerateRequest,
    YaraGenerateResponse,
    GraphLiveResponse,
    MitreMatrixResponse,
    TimelineResponse,
    CampaignSummaryResponse,
    ClusterStatusResponse,
)

from utils.logger import log
from auth.auth_middleware import RBACEnforcer
from auth.rbac_engine import Permission
from auth.jwt_manager import JWTManager
from storage.incident_store import IncidentStore
from storage.audit_store import AuditStore
from storage.agent_state_cache import AgentStateCache
from audit.immutable_event_store import ImmutableEventStore
from audit.compliance_engine import ComplianceEngine
from dashboard.realtime_dashboard import RealtimeDashboard
from dashboard.heatmap_engine import HeatmapEngine
from reporting.compliance_reporter import ComplianceReporter
from reporting.pdf_report_generator import PDFReportGenerator
from reporting.markdown_report_generator import MarkdownReportGenerator
from reporting.incident_exporter import IncidentExporter
from reporting.timeline_reporter import TimelineReporter

router = APIRouter()


# ─── State Accessor with Graceful Fallbacks ──────────────────────────────────

def _state(request: Request) -> dict:
    """Retrieve the shared IMMUNEX state from app.state, with lazy initialization of L5 components."""
    try:
        st = request.app.state.immunex
    except AttributeError:
        st = getattr(request.app.state, "_immunex_fallback", None)
        if st is None:
            st = {}
            request.app.state._immunex_fallback = st

    # Initialize missing L5 dependencies to ensure absolute system stability
    if "incident_store" not in st or st["incident_store"] is None:
        st["incident_store"] = IncidentStore(Path("data/logs/incidents_api.db"))
    if "audit_store" not in st or st["audit_store"] is None:
        st["audit_store"] = AuditStore(Path("data/logs/audit_api.db"))
    if "agent_state_cache" not in st or st["agent_state_cache"] is None:
        st["agent_state_cache"] = AgentStateCache()
    if "immutable_event_store" not in st or st["immutable_event_store"] is None:
        st["immutable_event_store"] = ImmutableEventStore(st["audit_store"])
    if "compliance_engine" not in st or st["compliance_engine"] is None:
        st["compliance_engine"] = ComplianceEngine(st["audit_store"])
    if "realtime_dashboard" not in st or st["realtime_dashboard"] is None:
        st["realtime_dashboard"] = RealtimeDashboard()
    if "heatmap_engine" not in st or st["heatmap_engine"] is None:
        st["heatmap_engine"] = HeatmapEngine()

    # Phase 5: Lazy-init SOC Copilot
    if "copilot" not in st or st["copilot"] is None:
        try:
            from soc_copilot import EnterpriseSOCCopilot
            st["copilot"] = EnterpriseSOCCopilot()
        except Exception:
            st["copilot"] = None

    return st


# ─── Public Authentication Route ──────────────────────────────────────────────

@router.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(body: LoginRequest, request: Request) -> TokenResponse:
    """
    Authenticates user and generates a dynamic JWT bearer token.
    Pre-configured enterprise users:
      - admin : administrator_secret_soc
      - analyst : analyst_secret_soc
      - responder : responder_secret_soc
      - auditor : auditor_secret_soc
    """
    valid_users = {
        "admin": ("ADMINISTRATOR", "administrator_secret_soc"),
        "analyst": ("SOC_ANALYST", "analyst_secret_soc"),
        "responder": ("INCIDENT_RESPONDER", "responder_secret_soc"),
        "auditor": ("AUDITOR", "auditor_secret_soc"),
    }

    username = body.username
    password = body.password

    if username not in valid_users or valid_users[username][1] != password:
        # Audit log failed authentication attempt
        st = _state(request)
        st["immutable_event_store"].append_event(
            user_identity=username,
            action_type="FAILED_LOGIN",
            api_endpoint="/auth/login",
            details={"reason": "Invalid credentials", "client_ip": request.client.host if request.client else "unknown"}
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    role = valid_users[username][0]
    token = JWTManager.generate_token(username, role)

    # Log successful login to the immutable ledger
    st = _state(request)
    st["immutable_event_store"].append_event(
        user_identity=username,
        action_type="SUCCESSFUL_LOGIN",
        api_endpoint="/auth/login",
        details={"role": role, "client_ip": request.client.host if request.client else "unknown"}
    )

    return TokenResponse(access_token=token, role=role)


# ─── System Health (Public) ───────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health(request: Request) -> HealthResponse:
    state = _state(request)
    components = {
        "anomaly_engine": "ready" if state.get("anomaly_engine") else "unavailable",
        "vector_engine":  "ready" if state.get("vector_engine")  else "unavailable",
        "layer4":         "ready" if state.get("layer4")         else "unavailable",
        "scheduler":      "ready" if state.get("scheduler")      else "unavailable",
        "ollama":         state.get("ollama_status", "unknown"),
        "soc_store":      "ready" if state.get("incident_store") else "unavailable",
        "audit_store":    "ready" if state.get("audit_store")    else "unavailable",
    }
    all_ready = all(v in ("ready", "unknown") for v in components.values())
    return HealthResponse(
        status="healthy" if all_ready else "degraded",
        uptime_s=round(time.time() - state.get("start_time", time.time()), 1),
        components=components,
    )


# ─── Protected Existing Layer 4 Endpoints ─────────────────────────────────────

@router.get("/stream", response_model=StreamStatusResponse, tags=["Pipeline"])
async def stream_status(
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_METRICS))
) -> StreamStatusResponse:
    state  = _state(request)
    stats  = state.get("pipeline_stats", {})
    uptime = time.time() - state.get("start_time", time.time())
    total  = stats.get("total_events", 0)
    return StreamStatusResponse(
        events_per_second=round(total / max(uptime, 1), 2),
        total_events=total,
        total_alerts=stats.get("total_alerts", 0),
        total_responses=stats.get("total_responses", 0),
        alert_rate_pct=round(stats.get("total_alerts", 0) / max(total, 1) * 100, 2),
        uptime_s=round(uptime, 1),
    )


@router.get("/alerts", response_model=AlertsResponse, tags=["Detection"])
async def get_alerts(
    request: Request,
    n: int = 20,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_ALERTS))
) -> AlertsResponse:
    state      = _state(request)
    raw_alerts = state.get("recent_alerts", [])
    alerts = []
    for a in raw_alerts[-n:]:
        try:
            alerts.append(AlertSummary(**a))
        except Exception:
            pass
    return AlertsResponse(total=len(raw_alerts), alerts=list(reversed(alerts)))


@router.get("/graph", response_model=GraphStatsResponse, tags=["Detection"])
async def graph_stats(
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_GRAPH))
) -> GraphStatsResponse:
    state  = _state(request)
    layer2 = state.get("layer2")
    if layer2 is None:
        raise HTTPException(status_code=503, detail="Layer 2 not initialised")
    try:
        graph_engine = layer2._graph_engine
        n_nodes = graph_engine._graph.number_of_nodes()
        n_edges = graph_engine._graph.number_of_edges()
    except Exception:
        n_nodes = n_edges = 0
    try:
        n_campaigns = len(layer2._correlation_engine._active_campaigns)
    except Exception:
        n_campaigns = 0
    return GraphStatsResponse(
        n_nodes=n_nodes,
        n_edges=n_edges,
        n_campaigns=n_campaigns,
        top_attackers=state.get("top_attackers", []),
    )


@router.post("/playbook", response_model=PlaybookResponse, tags=["Response"])
async def generate_playbook(
    body: PlaybookRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> PlaybookResponse:
    state  = _state(request)
    layer3 = state.get("layer3")
    if layer3 is None:
        raise HTTPException(status_code=503, detail="Layer 3 not initialised")
    
    # Audit log dynamic playbook generation
    state["immutable_event_store"].append_event(
        user_identity=user["username"],
        action_type="GENERATE_PLAYBOOK",
        api_endpoint="/playbook",
        details={"campaign_id": body.campaign_id, "attacker_ip": body.attacker_ip}
    )
    
    try:
        playbook_engine = layer3._playbook_engine
        playbook = playbook_engine.generate(
            campaign_id=body.campaign_id,
            attacker_ip=body.attacker_ip,
            severity=body.severity,
            stages=body.stages,
            target_ips=body.target_ips,
            action="BLOCK_IP",
            asset_tier="TIER_1",
            business_window="BUSINESS_HOURS",
        )
        return PlaybookResponse(
            campaign_id=body.campaign_id,
            playbook=playbook if isinstance(playbook, dict) else {"raw": str(playbook)},
        )
    except Exception as exc:
        log.error("Playbook generation failed", exc_info=exc)
        raise HTTPException(status_code=500, detail=f"Playbook generation failed: {exc}")


@router.get("/mitigation", response_model=list[MitigationResponse], tags=["Response"])
async def recent_mitigations(
    request: Request,
    n: int = 10,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_ALERTS))
) -> list[MitigationResponse]:
    state = _state(request)
    raw   = state.get("recent_mitigations", [])
    results = []
    for m in raw[-n:]:
        try:
            results.append(MitigationResponse(**m))
        except Exception:
            pass
    return list(reversed(results))


@router.post("/retrain", response_model=RetrainResponse, tags=["Adaptation"])
async def trigger_retrain(
    body: RetrainRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.RETRAIN_MODELS))
) -> RetrainResponse:
    state  = _state(request)
    layer4 = state.get("layer4")
    if layer4 is None:
        raise HTTPException(status_code=503, detail="Layer 4 not initialised")
    retrain = getattr(layer4, "_retrain", None)
    if retrain is None:
        raise HTTPException(status_code=503, detail="Retraining pipeline not ready")
    
    # Audit log retraining trigger
    state["immutable_event_store"].append_event(
        user_identity=user["username"],
        action_type="TRIGGER_RETRAIN",
        api_endpoint="/retrain",
        details={"triggered_by": body.triggered_by, "force": body.force}
    )
    
    try:
        import asyncio
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: retrain.retrain(triggered_by=body.triggered_by)
        )
        return RetrainResponse(
            session_id=result.session_id,
            triggered_by=result.triggered_by,
            success=result.success,
            rolled_back=result.rolled_back,
            pre_blind_spot_score=result.pre_blind_spot_score,
            post_blind_spot_score=result.post_blind_spot_score,
            improvement=result.improvement,
            model_version=result.model_version,
            latency_ms=result.latency_ms,
            completed_at=result.completed_at,
        )
    except Exception as exc:
        log.error("Retrain endpoint failed", exc_info=exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/metrics", response_model=MetricsResponse, tags=["Observability"])
async def get_metrics(
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_METRICS))
) -> MetricsResponse:
    state     = _state(request)
    layer4    = state.get("layer4")
    scheduler = state.get("scheduler")
    layer4_stats    = layer4.stats()    if layer4    else {}
    scheduler_stats = scheduler.metrics() if scheduler else {}

    model_version: Optional[str] = None
    try:
        import json
        ver_path = Path("data/models/model_version.json")
        if ver_path.exists():
            meta = json.loads(ver_path.read_text())
            model_version = meta.get("version")
    except Exception:
        pass

    last_drift = last_blind = None
    try:
        sched_metrics = scheduler_stats.get("metrics", {})
        dm = sched_metrics.get("drift_score", {})
        if dm:
            last_drift = dm.get("latest")
        bm = sched_metrics.get("blind_spot_score", {})
        if bm:
            last_blind = bm.get("latest")
    except Exception:
        pass

    return MetricsResponse(
        uptime_seconds=round(time.time() - state.get("start_time", time.time()), 1),
        layer4_stats=layer4_stats,
        scheduler_metrics=scheduler_stats,
        model_version=model_version,
        last_drift_score=last_drift,
        last_blind_spot_score=last_blind,
    )


@router.get("/threat-memory", response_model=ThreatMemoryResponse, tags=["Memory"])
async def threat_memory(
    request: Request,
    n: int = 20,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_ALERTS))
) -> ThreatMemoryResponse:
    state  = _state(request)
    layer4 = state.get("layer4")
    if layer4 is None:
        raise HTTPException(status_code=503, detail="Layer 4 not initialised")
    memory    = layer4._memory
    stats     = memory.stats()
    recent_raw = memory.list_recent(n=n)
    recent = []
    for r in recent_raw:
        try:
            recent.append(ThreatMemoryEntry(**r))
        except Exception:
            pass
    return ThreatMemoryResponse(
        total_entries=stats.get("total_entries", 0),
        attack_families=stats.get("attack_families", {}),
        recent=recent,
    )


@router.post("/threat-memory/correlate", response_model=ThreatCorrelateResponse, tags=["Memory"])
async def correlate_threat(
    body: ThreatCorrelateRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_ALERTS))
) -> ThreatCorrelateResponse:
    state  = _state(request)
    layer4 = state.get("layer4")
    if layer4 is None:
        raise HTTPException(status_code=503, detail="Layer 4 not initialised")
    try:
        fv     = np.array(body.feature_vector, dtype=np.float32)
        result = layer4._memory.correlate(body.campaign_id, fv, body.stages)
        return ThreatCorrelateResponse(**result.to_dict())
    except Exception as exc:
        log.error("Threat correlation failed", exc_info=exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ─── Layer 5: Case and Incident Management ───────────────────────────────────

@router.get("/soc/cases", response_model=List[CaseResponse], tags=["SOC Case Management"])
async def list_cases(
    request: Request,
    status: Optional[str] = None,
    limit: int = 50,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> List[CaseResponse]:
    """Retrieves all active case files recorded by the platform."""
    state = _state(request)
    incidents = state["incident_store"].list_incidents(status=status, limit=limit)
    
    results = []
    for inc in incidents:
        notes = [CaseNote(**n) for n in inc.get("notes", [])]
        results.append(CaseResponse(
            campaign_id=inc["campaign_id"],
            attacker_ip=inc["attacker_ip"],
            severity=inc["severity"],
            risk_score=inc["risk_score"],
            status=inc["status"],
            stages=inc["stages"],
            assigned_analyst=inc["assigned_analyst"] or "Unassigned",
            notes=notes,
            timeline=inc.get("timeline", []),
            mitigations=inc.get("mitigations", [])
        ))
    return results


@router.get("/soc/cases/{campaign_id}", response_model=CaseResponse, tags=["SOC Case Management"])
async def get_case(
    campaign_id: str,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> CaseResponse:
    """Retrieves details of a specific campaign incident case file."""
    state = _state(request)
    inc = state["incident_store"].get_incident(campaign_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Case {campaign_id} not found")
        
    notes = [CaseNote(**n) for n in inc.get("notes", [])]
    return CaseResponse(
        campaign_id=inc["campaign_id"],
        attacker_ip=inc["attacker_ip"],
        severity=inc["severity"],
        risk_score=inc["risk_score"],
        status=inc["status"],
        stages=inc["stages"],
        assigned_analyst=inc["assigned_analyst"] or "Unassigned",
        notes=notes,
        timeline=inc.get("timeline", []),
        mitigations=inc.get("mitigations", [])
    )


@router.post("/soc/cases/{campaign_id}/notes", response_model=CaseResponse, tags=["SOC Case Management"])
async def add_case_note(
    campaign_id: str,
    body: AddNoteRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> CaseResponse:
    """Appends dynamic investigator annotations onto the campaign case file."""
    state = _state(request)
    store = state["incident_store"]
    inc = store.get_incident(campaign_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Case {campaign_id} not found")
        
    new_note = {
        "author": user["username"],
        "timestamp": time.time(),
        "note": body.note
    }
    
    inc["notes"].append(new_note)
    inc["updated_at"] = time.time()
    store.upsert_incident(inc)
    
    # Audit log case update
    state["immutable_event_store"].append_event(
        user_identity=user["username"],
        action_type="ADD_CASE_NOTE",
        api_endpoint=f"/soc/cases/{campaign_id}/notes",
        details={"campaign_id": campaign_id, "note_length": len(body.note)}
    )
    
    notes = [CaseNote(**n) for n in inc["notes"]]
    return CaseResponse(
        campaign_id=inc["campaign_id"],
        attacker_ip=inc["attacker_ip"],
        severity=inc["severity"],
        risk_score=inc["risk_score"],
        status=inc["status"],
        stages=inc["stages"],
        assigned_analyst=inc["assigned_analyst"] or "Unassigned",
        notes=notes,
        timeline=inc.get("timeline", []),
        mitigations=inc.get("mitigations", [])
    )


@router.post("/soc/cases/{campaign_id}/assign", response_model=CaseResponse, tags=["SOC Case Management"])
async def assign_analyst(
    campaign_id: str,
    body: AssignAnalystRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> CaseResponse:
    """Assigns an active investigator role onto this campaign case."""
    state = _state(request)
    store = state["incident_store"]
    inc = store.get_incident(campaign_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Case {campaign_id} not found")
        
    inc["assigned_analyst"] = body.analyst
    inc["updated_at"] = time.time()
    
    # Record analyst update in case timeline
    timeline_event = {
        "timestamp": time.time(),
        "action": f"Case assigned to investigator: {body.analyst}",
        "tactic": "SOC-Operations"
    }
    inc.setdefault("timeline", []).append(timeline_event)
    store.upsert_incident(inc)
    
    # Audit log assignment
    state["immutable_event_store"].append_event(
        user_identity=user["username"],
        action_type="ASSIGN_CASE_ANALYST",
        api_endpoint=f"/soc/cases/{campaign_id}/assign",
        details={"campaign_id": campaign_id, "analyst": body.analyst}
    )
    
    notes = [CaseNote(**n) for n in inc.get("notes", [])]
    return CaseResponse(
        campaign_id=inc["campaign_id"],
        attacker_ip=inc["attacker_ip"],
        severity=inc["severity"],
        risk_score=inc["risk_score"],
        status=inc["status"],
        stages=inc["stages"],
        assigned_analyst=inc["assigned_analyst"] or "Unassigned",
        notes=notes,
        timeline=inc.get("timeline", []),
        mitigations=inc.get("mitigations", [])
    )


@router.patch("/soc/cases/{campaign_id}/status", response_model=CaseResponse, tags=["SOC Case Management"])
async def update_case_status(
    campaign_id: str,
    body: CaseUpdateRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> CaseResponse:
    """Modifies the status workflow value of the campaign incident."""
    state = _state(request)
    store = state["incident_store"]
    inc = store.get_incident(campaign_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Case {campaign_id} not found")
        
    old_status = inc["status"]
    inc["status"] = body.status
    inc["updated_at"] = time.time()
    
    # Record in case timeline
    timeline_event = {
        "timestamp": time.time(),
        "action": f"Case status updated from '{old_status}' to '{body.status}'",
        "tactic": "SOC-Operations"
    }
    inc.setdefault("timeline", []).append(timeline_event)
    store.upsert_incident(inc)
    
    # Audit log status modification
    state["immutable_event_store"].append_event(
        user_identity=user["username"],
        action_type="UPDATE_CASE_STATUS",
        api_endpoint=f"/soc/cases/{campaign_id}/status",
        details={"campaign_id": campaign_id, "old_status": old_status, "new_status": body.status}
    )
    
    notes = [CaseNote(**n) for n in inc.get("notes", [])]
    return CaseResponse(
        campaign_id=inc["campaign_id"],
        attacker_ip=inc["attacker_ip"],
        severity=inc["severity"],
        risk_score=inc["risk_score"],
        status=inc["status"],
        stages=inc["stages"],
        assigned_analyst=inc["assigned_analyst"] or "Unassigned",
        notes=notes,
        timeline=inc.get("timeline", []),
        mitigations=inc.get("mitigations", [])
    )


# ─── Layer 5: Distributed Endpoint Agent Telemetry ───────────────────────────

@router.post("/agents/register", response_model=AgentResponse, tags=["Distributed Agents"])
async def register_agent(body: AgentRegistrationRequest, request: Request) -> AgentResponse:
    """Invoked by active endpoint agent micro-daemons to announce themselves."""
    state = _state(request)
    state["agent_state_cache"].register_agent(
        agent_id=body.host_id,
        ip=body.ip_address,
        hostname=body.hostname,
        os_type=body.os_platform
    )
    
    # Log registry inside immutable logs
    state["immutable_event_store"].append_event(
        user_identity=f"agent-{body.host_id}",
        action_type="AGENT_REGISTER",
        api_endpoint="/agents/register",
        details={"hostname": body.hostname, "ip": body.ip_address, "os": body.os_platform}
    )
    
    return AgentResponse(success=True, message=f"Host {body.host_id} successfully enrolled in IMMUNEX SOC registry.")


@router.post("/agents/heartbeat", response_model=AgentResponse, tags=["Distributed Agents"])
async def agent_heartbeat(body: AgentHeartbeatRequest, request: Request) -> AgentResponse:
    """Dispatched periodically by endpoint micro-daemons to flag continuous health."""
    state = _state(request)
    metrics = {"load_percentage": body.load_percentage}
    success = state["agent_state_cache"].update_heartbeat(
        agent_id=body.host_id,
        status=body.status,
        metrics=metrics
    )
    
    if not success:
        # Agent isn't registered, so auto-register it
        state["agent_state_cache"].register_agent(
            agent_id=body.host_id,
            ip="0.0.0.0",
            hostname=f"unknown-{body.host_id[:8]}",
            os_type="Unknown"
        )
        state["agent_state_cache"].update_heartbeat(
            agent_id=body.host_id,
            status=body.status,
            metrics=metrics
        )
        
    return AgentResponse(success=True, message="Heartbeat acknowledged.")


@router.post("/agents/telemetry", response_model=AgentResponse, tags=["Distributed Agents"])
async def agent_telemetry(body: AgentTelemetryRequest, request: Request) -> AgentResponse:
    """Streams host processes, process executions, network socket openings into the SOC buffer."""
    state = _state(request)
    
    # Store telemetry inside state cache
    telemetry_item = {
        "timestamp": time.time(),
        "event_type": body.event_type,
        "payload": body.payload
    }
    state["agent_state_cache"].buffer_telemetry(body.host_id, telemetry_item)
    
    # Feed telemetry directly into IMMUNEX realtime pipeline stats
    state["pipeline_stats"]["total_events"] += 1
    
    # Push into real-time dashboard log metrics
    state["realtime_dashboard"].log_alert({
        "timestamp": telemetry_item["timestamp"],
        "event_type": body.event_type,
        "severity": body.payload.get("severity", "INFO"),
        "host_id": body.host_id
    })
    
    return AgentResponse(success=True, message="Telemetry packet ingested successfully.")


# ─── Layer 5: Dynamic Dashboard Feeds ────────────────────────────────────────

@router.get("/dashboard/realtime", response_model=DashboardRealtimeResponse, tags=["SOC Dashboard"])
async def get_realtime_dashboard(
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_DASHBOARD))
) -> DashboardRealtimeResponse:
    """Returns streaming high frequency key performance stats and event counts."""
    state = _state(request)
    dashboard_metrics = state["realtime_dashboard"].get_realtime_metrics()
    
    # Fill in actual counters from sharing states if history empty
    if dashboard_metrics["total_alerts"] == 0:
        dashboard_metrics["total_alerts"] = state["pipeline_stats"]["total_alerts"]
        
    return DashboardRealtimeResponse(
        uptime_seconds=dashboard_metrics["uptime_seconds"],
        total_alerts=dashboard_metrics["total_alerts"],
        alerts_per_hour=dashboard_metrics["alerts_per_hour"],
        recent_severity=dashboard_metrics["recent_severity"]
    )


@router.get("/dashboard/heatmap", response_model=MitreHeatmapResponse, tags=["SOC Dashboard"])
async def get_mitre_heatmap(
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_DASHBOARD))
) -> MitreHeatmapResponse:
    """Summarizes observed host threat vectors mapped strictly to MITRE ATT&CK tactics."""
    state = _state(request)
    
    # Extract techniques observed across active cases
    cases = state["incident_store"].list_incidents(limit=200)
    observed = []
    for c in cases:
        for stage in c.get("stages", []):
            # Translate campaign stages into classic MITRE technique patterns
            if "execution" in stage.lower():
                observed.append("T1059.001")
            elif "persist" in stage.lower():
                observed.append("T1053.005")
            elif "evasion" in stage.lower():
                observed.append("T1218.010")
            elif "discovery" in stage.lower():
                observed.append("T1033")
            elif "lateral" in stage.lower():
                observed.append("T1021.001")
                
    heatmap = state["heatmap_engine"].generate_mitre_heatmap(observed)
    return MitreHeatmapResponse(
        tactic_heat=heatmap["tactic_heat"],
        technique_heat=heatmap["technique_heat"],
        total_techniques_mapped=heatmap["total_techniques_mapped"]
    )


# ─── Layer 5: Immutable Compliance and Audit Trails ──────────────────────────

@router.get("/audit/logs", response_model=AuditLogsResponse, tags=["Audit and Compliance"])
async def list_audit_logs(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(RBACEnforcer(Permission.VIEW_AUDIT))
) -> AuditLogsResponse:
    """Fetches blocks from the persistent audit trails and evaluates complete chain integrity."""
    state = _state(request)
    logs = state["audit_store"].get_logs(limit=limit, offset=offset)
    integrity = state["immutable_event_store"].verify_integrity()
    
    formatted_logs = []
    for l in logs:
        formatted_logs.append(AuditLogEntry(
            id=l["id"],
            timestamp=l["timestamp"],
            user_identity=l["user_identity"],
            action_type=l["action_type"],
            api_endpoint=l["api_endpoint"] or "N/A",
            details=str(l["details"]),
            block_hash=l["block_hash"],
            previous_hash=l["previous_hash"]
        ))
        
    return AuditLogsResponse(logs=formatted_logs, integrity_valid=integrity)


# ─── Layer 5: Enterprise Reporting Suite ─────────────────────────────────────

@router.post("/reports/generate", response_model=GenerateReportResponse, tags=["Executive Reporting"])
async def generate_report(
    body: GenerateReportRequest,
    request: Request,
    user: dict = Depends(RBACEnforcer(Permission.MANAGE_INCIDENTS))
) -> GenerateReportResponse:
    """Generates official CISO reports of incidents or continuous compliance posture."""
    state = _state(request)
    
    # Record report generation request in the immutable event ledger
    state["immutable_event_store"].append_event(
        user_identity=user["username"],
        action_type="GENERATE_REPORT",
        api_endpoint="/reports/generate",
        details={"report_type": body.report_type, "format": body.format, "campaign_id": body.campaign_id}
    )
    
    report_id = f"REP-{int(time.time())}"
    
    # 1. Incident Report Generation
    if body.report_type == "incident":
        if not body.campaign_id:
            raise HTTPException(status_code=400, detail="campaign_id is required for incident reports")
            
        case_data = state["incident_store"].get_incident(body.campaign_id)
        if not case_data:
            raise HTTPException(status_code=404, detail=f"Campaign {body.campaign_id} case file not found")
            
        # Reconstruct standard structured report data
        full_report_data = {
            "report_id": report_id,
            "generated_at": time.time(),
            "summary": {
                "campaign_id": case_data["campaign_id"],
                "attacker_ip": case_data["attacker_ip"],
                "severity": case_data["severity"],
                "risk_score": case_data["risk_score"],
                "status": case_data["status"],
                "assigned_analyst": case_data["assigned_analyst"] or "Unassigned"
            },
            "timeline": case_data.get("timeline", []),
            "mitigations": case_data.get("mitigations", []),
            "notes": case_data.get("notes", [])
        }
        
        if body.format == "pdf":
            file_path = f"data/reports/incident_{body.campaign_id}_{report_id}.pdf"
            PDFReportGenerator().generate_incident_report(full_report_data, file_path)
            return GenerateReportResponse(
                success=True,
                report_id=report_id,
                file_path=os.path.abspath(file_path),
                content=f"Successfully generated dynamic ReportLab PDF at {file_path}"
            )
        else:
            file_path = f"data/reports/incident_{body.campaign_id}_{report_id}.md"
            md_content = MarkdownReportGenerator().generate_incident_markdown(full_report_data, file_path)
            return GenerateReportResponse(
                success=True,
                report_id=report_id,
                file_path=os.path.abspath(file_path),
                content=md_content
            )
            
    # 2. Compliance Report Generation
    else:
        reporter = ComplianceReporter(state["compliance_engine"])
        compliance_data = reporter.generate_compliance_data()
        
        if body.format == "pdf":
            file_path = f"data/reports/compliance_{report_id}.pdf"
            PDFReportGenerator().generate_compliance_report(compliance_data, file_path)
            return GenerateReportResponse(
                success=True,
                report_id=report_id,
                file_path=os.path.abspath(file_path),
                content=f"Successfully compiled corporate ReportLab PDF at {file_path}"
            )
        else:
            file_path = f"data/reports/compliance_{report_id}.md"
            md_content = MarkdownReportGenerator().generate_compliance_markdown(compliance_data, file_path)
            return GenerateReportResponse(
                success=True,
                report_id=report_id,
                file_path=os.path.abspath(file_path),
                content=md_content
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 5/6/7 — Copilot, Graph, MITRE, Cluster Endpoints (Additive Only)
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/copilot/ask", response_model=CopilotAskResponse, tags=["Copilot"])
async def copilot_ask(
    body: CopilotAskRequest,
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Conversational SOC Copilot query endpoint."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        raise HTTPException(503, "SOC Copilot not available")
    start = time.time()
    result = copilot.ask(body.question)
    return CopilotAskResponse(
        response=result.get("response", ""),
        response_type=result.get("type", "unknown"),
        data=result.get("data"),
        latency_ms=result.get("latency_ms", (time.time() - start) * 1000),
    )


@router.post("/copilot/hunt", response_model=CopilotHuntResponse, tags=["Copilot"])
async def copilot_hunt(
    body: CopilotHuntRequest,
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Natural language threat hunting endpoint."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        raise HTTPException(503, "SOC Copilot not available")
    start = time.time()
    result = copilot.hunt(body.query)
    return CopilotHuntResponse(
        results=result.get("results", []),
        query_parsed=result.get("query_parsed", {}),
        total=result.get("total", 0),
        latency_ms=result.get("latency_ms", (time.time() - start) * 1000),
    )


@router.post("/copilot/investigate", response_model=CopilotInvestigateResponse, tags=["Copilot"])
async def copilot_investigate(
    body: CopilotInvestigateRequest,
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Autonomous alert investigation endpoint."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        raise HTTPException(503, "SOC Copilot not available")
    start = time.time()
    result = copilot.investigate(body.alert_id)
    return CopilotInvestigateResponse(
        investigation=result,
        sigma_rule=result.get("sigma_rule"),
        yara_rule=result.get("yara_rule"),
        narrative=result.get("narrative", ""),
        latency_ms=result.get("latency_ms", (time.time() - start) * 1000),
    )


@router.post("/copilot/sigma", response_model=SigmaGenerateResponse, tags=["Copilot"])
async def copilot_sigma(
    body: SigmaGenerateRequest,
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Generate a Sigma detection rule."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        raise HTTPException(503, "SOC Copilot not available")
    rule = copilot.generate_sigma({
        "event_type": body.event_type,
        "process_name": body.process_name,
        "src_ip": body.src_ip,
        "severity": body.severity,
    })
    return SigmaGenerateResponse(rule=rule)


@router.post("/copilot/yara", response_model=YaraGenerateResponse, tags=["Copilot"])
async def copilot_yara(
    body: YaraGenerateRequest,
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Generate a YARA malware detection rule."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        raise HTTPException(503, "SOC Copilot not available")
    rule = copilot.generate_yara({
        "process_name": body.process_name,
        "process_hash": body.process_hash,
        "severity": body.severity,
    })
    return YaraGenerateResponse(rule=rule)


@router.get("/graph/live", response_model=GraphLiveResponse, tags=["Graph"])
async def graph_live(
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.VIEW_GRAPH)),
):
    """Live attack graph data for Cytoscape rendering."""
    st = _state(request)
    try:
        from twin_engine import DigitalTwinEngine
        twin = st.get("twin_engine")
        if twin is None:
            twin = DigitalTwinEngine()
            st["twin_engine"] = twin
        snapshot = twin.get_graph_snapshot() if hasattr(twin, "get_graph_snapshot") else {}
        return GraphLiveResponse(
            nodes=snapshot.get("nodes", []),
            edges=snapshot.get("edges", []),
            stats=snapshot.get("stats", {"total_nodes": 0, "total_edges": 0}),
        )
    except Exception:
        return GraphLiveResponse(nodes=[], edges=[], stats={"total_nodes": 0, "total_edges": 0, "status": "offline"})


@router.get("/mitre/matrix", response_model=MitreMatrixResponse, tags=["MITRE"])
async def mitre_matrix(
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.VIEW_DASHBOARD)),
):
    """Full MITRE ATT&CK heatmap matrix data."""
    try:
        from mitre_explainer import MITREExplainer
        explainer = MITREExplainer()
        matrix = explainer.get_full_matrix()
        tactics = []
        technique_counts = {}
        for tid, tdata in matrix.items():
            tactics.append({"id": tid, "name": tdata["name"], "description": tdata["description"],
                            "techniques": list(tdata["techniques"].keys())})
            technique_counts[tid] = len(tdata["techniques"])
        return MitreMatrixResponse(tactics=tactics, technique_counts=technique_counts, total_detections=0)
    except Exception:
        return MitreMatrixResponse(tactics=[], technique_counts={}, total_detections=0)


@router.get("/copilot/timeline", response_model=TimelineResponse, tags=["Copilot"])
async def copilot_timeline(
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Enriched threat timeline from RAG memory."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        return TimelineResponse(events=[], total=0)
    events = copilot.get_timeline()
    return TimelineResponse(events=events, total=len(events))


@router.get("/copilot/campaigns", response_model=CampaignSummaryResponse, tags=["Copilot"])
async def copilot_campaigns(
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.COPILOT_ACCESS)),
):
    """Active campaign summaries."""
    st = _state(request)
    copilot = st.get("copilot")
    if copilot is None:
        return CampaignSummaryResponse(campaigns=[], total=0)
    campaigns = copilot.get_campaigns()
    return CampaignSummaryResponse(campaigns=campaigns, total=len(campaigns))


@router.get("/cluster/status", response_model=ClusterStatusResponse, tags=["Cluster"])
async def cluster_status(
    request: Request,
    _auth=Depends(RBACEnforcer(Permission.CLUSTER_VIEW)),
):
    """Distributed cluster infrastructure health."""
    try:
        from telemetry_profiler import TelemetryProfiler
        from grpc_worker import create_worker_fabric
        profiler = TelemetryProfiler()
        fabric = create_worker_fabric()
        return ClusterStatusResponse(
            status="online",
            nodes=[{"node_id": "local", "status": "active", "backend": fabric.backend}],
            metrics=profiler.get_dashboard_metrics(),
        )
    except Exception:
        return ClusterStatusResponse(status="offline", nodes=[], metrics={})
