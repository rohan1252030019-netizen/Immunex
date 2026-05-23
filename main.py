"""
IMMUNEX – Innate Immunity + Adaptive Intelligence + Immune Response + Adaptive Immunization
============================================================================================
Entry point for the fully autonomous cyber-defense pipeline.

Pipeline (PART 4 — Layer 4 upgraded):
  Stream
    → Normalize
    → IsolationForest            [Layer 1]
    → FAISS                      [Layer 1]
    → Graph Correlation          [Layer 2]
    → Attack Reconstruction      [Layer 2]
    → Threat Prediction          [Layer 2]
    → Narrative Generation       [Layer 2]
    → RL Mitigation Evaluation   [Layer 3]
    → Policy Verification        [Layer 3]
    → Ollama Playbook Generation [Layer 3]
    → Threat Memory Correlation  [Layer 4]
    → Mutation Testing           [Layer 4]
    → Blind Spot Analysis        [Layer 4]
    → Drift Detection            [Layer 4]
    → Automated Retraining       [Layer 4]
    → Defensive Redeployment     [Layer 4]

Run:
    python main.py               # pipeline only
    python main.py --api         # pipeline + REST API on :8080
    python main.py --api-only    # REST API only (no stream)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections import deque
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import get_config
from core.innate_immunity import InnateImmunityLayer
from core.adaptive_intelligence import AdaptiveIntelligenceLayer, ThreatReport
from core.immune_response import ImmuneResponseEngine
from core.adaptive_immunization import AdaptiveImmunizationLayer, Layer4Event
from core.stream_engine import StreamEngine
from core.response_models import ImmunityResponse
from utils.logger import log, setup_logger
from utils.schemas import DetectionDecision

_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_RED     = "\033[91m"
_ORANGE  = "\033[93m"
_YELLOW  = "\033[33m"
_GREEN   = "\033[92m"
_CYAN    = "\033[96m"
_GREY    = "\033[90m"
_WHITE   = "\033[97m"
_MAGENTA = "\033[95m"
_BLUE    = "\033[94m"

_SEVERITY_COLOUR = {
    "INFO": _GREEN, "LOW": _CYAN, "MEDIUM": _YELLOW,
    "HIGH": _ORANGE, "CRITICAL": _RED,
}
_REASON_SHORT = {
    "IsolationForest_Score_Exceeded": "IF",
    "FAISS_Distance_Exceeded":        "FAISS",
    "IsolationForest+FAISS_Combined": "IF+FAISS",
    "Normal_Baseline":                "—",
}
_VERDICT_COLOUR = {"APPROVED": _GREEN, "DOWNGRADED": _YELLOW, "REJECTED": _RED}


def _colour_severity(s):
    return f"{_BOLD}{_SEVERITY_COLOUR.get(s, _WHITE)}{s:<8}{_RESET}"

def _format_score(score, threshold):
    c = _RED if score >= threshold else _GREEN
    return f"{c}{score:.4f}{_RESET}"

def _colour_verdict(v):
    return f"{_BOLD}{_VERDICT_COLOUR.get(v, _WHITE)}{v:<10}{_RESET}"


class Dashboard:
    HEADER_LINE = (
        f"{_BOLD}{_WHITE}"
        f"{'TIME':<12} {'EVENT_TYPE':<28} {'SRC_IP':<17} "
        f"{'ANOM':>7} {'FAISS':>8} {'SEVERITY':<10} REASON"
        f"{_RESET}"
    )
    SEPARATOR = f"{_GREY}{'─' * 110}{_RESET}"

    def __init__(self, max_rows=30):
        self._rows             = deque(maxlen=max_rows)
        self._total            = self._alerts = self._responses = 0
        self._layer4_events    = 0
        self._retrains         = 0
        self._start_time       = time.time()
        self._last_render      = 0.0
        self._last_drift_score = None
        self._last_blind_score = None

    def add(self, d: DetectionDecision, anomaly_threshold: float) -> None:
        self._total += 1
        if d.is_high_confidence_anomaly:
            self._alerts += 1
        ts     = d.timestamp.strftime("%H:%M:%S.%f")[:-3]
        ascore = _format_score(d.anomaly_score, anomaly_threshold)
        fscore = _format_score(d.faiss_distance, get_config().vector.faiss_distance_threshold)
        flag   = f"{_RED}▶ {_RESET}" if d.is_high_confidence_anomaly else "  "
        self._rows.append(
            f"{flag}{_CYAN}{ts:<12}{_RESET} {d.event_type[:26]:<28} {d.src_ip:<17} "
            f"{ascore:>13} {fscore:>14} {_colour_severity(d.severity):<18} "
            f"{_REASON_SHORT.get(d.detection_reason, d.detection_reason[:12])}"
        )

    def add_threat_report(self, report: ThreatReport) -> None:
        self._alerts += 1
        self._rows.append(
            f"{_BOLD}{_RED}▶▶ CAMPAIGN {report.campaign_id[:12]:<14}{_RESET}"
            f" {_ORANGE}{report.attacker_ip:<17}{_RESET}"
            f" Stages: {_YELLOW}{' → '.join(s[:4] for s in report.stages_observed)}{_RESET}"
            f" Next: {_RED}{report.predicted_next_stage}{_RESET}"
            f" ({report.prediction_confidence:.0%})"
        )

    def add_immunity_response(self, response: ImmunityResponse) -> None:
        self._responses += 1
        ac = _GREEN if response.policy_decision.verdict == "APPROVED" else _YELLOW
        self._rows.append(
            f"{_BOLD}{_MAGENTA}▶▶▶ RESPONSE  {response.campaign_id[:12]:<12}{_RESET}"
            f" {_colour_verdict(response.policy_decision.verdict)}"
            f" {ac}{response.final_action[:28]:<28}{_RESET}"
            f" reward={_CYAN}{response.rl_decision.reward_score:.3f}{_RESET}"
            f" contain={_GREEN}{response.containment_confidence:.0%}{_RESET}"
            f" {_GREY}{response.total_latency_ms:.0f}ms{_RESET}"
        )

    def add_layer4_event(self, event: Layer4Event) -> None:
        self._layer4_events += 1
        mem  = event.memory_correlation
        tags = []
        if mem.recurring_threat_score > 0.6:
            tags.append(f"{_RED}RECURRING{_RESET}")
        if event.blind_spot_report and event.blind_spot_report.blind_spot_score > 0.3:
            self._last_blind_score = event.blind_spot_report.blind_spot_score
            tags.append(f"{_ORANGE}BLIND_SPOT:{event.blind_spot_report.blind_spot_score:.0%}{_RESET}")
        if event.drift_report and event.drift_report.drift_detected:
            self._last_drift_score = event.drift_report.overall_drift_score
            tags.append(f"{_YELLOW}DRIFT:{event.drift_report.overall_drift_score:.2f}{_RESET}")
        if event.retraining_triggered:
            self._retrains += 1
            status = "OK" if (event.retrain_result and event.retrain_result.success) else "ROLLBACK"
            tags.append(f"{_BLUE}RETRAINED:{status}{_RESET}")

        tag_str = " ".join(tags) if tags else f"{_GREY}stable{_RESET}"
        self._rows.append(
            f"{_BOLD}{_BLUE}▶▶▶▶ L4 {event.campaign_id[:14]:<16}{_RESET}"
            f" family={_CYAN}{mem.known_attack_family[:16]:<16}{_RESET}"
            f" recur={_ORANGE}{mem.recurring_threat_score:.2f}{_RESET}"
            f" {tag_str}"
            f" {_GREY}{event.total_latency_ms:.0f}ms{_RESET}"
        )

    def render(self) -> None:
        now     = time.time()
        elapsed = now - self._start_time
        rate    = self._total / max(elapsed, 1.0)
        os.system("cls" if os.name == "nt" else "clear")
        print(f"{_BOLD}{_RED}{'═' * 110}{_RESET}")
        print(
            f"{_BOLD}{_RED}  IMMUNEX{_RESET} {_WHITE}Autonomous SOC · Layer 4{_RESET} "
            f"{_GREY}│ Air-Gapped │ CPU-Only │ Self-Evolving Cyber-Defense{_RESET}"
        )
        print(f"{_BOLD}{_RED}{'═' * 110}{_RESET}")
        print(
            f"  {_CYAN}Events:{_RESET} {_WHITE}{self._total:<8}{_RESET}"
            f" {_CYAN}Alerts:{_RESET} {_RED}{self._alerts:<6}{_RESET}"
            f" {_CYAN}Responses:{_RESET} {_MAGENTA}{self._responses:<5}{_RESET}"
            f" {_CYAN}L4:{_RESET} {_BLUE}{self._layer4_events:<5}{_RESET}"
            f" {_CYAN}Retrains:{_RESET} {_ORANGE}{self._retrains:<4}{_RESET}"
            f" {_CYAN}EPS:{_RESET} {_WHITE}{rate:.1f}{_RESET}"
            f" {_CYAN}Uptime:{_RESET} {_WHITE}{int(elapsed)}s{_RESET}"
        )
        drift_str = f"{self._last_drift_score:.3f}" if self._last_drift_score is not None else "—"
        blind_str = f"{self._last_blind_score:.0%}"  if self._last_blind_score is not None else "—"
        print(
            f"  {_CYAN}Drift:{_RESET} {_YELLOW}{drift_str:<10}{_RESET}"
            f" {_CYAN}BlindSpot:{_RESET} {_ORANGE}{blind_str:<10}{_RESET}"
            f" {_CYAN}Alert%:{_RESET} {_ORANGE}{self._alerts/max(self._total,1)*100:.1f}%{_RESET}"
        )
        print(self.SEPARATOR)
        print(self.HEADER_LINE)
        print(self.SEPARATOR)
        for row in self._rows:
            print(row)
        print(self.SEPARATOR)
        print(
            f"  {_GREY}Ctrl+C to stop │ Logs: data/logs/immunex.log │ "
            f"API: http://localhost:8080/docs{_RESET}"
        )


async def run_pipeline(enable_api: bool = False) -> None:
    cfg       = get_config()
    dashboard = Dashboard(max_rows=30)

    log.info("Bootstrapping Innate Immunity Layer...")
    layer1 = InnateImmunityLayer(cfg)
    layer1.initialise()
    log.info("Innate Immunity Layer ready")

    log.info("Initialising Adaptive Intelligence Layer...")
    layer2 = AdaptiveIntelligenceLayer(
        max_graph_nodes=5_000,
        max_graph_edges=20_000,
        correlation_window_seconds=300.0,
    )
    log.info("Adaptive Intelligence Layer ready")

    log.info("Initialising Immune Response Engine (Layer 3)...")
    layer3 = ImmuneResponseEngine(
        enable_ollama=True,
        ollama_base_url=cfg.layer3.ollama_base_url,
    )
    log.info(
        "Immune Response Engine ready",
        ollama=layer3.stats()["ollama_available"],
        model=layer3.stats()["ollama_model"],
    )

    log.info("Initialising Adaptive Immunization Layer (Layer 4)...")
    anomaly_engine = layer1._anomaly_engine
    vector_engine  = layer1._vector_engine
    layer4 = AdaptiveImmunizationLayer(
        innate_layer=layer1,
        anomaly_engine=anomaly_engine,
        vector_engine=vector_engine,
        enable_auto_retrain=True,
    )
    layer4.initialise()
    log.info("Adaptive Immunization Layer ready")

    from core.scheduler_engine import SchedulerEngine
    scheduler = SchedulerEngine(
        layer4,
        drift_interval_seconds=300,
        mutation_interval_seconds=600,
        health_interval_seconds=60,
        retrain_interval_seconds=3600,
    )
    await scheduler.start()
    log.info("SchedulerEngine started")

    from storage.incident_store import IncidentStore
    from storage.audit_store import AuditStore
    from storage.agent_state_cache import AgentStateCache
    from audit.immutable_event_store import ImmutableEventStore
    from audit.compliance_engine import ComplianceEngine
    from dashboard.realtime_dashboard import RealtimeDashboard
    from dashboard.heatmap_engine import HeatmapEngine

    incident_store = IncidentStore()
    audit_store = AuditStore()
    agent_state_cache = AgentStateCache()
    immutable_event_store = ImmutableEventStore(audit_store)
    compliance_engine = ComplianceEngine(audit_store)
    realtime_dashboard = RealtimeDashboard()
    heatmap_engine = HeatmapEngine()

    api_task = None
    if enable_api:
        from api.api_server import create_app, get_shared_state, update_state, increment_events
        state = get_shared_state()
        update_state(
            layer2=layer2,
            layer3=layer3,
            layer4=layer4,
            scheduler=scheduler,
            anomaly_engine=anomaly_engine,
            vector_engine=vector_engine,
            ollama_status="ready" if layer3.stats()["ollama_available"] else "unavailable",
            incident_store=incident_store,
            audit_store=audit_store,
            agent_state_cache=agent_state_cache,
            immutable_event_store=immutable_event_store,
            compliance_engine=compliance_engine,
            realtime_dashboard=realtime_dashboard,
            heatmap_engine=heatmap_engine,
        )
        import uvicorn
        api_app = create_app(immunex_state=state)
        config  = uvicorn.Config(api_app, host="0.0.0.0", port=8080,
                                 log_level="warning", access_log=False)
        server  = uvicorn.Server(config)
        api_task = asyncio.create_task(server.serve(), name="immunex_api")
        log.info("FastAPI server started on http://0.0.0.0:8080")

    stream_engine    = StreamEngine(cfg.stream)
    refresh_interval = 1.0 / cfg.dashboard_refresh_hz
    last_render      = 0.0

    async for event in stream_engine.stream():
        try:
            decision: DetectionDecision = layer1.process(event)
            dashboard.add(decision, cfg.anomaly.anomaly_score_threshold)
            layer4.ingest_decision(decision)

            if enable_api:
                from api.api_server import increment_events
                increment_events()

            report: ThreatReport | None = layer2.process(decision)
            if report is not None:
                # 1. Threat Intel Enrichment & SOC Case Management
                from threat_intelligence.mitre_mapper import MITREMapper
                from threat_intelligence.cve_mapper import CVEMapper
                
                mitre_matches = []
                cve_matches = []
                m_mapper = MITREMapper()
                c_mapper = CVEMapper()
                
                # Check for technique matches in stages
                for stg in report.stages_observed:
                    mitre_matches.extend(m_mapper.map_command(stg))
                    cve_matches.extend(c_mapper.map_by_pattern(stg))
                
                intel_desc = ""
                if mitre_matches:
                    intel_desc += f" MITRE Techniques: {', '.join(set(m['technique_id'] for m in mitre_matches))}."
                if cve_matches:
                    intel_desc += f" Mapped CVEs: {', '.join(set(c['cve_id'] for c in cve_matches))}."
                
                timeline_event = {
                    "timestamp": time.time(),
                    "action": f"Threat Campaign Detected: predicted next stage '{report.predicted_next_stage}' with {report.prediction_confidence:.0%} confidence.{intel_desc}",
                    "tactic": mitre_matches[0]["tactic"] if mitre_matches else "Execution"
                }

                existing_inc = incident_store.get_incident(report.campaign_id)
                if existing_inc:
                    existing_inc["stages"] = list(set(existing_inc["stages"] + report.stages_observed))
                    existing_inc["risk_score"] = max(existing_inc["risk_score"], report.risk_score)
                    existing_inc["timeline"].append(timeline_event)
                    existing_inc["updated_at"] = time.time()
                    incident_store.upsert_incident(existing_inc)
                else:
                    new_inc = {
                        "campaign_id": report.campaign_id,
                        "attacker_ip": report.attacker_ip,
                        "severity": report.severity,
                        "risk_score": report.risk_score,
                        "status": "OPEN",
                        "stages": report.stages_observed,
                        "assigned_analyst": None,
                        "detected_at": time.time(),
                        "updated_at": time.time(),
                        "notes": [],
                        "timeline": [timeline_event],
                        "mitigations": []
                    }
                    incident_store.upsert_incident(new_inc)

                # Feed observed techniques into heatmap engine
                for m in mitre_matches:
                    heatmap_engine.generate_mitre_heatmap([m["technique_id"]])

                dashboard.add_threat_report(report)
                log.info(
                    "Layer2 ThreatReport",
                    campaign_id=report.campaign_id,
                    severity=report.severity,
                    stages=report.stages_observed,
                    predicted=report.predicted_next_stage,
                )

                if enable_api:
                    from api.api_server import record_alert
                    record_alert({
                        "campaign_id":    report.campaign_id,
                        "attacker_ip":    report.attacker_ip,
                        "severity":       report.severity,
                        "stages":         report.stages_observed,
                        "risk_score":     report.risk_score,
                        "predicted_next": report.predicted_next_stage,
                        "confidence":     report.prediction_confidence,
                        "detected_at":    report.correlated_at,
                    })

                response = layer3.process(
                    report=report,
                    process_name=getattr(event, "process_name", "malicious_process"),
                    user_id=getattr(event, "user_id", "unknown"),
                )
                if response is not None:
                    # 2. Case Management Mitigation Recording & Immutable Event Auditing
                    mit_event = {
                        "action_type": response.final_action,
                        "host_id": "global",
                        "status": "SUCCESS" if response.policy_decision.verdict == "APPROVED" else "REJECTED"
                    }
                    
                    existing_inc = incident_store.get_incident(response.campaign_id)
                    if existing_inc:
                        existing_inc["mitigations"].append(mit_event)
                        existing_inc["timeline"].append({
                            "timestamp": time.time(),
                            "action": f"Autonomous Mitigation Applied: {response.final_action}. Verdict: {response.policy_decision.verdict}.",
                            "tactic": "Defense Evasion"
                        })
                        existing_inc["updated_at"] = time.time()
                        incident_store.upsert_incident(existing_inc)

                    # Dynamic logging of admin/mitigation actions inside blockchain database
                    immutable_event_store.append_event(
                        user_identity="system-orchestrator",
                        action_type="APPLY_MITIGATION",
                        api_endpoint="pipeline",
                        details={
                            "campaign_id": response.campaign_id,
                            "action": response.final_action,
                            "verdict": response.policy_decision.verdict,
                            "reward": response.rl_decision.reward_score,
                            "containment": response.containment_confidence
                        }
                    )

                    dashboard.add_immunity_response(response)
                    log.info(
                        "Layer3 ImmunityResponse",
                        campaign_id=response.campaign_id,
                        final_action=response.final_action,
                        verdict=response.policy_decision.verdict,
                        reward=response.rl_decision.reward_score,
                        containment=response.containment_confidence,
                        latency_ms=response.total_latency_ms,
                    )
                    if enable_api:
                        from api.api_server import record_mitigation
                        record_mitigation({
                            "campaign_id":            response.campaign_id,
                            "final_action":           response.final_action,
                            "verdict":                response.policy_decision.verdict,
                            "reward_score":           response.rl_decision.reward_score,
                            "containment_confidence": response.containment_confidence,
                            "commands":               [],
                            "latency_ms":             response.total_latency_ms,
                        })

                layer4_event: Layer4Event = await layer4.process_threat(report)
                dashboard.add_layer4_event(layer4_event)
                log.info(
                    "Layer4 Event",
                    campaign_id=layer4_event.campaign_id,
                    recurring=layer4_event.memory_correlation.recurring_threat_score,
                    retrained=layer4_event.retraining_triggered,
                    latency_ms=layer4_event.total_latency_ms,
                )

            now = time.time()
            if now - last_render >= refresh_interval:
                dashboard.render()
                last_render = now

        except Exception as exc:
            log.error(
                "Pipeline processing error",
                exc_info=exc,
                event_type=event.event_type,
                src_ip=event.src_ip,
            )

    if api_task:
        api_task.cancel()
    await scheduler.stop()


async def run_api_only() -> None:
    import uvicorn
    from api.api_server import create_app, get_shared_state
    state  = get_shared_state()
    app    = create_app(immunex_state=state)
    config = uvicorn.Config(app, host="0.0.0.0", port=8080, log_level="info")
    server = uvicorn.Server(config)
    log.info("IMMUNEX API-only mode — http://0.0.0.0:8080/docs")
    await server.serve()


def main() -> None:
    parser = argparse.ArgumentParser(description="IMMUNEX Autonomous SOC")
    parser.add_argument("--api",      action="store_true", help="Enable REST API alongside pipeline")
    parser.add_argument("--api-only", dest="api_only", action="store_true",
                        help="Run REST API only (no stream)")
    args = parser.parse_args()

    setup_logger()
    log.info("IMMUNEX starting", version="4.0.0-LAYER4")

    try:
        if args.api_only:
            asyncio.run(run_api_only())
        else:
            asyncio.run(run_pipeline(enable_api=args.api))
    except KeyboardInterrupt:
        print(f"\n{_ORANGE}IMMUNEX shutdown requested.{_RESET}")
        log.info("IMMUNEX shutdown by user")
    except Exception as exc:
        log.critical("Fatal error in main pipeline", exc_info=exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
