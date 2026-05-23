"""
IMMUNEX Layer 3 — Immune Response Engine
==========================================
Top-level orchestrator for the Immune Response & Safe Decision Engine.

This module is the single integration point that main.py calls to invoke
the complete Layer 3 pipeline.  It chains:

  1. RLDecisionEngine    → compute optimal mitigation action
  2. PolicyEngine        → validate action against safety constraints
  3. MitigationActions   → generate executable platform commands
  4. PlaybookEngine      → produce full incident response playbook
  5. ImmunityResponse    → assemble & return unified output

Integration with existing layers:
  - Accepts ThreatReport from AdaptiveIntelligenceLayer (Layer 2)
  - Works with DetectionDecision from InnateImmunityLayer (Layer 1)
  - Fully backward-compatible — Layer 1/2 pipelines unchanged

Usage from main.py::

    layer3 = ImmuneResponseEngine()
    response: ImmunityResponse = layer3.process(threat_report)
    if response:
        dashboard.add_immunity_response(response)
        log.info("Layer3", **response.to_dict())
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any, Optional

from utils.logger import log
from core.rl_decision_engine import RLDecisionEngine
from core.policy_engine import PolicyEngine
from core.playbook_engine import PlaybookEngine
from core.ollama_orchestrator import OllamaOrchestrator
from core.mitigation_actions import generate_commands
from core.response_models import (
    ActionType,
    AssetTier,
    BusinessWindow,
    ImmunityResponse,
    MitigationAction,
    PolicyDecision,
    RLDecision,
)


# ─── Asset Tier Inference ─────────────────────────────────────────────────────


def _infer_asset_tier(asset_criticality: str) -> str:
    """Map raw asset_criticality label to AssetTier."""
    mapping = {
        "CRITICAL": AssetTier.TIER_1.value,
        "HIGH":     AssetTier.TIER_2.value,
        "MEDIUM":   AssetTier.TIER_3.value,
        "LOW":      AssetTier.TIER_4.value,
    }
    return mapping.get(asset_criticality.upper(), AssetTier.TIER_3.value)


def _infer_business_window() -> str:
    """Classify current UTC time into BusinessWindow."""
    hour = datetime.utcnow().hour
    day = datetime.utcnow().weekday()
    if day >= 5:
        return BusinessWindow.OFF_HOURS.value
    return (
        BusinessWindow.BUSINESS_HOURS.value
        if 9 <= hour < 17
        else BusinessWindow.OFF_HOURS.value
    )


# ─── Immune Response Engine ───────────────────────────────────────────────────


class ImmuneResponseEngine:
    """
    Layer 3 Immune Response & Safe Decision Engine.

    Orchestrates the full autonomous response pipeline:
      RL Evaluation → Policy Validation → Command Generation → Playbook

    Lifecycle::

        # Instantiate once at startup
        layer3 = ImmuneResponseEngine()

        # Call for every ThreatReport from Layer 2
        response = layer3.process(threat_report)
        if response:
            log.info("Response generated", **response.to_dict())

    Thread-safety:
        All sub-engines are stateless per call. Concurrent calls are safe.
    """

    def __init__(
        self,
        enable_ollama: bool = True,
        ollama_base_url: str = "http://localhost:11434",
    ) -> None:
        # Sub-engines
        self._rl = RLDecisionEngine()
        self._policy = PolicyEngine()

        # Ollama orchestrator (shared across PlaybookEngine)
        self._ollama = OllamaOrchestrator(base_url=ollama_base_url, enable=enable_ollama)
        self._playbook = PlaybookEngine(orchestrator=self._ollama)

        # Telemetry counters
        self._total_processed: int = 0
        self._total_approved: int = 0
        self._total_downgraded: int = 0
        self._total_rejected: int = 0
        self._start_time: float = time.time()

        log.info(
            "ImmuneResponseEngine initialised",
            ollama_available=self._ollama.is_available(),
            model=self._ollama.active_model(),
        )

    # ── Primary API ───────────────────────────────────────────────────────────

    def process(
        self,
        report: Any,  # ThreatReport from AdaptiveIntelligenceLayer
        process_name: str = "malicious_process",
        user_id: str = "compromised_user",
    ) -> Optional[ImmunityResponse]:
        """
        Run the full Layer 3 pipeline for a correlated threat campaign.

        Args:
            report:       ThreatReport from AdaptiveIntelligenceLayer.process().
            process_name: Malicious process name (from raw event if available).
            user_id:      Compromised user account identifier.

        Returns:
            ImmunityResponse or None if processing fails.
        """
        t_total_start = time.perf_counter()
        self._total_processed += 1

        try:
            # Extract key fields from ThreatReport
            attacker_ip = getattr(report, "attacker_ip", "0.0.0.0")
            target_ips = list(getattr(report, "target_ips", []))
            stages = list(getattr(report, "stages_observed", ["Unknown"]))
            severity = getattr(report, "severity", "HIGH")
            risk_score = float(getattr(report, "risk_score", 0.5))
            confidence = float(getattr(report, "prediction_confidence", 0.5))
            predicted_next = getattr(report, "predicted_next_stage", "Unknown")
            campaign_id = getattr(report, "campaign_id", str(uuid.uuid4())[:12])

            # Infer asset criticality from severity
            criticality_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "INFO": "LOW",
            }
            asset_criticality = criticality_map.get(severity, "MEDIUM")
            asset_tier = _infer_asset_tier(asset_criticality)

            # ── Step 1: RL Decision ───────────────────────────────────────
            t_rl_start = time.perf_counter()
            rl_decision: RLDecision = self._rl.evaluate(
                threat_impact=risk_score,
                asset_criticality=asset_criticality,
                business_risk=risk_score * 0.85,
                attack_severity=severity,
                attack_stage=stages[-1] if stages else "Unknown",
                confidence_score=confidence,
                predicted_next_stage=predicted_next,
                is_anomaly=True,
            )
            rl_latency_ms = (time.perf_counter() - t_rl_start) * 1000

            # ── Step 2: Build MitigationAction for Policy ─────────────────
            action = MitigationAction(
                action_id=f"ACT-{campaign_id[:8]}-{int(time.time())}",
                action_type=rl_decision.optimal_action,
                target_ip=target_ips[0] if target_ips else "10.0.0.100",
                target_asset=f"ASSET-{(target_ips[0] if target_ips else '10.0.0.100').replace('.', '-')}",
                asset_tier=asset_tier,
                asset_criticality=asset_criticality,
                attacker_ip=attacker_ip,
                campaign_id=campaign_id,
                attack_stage=stages[-1] if stages else "Unknown",
                severity=severity,
                confidence=confidence,
                risk_score=risk_score,
                predicted_next_stage=predicted_next,
                is_payment_gateway=self._is_payment_gateway(target_ips),
                is_executive_account=False,
                business_window=_infer_business_window(),
            )

            # ── Step 3: Policy Validation ─────────────────────────────────
            t_policy_start = time.perf_counter()
            policy_decision: PolicyDecision = self._policy.evaluate(action)
            policy_latency_ms = (time.perf_counter() - t_policy_start) * 1000

            # Track verdicts
            v = policy_decision.verdict
            if v == "APPROVED":
                self._total_approved += 1
            elif v == "DOWNGRADED":
                self._total_downgraded += 1
            else:
                self._total_rejected += 1

            # ── Step 4: Playbook Generation ───────────────────────────────
            t_pb_start = time.perf_counter()
            playbook = self._playbook.generate(
                report=report,
                rl_decision=rl_decision,
                policy_decision=policy_decision,
                attacker_ip=attacker_ip,
                target_ips=target_ips,
                process_name=process_name,
                user_id=user_id,
            )
            playbook_latency_ms = (time.perf_counter() - t_pb_start) * 1000

            # ── Step 5: Assemble ImmunityResponse ─────────────────────────
            total_latency_ms = (time.perf_counter() - t_total_start) * 1000
            containment_confidence = round(
                rl_decision.confidence_level
                * rl_decision.risk_reduction_score
                * (1.0 if v == "APPROVED" else 0.85),
                4,
            )

            response = ImmunityResponse(
                response_id=f"IR-{campaign_id[:8].upper()}-{int(time.time())}",
                campaign_id=campaign_id,
                rl_decision=rl_decision,
                policy_decision=policy_decision,
                final_action=policy_decision.approved_action,
                playbook=playbook,
                total_latency_ms=round(total_latency_ms, 2),
                rl_latency_ms=round(rl_latency_ms, 2),
                policy_latency_ms=round(policy_latency_ms, 2),
                playbook_latency_ms=round(playbook_latency_ms, 2),
                ollama_model_used=self._ollama.active_model(),
                containment_confidence=containment_confidence,
            )

            log.info(
                "ImmuneResponseEngine: response generated",
                campaign_id=campaign_id,
                final_action=response.final_action,
                verdict=policy_decision.verdict,
                reward=rl_decision.reward_score,
                containment=containment_confidence,
                total_latency_ms=round(total_latency_ms, 1),
            )

            return response

        except Exception as exc:
            log.error(
                "ImmuneResponseEngine: pipeline error",
                exc_info=exc,
                campaign_id=getattr(report, "campaign_id", "UNKNOWN"),
            )
            return None

    def process_from_decision(
        self,
        decision: Any,  # DetectionDecision from InnateImmunityLayer
    ) -> Optional[ImmunityResponse]:
        """
        Process a Layer 1 DetectionDecision directly (bypass Layer 2 correlation).

        Used for high-confidence individual anomalies requiring immediate response.
        Constructs a synthetic ThreatReport-like object and processes normally.
        """

        class _SyntheticReport:
            """Minimal ThreatReport-compatible object from a DetectionDecision."""
            attacker_ip = getattr(decision, "src_ip", "0.0.0.0")
            target_ips = [getattr(decision, "dst_ip", "10.0.0.1")]
            stages_observed = [
                self._infer_stage_from_event(
                    getattr(decision, "event_type", "Unknown")
                )
            ]
            severity = getattr(decision, "severity", "HIGH")
            risk_score = float(getattr(decision, "anomaly_score", 0.6))
            prediction_confidence = float(getattr(decision, "confidence_score", 0.5))
            predicted_next_stage = "Unknown"
            campaign_id = f"SINGLE-{getattr(decision, 'event_id', 'UNKNOWN')[:8]}"
            narrative = {}
            formatted_report = f"Single anomaly: {getattr(decision, 'event_type', 'Unknown')}"

        synthetic = _SyntheticReport()
        return self.process(
            report=synthetic,
            process_name=getattr(
                getattr(decision, "raw_event", None), "process_name", "unknown"
            ),
            user_id=getattr(
                getattr(decision, "raw_event", None), "user_id", "unknown"
            ),
        )

    # ── Telemetry ─────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return Layer 3 telemetry counters."""
        uptime = time.time() - self._start_time
        return {
            "total_processed": self._total_processed,
            "total_approved": self._total_approved,
            "total_downgraded": self._total_downgraded,
            "total_rejected": self._total_rejected,
            "uptime_seconds": round(uptime, 1),
            "ollama_available": self._ollama.is_available(),
            "ollama_model": self._ollama.active_model(),
        }

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_payment_gateway(ips: list[str]) -> bool:
        """
        Heuristic to detect payment-gateway assets.
        In production, this would query a CMDB.
        """
        payment_octets = {"172.16.10", "10.100.0", "192.168.100"}
        for ip in ips:
            prefix = ".".join(ip.split(".")[:3])
            if prefix in payment_octets:
                return True
        return False

    @staticmethod
    def _infer_stage_from_event(event_type: str) -> str:
        """Map event_type to kill-chain stage name."""
        mapping = {
            "Port_Scan": "Reconnaissance",
            "Network_Sweep": "Reconnaissance",
            "Brute_Force_Login": "Credential_Access",
            "Password_Spray": "Credential_Access",
            "PowerShell_Execution": "Execution",
            "Suspicious_Process_Spawn": "Execution",
            "Registry_Modification": "Persistence",
            "Scheduled_Task": "Persistence",
            "Data_Exfiltration": "Exfiltration",
            "DNS_Tunneling": "Exfiltration",
        }
        return mapping.get(event_type, "Unknown")
