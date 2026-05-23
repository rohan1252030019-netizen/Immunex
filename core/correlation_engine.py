"""
IMMUNEX Correlation Engine
===========================
Multi-stage attack correlator that consumes DetectionDecisions and the
attack graph to identify temporally correlated attack sequences.

Responsibilities:
1. Group anomaly alerts by attacker IP and temporal proximity
2. Walk connected components in the graph to build attack sequences
3. Feed observed stage sequences to the MarkovPredictor for learning
4. Produce CorrelatedAttack objects for the NarrativeEngine
5. Track active campaigns across calls

Design:
- Stateful: keeps an in-memory campaign registry keyed by attacker IP
- Stateless per call: each ingest() call returns an updated view
- Thread-safe by design: operates synchronously within the async pipeline
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from core.graph_engine import (
    ENTITY_IP,
    STAGE_SEVERITY_WEIGHT,
    GraphEngine,
    _node_id,
)
from core.markov_predictor import MarkovPredictor, STAGES
from utils.logger import log
from utils.schemas import DetectionDecision

# ─── Correlation Window ───────────────────────────────────────────────────────

# Events from the same source IP within this window are correlated
CORRELATION_WINDOW_SECONDS: float = 300.0  # 5 minutes
# Minimum number of distinct stages to declare a multi-stage attack
MIN_STAGES_FOR_CAMPAIGN: int = 2


# ─── Data Structures ──────────────────────────────────────────────────────────

class AttackerProfile:
    """Tracks the evolving state of a single attacker IP."""

    def __init__(self, attacker_ip: str) -> None:
        self.attacker_ip = attacker_ip
        self.first_seen: datetime = datetime.utcnow()
        self.last_seen:  datetime = datetime.utcnow()
        self.stages_observed: list[str] = []
        self.stage_timestamps: dict[str, datetime] = {}
        self.decisions: list[DetectionDecision] = []
        self.target_ips: set[str] = set()
        self.campaign_id: str = _campaign_id(attacker_ip)

    def record(self, decision: DetectionDecision, stage: str) -> None:
        self.last_seen = decision.timestamp
        self.decisions.append(decision)
        self.target_ips.add(decision.dst_ip)
        if stage not in self.stage_timestamps:
            self.stages_observed.append(stage)
            self.stage_timestamps[stage] = decision.timestamp

    @property
    def duration_seconds(self) -> float:
        delta = self.last_seen - self.first_seen
        return delta.total_seconds()

    @property
    def max_risk(self) -> float:
        if not self.decisions:
            return 0.0
        return max(d.anomaly_score for d in self.decisions)

    @property
    def is_multi_stage(self) -> bool:
        return len(set(self.stages_observed)) >= MIN_STAGES_FOR_CAMPAIGN


def _campaign_id(attacker_ip: str) -> str:
    seed = f"{attacker_ip}:{time.time_ns()}"
    return "CMP-" + hashlib.sha1(seed.encode()).hexdigest()[:8].upper()


class CorrelatedAttack:
    """
    A fully correlated, multi-stage attack event ready for narrative generation.
    """

    def __init__(
        self,
        campaign_id: str,
        attacker_ip: str,
        target_ips: list[str],
        stages_observed: list[str],
        stage_timestamps: dict[str, datetime],
        decisions: list[DetectionDecision],
        predicted_next_stage: str,
        prediction_confidence: float,
        probability_dist: dict[str, float],
        graph_chain: dict,
        risk_score: float,
    ) -> None:
        self.campaign_id           = campaign_id
        self.attacker_ip           = attacker_ip
        self.target_ips            = target_ips
        self.stages_observed       = stages_observed
        self.stage_timestamps      = stage_timestamps
        self.decisions             = decisions
        self.predicted_next_stage  = predicted_next_stage
        self.prediction_confidence = prediction_confidence
        self.probability_dist      = probability_dist
        self.graph_chain           = graph_chain
        self.risk_score            = risk_score
        self.correlated_at         = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "campaign_id":           self.campaign_id,
            "attacker_ip":           self.attacker_ip,
            "target_ips":            self.target_ips,
            "stages_observed":       self.stages_observed,
            "predicted_next_stage":  self.predicted_next_stage,
            "prediction_confidence": round(self.prediction_confidence, 4),
            "risk_score":            round(self.risk_score, 4),
            "event_count":           len(self.decisions),
            "correlated_at":         self.correlated_at.isoformat(),
        }


# ─── Correlation Engine ───────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Stateful multi-stage attack correlator.

    Call ingest() for each DetectionDecision that passed through Layer 1.
    Returns a CorrelatedAttack when a multi-stage campaign is detected,
    otherwise returns None.
    """

    def __init__(
        self,
        graph_engine: GraphEngine,
        markov_predictor: MarkovPredictor,
        correlation_window: float = CORRELATION_WINDOW_SECONDS,
    ) -> None:
        self._graph    = graph_engine
        self._markov   = markov_predictor
        self._window   = correlation_window
        # Active attacker profiles keyed by src_ip
        self._profiles: dict[str, AttackerProfile] = {}
        self._campaigns_detected: int = 0
        log.info(
            "CorrelationEngine initialised",
            correlation_window_s=correlation_window,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(
        self, decision: DetectionDecision
    ) -> Optional[CorrelatedAttack]:
        """
        Process a single DetectionDecision.

        1. Ingest into the graph engine (always).
        2. For high-confidence anomalies, update the attacker profile.
        3. If a multi-stage campaign is detected, return a CorrelatedAttack.

        Args:
            decision: The DetectionDecision from InnateImmunityLayer.

        Returns:
            CorrelatedAttack if multi-stage attack detected, else None.
        """
        # Always feed the graph
        self._graph.ingest(decision)

        if not decision.is_high_confidence_anomaly:
            return None

        # Determine attack stage for this event
        from core.graph_engine import EVENT_TO_STAGE
        stage = EVENT_TO_STAGE.get(decision.event_type, "Reconnaissance")

        # Get or create attacker profile
        profile = self._profiles.setdefault(
            decision.src_ip,
            AttackerProfile(decision.src_ip),
        )

        # Expire old profiles (outside correlation window)
        elapsed = (decision.timestamp - profile.last_seen).total_seconds()
        if elapsed > self._window and len(profile.stages_observed) > 0:
            # Archive old campaign, start fresh
            log.info(
                "CorrelationEngine: attacker profile expired, resetting",
                attacker_ip=decision.src_ip,
                elapsed_s=round(elapsed, 1),
            )
            self._profiles[decision.src_ip] = AttackerProfile(decision.src_ip)
            profile = self._profiles[decision.src_ip]

        # Record this event in the profile
        prev_stage = profile.stages_observed[-1] if profile.stages_observed else None
        profile.record(decision, stage)

        # Feed Markov learner with observed transitions
        if prev_stage and prev_stage != stage:
            self._markov.observe_transition(prev_stage, stage)

        # Check for multi-stage campaign
        if profile.is_multi_stage:
            return self._build_correlated_attack(profile, stage)

        return None

    def ingest_batch(
        self, decisions: list[DetectionDecision]
    ) -> list[CorrelatedAttack]:
        """Process a list of decisions and return all detected campaigns."""
        results: list[CorrelatedAttack] = []
        for d in decisions:
            ca = self.ingest(d)
            if ca is not None:
                results.append(ca)
        return results

    def get_active_profiles(self) -> dict[str, dict]:
        """Return a summary of all active attacker profiles."""
        return {
            ip: {
                "campaign_id":      p.campaign_id,
                "stages_observed":  p.stages_observed,
                "target_count":     len(p.target_ips),
                "event_count":      len(p.decisions),
                "risk_score":       round(p.max_risk, 4),
                "duration_seconds": round(p.duration_seconds, 1),
                "is_multi_stage":   p.is_multi_stage,
            }
            for ip, p in self._profiles.items()
        }

    def stats(self) -> dict:
        return {
            "active_profiles":    len(self._profiles),
            "campaigns_detected": self._campaigns_detected,
            "graph_stats":        self._graph.stats(),
            "markov_stats":       self._markov.stats(),
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _build_correlated_attack(
        self,
        profile: AttackerProfile,
        current_stage: str,
    ) -> CorrelatedAttack:
        """Build a CorrelatedAttack from the current attacker profile."""
        self._campaigns_detected += 1

        # Predict next stage
        prediction = self._markov.predict(current_stage)

        # Get graph chain for this attacker
        subgraph = self._graph.get_subgraph_for_ip(profile.attacker_ip)
        component_nodes = list(subgraph.nodes())
        graph_chain = self._graph.reconstruct_chain(component_nodes)

        ca = CorrelatedAttack(
            campaign_id=profile.campaign_id,
            attacker_ip=profile.attacker_ip,
            target_ips=list(profile.target_ips),
            stages_observed=list(profile.stages_observed),
            stage_timestamps=dict(profile.stage_timestamps),
            decisions=list(profile.decisions),
            predicted_next_stage=prediction["predicted_stage"],
            prediction_confidence=prediction["confidence_score"],
            probability_dist=prediction["probability_dist"],
            graph_chain=graph_chain,
            risk_score=profile.max_risk,
        )

        log.warning(
            "MULTI_STAGE_ATTACK correlated",
            campaign_id=ca.campaign_id,
            attacker_ip=ca.attacker_ip,
            stages=ca.stages_observed,
            predicted_next=ca.predicted_next_stage,
            confidence=round(ca.prediction_confidence, 3),
            targets=len(ca.target_ips),
        )

        return ca
