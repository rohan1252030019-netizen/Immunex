"""
IMMUNEX Innate Immunity Layer
==============================
Orchestrates the full detection pipeline:

  SecurityEvent
    → FeaturePipeline.transform()        [normalisation]
    → AnomalyEngine.score()              [IsolationForest]
    → VectorEngine.query()               [FAISS similarity]
    → routing logic                      [threshold evaluation]
    → DetectionDecision                  [final verdict]

Initialisation sequence:
1. Generate synthetic baseline traffic (normal events)
2. Build feature vectors from baseline
3. Train IsolationForest on baseline
4. Populate FAISS index with baseline vectors
5. Begin real-time processing loop
"""

from __future__ import annotations

from typing import Optional

import numpy as np

from config import IMMUNEXConfig, get_config
from core.anomaly_engine import AnomalyEngine
from core.feature_pipeline import FeaturePipeline
from core.stream_engine import StreamEngine
from core.vector_engine import VectorEngine
from utils.constants import (
    REASON_COMBINED,
    REASON_FAISS_DISTANCE,
    REASON_ISOLATION_FOREST,
    REASON_NORMAL,
)
from utils.helpers import compute_severity
from utils.logger import log
from utils.schemas import (
    AnomalyResult,
    DetectionDecision,
    FAISSResult,
    FeatureVector,
    SecurityEvent,
)
from cyber_reasoning import EnsembleReasoningSystem



class InnateImmunityLayer:
    """
    The Innate Immunity Layer provides the first line of automated detection.

    It combines statistical anomaly detection (IsolationForest) with
    vector-space similarity (FAISS) to classify every event as either:
    - Normal baseline traffic
    - HIGH_CONFIDENCE_ANOMALY (requires routing to adaptive layer)

    Design principles:
    - Single-responsibility: each engine handles one concern
    - Stateless processing per event (state lives inside engines)
    - Fully offline: no network calls, no external dependencies
    """

    def __init__(self, cfg: Optional[IMMUNEXConfig] = None) -> None:
        self._cfg: IMMUNEXConfig = cfg or get_config()
        self._feature_pipeline = FeaturePipeline()
        self._anomaly_engine = AnomalyEngine(self._cfg.anomaly)
        self._vector_engine = VectorEngine(self._cfg.vector)
        self._stream_engine = StreamEngine(self._cfg.stream)
        self._initialised: bool = False
        self._events_processed: int = 0
        self._alerts_raised: int = 0
        self._reasoning_system = EnsembleReasoningSystem()

    # ── Initialisation ────────────────────────────────────────────────────────

    def initialise(self) -> None:
        """
        Bootstrap the detection engines.

        1. Check for persisted models; load if available.
        2. Otherwise generate baseline traffic and train from scratch.
        """
        anomaly_path = self._cfg.anomaly.model_path
        vector_path = self._cfg.vector.index_path

        if anomaly_path.exists() and vector_path.exists():
            log.info("Loading persisted models from disk")
            self._anomaly_engine.load(anomaly_path)
            self._vector_engine.load_index(vector_path)
            self._initialised = True
            log.success("Innate Immunity Layer restored from disk")
        else:
            log.info("No persisted models found — bootstrapping from synthetic baseline")
            self._bootstrap()

    def _bootstrap(self) -> None:
        """Train engines on synthetic normal baseline traffic."""
        n_samples = self._cfg.anomaly.warmup_samples
        log.info("Generating synthetic baseline", n_samples=n_samples)

        # Generate normal events
        baseline_events = self._stream_engine.generate_batch(n_samples)

        # Extract features
        baseline_features: list[FeatureVector] = (
            self._feature_pipeline.transform_batch(baseline_events)
        )

        # Build matrix
        X = self._feature_pipeline.to_matrix(baseline_features)

        # Train IsolationForest
        self._anomaly_engine.train(X)
        self._anomaly_engine.save()

        # Build FAISS baseline
        # Use only the first cfg.vector.baseline_samples from the normal set
        baseline_n = min(self._cfg.vector.baseline_samples, len(baseline_features))
        self._vector_engine.build_baseline(baseline_features[:baseline_n])
        self._vector_engine.save_index()

        self._initialised = True
        log.success("Innate Immunity Layer bootstrap complete",
                    n_trained=n_samples, n_baseline_vectors=baseline_n)

    # ── Core Processing ───────────────────────────────────────────────────────

    def process(self, event: SecurityEvent) -> DetectionDecision:
        """
        Process a single SecurityEvent through the full detection pipeline.

        Args:
            event: Raw security event from the stream engine.

        Returns:
            DetectionDecision with severity, confidence, and routing verdict.

        Raises:
            RuntimeError: If the layer has not been initialised.
        """
        if not self._initialised:
            raise RuntimeError(
                "InnateImmunityLayer must be initialised before processing. "
                "Call initialise() first."
            )

        # Step 1: Feature extraction
        feature_vector: FeatureVector = self._feature_pipeline.transform(event)

        # Step 2: IsolationForest scoring
        anomaly_result: AnomalyResult = self._anomaly_engine.score(feature_vector)

        # Step 3: FAISS similarity lookup
        faiss_result: FAISSResult = self._vector_engine.query(feature_vector)

        # Step 4: Routing decision
        decision: DetectionDecision = self._decide(
            event, feature_vector, anomaly_result, faiss_result
        )

        # Step 4.5: Ensemble Reasoning Scoring & Graph Enrichment
        # Get simulated/mocked Markov and RL decision scores to maintain fusion consistency
        markov_score = 0.5
        rl_score = 0.5
        
        reasoning_res = self._reasoning_system.reason(
            event=event,
            fv=feature_vector,
            anomaly_score=anomaly_result.anomaly_score,
            faiss_distance=faiss_result.nearest_distance,
            markov_score=markov_score,
            rl_score=rl_score
        )

        # Enrich the decision with Ensemble reasoning results
        decision.consensus_score = reasoning_res["consensus_score"]
        decision.mitre_tactic = reasoning_res["mitre_tactic"]
        decision.predicted_attack_chain = reasoning_res["predicted_attack_chain"]
        decision.confidence_breakdown = reasoning_res["confidence_breakdown"]
        decision.suppression_reason = reasoning_res["suppression_reason"]
        decision.recommended_mitigation = reasoning_res["recommended_mitigation"]
        decision.blast_radius_estimate = reasoning_res["blast_radius_estimate"]

        decision.attack_path = reasoning_res["attack_path"]
        decision.crown_jewel_target = reasoning_res["crown_jewel_target"]
        decision.blast_radius_score = reasoning_res["blast_radius_score"]
        decision.privilege_risk_score = reasoning_res["privilege_risk_score"]
        decision.lateral_movement_probability = reasoning_res["lateral_movement_probability"]
        decision.graph_risk_score = reasoning_res["graph_risk_score"]

        # Log reasoning events with loguru headers
        log.info(
            "AI_CONSENSUS_GENERATED",
            event_id=feature_vector.event_id,
            consensus_score=decision.consensus_score,
            severity=decision.severity
        )
        log.info(
            "DIGITAL_TWIN_UPDATED",
            event_id=feature_vector.event_id,
            nodes=self._reasoning_system.twin.graph.number_of_nodes(),
            edges=self._reasoning_system.twin.graph.number_of_edges()
        )
        if decision.attack_path:
            log.warning(
                "ATTACK_PATH_DETECTED",
                event_id=feature_vector.event_id,
                path=decision.attack_path,
                risk=decision.graph_risk_score
            )
        if decision.blast_radius_score is not None:
            log.warning(
                "BLAST_RADIUS_COMPUTED",
                event_id=feature_vector.event_id,
                score=decision.blast_radius_score
            )
        if decision.crown_jewel_target:
            log.warning(
                "CROWN_JEWEL_TARGETED",
                event_id=feature_vector.event_id,
                target=decision.crown_jewel_target
            )
        if decision.lateral_movement_probability is not None and decision.lateral_movement_probability > 0.5:
            log.warning(
                "LATERAL_MOVEMENT_PREDICTED",
                event_id=feature_vector.event_id,
                probability=decision.lateral_movement_probability
            )

        # Step 5: Telemetry update
        self._events_processed += 1
        if decision.is_high_confidence_anomaly:
            self._alerts_raised += 1

        if decision.is_high_confidence_anomaly:
            log.warning(
                "HIGH_CONFIDENCE_ANOMALY detected",
                event_id=feature_vector.event_id,
                event_type=event.event_type,
                src_ip=event.src_ip,
                anomaly_score=anomaly_result.anomaly_score,
                faiss_distance=faiss_result.nearest_distance,
                severity=decision.severity,
                reason=decision.detection_reason,
            )

        # Phase 5: Forward to RAG memory pipeline for Copilot context
        try:
            if not hasattr(self, '_rag_pipeline'):
                from rag_memory import MemoryIngestionPipeline
                self._rag_pipeline = MemoryIngestionPipeline()
            self._rag_pipeline.ingest(decision)
            log.debug('COPILOT_CONTEXT_INGESTED', event_id=feature_vector.event_id)
        except Exception:
            pass  # Graceful degradation if RAG not available

        return decision

    def process_batch(self, events: list[SecurityEvent]) -> list[DetectionDecision]:
        """Process a list of SecurityEvents and return decisions."""
        return [self.process(e) for e in events]

    # ── Metrics ───────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "events_processed": self._events_processed,
            "alerts_raised": self._alerts_raised,
            "alert_rate": (
                self._alerts_raised / max(self._events_processed, 1)
            ),
            "initialised": self._initialised,
        }

    # ── Private Decision Logic ────────────────────────────────────────────────

    def _decide(
        self,
        event: SecurityEvent,
        fv: FeatureVector,
        anomaly: AnomalyResult,
        faiss: FAISSResult,
    ) -> DetectionDecision:
        """
        Combine IsolationForest and FAISS signals into a routing verdict.

        High-confidence anomaly criteria (configurable OR / AND):
        - anomaly_score exceeds threshold  OR  faiss_distance exceeds threshold
        """
        if self._cfg.high_confidence_threshold_combo:
            # Combined: both signals must agree for highest confidence
            # But either alone is sufficient for high-confidence flag
            is_hca = anomaly.threshold_breached or faiss.threshold_breached
        else:
            is_hca = anomaly.threshold_breached

        # Determine detection reason
        if anomaly.threshold_breached and faiss.threshold_breached:
            reason = REASON_COMBINED
        elif anomaly.threshold_breached:
            reason = REASON_ISOLATION_FOREST
        elif faiss.threshold_breached:
            reason = REASON_FAISS_DISTANCE
        else:
            reason = REASON_NORMAL

        severity = compute_severity(
            anomaly_score=anomaly.anomaly_score,
            faiss_distance=faiss.nearest_distance,
            asset_criticality=event.asset_criticality,
            is_high_confidence=is_hca,
        )

        return DetectionDecision(
            event_id=fv.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            asset_criticality=event.asset_criticality,
            anomaly_score=anomaly.anomaly_score,
            faiss_distance=faiss.nearest_distance,
            confidence_score=anomaly.confidence_score,
            severity=severity,
            is_high_confidence_anomaly=is_hca,
            detection_reason=reason,
            raw_event=event,
        )
