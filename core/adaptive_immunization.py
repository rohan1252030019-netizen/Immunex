"""
IMMUNEX Adaptive Immunization
==============================
Layer 4: Self-evolving immunization orchestrator.

This is the top-level Layer 4 engine that integrates all new components:

  ThreatReport (from Layer 2/3)
    → DefensiveMemory.correlate()     [historical pattern match]
    → MutationEngine.generate_batch() [synthetic zero-day simulation]
    → ValidationEngine.evaluate()     [blind spot analysis]
    → DriftDetector.analyse()         [model drift assessment]
    → RetrainingPipeline.retrain()    [autonomous model update]
    → Defensive Redeployment          [hot-swap updated models]

Designed for integration with main.py as a non-blocking extension
of the existing pipeline.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, TYPE_CHECKING

import numpy as np

from core.defensive_memory import DefensiveMemory, MemoryCorrelationResult
from core.drift_detector   import DriftDetector, DriftReport
from core.mutation_engine  import MutationEngine, MutationType
from core.retraining_pipeline import RetrainingPipeline, RetrainingResult
from core.validation_engine   import ValidationEngine, BlindSpotReport
from utils.logger import log

if TYPE_CHECKING:
    from core.adaptive_intelligence import ThreatReport
    from utils.schemas import DetectionDecision


# ─── Layer 4 Event ────────────────────────────────────────────────────────────

@dataclass
class Layer4Event:
    campaign_id:         str
    memory_correlation:  MemoryCorrelationResult
    blind_spot_report:   Optional[BlindSpotReport]
    drift_report:        Optional[DriftReport]
    retrain_result:      Optional[RetrainingResult]
    retraining_triggered: bool
    total_latency_ms:    float
    produced_at:         datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "campaign_id":          self.campaign_id,
            "memory_correlation":   self.memory_correlation.to_dict(),
            "blind_spot_report":    self.blind_spot_report.to_dict() if self.blind_spot_report else None,
            "drift_report":         self.drift_report.to_dict()      if self.drift_report      else None,
            "retrain_result":       self.retrain_result.to_dict()    if self.retrain_result    else None,
            "retraining_triggered": self.retraining_triggered,
            "total_latency_ms":     round(self.total_latency_ms, 1),
            "produced_at":          self.produced_at.isoformat(),
        }


# ─── Adaptive Immunization Layer ──────────────────────────────────────────────

class AdaptiveImmunizationLayer:
    """
    Layer 4: Self-evolving autonomous cyber-defense engine.

    Integrates with the existing pipeline by receiving ThreatReports from
    AdaptiveIntelligenceLayer (Layer 2) and DetectionDecisions from
    InnateImmunityLayer (Layer 1).

    Autonomous actions:
      - Correlate every campaign against defensive memory
      - Periodically test for detection blind spots
      - Monitor for model/feature drift
      - Trigger retraining when quality degrades
      - Update defensive memory with new threat patterns

    Call sequence from main.py::

        layer4 = AdaptiveImmunizationLayer(layer1, layer2, layer3)
        layer4.initialise()

        # In pipeline loop:
        layer4.ingest_decision(decision)   # every event
        if report is not None:
            event4 = await layer4.process_threat(report)  # per campaign
    """

    # Blind spot evaluation interval (number of campaigns)
    _BLIND_SPOT_EVERY    = 20
    # Drift analysis interval (number of ingested decisions)
    _DRIFT_ANALYSE_EVERY = 500
    # Auto-retrain if blind spot score exceeds this
    _RETRAIN_THRESHOLD   = 0.30

    def __init__(
        self,
        innate_layer,
        anomaly_engine,
        vector_engine,
        enable_auto_retrain: bool = True,
        seed: Optional[int]  = None,
    ) -> None:
        self._innate_layer        = innate_layer
        self._anomaly_engine      = anomaly_engine
        self._vector_engine       = vector_engine
        self._enable_auto_retrain = enable_auto_retrain

        # Sub-components
        self._memory     = DefensiveMemory()
        self._drift      = DriftDetector(window_size=1000)
        self._mutation   = MutationEngine(seed=seed)
        self._validation: Optional[ValidationEngine]  = None
        self._retrain:    Optional[RetrainingPipeline] = None

        # Counters
        self._campaign_count  = 0
        self._decision_count  = 0
        self._retrain_count   = 0

        log.info(
            "AdaptiveImmunizationLayer created",
            auto_retrain=enable_auto_retrain,
        )

    def initialise(self) -> None:
        """Set up sub-components that require trained engine references."""
        self._validation = ValidationEngine(
            anomaly_engine=self._anomaly_engine,
            vector_engine=self._vector_engine,
            mutation_engine=self._mutation,
        )
        self._retrain = RetrainingPipeline(
            innate_layer=self._innate_layer,
            anomaly_engine=self._anomaly_engine,
            vector_engine=self._vector_engine,
            mutation_engine=self._mutation,
            validation_engine=self._validation,
        )

        # Seed drift detector baseline from current model
        self._seed_drift_baseline()

        log.info("AdaptiveImmunizationLayer initialised — Layer 4 active")

    # ── Per-decision ingestion ────────────────────────────────────────────────

    def ingest_decision(self, decision) -> None:
        """
        Called for every DetectionDecision from Layer 1.
        Feeds data into the drift detector rolling window.
        """
        self._decision_count += 1
        try:
            fv = getattr(decision, "feature_vector", None)
            if fv is not None:
                vec = fv if isinstance(fv, np.ndarray) else np.array(fv, dtype=np.float32)
                self._drift.ingest(
                    feature_vector=vec,
                    anomaly_score=float(decision.anomaly_score),
                    faiss_dist=float(decision.faiss_distance),
                )
        except Exception as exc:
            log.debug("Layer4: drift ingest error", exc_info=exc)

    # ── Per-campaign processing ───────────────────────────────────────────────

    async def process_threat(self, report) -> Layer4Event:
        """
        Full Layer 4 processing for a ThreatReport.
        Returns a Layer4Event with memory correlation and adaptive analysis.
        """
        t0 = time.perf_counter()
        self._campaign_count += 1
        campaign_id = getattr(report, "campaign_id", f"CAM-{self._campaign_count}")

        # 1. Extract feature vector from report (best-effort)
        feature_vec = self._extract_feature_vector(report)

        # 2. Memory correlation
        stages   = getattr(report, "stages_observed", [])
        severity = getattr(report, "severity", "MEDIUM")
        attacker = getattr(report, "attacker_ip", "0.0.0.0")
        memory_result = self._memory.correlate(campaign_id, feature_vec, stages)

        # Store in memory
        self._memory.store(
            campaign_id=campaign_id,
            attacker_ip=attacker,
            feature_vector=feature_vec,
            stages=stages,
            severity=severity,
            attack_family=memory_result.known_attack_family,
        )

        # 3. Periodic blind spot analysis
        blind_spot_report: Optional[BlindSpotReport] = None
        if self._campaign_count % self._BLIND_SPOT_EVERY == 0 and self._validation:
            log.info("Layer4: running blind spot analysis", campaign=self._campaign_count)
            blind_spot_report = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._validation.evaluate(n_mutations=100)
            )

        # 4. Periodic drift analysis
        drift_report: Optional[DriftReport] = None
        if self._decision_count % self._DRIFT_ANALYSE_EVERY == 0:
            log.info("Layer4: running drift analysis", decisions=self._decision_count)
            drift_report = await asyncio.get_event_loop().run_in_executor(
                None, self._drift.analyse
            )

        # 5. Auto-retrain if triggered
        retrain_result: Optional[RetrainingResult] = None
        retraining_triggered = False

        if self._enable_auto_retrain and self._retrain:
            should_retrain = False
            triggered_by   = "none"

            if blind_spot_report and blind_spot_report.blind_spot_score > self._RETRAIN_THRESHOLD:
                should_retrain = True
                triggered_by   = "blind_spot"
            elif drift_report and drift_report.retrain_recommended:
                should_retrain = True
                triggered_by   = "drift"

            if should_retrain:
                log.warning(
                    "Layer4: triggering autonomous retraining",
                    reason=triggered_by,
                    campaign_id=campaign_id,
                )
                retraining_triggered = True
                self._retrain_count += 1
                retrain_result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._retrain.retrain(triggered_by=triggered_by)
                )

        elapsed_ms = (time.perf_counter() - t0) * 1000

        event = Layer4Event(
            campaign_id=campaign_id,
            memory_correlation=memory_result,
            blind_spot_report=blind_spot_report,
            drift_report=drift_report,
            retrain_result=retrain_result,
            retraining_triggered=retraining_triggered,
            total_latency_ms=elapsed_ms,
        )

        log.info(
            "Layer4 event produced",
            campaign_id=campaign_id,
            recurring_score=round(memory_result.recurring_threat_score, 3),
            blind_spot=blind_spot_report.blind_spot_score if blind_spot_report else None,
            drift=drift_report.overall_drift_score if drift_report else None,
            retrained=retraining_triggered,
            latency_ms=round(elapsed_ms, 1),
        )
        return event

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "campaigns_processed":  self._campaign_count,
            "decisions_ingested":   self._decision_count,
            "retraining_sessions":  self._retrain_count,
            "memory":               self._memory.stats(),
            "drift":                self._drift.stats(),
            "mutation":             self._mutation.stats(),
            "validation":           self._validation.stats() if self._validation else {},
            "retrain":              self._retrain.stats()    if self._retrain    else {},
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_feature_vector(self, report) -> np.ndarray:
        """Best-effort extraction of a representative feature vector from a ThreatReport."""
        from utils.constants import FEATURE_DIM

        # Try to get risk_score and other numeric fields
        try:
            risk  = float(getattr(report, "risk_score", 0.5))
            conf  = float(getattr(report, "prediction_confidence", 0.5))
            n_stg = float(len(getattr(report, "stages_observed", [])))
            n_tgt = float(len(getattr(report, "target_ips", [])))
            # Build a proxy vector from available report fields
            vec = np.array([
                risk * 100_000,   # src_bytes proxy
                conf * 3_000,     # dst_bytes proxy
                1.0 / max(conf, 0.01),  # duration proxy
                n_stg * 50,       # packet_rate proxy
                n_tgt * 5,        # connection_count proxy
                n_stg * 2,        # failed_logins proxy
                n_stg,            # event_frequency proxy
                0.5,              # event_interval proxy
                6.0,              # protocol (SMB - attack default)
                30.0,             # event_type (PowerShell)
            ], dtype=np.float32)
            return vec
        except Exception:
            rng = np.random.default_rng()
            return rng.random(FEATURE_DIM).astype(np.float32)

    def _seed_drift_baseline(self) -> None:
        """Seed the drift detector baseline from synthetic normal data."""
        try:
            rng = np.random.default_rng(seed=42)
            N = 500
            X = np.column_stack([
                rng.uniform(500, 5000, N),
                rng.uniform(200, 3000, N),
                rng.uniform(0.1, 5.0, N),
                rng.uniform(10, 200, N),
                rng.uniform(1, 20, N),
                rng.uniform(0, 1, N),
                rng.uniform(0.5, 3.0, N),
                rng.uniform(0.3, 2.0, N),
                rng.integers(0, 5, N).astype(float),
                rng.integers(0, 5, N).astype(float),
            ]).astype(np.float32)

            anomaly_scores = rng.uniform(0.0, 0.35, N).astype(np.float32)
            faiss_dists    = rng.uniform(1.0, 15.0,  N).astype(np.float32)

            self._drift.set_baseline(X, anomaly_scores, faiss_dists)
            log.info("Layer4: drift baseline seeded from synthetic normal traffic")
        except Exception as exc:
            log.warning("Layer4: drift baseline seeding failed", exc_info=exc)
