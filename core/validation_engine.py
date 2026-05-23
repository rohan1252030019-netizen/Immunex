"""
IMMUNEX Validation Engine
==========================
Layer 4: Detection gap analysis and blind spot identification.

Evaluates the current detection pipeline by running synthetic mutations
through IsolationForest + FAISS and measuring:
  - False negative rate (missed attacks)
  - FAISS similarity blind spots
  - Anomaly scoring failures
  - Missed attack chain sequences
  - Detection coverage across mutation types
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Optional

import numpy as np

from core.mutation_engine import MutationEngine, MutationResult, MutationType
from utils.logger import log

if TYPE_CHECKING:
    from core.anomaly_engine import AnomalyEngine
    from core.vector_engine import VectorEngine


# ─── Validation Result ────────────────────────────────────────────────────────

@dataclass
class BlindSpotReport:
    report_id:             str
    n_mutations_tested:    int
    n_bypassed:            int
    blind_spot_score:      float           # 0=perfect detection, 1=completely blind
    detection_gap_summary: dict[str, dict] # per-mutation-type breakdown
    affected_model_component: list[str]    # ["IsolationForest", "FAISS", "Both", "None"]
    mitigation_recommendation: str
    false_negative_rate:   float
    coverage_by_type:      dict[str, float]  # {MutationType: detection_rate}
    evaluated_at:          datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "report_id":                  self.report_id,
            "n_mutations_tested":         self.n_mutations_tested,
            "n_bypassed":                 self.n_bypassed,
            "blind_spot_score":           round(self.blind_spot_score, 4),
            "detection_gap_summary":      self.detection_gap_summary,
            "affected_model_component":   self.affected_model_component,
            "mitigation_recommendation":  self.mitigation_recommendation,
            "false_negative_rate":        round(self.false_negative_rate, 4),
            "coverage_by_type":           {k: round(v, 4) for k, v in self.coverage_by_type.items()},
            "evaluated_at":               self.evaluated_at.isoformat(),
        }


# ─── Validation Engine ────────────────────────────────────────────────────────

class ValidationEngine:
    """
    Runs the mutation engine against live detection components to find gaps.

    Usage::

        validator = ValidationEngine(anomaly_engine, vector_engine)
        report = validator.evaluate(n_mutations=200)
        if report.blind_spot_score > 0.3:
            trigger_retraining()
    """

    def __init__(
        self,
        anomaly_engine,
        vector_engine,
        anomaly_threshold: float = 0.55,
        faiss_threshold:   float = 25.0,
        mutation_engine:   Optional[MutationEngine] = None,
    ) -> None:
        self._anomaly_engine    = anomaly_engine
        self._vector_engine     = vector_engine
        self._anomaly_threshold = anomaly_threshold
        self._faiss_threshold   = faiss_threshold
        self._mutation_engine   = mutation_engine or MutationEngine(
            anomaly_threshold=anomaly_threshold,
            faiss_threshold=faiss_threshold,
            seed=99,
        )
        self._eval_count = 0
        log.info("ValidationEngine initialised")

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(self, n_mutations: int = 200) -> BlindSpotReport:
        """
        Generate n_mutations and evaluate detection coverage.
        Returns a BlindSpotReport with full gap analysis.
        """
        t0 = time.perf_counter()
        self._eval_count += 1
        report_id = f"BSPT-{self._eval_count:04d}"

        mutations = self._mutation_engine.generate_batch(n=n_mutations)

        # Per-type tracking
        type_results: dict[str, dict] = {
            mt.value: {"tested": 0, "bypassed": 0, "if_bypassed": 0, "faiss_bypassed": 0}
            for mt in MutationType
        }

        n_bypassed = 0
        bypassed_mutations: list[MutationResult] = []

        for mut in mutations:
            vec_2d = mut.feature_vector.reshape(1, -1)
            mtype  = mut.mutation_type.value
            type_results[mtype]["tested"] += 1

            # IsolationForest scoring
            if_bypassed   = False
            faiss_bypassed = False

            try:
                if self._anomaly_engine._is_trained and self._anomaly_engine._model is not None:
                    raw = self._anomaly_engine._model.decision_function(vec_2d)[0]
                    # Convert to [0,1] anomaly score (higher = more anomalous)
                    anomaly_score = float(np.clip(-raw / 0.5, 0.0, 1.0))
                    if_bypassed = anomaly_score < self._anomaly_threshold
                else:
                    # Model not trained — treat as bypass (worst case)
                    if_bypassed = True
            except Exception:
                if_bypassed = True

            try:
                if self._vector_engine._index is not None and self._vector_engine._baseline_count > 0:
                    fv32 = vec_2d.astype(np.float32)
                    import faiss as _faiss
                    D, _ = self._vector_engine._index.search(fv32, 1)
                    faiss_dist = float(D[0][0])
                    faiss_bypassed = faiss_dist < self._faiss_threshold
                else:
                    faiss_bypassed = True
            except Exception:
                faiss_bypassed = True

            # Mutation bypasses if BOTH detectors miss it
            bypassed = if_bypassed and faiss_bypassed
            if bypassed:
                n_bypassed += 1
                bypassed_mutations.append(mut)

            type_results[mtype]["bypassed"]      += int(bypassed)
            type_results[mtype]["if_bypassed"]   += int(if_bypassed)
            type_results[mtype]["faiss_bypassed"] += int(faiss_bypassed)

        # Coverage by type
        coverage_by_type = {}
        for mtype, r in type_results.items():
            tested = r["tested"]
            if tested > 0:
                detected = tested - r["bypassed"]
                coverage_by_type[mtype] = detected / tested
            else:
                coverage_by_type[mtype] = 1.0

        blind_spot_score   = n_bypassed / max(n_mutations, 1)
        false_negative_rate = blind_spot_score

        # Identify affected components
        affected = set()
        for r in type_results.values():
            if r["if_bypassed"] > r["tested"] * 0.3:
                affected.add("IsolationForest")
            if r["faiss_bypassed"] > r["tested"] * 0.3:
                affected.add("FAISS")
        affected_list = sorted(affected) or ["None"]

        # Build per-type gap summary
        gap_summary = {}
        for mtype, r in type_results.items():
            if r["tested"] > 0:
                gap_summary[mtype] = {
                    "tested":          r["tested"],
                    "bypassed":        r["bypassed"],
                    "bypass_rate":     round(r["bypassed"] / r["tested"], 3),
                    "if_bypass_rate":  round(r["if_bypassed"] / r["tested"], 3),
                    "faiss_bypass_rate": round(r["faiss_bypassed"] / r["tested"], 3),
                }

        # Mitigation recommendation
        mitigation = self._build_recommendation(blind_spot_score, affected_list, coverage_by_type)

        elapsed = (time.perf_counter() - t0) * 1000
        log.info(
            "Validation complete",
            report_id=report_id,
            n_mutations=n_mutations,
            n_bypassed=n_bypassed,
            blind_spot_score=round(blind_spot_score, 3),
            elapsed_ms=round(elapsed, 1),
        )

        return BlindSpotReport(
            report_id=report_id,
            n_mutations_tested=n_mutations,
            n_bypassed=n_bypassed,
            blind_spot_score=blind_spot_score,
            detection_gap_summary=gap_summary,
            affected_model_component=affected_list,
            mitigation_recommendation=mitigation,
            false_negative_rate=false_negative_rate,
            coverage_by_type=coverage_by_type,
        )

    def stats(self) -> dict:
        return {"evaluations_run": self._eval_count}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_recommendation(
        self,
        blind_spot_score: float,
        affected: list[str],
        coverage: dict[str, float],
    ) -> str:
        worst_type = min(coverage, key=coverage.get) if coverage else "unknown"
        worst_rate = min(coverage.values()) if coverage else 0.0

        if blind_spot_score < 0.1:
            return (
                "Detection coverage is strong (blind spot score < 10%). "
                "Continue monitoring; schedule next validation in 24h."
            )
        elif blind_spot_score < 0.3:
            return (
                f"Moderate blind spots detected ({blind_spot_score:.0%}). "
                f"Weakest coverage: '{worst_type}' at {worst_rate:.0%}. "
                f"Affected components: {', '.join(affected)}. "
                "Recommend targeted retraining with augmented mutation data."
            )
        else:
            return (
                f"CRITICAL: High blind spot score ({blind_spot_score:.0%}). "
                f"Affected: {', '.join(affected)}. "
                f"Worst mutation type: '{worst_type}' ({worst_rate:.0%} detection). "
                "Immediate automated retraining required with full mutation corpus."
            )
