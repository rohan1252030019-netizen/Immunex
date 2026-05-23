"""
IMMUNEX Drift Detector
=======================
Layer 4: Statistical model and feature distribution drift detection.

Monitors:
  - Feature distribution shifts (KL divergence, PSI)
  - Anomaly score baseline deviation
  - Concept drift via rolling window comparison
  - FAISS distance distribution changes

Triggers automated retraining when drift exceeds configured thresholds.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np

from utils.logger import log

_DRIFT_DATA_DIR = Path(__file__).parent.parent / "data" / "drift"
_DRIFT_DATA_DIR.mkdir(parents=True, exist_ok=True)


# ─── Drift Report ─────────────────────────────────────────────────────────────

@dataclass
class DriftReport:
    drift_id:            str
    overall_drift_score: float        # 0=stable, 1=severe drift
    feature_drift:       dict[str, float]   # per-feature PSI scores
    anomaly_drift:       float        # deviation in anomaly score distribution
    faiss_drift:         float        # deviation in FAISS distance distribution
    drift_detected:      bool
    retrain_recommended: bool
    affected_features:   list[str]
    summary:             str
    evaluated_at:        datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "drift_id":            self.drift_id,
            "overall_drift_score": round(self.overall_drift_score, 4),
            "feature_drift":       {k: round(v, 4) for k, v in self.feature_drift.items()},
            "anomaly_drift":       round(self.anomaly_drift, 4),
            "faiss_drift":         round(self.faiss_drift, 4),
            "drift_detected":      self.drift_detected,
            "retrain_recommended": self.retrain_recommended,
            "affected_features":   self.affected_features,
            "summary":             self.summary,
            "evaluated_at":        self.evaluated_at.isoformat(),
        }


# ─── Drift Detector ───────────────────────────────────────────────────────────

class DriftDetector:
    """
    Statistical drift detector using Population Stability Index (PSI)
    and KL-divergence for per-feature monitoring.

    PSI thresholds (industry standard):
      PSI < 0.1   → No significant change
      PSI 0.1-0.2 → Moderate change (monitor)
      PSI > 0.2   → Significant change (retrain)
    """

    def __init__(
        self,
        drift_threshold:   float = 0.2,
        retrain_threshold: float = 0.35,
        window_size:       int   = 1000,
        feature_names: Optional[list[str]] = None,
    ) -> None:
        self._drift_threshold   = drift_threshold
        self._retrain_threshold = retrain_threshold
        self._window_size       = window_size

        from utils.constants import FEATURE_NAMES
        self._feature_names = feature_names or FEATURE_NAMES

        # Baseline distributions (set from training data)
        self._baseline_features:     Optional[np.ndarray] = None  # (N, dim)
        self._baseline_anomaly_scores: Optional[np.ndarray] = None  # (N,)
        self._baseline_faiss_dists:   Optional[np.ndarray] = None  # (N,)

        # Rolling buffers for incoming data
        self._current_features:      list[np.ndarray] = []
        self._current_anomaly_scores: list[float]     = []
        self._current_faiss_dists:   list[float]      = []

        # History
        self._drift_history: list[dict] = []
        self._drift_count = 0
        self._retrain_triggers = 0

        log.info(
            "DriftDetector initialised",
            drift_threshold=drift_threshold,
            retrain_threshold=retrain_threshold,
            window_size=window_size,
        )

    # ── Baseline Setup ────────────────────────────────────────────────────────

    def set_baseline(
        self,
        features:      np.ndarray,
        anomaly_scores: np.ndarray,
        faiss_dists:   np.ndarray,
    ) -> None:
        """Register baseline distributions from training data."""
        self._baseline_features      = features.astype(np.float32)
        self._baseline_anomaly_scores = anomaly_scores.astype(np.float32)
        self._baseline_faiss_dists   = faiss_dists.astype(np.float32)
        log.info(
            "DriftDetector baseline set",
            n_samples=features.shape[0],
            anomaly_mean=float(np.mean(anomaly_scores)),
            faiss_mean=float(np.mean(faiss_dists)),
        )

    # ── Data Ingestion ────────────────────────────────────────────────────────

    def ingest(
        self,
        feature_vector: np.ndarray,
        anomaly_score:  float,
        faiss_dist:     float,
    ) -> None:
        """Record a single event observation into the rolling window."""
        self._current_features.append(feature_vector.astype(np.float32))
        self._current_anomaly_scores.append(anomaly_score)
        self._current_faiss_dists.append(faiss_dist)

        # Trim to window
        if len(self._current_features) > self._window_size:
            self._current_features.pop(0)
            self._current_anomaly_scores.pop(0)
            self._current_faiss_dists.pop(0)

    # ── Analysis ──────────────────────────────────────────────────────────────

    def analyse(self) -> Optional[DriftReport]:
        """
        Run drift analysis on the current window vs baseline.
        Returns None if insufficient data (< 100 samples).
        """
        n_current = len(self._current_features)
        if n_current < 100:
            log.debug("DriftDetector: insufficient data", n=n_current, required=100)
            return None

        if self._baseline_features is None:
            log.warning("DriftDetector: no baseline set, skipping analysis")
            return None

        current_arr = np.vstack(self._current_features)
        current_anom = np.array(self._current_anomaly_scores, dtype=np.float32)
        current_faiss = np.array(self._current_faiss_dists, dtype=np.float32)

        # Per-feature PSI
        feature_drift = {}
        for i, name in enumerate(self._feature_names):
            psi = self._psi(
                self._baseline_features[:, i],
                current_arr[:, i],
            )
            feature_drift[name] = float(psi)

        # Anomaly score drift
        anomaly_drift = self._psi(self._baseline_anomaly_scores, current_anom)

        # FAISS distance drift
        faiss_drift = self._psi(self._baseline_faiss_dists, current_faiss)

        # Overall score (weighted average)
        feature_mean = float(np.mean(list(feature_drift.values())))
        overall = float(0.4 * feature_mean + 0.35 * anomaly_drift + 0.25 * faiss_drift)

        affected = [k for k, v in feature_drift.items() if v > self._drift_threshold]
        drift_detected     = overall > self._drift_threshold
        retrain_recommended = overall > self._retrain_threshold

        if retrain_recommended:
            self._retrain_triggers += 1

        self._drift_count += 1
        drift_id = f"DRIFT-{self._drift_count:05d}"

        summary = (
            f"Drift score {overall:.3f} | "
            f"Features drifted: {len(affected)}/{len(self._feature_names)} | "
            f"Retrain: {'YES' if retrain_recommended else 'no'}"
        )

        report = DriftReport(
            drift_id=drift_id,
            overall_drift_score=overall,
            feature_drift=feature_drift,
            anomaly_drift=float(anomaly_drift),
            faiss_drift=float(faiss_drift),
            drift_detected=drift_detected,
            retrain_recommended=retrain_recommended,
            affected_features=affected,
            summary=summary,
        )

        self._drift_history.append(report.to_dict())
        self._persist_report(report)

        if drift_detected:
            log.warning(
                "Drift detected",
                drift_id=drift_id,
                overall=overall,
                affected_features=affected,
                retrain=retrain_recommended,
            )
        else:
            log.debug("Drift analysis complete — stable", drift_id=drift_id, overall=overall)

        return report

    def recent_history(self, n: int = 10) -> list[dict]:
        return self._drift_history[-n:]

    def stats(self) -> dict:
        return {
            "drift_analyses_run":       self._drift_count,
            "retrain_triggers":         self._retrain_triggers,
            "current_window_size":      len(self._current_features),
            "baseline_set":             self._baseline_features is not None,
        }

    # ── Statistical Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _psi(baseline: np.ndarray, current: np.ndarray, n_bins: int = 10) -> float:
        """
        Population Stability Index between two distributions.
        PSI = sum((current_pct - baseline_pct) * ln(current_pct / baseline_pct))
        """
        eps = 1e-8
        # Build shared bin edges from combined range
        combined = np.concatenate([baseline, current])
        lo, hi = float(np.min(combined)), float(np.max(combined))
        if hi - lo < eps:
            return 0.0  # Identical distributions

        edges = np.linspace(lo, hi, n_bins + 1)
        b_hist, _ = np.histogram(baseline, bins=edges)
        c_hist, _ = np.histogram(current,  bins=edges)

        b_pct = (b_hist + eps) / (len(baseline) + eps * n_bins)
        c_pct = (c_hist + eps) / (len(current)  + eps * n_bins)

        psi = float(np.sum((c_pct - b_pct) * np.log(c_pct / b_pct + eps)))
        return max(0.0, psi)

    def _persist_report(self, report: DriftReport) -> None:
        path = _DRIFT_DATA_DIR / f"{report.drift_id}.json"
        try:
            path.write_text(json.dumps(report.to_dict(), indent=2))
        except Exception as exc:
            log.warning("DriftDetector: failed to persist report", exc_info=exc)
