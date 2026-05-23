"""
IMMUNEX Anomaly Engine
=======================
IsolationForest-based anomaly detection with:
- Training pipeline (offline warm-up phase)
- Model persistence via joblib
- Incremental online scoring
- Threshold calibration
- Confidence score derivation

The anomaly_score returned is normalised to [0, 1] where higher = more anomalous.
sklearn's raw decision_function returns negative scores for anomalies;
we invert and scale for human readability.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from config import AnomalyEngineConfig, get_config
from utils.constants import FEATURE_DIM
from utils.logger import log
from utils.schemas import AnomalyResult, FeatureVector


class AnomalyEngine:
    """
    Wraps scikit-learn IsolationForest with lifecycle management.

    Lifecycle:
    1. `train(X)` — fits the model on baseline normal traffic
    2. `save()` — persists model to disk
    3. `load()` — restores model from disk
    4. `score(fv)` — scores a single FeatureVector online
    5. `score_batch(fvs)` — scores a list of FeatureVectors
    """

    def __init__(self, cfg: Optional[AnomalyEngineConfig] = None) -> None:
        self._cfg: AnomalyEngineConfig = cfg or get_config().anomaly
        self._model: Optional[IsolationForest] = None
        self._is_trained: bool = False
        # Track score distribution for threshold calibration
        self._score_history: list[float] = []
        log.info("AnomalyEngine initialised", config=self._cfg.model_dump())

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, X: np.ndarray) -> None:
        """
        Fit IsolationForest on a baseline dataset.

        Args:
            X: float32 array of shape (N, FEATURE_DIM)
        """
        if X.ndim != 2 or X.shape[1] != FEATURE_DIM:
            raise ValueError(
                f"Expected X of shape (N, {FEATURE_DIM}), got {X.shape}"
            )
        if X.shape[0] < 10:
            raise ValueError(
                f"Need at least 10 samples to train, got {X.shape[0]}"
            )

        log.info("Training IsolationForest", n_samples=X.shape[0],
                 n_estimators=self._cfg.n_estimators,
                 contamination=self._cfg.contamination)

        self._model = IsolationForest(
            n_estimators=self._cfg.n_estimators,
            contamination=self._cfg.contamination,
            max_samples=self._cfg.max_samples,
            random_state=self._cfg.random_state,
            n_jobs=-1,          # Use all CPU cores
            warm_start=False,
        )
        self._model.fit(X)
        self._is_trained = True

        # Compute training-set scores for calibration reference
        raw_scores = self._model.score_samples(X)
        self._score_history = raw_scores.tolist()

        log.success("IsolationForest training complete",
                    score_min=float(np.min(raw_scores)),
                    score_max=float(np.max(raw_scores)),
                    score_mean=float(np.mean(raw_scores)))

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> Path:
        """Persist the trained model to disk using joblib."""
        if not self._is_trained or self._model is None:
            raise RuntimeError("Cannot save: model has not been trained yet.")

        target = path or self._cfg.model_path
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, target)
        log.info("IsolationForest model saved", path=str(target))
        return target

    def load(self, path: Optional[Path] = None) -> None:
        """Load a persisted model from disk."""
        target = path or self._cfg.model_path
        if not target.exists():
            raise FileNotFoundError(f"Model file not found: {target}")

        self._model = joblib.load(target)
        self._is_trained = True
        log.info("IsolationForest model loaded", path=str(target))

    def is_trained(self) -> bool:
        return self._is_trained

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, fv: FeatureVector) -> AnomalyResult:
        """
        Score a single FeatureVector.

        Returns:
            AnomalyResult with normalised anomaly_score in [0, 1].
        """
        self._assert_trained()
        vec = fv.to_numpy().reshape(1, -1)
        return self._compute_result(fv.event_id, vec)

    def score_batch(self, fvs: list[FeatureVector]) -> list[AnomalyResult]:
        """Score a list of FeatureVectors efficiently."""
        self._assert_trained()
        if not fvs:
            return []
        X = np.vstack([fv.to_numpy() for fv in fvs]).astype(np.float32)
        results: list[AnomalyResult] = []
        for i, fv in enumerate(fvs):
            vec = X[i : i + 1]
            results.append(self._compute_result(fv.event_id, vec))
        return results

    def score_matrix(self, X: np.ndarray, event_ids: list[str]) -> list[AnomalyResult]:
        """Score a pre-built matrix; event_ids must align with rows."""
        self._assert_trained()
        assert X.shape[0] == len(event_ids), "Matrix rows must match event_ids length"
        results: list[AnomalyResult] = []
        for i, eid in enumerate(event_ids):
            vec = X[i : i + 1]
            results.append(self._compute_result(eid, vec))
        return results

    # ── Threshold Calibration ─────────────────────────────────────────────────

    def calibrate_threshold(self, percentile: float = 95.0) -> float:
        """
        Suggest an anomaly_score threshold at the given percentile of training scores.

        Higher percentile → fewer (but higher quality) alerts.
        """
        if not self._score_history:
            return self._cfg.anomaly_score_threshold

        # score_samples returns more-negative for anomalies
        # We invert to [0,1] consistent with score()
        raw = np.array(self._score_history)
        normalised = self._normalise_scores(raw)
        threshold = float(np.percentile(normalised, percentile))
        log.info("Threshold calibrated",
                 percentile=percentile, suggested_threshold=threshold)
        return threshold

    # ── Private ───────────────────────────────────────────────────────────────

    def _assert_trained(self) -> None:
        if not self._is_trained or self._model is None:
            raise RuntimeError(
                "AnomalyEngine has not been trained. Call train() or load() first."
            )

    def _compute_result(self, event_id: str, vec: np.ndarray) -> AnomalyResult:
        """
        Internal scoring helper.

        sklearn IsolationForest:
        - predict(): returns 1 (normal) or -1 (anomaly)
        - score_samples(): returns negative anomaly score (more negative = more anomalous)
        """
        assert self._model is not None

        label: int = int(self._model.predict(vec)[0])
        raw_score: float = float(self._model.score_samples(vec)[0])

        # Normalise to [0, 1]: raw_score ∈ [-0.5, 0.5] approximately
        # We map so that 0.5 raw → 0.0 normalised, -0.5 raw → 1.0 normalised
        anomaly_score = self._normalise_single(raw_score)

        # Confidence: distance from decision boundary (0.5 threshold)
        confidence = clamp_float(abs(anomaly_score - 0.5) * 2.0, 0.0, 1.0)

        threshold_breached = anomaly_score >= self._cfg.anomaly_score_threshold

        # Track for calibration
        self._score_history.append(raw_score)
        if len(self._score_history) > 50_000:
            self._score_history = self._score_history[-50_000:]

        return AnomalyResult(
            event_id=event_id,
            anomaly_score=anomaly_score,
            anomaly_label=label,
            confidence_score=confidence,
            threshold_breached=threshold_breached,
        )

    @staticmethod
    def _normalise_scores(raw: np.ndarray) -> np.ndarray:
        """Normalise an array of raw score_samples values to [0, 1]."""
        # score_samples returns higher = more normal; invert for anomaly score
        # Typical range is roughly [-0.6, 0.2]; clamp then scale
        clamped = np.clip(raw, -1.0, 0.5)
        # Shift so max maps to 0.0, min maps to 1.0
        shifted = clamped - 0.5          # now in [-1.5, 0.0]
        normalised = -shifted / 1.5      # now in [0.0, 1.0]; more-anomalous = higher
        return np.clip(normalised, 0.0, 1.0)

    @staticmethod
    def _normalise_single(raw: float) -> float:
        """Normalise a single raw score_samples value to [0, 1]."""
        clamped = max(-1.0, min(0.5, raw))
        shifted = clamped - 0.5
        normalised = -shifted / 1.5
        return max(0.0, min(1.0, normalised))


# ── Module-level helper ───────────────────────────────────────────────────────

def clamp_float(val: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, val))
