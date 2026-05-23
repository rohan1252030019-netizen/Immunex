"""
IMMUNEX Retraining Pipeline
============================
Layer 4: Automated model retraining with versioning and rollback.

Pipeline:
  1. Detect blind spots (ValidationEngine)
  2. Generate synthetic mutation corpus
  3. Augment training data with mutations
  4. Retrain IsolationForest
  5. Rebuild FAISS baseline index
  6. Recalibrate anomaly threshold
  7. Validate improvement (re-run ValidationEngine)
  8. Redeploy if validation passes, else rollback
  9. Archive all artifacts with version metadata
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from core.mutation_engine import MutationEngine, MutationType
from core.validation_engine import ValidationEngine, BlindSpotReport
from utils.logger import log

_RETRAIN_ARCHIVE = Path(__file__).parent.parent / "data" / "retrain_archive"
_MODELS_DIR      = Path(__file__).parent.parent / "data" / "models"
_VECTORS_DIR     = Path(__file__).parent.parent / "data" / "baseline_vectors"

for _d in [_RETRAIN_ARCHIVE, _MODELS_DIR, _VECTORS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


# ─── Retraining Result ────────────────────────────────────────────────────────

@dataclass
class RetrainingResult:
    session_id:          str
    triggered_by:        str           # "scheduled" | "drift" | "blind_spot" | "manual"
    pre_blind_spot_score: float
    post_blind_spot_score: float
    improvement:         float         # positive = better
    model_version:       str
    n_training_samples:  int
    n_mutation_samples:  int
    threshold_old:       float
    threshold_new:       float
    success:             bool
    rolled_back:         bool
    archive_path:        str
    latency_ms:          float
    completed_at:        datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "session_id":           self.session_id,
            "triggered_by":         self.triggered_by,
            "pre_blind_spot_score": round(self.pre_blind_spot_score, 4),
            "post_blind_spot_score": round(self.post_blind_spot_score, 4),
            "improvement":          round(self.improvement, 4),
            "model_version":        self.model_version,
            "n_training_samples":   self.n_training_samples,
            "n_mutation_samples":   self.n_mutation_samples,
            "threshold_old":        round(self.threshold_old, 4),
            "threshold_new":        round(self.threshold_new, 4),
            "success":              self.success,
            "rolled_back":          self.rolled_back,
            "archive_path":         self.archive_path,
            "latency_ms":           round(self.latency_ms, 1),
            "completed_at":         self.completed_at.isoformat(),
        }


# ─── Retraining Pipeline ──────────────────────────────────────────────────────

class RetrainingPipeline:
    """
    Orchestrates full model retraining with backup, validation, and rollback.

    Usage::

        pipeline = RetrainingPipeline(layer1, anomaly_engine, vector_engine)
        result = pipeline.retrain(triggered_by="drift")
        if result.success:
            log.info("Retraining succeeded", improvement=result.improvement)
    """

    def __init__(
        self,
        innate_layer,
        anomaly_engine,
        vector_engine,
        mutation_engine:    Optional[MutationEngine]   = None,
        validation_engine:  Optional[ValidationEngine] = None,
        n_baseline_samples: int   = 1_000,
        n_mutation_augment: int   = 200,
        blind_spot_trigger: float = 0.25,
        validation_n_muts:  int   = 100,
    ) -> None:
        self._layer1             = innate_layer
        self._anomaly_engine     = anomaly_engine
        self._vector_engine      = vector_engine
        self._n_baseline_samples = n_baseline_samples
        self._n_mutation_augment = n_mutation_augment
        self._blind_spot_trigger = blind_spot_trigger
        self._validation_n_muts  = validation_n_muts

        self._mutation_engine   = mutation_engine or MutationEngine(seed=77)
        self._validation_engine = validation_engine or ValidationEngine(
            anomaly_engine=anomaly_engine,
            vector_engine=vector_engine,
        )

        self._session_counter = 0
        self._history: list[dict] = []
        log.info(
            "RetrainingPipeline initialised",
            n_baseline=n_baseline_samples,
            n_augment=n_mutation_augment,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def retrain(self, triggered_by: str = "manual") -> RetrainingResult:
        """
        Full automated retraining cycle.

        Steps:
          1. Pre-validation (measure current blind spot score)
          2. Archive current models
          3. Generate augmented training data
          4. Retrain IsolationForest + FAISS
          5. Post-validation (measure new blind spot score)
          6. Deploy if improved, else rollback
        """
        t0 = time.perf_counter()
        self._session_counter += 1
        session_id = f"RTN-{self._session_counter:04d}"
        timestamp  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        version    = f"v{self._session_counter}.{timestamp}"

        log.info("Retraining session started", session_id=session_id, triggered_by=triggered_by)

        # 1. Pre-validation
        pre_report = self._validation_engine.evaluate(n_mutations=self._validation_n_muts)
        pre_score  = pre_report.blind_spot_score
        threshold_old = self._anomaly_engine._cfg.anomaly_score_threshold

        # 2. Archive current models
        archive_path = self._archive_models(session_id, timestamp)

        success     = False
        rolled_back = False
        post_score  = pre_score
        threshold_new = threshold_old
        n_mutations = 0
        n_baseline  = 0

        try:
            # 3. Generate augmented training data
            X_baseline, X_mutations = self._build_training_data()
            n_baseline  = X_baseline.shape[0]
            n_mutations = X_mutations.shape[0]

            X_combined = np.vstack([X_baseline, X_mutations]).astype(np.float32)
            log.info(
                "Training data assembled",
                session_id=session_id,
                n_baseline=n_baseline,
                n_mutations=n_mutations,
                n_total=X_combined.shape[0],
            )

            # 4a. Retrain IsolationForest
            self._anomaly_engine.train(X_combined)
            self._anomaly_engine.save()

            # 4b. Recalibrate anomaly threshold
            threshold_new = self._recalibrate_threshold(X_baseline, X_mutations)
            self._anomaly_engine._cfg.anomaly_score_threshold = threshold_new

            # 4c. Rebuild FAISS index (baseline-only for clean reference distribution)
            self._vector_engine.build_baseline(X_baseline)
            self._vector_engine.save_index()

            # 5. Post-validation
            post_report = self._validation_engine.evaluate(n_mutations=self._validation_n_muts)
            post_score  = post_report.blind_spot_score
            improvement = pre_score - post_score  # positive = better

            if improvement >= -0.05:  # Allow up to 5% regression as noise
                success = True
                log.info(
                    "Retraining successful",
                    session_id=session_id,
                    pre_score=pre_score,
                    post_score=post_score,
                    improvement=improvement,
                )
                self._save_version_metadata(session_id, version, post_report)
            else:
                # Rollback
                log.warning(
                    "Retraining regressed — rolling back",
                    session_id=session_id,
                    pre_score=pre_score,
                    post_score=post_score,
                    regression=improvement,
                )
                self._rollback_models(archive_path)
                self._anomaly_engine._cfg.anomaly_score_threshold = threshold_old
                rolled_back = True

        except Exception as exc:
            log.error("Retraining failed — rolling back", session_id=session_id, exc_info=exc)
            self._rollback_models(archive_path)
            rolled_back = True

        latency_ms = (time.perf_counter() - t0) * 1000

        result = RetrainingResult(
            session_id=session_id,
            triggered_by=triggered_by,
            pre_blind_spot_score=pre_score,
            post_blind_spot_score=post_score,
            improvement=pre_score - post_score,
            model_version=version,
            n_training_samples=n_baseline,
            n_mutation_samples=n_mutations,
            threshold_old=threshold_old,
            threshold_new=threshold_new if not rolled_back else threshold_old,
            success=success and not rolled_back,
            rolled_back=rolled_back,
            archive_path=str(archive_path),
            latency_ms=latency_ms,
        )

        self._history.append(result.to_dict())
        log.info(
            "Retraining session complete",
            session_id=session_id,
            success=result.success,
            rolled_back=rolled_back,
            latency_ms=round(latency_ms, 1),
        )
        return result

    def history(self, n: int = 10) -> list[dict]:
        return self._history[-n:]

    def stats(self) -> dict:
        total = len(self._history)
        succeeded = sum(1 for h in self._history if h.get("success"))
        return {
            "retraining_sessions": total,
            "successful":          succeeded,
            "rollbacks":           total - succeeded,
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_training_data(self) -> tuple[np.ndarray, np.ndarray]:
        """Build baseline normal traffic array + mutation-augmented attack array."""
        from utils.constants import FEATURE_DIM

        # Generate synthetic normal baseline via feature pipeline
        try:
            from core.feature_pipeline import FeaturePipeline
            from core.stream_engine import StreamEngine
            from config import get_config

            cfg = get_config()
            pipeline = FeaturePipeline()
            stream = StreamEngine(cfg.stream)

            # Sample from normal traffic (sync-compatible)
            normal_vecs = []
            rng = np.random.default_rng(seed=42)

            # Fast synthetic normal data using known normal ranges
            for _ in range(self._n_baseline_samples):
                vec = np.array([
                    rng.uniform(500, 5000),      # src_bytes
                    rng.uniform(200, 3000),      # dst_bytes
                    rng.uniform(0.1, 5.0),       # duration
                    rng.uniform(10, 200),        # packet_rate
                    rng.uniform(1, 20),          # connection_count
                    rng.uniform(0, 1),           # failed_logins
                    rng.uniform(0.5, 3.0),       # event_frequency
                    rng.uniform(0.3, 2.0),       # event_interval
                    float(rng.integers(0, 5)),   # protocol_encoding
                    float(rng.integers(0, 5)),   # event_type_encoding
                ], dtype=np.float32)
                normal_vecs.append(vec)
            X_baseline = np.vstack(normal_vecs)
        except Exception:
            rng = np.random.default_rng(seed=42)
            X_baseline = rng.random((self._n_baseline_samples, 10)).astype(np.float32) * 10

        # Generate mutations for augmentation
        mutations = self._mutation_engine.generate_batch(n=self._n_mutation_augment)
        X_mutations = np.vstack([m.feature_vector for m in mutations]).astype(np.float32)

        return X_baseline, X_mutations

    def _recalibrate_threshold(
        self,
        X_baseline:  np.ndarray,
        X_mutations: np.ndarray,
    ) -> float:
        """
        Recalibrate anomaly threshold to maximise separation between
        normal and attack distributions.
        """
        if not self._anomaly_engine._is_trained:
            return self._anomaly_engine._cfg.anomaly_score_threshold

        # Score both sets
        model = self._anomaly_engine._model
        n_raw  = model.decision_function(X_baseline)
        a_raw  = model.decision_function(X_mutations)

        n_scores = np.clip(-n_raw / 0.5, 0.0, 1.0)
        a_scores = np.clip(-a_raw / 0.5, 0.0, 1.0)

        # Find threshold that minimises (FN + FP) using simple sweep
        best_thresh = float(np.percentile(n_scores, 95))  # 5th percentile false positives
        best_err = float("inf")
        for pct in range(70, 98):
            t = float(np.percentile(n_scores, pct))
            fp = float(np.mean(n_scores >= t))    # false positive rate
            fn = float(np.mean(a_scores < t))     # false negative rate
            err = fp + fn
            if err < best_err:
                best_err   = err
                best_thresh = t

        best_thresh = float(np.clip(best_thresh, 0.40, 0.80))
        log.info("Threshold recalibrated", old=self._anomaly_engine._cfg.anomaly_score_threshold,
                 new=best_thresh, combined_error=best_err)
        return best_thresh

    def _archive_models(self, session_id: str, timestamp: str) -> Path:
        """Copy current model files to versioned archive."""
        archive_dir = _RETRAIN_ARCHIVE / f"{session_id}_{timestamp}"
        archive_dir.mkdir(parents=True, exist_ok=True)

        for src_path in [
            _MODELS_DIR / "isolation_forest.joblib",
            _VECTORS_DIR / "faiss_baseline.index",
        ]:
            if src_path.exists():
                dest = archive_dir / src_path.name
                shutil.copy2(src_path, dest)

        log.info("Models archived", session_id=session_id, archive=str(archive_dir))
        return archive_dir

    def _rollback_models(self, archive_path: Path) -> None:
        """Restore models from archive."""
        if not archive_path.exists():
            log.error("Rollback failed: archive not found", path=str(archive_path))
            return

        for archived_file in archive_path.iterdir():
            if archived_file.name.endswith(".joblib"):
                shutil.copy2(archived_file, _MODELS_DIR / archived_file.name)
            elif archived_file.name.endswith(".index"):
                shutil.copy2(archived_file, _VECTORS_DIR / archived_file.name)

        # Reload models
        try:
            self._anomaly_engine.load()
        except Exception:
            pass
        try:
            self._vector_engine.load_index()
        except Exception:
            pass

        log.info("Models rolled back from archive", path=str(archive_path))

    def _save_version_metadata(
        self,
        session_id: str,
        version:    str,
        report:     BlindSpotReport,
    ) -> None:
        meta = {
            "session_id":       session_id,
            "version":          version,
            "saved_at":         datetime.utcnow().isoformat(),
            "blind_spot_score": report.blind_spot_score,
            "false_negative_rate": report.false_negative_rate,
        }
        path = _MODELS_DIR / "model_version.json"
        try:
            path.write_text(json.dumps(meta, indent=2))
        except Exception as exc:
            log.warning("Failed to save version metadata", exc_info=exc)
