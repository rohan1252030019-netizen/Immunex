"""
Tests for IMMUNEX AnomalyEngine (IsolationForest)
"""

import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest

from config import AnomalyEngineConfig
from core.anomaly_engine import AnomalyEngine
from core.feature_pipeline import FeaturePipeline
from core.stream_engine import StreamEngine
from config import StreamConfig
from utils.schemas import AnomalyResult, FeatureVector
from datetime import datetime


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_model_path(tmp_path: Path) -> Path:
    return tmp_path / "test_isolation_forest.joblib"


@pytest.fixture
def anomaly_config(tmp_model_path: Path) -> AnomalyEngineConfig:
    return AnomalyEngineConfig(
        n_estimators=50,
        contamination=0.1,
        random_state=42,
        anomaly_score_threshold=0.55,
        model_path=tmp_model_path,
        warmup_samples=200,
    )


@pytest.fixture
def trained_engine(anomaly_config: AnomalyEngineConfig) -> AnomalyEngine:
    """Return a trained AnomalyEngine on synthetic normal traffic."""
    engine = AnomalyEngine(cfg=anomaly_config)
    rng = np.random.default_rng(42)
    # Simulate 300 normal feature vectors
    X = rng.normal(loc=0.5, scale=0.1, size=(300, 10)).astype(np.float32)
    engine.train(X)
    return engine


@pytest.fixture
def sample_feature_vector() -> FeatureVector:
    return FeatureVector(
        event_id="TEST0001",
        timestamp=datetime.utcnow(),
        src_bytes=5.0,
        dst_bytes=7.0,
        duration=1.2,
        packet_rate=2.0,
        connection_count=3.0,
        failed_logins=0.0,
        event_frequency=0.5,
        event_interval=0.1,
        protocol_encoding=0.0,
        event_type_encoding=0.0,
    )


# ── Unit Tests ────────────────────────────────────────────────────────────────

class TestAnomalyEngineTraining:

    def test_train_succeeds_with_valid_data(self, anomaly_config: AnomalyEngineConfig):
        engine = AnomalyEngine(cfg=anomaly_config)
        X = np.random.default_rng(1).random((200, 10)).astype(np.float32)
        engine.train(X)
        assert engine.is_trained()

    def test_train_fails_wrong_feature_dim(self, anomaly_config: AnomalyEngineConfig):
        engine = AnomalyEngine(cfg=anomaly_config)
        X = np.random.default_rng(1).random((200, 5)).astype(np.float32)
        with pytest.raises(ValueError, match="Expected X of shape"):
            engine.train(X)

    def test_train_fails_too_few_samples(self, anomaly_config: AnomalyEngineConfig):
        engine = AnomalyEngine(cfg=anomaly_config)
        X = np.random.default_rng(1).random((5, 10)).astype(np.float32)
        with pytest.raises(ValueError, match="at least 10 samples"):
            engine.train(X)

    def test_untrained_engine_raises_on_score(
        self, anomaly_config: AnomalyEngineConfig, sample_feature_vector: FeatureVector
    ):
        engine = AnomalyEngine(cfg=anomaly_config)
        with pytest.raises(RuntimeError, match="not been trained"):
            engine.score(sample_feature_vector)


class TestAnomalyEngineScoring:

    def test_score_returns_anomaly_result(
        self, trained_engine: AnomalyEngine, sample_feature_vector: FeatureVector
    ):
        result = trained_engine.score(sample_feature_vector)
        assert isinstance(result, AnomalyResult)

    def test_anomaly_score_in_range(
        self, trained_engine: AnomalyEngine, sample_feature_vector: FeatureVector
    ):
        result = trained_engine.score(sample_feature_vector)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_confidence_score_in_range(
        self, trained_engine: AnomalyEngine, sample_feature_vector: FeatureVector
    ):
        result = trained_engine.score(sample_feature_vector)
        assert 0.0 <= result.confidence_score <= 1.0

    def test_anomaly_label_valid(
        self, trained_engine: AnomalyEngine, sample_feature_vector: FeatureVector
    ):
        result = trained_engine.score(sample_feature_vector)
        assert result.anomaly_label in (-1, 1)

    def test_normal_traffic_scores_lower_than_attack(
        self, anomaly_config: AnomalyEngineConfig
    ):
        """Vectors clearly outside training distribution should score higher."""
        engine = AnomalyEngine(cfg=anomaly_config)
        rng = np.random.default_rng(42)
        # Normal: tight cluster near 0.5
        X_train = rng.normal(loc=0.5, scale=0.05, size=(300, 10)).astype(np.float32)
        engine.train(X_train)

        # Normal test vector (in-distribution)
        normal_fv = FeatureVector(
            event_id="NORM",
            timestamp=datetime.utcnow(),
            **{k: 0.5 for k in [
                "src_bytes","dst_bytes","duration","packet_rate",
                "connection_count","failed_logins","event_frequency",
                "event_interval","protocol_encoding","event_type_encoding"
            ]},
        )

        # Anomalous test vector (far outside training distribution)
        anomalous_fv = FeatureVector(
            event_id="ANOM",
            timestamp=datetime.utcnow(),
            **{k: 99.0 for k in [
                "src_bytes","dst_bytes","duration","packet_rate",
                "connection_count","failed_logins","event_frequency",
                "event_interval","protocol_encoding","event_type_encoding"
            ]},
        )

        normal_result = engine.score(normal_fv)
        anomalous_result = engine.score(anomalous_fv)
        assert anomalous_result.anomaly_score > normal_result.anomaly_score

    def test_batch_scoring_consistent_with_individual(
        self, trained_engine: AnomalyEngine
    ):
        fvs = [
            FeatureVector(
                event_id=f"T{i:04d}",
                timestamp=datetime.utcnow(),
                **{k: float(i) * 0.1 for k in [
                    "src_bytes","dst_bytes","duration","packet_rate",
                    "connection_count","failed_logins","event_frequency",
                    "event_interval","protocol_encoding","event_type_encoding"
                ]},
            )
            for i in range(5)
        ]
        batch_results = trained_engine.score_batch(fvs)
        individual_results = [trained_engine.score(fv) for fv in fvs]

        for b, ind in zip(batch_results, individual_results):
            assert abs(b.anomaly_score - ind.anomaly_score) < 1e-6


class TestAnomalyEnginePersistence:

    def test_save_and_load_round_trip(
        self, trained_engine: AnomalyEngine,
        anomaly_config: AnomalyEngineConfig,
        sample_feature_vector: FeatureVector,
        tmp_model_path: Path,
    ):
        # Save
        trained_engine.save(tmp_model_path)
        assert tmp_model_path.exists()

        # Load into fresh engine
        fresh = AnomalyEngine(cfg=anomaly_config)
        fresh.load(tmp_model_path)
        assert fresh.is_trained()

        # Scores should be identical
        original = trained_engine.score(sample_feature_vector)
        loaded = fresh.score(sample_feature_vector)
        assert abs(original.anomaly_score - loaded.anomaly_score) < 1e-6

    def test_load_nonexistent_raises(
        self, anomaly_config: AnomalyEngineConfig, tmp_path: Path
    ):
        engine = AnomalyEngine(cfg=anomaly_config)
        with pytest.raises(FileNotFoundError):
            engine.load(tmp_path / "nonexistent.joblib")

    def test_save_untrained_raises(
        self, anomaly_config: AnomalyEngineConfig, tmp_model_path: Path
    ):
        engine = AnomalyEngine(cfg=anomaly_config)
        with pytest.raises(RuntimeError, match="not been trained"):
            engine.save(tmp_model_path)


class TestAnomalyEngineThreshold:

    def test_calibrate_returns_float(self, trained_engine: AnomalyEngine):
        threshold = trained_engine.calibrate_threshold(percentile=95.0)
        assert isinstance(threshold, float)
        assert 0.0 <= threshold <= 1.0
