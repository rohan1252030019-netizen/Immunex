"""
Tests for IMMUNEX VectorEngine (FAISS)
"""

import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest

from config import VectorEngineConfig
from core.vector_engine import VectorEngine
from utils.constants import FEATURE_DIM
from utils.schemas import FAISSResult, FeatureVector


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def vector_config(tmp_path: Path) -> VectorEngineConfig:
    return VectorEngineConfig(
        feature_dim=FEATURE_DIM,
        index_path=tmp_path / "test_faiss.index",
        baseline_samples=100,
        faiss_distance_threshold=25.0,
        top_k=5,
    )


def make_feature_vector(event_id: str, values: list[float]) -> FeatureVector:
    assert len(values) == FEATURE_DIM
    keys = [
        "src_bytes", "dst_bytes", "duration", "packet_rate",
        "connection_count", "failed_logins", "event_frequency",
        "event_interval", "protocol_encoding", "event_type_encoding",
    ]
    return FeatureVector(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        **dict(zip(keys, values)),
    )


def make_normal_vectors(n: int, seed: int = 42) -> list[FeatureVector]:
    rng = np.random.default_rng(seed)
    vals = rng.uniform(0.0, 5.0, size=(n, FEATURE_DIM)).tolist()
    return [make_feature_vector(f"N{i:04d}", row) for i, row in enumerate(vals)]


@pytest.fixture
def ready_engine(vector_config: VectorEngineConfig) -> VectorEngine:
    engine = VectorEngine(cfg=vector_config)
    vectors = make_normal_vectors(200)
    engine.build_baseline(vectors)
    return engine


# ── Unit Tests ────────────────────────────────────────────────────────────────

class TestVectorEngineBaseline:

    def test_build_baseline_succeeds(self, vector_config: VectorEngineConfig):
        engine = VectorEngine(cfg=vector_config)
        vectors = make_normal_vectors(100)
        engine.build_baseline(vectors)
        assert engine.is_ready()

    def test_build_baseline_numpy_input(self, vector_config: VectorEngineConfig):
        engine = VectorEngine(cfg=vector_config)
        X = np.random.default_rng(0).uniform(0, 5, (100, FEATURE_DIM)).astype(np.float32)
        engine.build_baseline(X)
        assert engine.is_ready()

    def test_build_baseline_empty_raises(self, vector_config: VectorEngineConfig):
        engine = VectorEngine(cfg=vector_config)
        with pytest.raises(ValueError, match="empty"):
            engine.build_baseline([])

    def test_build_baseline_wrong_dim_raises(self, vector_config: VectorEngineConfig):
        engine = VectorEngine(cfg=vector_config)
        X = np.random.default_rng(0).uniform(0, 1, (50, 5)).astype(np.float32)
        with pytest.raises(ValueError, match="Expected vectors of shape"):
            engine.build_baseline(X)

    def test_not_ready_before_build(self, vector_config: VectorEngineConfig):
        engine = VectorEngine(cfg=vector_config)
        assert not engine.is_ready()

    def test_query_before_build_raises(self, vector_config: VectorEngineConfig):
        engine = VectorEngine(cfg=vector_config)
        fv = make_feature_vector("X001", [1.0] * FEATURE_DIM)
        with pytest.raises(RuntimeError, match="not ready"):
            engine.query(fv)


class TestVectorEngineQuery:

    def test_query_returns_faiss_result(self, ready_engine: VectorEngine):
        fv = make_feature_vector("Q001", [2.5] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert isinstance(result, FAISSResult)

    def test_nearest_distance_non_negative(self, ready_engine: VectorEngine):
        fv = make_feature_vector("Q002", [2.5] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert result.nearest_distance >= 0.0

    def test_in_distribution_vector_low_distance(self, ready_engine: VectorEngine):
        """A vector within the baseline range should have low L2 distance."""
        fv = make_feature_vector("Q003", [2.5] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert not result.threshold_breached

    def test_out_of_distribution_vector_high_distance(self, ready_engine: VectorEngine):
        """A vector very far from baseline should breach the threshold."""
        fv = make_feature_vector("Q004", [1000.0] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert result.threshold_breached

    def test_zero_vector_returns_result(self, ready_engine: VectorEngine):
        fv = make_feature_vector("Q005", [0.0] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert isinstance(result, FAISSResult)

    def test_distances_list_has_k_elements(
        self, vector_config: VectorEngineConfig
    ):
        engine = VectorEngine(cfg=vector_config)
        vecs = make_normal_vectors(100)
        engine.build_baseline(vecs)
        fv = make_feature_vector("Q006", [2.5] * FEATURE_DIM)
        result = engine.query(fv)
        assert len(result.distances) == vector_config.top_k

    def test_distances_are_sorted_ascending(self, ready_engine: VectorEngine):
        fv = make_feature_vector("Q007", [1.0] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert result.distances == sorted(result.distances)

    def test_nearest_distance_is_minimum(self, ready_engine: VectorEngine):
        fv = make_feature_vector("Q008", [3.0] * FEATURE_DIM)
        result = ready_engine.query(fv)
        assert result.nearest_distance == min(result.distances)

    def test_batch_query_matches_individual(self, ready_engine: VectorEngine):
        fvs = [make_feature_vector(f"B{i:03d}", [float(i)] * FEATURE_DIM) for i in range(5)]
        batch_results = ready_engine.query_batch(fvs)
        for fv, batch_res in zip(fvs, batch_results):
            individual = ready_engine.query(fv)
            assert abs(batch_res.nearest_distance - individual.nearest_distance) < 1e-4


class TestVectorEnginePersistence:

    def test_save_and_load_round_trip(
        self, ready_engine: VectorEngine, vector_config: VectorEngineConfig
    ):
        path = vector_config.index_path
        ready_engine.save_index(path)
        assert path.exists()

        fresh = VectorEngine(cfg=vector_config)
        fresh.load_index(path)
        assert fresh.is_ready()

    def test_query_after_load_matches_original(
        self, ready_engine: VectorEngine, vector_config: VectorEngineConfig
    ):
        path = vector_config.index_path
        ready_engine.save_index(path)

        fresh = VectorEngine(cfg=vector_config)
        fresh.load_index(path)

        fv = make_feature_vector("LOAD01", [1.5] * FEATURE_DIM)
        original_result = ready_engine.query(fv)
        loaded_result = fresh.query(fv)
        assert abs(original_result.nearest_distance - loaded_result.nearest_distance) < 1e-4

    def test_load_nonexistent_raises(self, vector_config: VectorEngineConfig, tmp_path: Path):
        engine = VectorEngine(cfg=vector_config)
        with pytest.raises(FileNotFoundError):
            engine.load_index(tmp_path / "ghost.index")

    def test_add_vectors_increases_index_size(self, ready_engine: VectorEngine):
        before = ready_engine._baseline_count
        extra = make_normal_vectors(50, seed=99)
        ready_engine.add_vectors(extra)
        assert ready_engine._baseline_count == before + 50
