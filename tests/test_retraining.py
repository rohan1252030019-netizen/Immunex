"""
Tests for IMMUNEX RetrainingPipeline, ValidationEngine, and DefensiveMemory (Layer 4).
"""

from __future__ import annotations

import sys
import os
import json
import tempfile
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mutation_engine import MutationEngine, MutationType
from core.validation_engine import ValidationEngine, BlindSpotReport
from core.defensive_memory import DefensiveMemory, MemoryCorrelationResult
from utils.constants import FEATURE_DIM


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def trained_anomaly_engine():
    """Returns a trained AnomalyEngine."""
    from core.anomaly_engine import AnomalyEngine
    from config import AnomalyEngineConfig
    import tempfile
    from pathlib import Path

    cfg = AnomalyEngineConfig(
        n_estimators=50,
        contamination=0.1,
        model_path=Path(tempfile.mkdtemp()) / "test_if.joblib",
    )
    engine = AnomalyEngine(cfg)
    rng = np.random.default_rng(42)
    X = rng.random((300, FEATURE_DIM)).astype(np.float32) * 10
    engine.train(X)
    return engine


@pytest.fixture
def trained_vector_engine():
    """Returns a VectorEngine with baseline."""
    from core.vector_engine import VectorEngine
    from config import VectorEngineConfig
    import tempfile
    from pathlib import Path

    cfg = VectorEngineConfig(
        index_path=Path(tempfile.mkdtemp()) / "test_faiss.index",
    )
    engine = VectorEngine(cfg)
    rng = np.random.default_rng(42)
    X = rng.random((300, FEATURE_DIM)).astype(np.float32) * 10
    engine.build_baseline(X)
    return engine


@pytest.fixture
def memory(tmp_path):
    """Returns a fresh DefensiveMemory backed by a temp DB."""
    return DefensiveMemory(db_path=tmp_path / "test_memory.db")


# ─── ValidationEngine Tests ───────────────────────────────────────────────────

def test_validation_engine_init(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    assert ve is not None
    stats = ve.stats()
    assert stats["evaluations_run"] == 0


def test_validation_evaluate_returns_report(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    report = ve.evaluate(n_mutations=30)
    assert isinstance(report, BlindSpotReport)
    assert 0.0 <= report.blind_spot_score <= 1.0
    assert 0.0 <= report.false_negative_rate <= 1.0
    assert report.n_mutations_tested == 30
    assert report.n_bypassed <= 30


def test_validation_gap_summary_all_types(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    report = ve.evaluate(n_mutations=70)
    assert len(report.detection_gap_summary) == len(MutationType)
    for mtype in MutationType:
        assert mtype.value in report.detection_gap_summary


def test_validation_coverage_sums_correctly(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    report = ve.evaluate(n_mutations=70)
    for mtype_name, coverage in report.coverage_by_type.items():
        assert 0.0 <= coverage <= 1.0, f"Invalid coverage for {mtype_name}: {coverage}"


def test_validation_recommendation_present(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    report = ve.evaluate(n_mutations=30)
    assert len(report.mitigation_recommendation) > 10


def test_validation_to_dict_serializable(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    report = ve.evaluate(n_mutations=20)
    d = report.to_dict()
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert parsed["n_mutations_tested"] == 20


def test_validation_eval_counter(trained_anomaly_engine, trained_vector_engine):
    ve = ValidationEngine(
        anomaly_engine=trained_anomaly_engine,
        vector_engine=trained_vector_engine,
    )
    ve.evaluate(n_mutations=10)
    ve.evaluate(n_mutations=10)
    assert ve.stats()["evaluations_run"] == 2


# ─── DefensiveMemory Tests ────────────────────────────────────────────────────

def test_memory_init(memory):
    assert memory is not None
    stats = memory.stats()
    assert stats["total_entries"] == 0
    assert stats["cached_vectors"] == 0


def test_memory_store_and_retrieve(memory):
    rng = np.random.default_rng(0)
    vec = rng.random(FEATURE_DIM).astype(np.float32)
    entry_id = memory.store(
        campaign_id="CAM-001",
        attacker_ip="10.0.0.1",
        feature_vector=vec,
        stages=["Port_Scan", "Brute_Force_Login"],
        severity="HIGH",
        attack_family="apt_simulation",
    )
    assert len(entry_id) == 24
    stats = memory.stats()
    assert stats["total_entries"] == 1


def test_memory_correlate_empty(memory):
    rng = np.random.default_rng(1)
    vec = rng.random(FEATURE_DIM).astype(np.float32)
    result = memory.correlate("NEW-CAM", vec, [])
    assert result.recurring_threat_score == 0.0
    assert result.known_attack_family == "no_history"
    assert result.n_similar_incidents == 0


def test_memory_correlate_exact_match(memory):
    rng = np.random.default_rng(2)
    vec = rng.random(FEATURE_DIM).astype(np.float32)
    memory.store("CAM-A", "1.2.3.4", vec, ["Stage1"], "HIGH", "known_apt")
    # Query with identical vector
    result = memory.correlate("CAM-B", vec.copy(), ["Stage1"])
    assert result.recurring_threat_score > 0.5
    assert result.historical_match_probability > 0.5
    assert result.closest_similarity > 0.9


def test_memory_correlate_dissimilar(memory):
    rng = np.random.default_rng(3)
    vec_a = np.ones(FEATURE_DIM, dtype=np.float32)
    vec_b = np.ones(FEATURE_DIM, dtype=np.float32) * (-1)  # opposite direction
    memory.store("CAM-A", "1.2.3.4", vec_a, [], "LOW", "benign")
    result = memory.correlate("CAM-B", vec_b, [])
    # Should have low similarity (cosine handles negative values)
    assert result.closest_similarity < 0.5


def test_memory_stores_multiple_entries(memory):
    rng = np.random.default_rng(4)
    for i in range(10):
        vec = rng.random(FEATURE_DIM).astype(np.float32)
        memory.store(f"CAM-{i:03d}", f"10.0.0.{i}", vec, ["Stage1"], "MEDIUM", "test_family")
    stats = memory.stats()
    assert stats["total_entries"] == 10


def test_memory_seen_count_increments(memory):
    rng = np.random.default_rng(5)
    vec = rng.random(FEATURE_DIM).astype(np.float32)
    # Store same campaign twice — should increment seen_count
    memory.store("SAME-CAM", "10.0.0.1", vec, ["Stage1"], "HIGH", "apt")
    memory.store("SAME-CAM", "10.0.0.1", vec, ["Stage1"], "HIGH", "apt")
    recent = memory.list_recent(n=10)
    assert len(recent) == 1
    assert recent[0]["seen_count"] == 2


def test_memory_list_recent(memory):
    rng = np.random.default_rng(6)
    for i in range(5):
        vec = rng.random(FEATURE_DIM).astype(np.float32)
        memory.store(f"CAM-{i}", "10.0.0.1", vec, [], "LOW", "test")
    recent = memory.list_recent(n=3)
    assert len(recent) == 3


def test_memory_cleanup(memory):
    rng = np.random.default_rng(7)
    # Store some entries
    for i in range(5):
        vec = rng.random(FEATURE_DIM).astype(np.float32)
        memory.store(f"OLD-{i}", "10.0.0.1", vec, [], "LOW", "old_threat")
    # Cleanup with 0 days (delete everything)
    deleted = memory.cleanup_old_entries(days=0)
    assert deleted == 5
    assert memory.stats()["total_entries"] == 0


def test_memory_to_dict_serializable(memory):
    rng = np.random.default_rng(8)
    vec = rng.random(FEATURE_DIM).astype(np.float32)
    memory.store("CAM-DICT", "192.168.1.1", vec, ["Recon", "Exfil"], "CRITICAL", "ransomware")
    result = memory.correlate("CAM-DICT-Q", vec, ["Recon"])
    d = result.to_dict()
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert "recurring_threat_score" in parsed
    assert "known_attack_family" in parsed


def test_memory_attack_families_stats(memory):
    rng = np.random.default_rng(9)
    for family in ["apt1", "apt1", "ransomware", "insider"]:
        vec = rng.random(FEATURE_DIM).astype(np.float32)
        memory.store(f"CAM-{family}", "10.0.0.1", vec, [], "HIGH", family)
    stats = memory.stats()
    families = stats["attack_families"]
    assert families.get("apt1", 0) == 2
    assert families.get("ransomware", 0) == 1
    assert families.get("insider", 0) == 1
