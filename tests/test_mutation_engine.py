"""
Tests for IMMUNEX MutationEngine (Layer 4).
"""

from __future__ import annotations

import sys
import os
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mutation_engine import MutationEngine, MutationType, MutationResult
from utils.constants import FEATURE_DIM


@pytest.fixture
def engine():
    return MutationEngine(anomaly_threshold=0.55, faiss_threshold=25.0, seed=42)


def test_mutation_engine_init(engine):
    assert engine is not None
    stats = engine.stats()
    assert stats["total_mutations_generated"] == 0


def test_generate_single_all_types(engine):
    for mtype in MutationType:
        result = engine.generate_single(mtype)
        assert isinstance(result, MutationResult)
        assert result.mutation_type == mtype
        assert result.feature_vector.shape == (FEATURE_DIM,)
        assert 0.0 <= result.evasion_score <= 1.0
        assert isinstance(result.expected_bypass, bool)
        assert len(result.mutation_id) > 0
        assert len(result.description) > 0


def test_generate_batch_default(engine):
    results = engine.generate_batch(n=50)
    assert len(results) == 50
    assert all(isinstance(r, MutationResult) for r in results)
    assert engine.stats()["total_mutations_generated"] == 50


def test_generate_batch_specific_types(engine):
    types = [MutationType.STEALTH, MutationType.INSIDER_THREAT]
    results = engine.generate_batch(n=20, mutation_types=types)
    assert len(results) == 20
    for r in results:
        assert r.mutation_type in types


def test_feature_vectors_are_finite(engine):
    results = engine.generate_batch(n=30)
    for r in results:
        assert np.all(np.isfinite(r.feature_vector)), \
            f"Non-finite values in {r.mutation_type} mutation: {r.feature_vector}"


def test_polymorphic_mutations_are_diverse(engine):
    results = engine.generate_batch(n=20, mutation_types=[MutationType.POLYMORPHIC])
    vecs = np.vstack([r.feature_vector for r in results])
    # Polymorphic mutations should not all be identical
    assert np.std(vecs, axis=0).mean() > 0.01, "Polymorphic mutations lack diversity"


def test_stealth_evasion_score_higher_than_polymorphic(engine):
    stealth = engine.generate_batch(n=30, mutation_types=[MutationType.STEALTH])
    poly    = engine.generate_batch(n=30, mutation_types=[MutationType.POLYMORPHIC])
    mean_stealth = np.mean([r.evasion_score for r in stealth])
    mean_poly    = np.mean([r.evasion_score for r in poly])
    # Stealth mutations should be harder to detect (higher evasion score)
    assert mean_stealth > mean_poly, \
        f"Expected stealth ({mean_stealth:.3f}) > polymorphic ({mean_poly:.3f})"


def test_raw_event_structure(engine):
    result = engine.generate_single(MutationType.LATERAL_MOVEMENT)
    ev = result.raw_event
    required_keys = {
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "user_id", "process_name", "event_type", "src_bytes",
        "dst_bytes", "duration",
    }
    assert required_keys.issubset(set(ev.keys()))


def test_mutation_ids_are_unique(engine):
    results = engine.generate_batch(n=100)
    ids = [r.mutation_id for r in results]
    assert len(set(ids)) == len(ids), "Duplicate mutation IDs detected"


def test_to_dict_serializable(engine):
    import json
    result = engine.generate_single(MutationType.EXFILTRATION)
    d = result.to_dict()
    # Should be JSON-serializable
    serialized = json.dumps(d)
    assert len(serialized) > 0
    parsed = json.loads(serialized)
    assert parsed["mutation_type"] == "exfiltration"
    assert len(parsed["feature_vector"]) == FEATURE_DIM


def test_counter_increments(engine):
    engine.generate_batch(n=10)
    engine.generate_single(MutationType.STEALTH)
    before = engine.stats()["total_mutations_generated"]
    engine.generate_batch(n=10)
    engine.generate_single(MutationType.STEALTH)
    after = engine.stats()["total_mutations_generated"]
    assert after == before + 11


def test_seeded_reproducibility():
    e1 = MutationEngine(seed=123)
    e2 = MutationEngine(seed=123)
    r1 = e1.generate_single(MutationType.POLYMORPHIC)
    r2 = e2.generate_single(MutationType.POLYMORPHIC)
    np.testing.assert_array_almost_equal(r1.feature_vector, r2.feature_vector, decimal=5)
