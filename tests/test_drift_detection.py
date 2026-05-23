"""
Tests for IMMUNEX RetrainingPipeline and DriftDetector (Layer 4).
"""

from __future__ import annotations

import sys
import os
import json
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.drift_detector import DriftDetector, DriftReport
from core.mutation_engine import MutationEngine
from utils.constants import FEATURE_DIM, FEATURE_NAMES


# ─── DriftDetector Tests ──────────────────────────────────────────────────────

@pytest.fixture
def rng():
    return np.random.default_rng(seed=0)


@pytest.fixture
def detector():
    return DriftDetector(
        drift_threshold=0.2,
        retrain_threshold=0.35,
        window_size=500,
    )


@pytest.fixture
def baseline_data(rng):
    N = 300
    X = np.column_stack([
        rng.uniform(500,  5000, N),
        rng.uniform(200,  3000, N),
        rng.uniform(0.1,  5.0,  N),
        rng.uniform(10,   200,  N),
        rng.uniform(1,    20,   N),
        rng.uniform(0,    1,    N),
        rng.uniform(0.5,  3.0,  N),
        rng.uniform(0.3,  2.0,  N),
        rng.integers(0, 5, N).astype(float),
        rng.integers(0, 5, N).astype(float),
    ]).astype(np.float32)
    anom  = rng.uniform(0.0, 0.3, N).astype(np.float32)
    faiss = rng.uniform(1.0, 15.0, N).astype(np.float32)
    return X, anom, faiss


def test_drift_detector_init(detector):
    assert detector is not None
    stats = detector.stats()
    assert stats["baseline_set"] is False
    assert stats["drift_analyses_run"] == 0


def test_set_baseline(detector, baseline_data):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    stats = detector.stats()
    assert stats["baseline_set"] is True


def test_ingest_updates_window(detector, baseline_data, rng):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    vec = rng.random(FEATURE_DIM).astype(np.float32)
    detector.ingest(vec, anomaly_score=0.2, faiss_dist=10.0)
    stats = detector.stats()
    assert stats["current_window_size"] == 1


def test_analyse_returns_none_when_insufficient_data(detector, baseline_data):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    # Only 10 samples — below 100 minimum
    rng = np.random.default_rng(1)
    for _ in range(10):
        detector.ingest(rng.random(FEATURE_DIM).astype(np.float32), 0.2, 10.0)
    result = detector.analyse()
    assert result is None


def test_analyse_stable_traffic(detector, baseline_data, rng):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    # Ingest similar normal traffic
    for _ in range(150):
        vec = np.column_stack([
            rng.uniform(500, 5000, 1),
            rng.uniform(200, 3000, 1),
            rng.uniform(0.1, 5.0, 1),
            rng.uniform(10, 200, 1),
            rng.uniform(1, 20, 1),
            rng.uniform(0, 1, 1),
            rng.uniform(0.5, 3.0, 1),
            rng.uniform(0.3, 2.0, 1),
            rng.integers(0, 5, (1,1)).astype(float),
            rng.integers(0, 5, (1,1)).astype(float),
        ]).flatten().astype(np.float32)
        detector.ingest(vec, rng.uniform(0, 0.3), rng.uniform(1, 15))
    report = detector.analyse()
    assert report is not None
    assert isinstance(report, DriftReport)
    # Stable traffic should have low drift
    assert report.overall_drift_score < 0.5


def test_analyse_drifted_traffic_detected(detector, baseline_data, rng):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    # Ingest attack-like traffic (drastically different from baseline)
    for _ in range(150):
        vec = np.array([
            rng.uniform(100_000, 500_000),  # massive src_bytes
            rng.uniform(50, 100),            # tiny dst_bytes
            rng.uniform(0.001, 0.01),        # very short duration
            rng.uniform(1000, 5000),         # very high packet rate
            rng.uniform(100, 500),           # many connections
            rng.uniform(20, 50),             # many failed logins
            rng.uniform(50, 100),            # very high event frequency
            rng.uniform(0.001, 0.01),        # very short interval
            7.0,                             # RDP protocol
            30.0,                            # PowerShell event
        ], dtype=np.float32)
        detector.ingest(vec, rng.uniform(0.8, 1.0), rng.uniform(100, 500))
    report = detector.analyse()
    assert report is not None
    assert report.drift_detected is True
    assert report.overall_drift_score > 0.2


def test_drift_report_structure(detector, baseline_data, rng):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    for _ in range(120):
        vec = rng.random(FEATURE_DIM).astype(np.float32) * 1000
        detector.ingest(vec, 0.5, 20.0)
    report = detector.analyse()
    assert report is not None
    assert len(report.feature_drift) == FEATURE_DIM
    for name in FEATURE_NAMES:
        assert name in report.feature_drift
    assert 0.0 <= report.overall_drift_score
    assert isinstance(report.drift_detected, bool)
    assert isinstance(report.retrain_recommended, bool)
    assert isinstance(report.affected_features, list)


def test_psi_identical_distributions():
    """PSI between identical distributions should be ~0."""
    rng = np.random.default_rng(5)
    x = rng.uniform(0, 100, 500).astype(np.float32)
    psi = DriftDetector._psi(x, x)
    assert psi < 0.01


def test_psi_different_distributions():
    """PSI between very different distributions should be high."""
    rng = np.random.default_rng(5)
    x = rng.uniform(0, 1,    500).astype(np.float32)
    y = rng.uniform(100, 200, 500).astype(np.float32)
    psi = DriftDetector._psi(x, y)
    assert psi > 0.5


def test_to_dict_serializable(detector, baseline_data, rng):
    import json
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    for _ in range(120):
        detector.ingest(rng.random(FEATURE_DIM).astype(np.float32), 0.3, 12.0)
    report = detector.analyse()
    if report is not None:
        d = report.to_dict()
        serialized = json.dumps(d)
        assert len(serialized) > 0


def test_recent_history_accumulates(detector, baseline_data, rng):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    for run in range(3):
        # Reset window between analyses
        for _ in range(120):
            detector.ingest(rng.random(FEATURE_DIM).astype(np.float32) * (run + 1) * 10, 0.4, 15.0)
        detector.analyse()
    history = detector.recent_history(n=10)
    assert len(history) >= 1  # at least one analysis produced a report


def test_drift_stats_tracking(detector, baseline_data, rng):
    X, anom, faiss = baseline_data
    detector.set_baseline(X, anom, faiss)
    for _ in range(120):
        detector.ingest(rng.random(FEATURE_DIM).astype(np.float32), 0.3, 10.0)
    detector.analyse()
    stats = detector.stats()
    assert stats["drift_analyses_run"] >= 1
