"""
Tests for core/markov_predictor.py
=====================================
Validates:
- Transition matrix initialisation
- observe_transition() updates counts
- predict() returns correct structure
- Confidence is highest for the predicted stage
- Probability distribution sums to 1.0
- predict_sequence() chains correctly
- stationary distribution sums to 1.0
- Unknown stage handling
- Stats reporting
"""

from __future__ import annotations

import numpy as np
import pytest

from core.markov_predictor import MarkovPredictor, STAGES, STAGE_INDEX, N_STAGES


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def predictor() -> MarkovPredictor:
    return MarkovPredictor(smoothing=1.0, prior_weight=5.0)


# ─── Initialisation ───────────────────────────────────────────────────────────

class TestMarkovInit:
    def test_stages_list_not_empty(self):
        assert len(STAGES) == 7

    def test_stage_index_complete(self):
        for s in STAGES:
            assert s in STAGE_INDEX

    def test_counts_matrix_shape(self, predictor):
        assert predictor._counts.shape == (N_STAGES, N_STAGES)

    def test_counts_all_positive(self, predictor):
        assert np.all(predictor._counts > 0)


# ─── observe_transition ───────────────────────────────────────────────────────

class TestObserveTransition:
    def test_observe_increments_count(self, predictor):
        i = STAGE_INDEX["Reconnaissance"]
        j = STAGE_INDEX["Credential_Access"]
        before = predictor._counts[i, j]
        predictor.observe_transition("Reconnaissance", "Credential_Access")
        after = predictor._counts[i, j]
        assert after == before + 1.0

    def test_observe_increments_total(self, predictor):
        predictor.observe_transition("Execution", "Persistence")
        assert predictor._total_transitions == 1

    def test_observe_unknown_stage_logs_warning(self, predictor, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            predictor.observe_transition("UnknownStage", "Reconnaissance")
        assert predictor._total_transitions == 0

    def test_observe_sequence_records_all_pairs(self, predictor):
        stages = ["Reconnaissance", "Credential_Access", "Execution"]
        predictor.observe_sequence(stages)
        assert predictor._total_transitions == 2


# ─── predict ─────────────────────────────────────────────────────────────────

class TestPredict:
    def test_predict_returns_dict(self, predictor):
        result = predictor.predict("Reconnaissance")
        assert isinstance(result, dict)

    def test_predict_keys_present(self, predictor):
        result = predictor.predict("Reconnaissance")
        for key in ["predicted_stage", "probability_dist", "confidence_score", "entropy", "current_stage"]:
            assert key in result

    def test_predicted_stage_is_valid(self, predictor):
        for stage in STAGES:
            result = predictor.predict(stage)
            assert result["predicted_stage"] in STAGES

    def test_probability_dist_sums_to_one(self, predictor):
        for stage in STAGES:
            dist = predictor.predict(stage)["probability_dist"]
            total = sum(dist.values())
            assert abs(total - 1.0) < 1e-6

    def test_confidence_is_max_probability(self, predictor):
        for stage in STAGES:
            result = predictor.predict(stage)
            max_prob = max(result["probability_dist"].values())
            assert abs(result["confidence_score"] - max_prob) < 1e-9

    def test_confidence_between_zero_and_one(self, predictor):
        for stage in STAGES:
            conf = predictor.predict(stage)["confidence_score"]
            assert 0.0 <= conf <= 1.0

    def test_entropy_non_negative(self, predictor):
        for stage in STAGES:
            entropy = predictor.predict(stage)["entropy"]
            assert entropy >= 0.0

    def test_current_stage_echoed(self, predictor):
        result = predictor.predict("Exfiltration")
        assert result["current_stage"] == "Exfiltration"

    def test_unknown_stage_returns_uniform_dist(self, predictor):
        result = predictor.predict("TOTALLY_UNKNOWN_STAGE")
        expected = 1.0 / N_STAGES
        for prob in result["probability_dist"].values():
            assert abs(prob - expected) < 1e-9

    def test_exfil_predicts_exfil(self, predictor):
        """With repeated exfil→exfil observations, exfil should predict exfil."""
        for _ in range(50):
            predictor.observe_transition("Exfiltration", "Exfiltration")
        result = predictor.predict("Exfiltration")
        assert result["predicted_stage"] == "Exfiltration"

    def test_recon_predicts_credential_access_by_prior(self, predictor):
        """Default prior should bias Recon → Credential_Access."""
        result = predictor.predict("Reconnaissance")
        assert result["predicted_stage"] == "Credential_Access"


# ─── predict_sequence ────────────────────────────────────────────────────────

class TestPredictSequence:
    def test_sequence_length(self, predictor):
        seq = predictor.predict_sequence("Reconnaissance", steps=3)
        assert len(seq) == 3

    def test_sequence_chained(self, predictor):
        seq = predictor.predict_sequence("Reconnaissance", steps=4)
        for i in range(1, len(seq)):
            assert seq[i]["current_stage"] == seq[i - 1]["predicted_stage"]


# ─── get_transition_matrix ───────────────────────────────────────────────────

class TestTransitionMatrix:
    def test_matrix_shape(self, predictor):
        P = predictor.get_transition_matrix()
        assert P.shape == (N_STAGES, N_STAGES)

    def test_rows_sum_to_one(self, predictor):
        P = predictor.get_transition_matrix()
        row_sums = P.sum(axis=1)
        assert np.allclose(row_sums, 1.0)

    def test_all_entries_non_negative(self, predictor):
        P = predictor.get_transition_matrix()
        assert np.all(P >= 0)


# ─── stationary distribution ─────────────────────────────────────────────────

class TestStationaryDistribution:
    def test_stationary_sums_to_one(self, predictor):
        dist = predictor.get_stage_distribution()
        total = sum(dist.values())
        assert abs(total - 1.0) < 1e-6

    def test_stationary_all_keys_present(self, predictor):
        dist = predictor.get_stage_distribution()
        for s in STAGES:
            assert s in dist

    def test_stationary_all_non_negative(self, predictor):
        dist = predictor.get_stage_distribution()
        for v in dist.values():
            assert v >= 0.0


# ─── stats ───────────────────────────────────────────────────────────────────

class TestMarkovStats:
    def test_stats_structure(self, predictor):
        s = predictor.stats()
        assert "total_transitions" in s
        assert "stage_observations" in s
        assert "matrix_shape" in s

    def test_stats_transitions_counts(self, predictor):
        predictor.observe_transition("Reconnaissance", "Execution")
        predictor.observe_transition("Execution", "Persistence")
        assert predictor.stats()["total_transitions"] == 2
