"""
IMMUNEX Markov Predictor
========================
Probabilistic next-attack-stage prediction using a first-order Markov chain.

The transition matrix is built from observed stage sequences in the attack graph.
Each time a new stage is observed following a previous stage, the corresponding
matrix cell is incremented and the row re-normalised.

At prediction time, given the most recently observed stage, the engine returns:
  - predicted_stage    : str   – highest-probability next stage
  - probability_dist   : dict  – {stage_name: probability} for all stages
  - confidence_score   : float – max probability (how decisive the prediction is)
  - entropy            : float – Shannon entropy of the distribution

No external ML libraries are used — only numpy.
"""

from __future__ import annotations

import numpy as np
from typing import Optional

from utils.logger import log

# ─── Kill-Chain Stage Index ───────────────────────────────────────────────────

STAGES: list[str] = [
    "Reconnaissance",
    "Credential_Access",
    "Lateral_Movement",
    "Execution",
    "Persistence",
    "Privilege_Escalation",
    "Exfiltration",
]

STAGE_INDEX: dict[str, int] = {s: i for i, s in enumerate(STAGES)}
N_STAGES = len(STAGES)

# Prior: attackers statistically tend to progress forward
# Seeded with weak domain knowledge so cold-start predictions are sensible
_DEFAULT_PRIOR = np.array(
    [
        #  Rec   CA   LM   Exe  Per  PE   Exf
        [0.05, 0.50, 0.20, 0.10, 0.05, 0.05, 0.05],  # Reconnaissance
        [0.05, 0.05, 0.50, 0.25, 0.10, 0.05, 0.00],  # Credential_Access
        [0.05, 0.05, 0.10, 0.40, 0.20, 0.15, 0.05],  # Lateral_Movement
        [0.05, 0.05, 0.05, 0.10, 0.35, 0.20, 0.20],  # Execution
        [0.05, 0.05, 0.05, 0.10, 0.10, 0.30, 0.35],  # Persistence
        [0.05, 0.05, 0.05, 0.10, 0.05, 0.10, 0.60],  # Privilege_Escalation
        [0.10, 0.05, 0.05, 0.05, 0.05, 0.05, 0.65],  # Exfiltration (terminal)
    ],
    dtype=np.float64,
)


class MarkovPredictor:
    """
    First-order Markov chain for attack-stage prediction.

    The transition matrix T[i, j] holds the (smoothed) probability of
    transitioning from stage i to stage j.

    Laplace smoothing is applied to avoid zero-probability traps.
    """

    def __init__(
        self,
        smoothing: float = 1.0,
        prior_weight: float = 5.0,
    ) -> None:
        """
        Args:
            smoothing     : Laplace smoothing constant (added to each cell).
            prior_weight  : Weight of domain-knowledge prior vs observed data.
        """
        self._smoothing = smoothing
        # Raw frequency counts; initialised with weighted prior
        self._counts: np.ndarray = _DEFAULT_PRIOR * prior_weight + smoothing
        self._total_transitions: int = 0
        self._stage_observations: dict[str, int] = {s: 0 for s in STAGES}
        log.info("MarkovPredictor initialised", stages=N_STAGES, smoothing=smoothing)

    # ── Learning ──────────────────────────────────────────────────────────────

    def observe_transition(self, from_stage: str, to_stage: str) -> None:
        """
        Record an observed stage transition and update the matrix.

        Args:
            from_stage : Stage that was just completed.
            to_stage   : Stage that is now being observed.
        """
        if from_stage not in STAGE_INDEX or to_stage not in STAGE_INDEX:
            log.warning(
                "MarkovPredictor: unknown stage in transition",
                from_stage=from_stage,
                to_stage=to_stage,
            )
            return

        i = STAGE_INDEX[from_stage]
        j = STAGE_INDEX[to_stage]
        self._counts[i, j] += 1.0
        self._total_transitions += 1
        self._stage_observations[from_stage] += 1
        log.debug("Markov: transition observed", frm=from_stage, to=to_stage)

    def observe_sequence(self, stages: list[str]) -> None:
        """Record all consecutive transitions in a stage sequence."""
        for i in range(len(stages) - 1):
            self.observe_transition(stages[i], stages[i + 1])

    # ── Prediction ────────────────────────────────────────────────────────────

    def predict(self, current_stage: str) -> dict:
        """
        Predict the most likely next attack stage given the current stage.

        Args:
            current_stage : The attacker's most recently observed stage.

        Returns:
            {
                predicted_stage   : str,
                probability_dist  : {stage: float},
                confidence_score  : float,
                entropy           : float,
                current_stage     : str,
            }
        """
        if current_stage not in STAGE_INDEX:
            log.warning("MarkovPredictor: unknown current_stage", stage=current_stage)
            return self._unknown_stage_result(current_stage)

        idx = STAGE_INDEX[current_stage]
        row = self._counts[idx].copy()

        # Normalise to probability distribution
        total = row.sum()
        probs = row / total

        # Predicted next stage = argmax
        next_idx = int(np.argmax(probs))
        predicted_stage = STAGES[next_idx]

        # Shannon entropy (nats)
        entropy = float(-np.sum(probs * np.log(probs + 1e-12)))

        # Confidence = max probability (0 → uniform, 1 → deterministic)
        confidence = float(probs[next_idx])

        prob_dist = {stage: float(probs[i]) for i, stage in enumerate(STAGES)}

        log.debug(
            "MarkovPredictor: prediction",
            current=current_stage,
            predicted=predicted_stage,
            confidence=round(confidence, 4),
        )

        return {
            "predicted_stage":  predicted_stage,
            "probability_dist": prob_dist,
            "confidence_score": confidence,
            "entropy":          entropy,
            "current_stage":    current_stage,
        }

    def predict_sequence(
        self, current_stage: str, steps: int = 3
    ) -> list[dict]:
        """
        Predict the next `steps` most likely stages using greedy Markov rollout.

        Returns a list of prediction dicts (one per step).
        """
        results: list[dict] = []
        stage = current_stage
        for _ in range(steps):
            pred = self.predict(stage)
            results.append(pred)
            stage = pred["predicted_stage"]
        return results

    def get_transition_matrix(self) -> np.ndarray:
        """Return the row-normalised transition probability matrix."""
        row_sums = self._counts.sum(axis=1, keepdims=True)
        return self._counts / row_sums

    def get_stage_distribution(self) -> dict[str, float]:
        """
        Return the stationary (long-run) distribution over stages.
        Computed as the left eigenvector corresponding to eigenvalue 1.
        """
        P = self.get_transition_matrix()
        # Left eigenvectors: solve π P = π  →  (P^T) v = v
        eigenvalues, eigenvectors = np.linalg.eig(P.T)
        # Find eigenvector for eigenvalue closest to 1
        idx = int(np.argmin(np.abs(eigenvalues - 1.0)))
        stationary = np.real(eigenvectors[:, idx])
        stationary = np.abs(stationary)
        stationary /= stationary.sum()
        return {stage: float(stationary[i]) for i, stage in enumerate(STAGES)}

    def stats(self) -> dict:
        return {
            "total_transitions": self._total_transitions,
            "stage_observations": dict(self._stage_observations),
            "matrix_shape": list(self._counts.shape),
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _unknown_stage_result(self, stage: str) -> dict:
        uniform = 1.0 / N_STAGES
        return {
            "predicted_stage":  STAGES[0],
            "probability_dist": {s: uniform for s in STAGES},
            "confidence_score": uniform,
            "entropy":          float(np.log(N_STAGES)),
            "current_stage":    stage,
        }
