"""
IMMUNEX Vector Engine
======================
FAISS CPU-based nearest-neighbour vector similarity engine.

Responsibilities:
- Build and persist a FAISS IndexFlatL2 index of baseline normal vectors
- Query incoming feature vectors at runtime
- Return L2 distance scores to nearest neighbours
- Determine whether distance exceeds deviation threshold

Index type: IndexFlatL2
- Exact (not approximate) nearest-neighbour search
- CPU-only (faiss-cpu)
- Deterministic results
- Suitable for feature dimensions up to ~1000 at low latency

Baseline ingestion:
- Normal-traffic FeatureVectors are added at start-up
- Index is persisted to disk and reloaded on subsequent runs
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import faiss
import numpy as np

from config import VectorEngineConfig, get_config
from utils.constants import FEATURE_DIM
from utils.logger import log
from utils.schemas import FAISSResult, FeatureVector


class VectorEngine:
    """
    Manages a FAISS IndexFlatL2 for real-time vector deviation scoring.

    Usage::

        engine = VectorEngine()
        engine.build_baseline(normal_vectors)
        engine.save_index()

        # At query time:
        result = engine.query(feature_vector)
        if result.threshold_breached:
            route_to_alert(...)
    """

    def __init__(self, cfg: Optional[VectorEngineConfig] = None) -> None:
        self._cfg: VectorEngineConfig = cfg or get_config().vector
        self._index: Optional[faiss.IndexFlatL2] = None
        self._baseline_count: int = 0
        log.info("VectorEngine initialised", dim=self._cfg.feature_dim,
                 threshold=self._cfg.faiss_distance_threshold)

    # ── Index Lifecycle ───────────────────────────────────────────────────────

    def build_baseline(self, vectors: list[FeatureVector] | np.ndarray) -> None:
        """
        Construct a fresh FAISS index and add baseline normal vectors.

        Args:
            vectors: Either a list of FeatureVector objects or a pre-built
                     float32 matrix of shape (N, FEATURE_DIM).
        """
        dim = self._cfg.feature_dim

        if isinstance(vectors, np.ndarray):
            X = vectors.astype(np.float32)
        else:
            if not vectors:
                raise ValueError("Cannot build baseline from empty vector list.")
            X = np.vstack([v.to_numpy() for v in vectors]).astype(np.float32)

        if X.ndim != 2 or X.shape[1] != dim:
            raise ValueError(
                f"Expected vectors of shape (N, {dim}), got {X.shape}"
            )

        # Ensure contiguous memory layout (FAISS requirement)
        X = np.ascontiguousarray(X, dtype=np.float32)

        self._index = faiss.IndexFlatL2(dim)
        self._index.add(X)
        self._baseline_count = self._index.ntotal

        log.info("FAISS baseline index built",
                 n_vectors=self._baseline_count, dim=dim)

    def add_vectors(self, vectors: list[FeatureVector] | np.ndarray) -> None:
        """Append additional vectors to the existing index (online learning)."""
        self._assert_index_ready()
        if isinstance(vectors, np.ndarray):
            X = np.ascontiguousarray(vectors.astype(np.float32))
        else:
            X = np.ascontiguousarray(
                np.vstack([v.to_numpy() for v in vectors]).astype(np.float32)
            )
        assert self._index is not None
        self._index.add(X)
        self._baseline_count = self._index.ntotal
        log.debug("Vectors added to FAISS index", total=self._baseline_count)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save_index(self, path: Optional[Path] = None) -> Path:
        """Write the FAISS index to disk."""
        self._assert_index_ready()
        target = path or self._cfg.index_path
        target.parent.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self._index, str(target))
        log.info("FAISS index saved", path=str(target),
                 n_vectors=self._baseline_count)
        return target

    def load_index(self, path: Optional[Path] = None) -> None:
        """Load a FAISS index from disk."""
        target = path or self._cfg.index_path
        if not target.exists():
            raise FileNotFoundError(f"FAISS index not found: {target}")
        self._index = faiss.read_index(str(target))
        self._baseline_count = self._index.ntotal
        log.info("FAISS index loaded", path=str(target),
                 n_vectors=self._baseline_count)

    def is_ready(self) -> bool:
        return self._index is not None and self._baseline_count > 0

    # ── Query ─────────────────────────────────────────────────────────────────

    def query(self, fv: FeatureVector) -> FAISSResult:
        """
        Query the index for the top-k nearest neighbours of a FeatureVector.

        Returns:
            FAISSResult with:
            - nearest_distance: L2 distance to closest baseline vector
            - distances: list of top-k distances
            - threshold_breached: True if nearest_distance > configured threshold
        """
        self._assert_index_ready()
        vec = np.ascontiguousarray(
            fv.to_numpy().reshape(1, -1).astype(np.float32)
        )
        return self._run_query(fv.event_id, vec)

    def query_numpy(self, event_id: str, vec: np.ndarray) -> FAISSResult:
        """
        Query the index with a raw float32 numpy array (shape: [FEATURE_DIM]).
        """
        self._assert_index_ready()
        arr = np.ascontiguousarray(
            vec.reshape(1, -1).astype(np.float32)
        )
        return self._run_query(event_id, arr)

    def query_batch(self, fvs: list[FeatureVector]) -> list[FAISSResult]:
        """Batch query for efficiency."""
        self._assert_index_ready()
        if not fvs:
            return []
        X = np.ascontiguousarray(
            np.vstack([fv.to_numpy() for fv in fvs]).astype(np.float32)
        )
        k = min(self._cfg.top_k, self._baseline_count)
        assert self._index is not None
        distances, _ = self._index.search(X, k)

        results: list[FAISSResult] = []
        for i, fv in enumerate(fvs):
            row_dists = distances[i].tolist()
            nearest = float(distances[i][0])
            results.append(FAISSResult(
                event_id=fv.event_id,
                nearest_distance=nearest,
                distances=row_dists,
                threshold_breached=nearest > self._cfg.faiss_distance_threshold,
            ))
        return results

    # ── Private ───────────────────────────────────────────────────────────────

    def _run_query(self, event_id: str, vec: np.ndarray) -> FAISSResult:
        """Internal query execution."""
        assert self._index is not None
        k = min(self._cfg.top_k, self._baseline_count)
        if k == 0:
            return FAISSResult(
                event_id=event_id,
                nearest_distance=0.0,
                distances=[0.0],
                threshold_breached=False,
            )
        distances, _ = self._index.search(vec, k)
        dist_list = distances[0].tolist()
        nearest = float(dist_list[0]) if dist_list else 0.0
        return FAISSResult(
            event_id=event_id,
            nearest_distance=nearest,
            distances=dist_list,
            threshold_breached=nearest > self._cfg.faiss_distance_threshold,
        )

    def _assert_index_ready(self) -> None:
        if self._index is None or self._baseline_count == 0:
            raise RuntimeError(
                "VectorEngine index is not ready. "
                "Call build_baseline() or load_index() first."
            )
