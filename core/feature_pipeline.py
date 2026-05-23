"""
IMMUNEX Feature Pipeline
=========================
Transforms raw SecurityEvent objects into fixed-size 10-dimensional
FeatureVector objects suitable for IsolationForest and FAISS.

Pipeline steps:
1. Extract numeric telemetry from the event
2. Apply log1p normalisation to byte/count fields
3. Compute sliding-window event frequency (events/second)
4. Compute inter-event timing (seconds between consecutive events)
5. Encode categorical fields (protocol, event_type) as integers
6. Return FeatureVector(event_id, timestamp, f0..f9)
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from typing import Optional

import numpy as np

from config import get_config
from utils.constants import EVENT_TYPE_MAP, FEATURE_NAMES, PROTOCOL_MAP
from utils.helpers import clamp, new_event_id, safe_log1p, utcnow
from utils.logger import log
from utils.schemas import FeatureVector, SecurityEvent


class FeaturePipeline:
    """
    Stateful feature extractor that tracks recent event history to compute
    frequency and inter-event-interval features.

    The pipeline is designed to be called once per event in arrival order.
    It is NOT thread-safe; use one instance per worker coroutine.
    """

    def __init__(self, window_seconds: float = 10.0) -> None:
        """
        Args:
            window_seconds: Time window used for event-frequency calculation.
        """
        self._window_seconds = window_seconds
        # Stores (unix_timestamp) of recent events for frequency calculation
        self._event_times: deque[float] = deque(maxlen=10_000)
        self._last_event_ts: Optional[float] = None
        log.debug("FeaturePipeline initialised", window_seconds=window_seconds)

    # ── Public API ────────────────────────────────────────────────────────────

    def transform(self, event: SecurityEvent) -> FeatureVector:
        """
        Extract a 10-dimensional FeatureVector from a SecurityEvent.

        Returns:
            FeatureVector with all features normalised.
        """
        ts_unix = event.timestamp.timestamp()

        # ── Frequency & Interval ──────────────────────────────────────────────
        event_frequency = self._compute_frequency(ts_unix)
        event_interval = self._compute_interval(ts_unix)

        # Update state
        self._event_times.append(ts_unix)
        self._last_event_ts = ts_unix

        # ── Numeric Telemetry ─────────────────────────────────────────────────
        src_bytes_norm = safe_log1p(float(event.src_bytes))
        dst_bytes_norm = safe_log1p(float(event.dst_bytes))
        duration_norm = safe_log1p(float(event.duration))
        packet_rate_norm = safe_log1p(float(event.packet_rate))
        connection_count_norm = safe_log1p(float(event.connection_count))
        failed_logins_norm = safe_log1p(float(event.failed_logins))

        # ── Categorical Encoding ──────────────────────────────────────────────
        protocol_enc = float(
            PROTOCOL_MAP.get(event.protocol.upper(), len(PROTOCOL_MAP))
        )
        event_type_enc = float(
            EVENT_TYPE_MAP.get(event.event_type, 99)
        )

        return FeatureVector(
            event_id=new_event_id(),
            timestamp=event.timestamp,
            src_bytes=src_bytes_norm,
            dst_bytes=dst_bytes_norm,
            duration=duration_norm,
            packet_rate=packet_rate_norm,
            connection_count=connection_count_norm,
            failed_logins=failed_logins_norm,
            event_frequency=safe_log1p(event_frequency),
            event_interval=safe_log1p(event_interval),
            protocol_encoding=protocol_enc,
            event_type_encoding=event_type_enc,
        )

    def transform_batch(self, events: list[SecurityEvent]) -> list[FeatureVector]:
        """Transform a batch of events in order."""
        return [self.transform(e) for e in events]

    def to_matrix(self, feature_vectors: list[FeatureVector]) -> np.ndarray:
        """
        Stack a list of FeatureVectors into a 2D float32 numpy matrix.

        Returns:
            np.ndarray of shape (N, 10)
        """
        if not feature_vectors:
            return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)
        return np.vstack([fv.to_numpy() for fv in feature_vectors]).astype(np.float32)

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _compute_frequency(self, ts_unix: float) -> float:
        """
        Compute how many events have occurred in the last `window_seconds`.
        Returns events-per-second rate.
        """
        window_start = ts_unix - self._window_seconds
        recent_count = sum(1 for t in self._event_times if t >= window_start)
        # Rate = count / window_duration (avoid division by zero)
        return float(recent_count) / max(self._window_seconds, 1e-6)

    def _compute_interval(self, ts_unix: float) -> float:
        """
        Compute seconds since the last event.
        Returns 0.0 on the first call.
        """
        if self._last_event_ts is None:
            return 0.0
        interval = ts_unix - self._last_event_ts
        return clamp(interval, 0.0, 3600.0)  # cap at 1 hour
