"""
IMMUNEX Helper Utilities
Reusable functions for IP generation, hashing, ID creation, and severity mapping.
"""

from __future__ import annotations

import hashlib
import random
import string
import uuid
from datetime import datetime
from typing import Optional

import numpy as np

from utils.constants import (
    ASSET_CRITICALITY_LEVELS,
    ASSET_CRITICALITY_SCORE,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)


# ─── IP Helpers ───────────────────────────────────────────────────────────────

def random_internal_ip(rng: Optional[random.Random] = None) -> str:
    """Generate a random RFC-1918 internal IP (10.x.x.x)."""
    r = rng or random
    return f"10.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"


def random_external_ip(rng: Optional[random.Random] = None) -> str:
    """Generate a random routable external IP (excluding RFC-1918 ranges)."""
    r = rng or random
    while True:
        a = r.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        b = r.randint(0, 255)
        c = r.randint(0, 255)
        d = r.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


# ─── Hash Helpers ─────────────────────────────────────────────────────────────

def fake_sha256(seed: str) -> str:
    """Deterministic SHA-256 hex from a seed string."""
    return hashlib.sha256(seed.encode()).hexdigest()


def random_sha256(rng: Optional[random.Random] = None) -> str:
    """Non-deterministic random SHA-256 hex string."""
    r = rng or random
    raw = "".join(r.choices(string.hexdigits, k=128))
    return hashlib.sha256(raw.encode()).hexdigest()


# ─── ID Helpers ──────────────────────────────────────────────────────────────

def new_event_id() -> str:
    """Return a short unique event identifier."""
    return uuid.uuid4().hex[:16].upper()


def new_chain_id() -> str:
    """Return a unique attack-chain identifier."""
    return f"CHAIN-{uuid.uuid4().hex[:8].upper()}"


# ─── Severity Mapping ────────────────────────────────────────────────────────

def compute_severity(
    anomaly_score: float,
    faiss_distance: float,
    asset_criticality: str,
    is_high_confidence: bool,
) -> str:
    """
    Map composite signals to a severity label.

    Severity escalation logic:
    - Base severity derived from anomaly_score
    - Escalated by FAISS deviation
    - Further escalated by asset criticality
    """
    crit_boost = ASSET_CRITICALITY_SCORE.get(asset_criticality, 1) - 1

    if not is_high_confidence:
        if anomaly_score < 0.3:
            base = 0  # INFO
        else:
            base = 1  # LOW
    else:
        if anomaly_score < 0.6:
            base = 2  # MEDIUM
        elif anomaly_score < 0.8:
            base = 3  # HIGH
        else:
            base = 4  # CRITICAL

    # FAISS distance boost
    if faiss_distance > 100.0:
        base = min(base + 2, 4)
    elif faiss_distance > 50.0:
        base = min(base + 1, 4)

    # Asset criticality boost
    base = min(base + crit_boost, 4)

    severity_map = {0: SEVERITY_INFO, 1: SEVERITY_LOW, 2: SEVERITY_MEDIUM,
                    3: SEVERITY_HIGH, 4: SEVERITY_CRITICAL}
    return severity_map[base]


# ─── Feature Normalisation Helpers ───────────────────────────────────────────

def safe_log1p(x: float) -> float:
    """Apply log1p with a floor at 0 to avoid log of negative numbers."""
    return float(np.log1p(max(0.0, x)))


def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp value within [lo, hi]."""
    return max(lo, min(hi, value))


# ─── Time Helpers ─────────────────────────────────────────────────────────────

def utcnow() -> datetime:
    """Return timezone-naive UTC datetime (consistent throughout the project)."""
    return datetime.utcnow()
