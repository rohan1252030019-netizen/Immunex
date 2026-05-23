"""
IMMUNEX Mutation Engine
========================
Layer 4: Synthetic adversarial attack mutation generator.

Generates polymorphic attack variants to stress-test the anomaly detection
pipeline and identify blind spots before real attackers do.

Mutation types:
  - Polymorphic attack variants (randomised feature perturbations)
  - Stealth telemetry mutations (sub-threshold evasion)
  - Protocol abuse simulations (protocol field anomalies)
  - Randomised behavioural deviations (timing/frequency jitter)
  - Synthetic insider threats (low-anomaly-score malicious events)
  - Mutated lateral movement sequences (graph-aware campaign simulation)
  - Adaptive exfiltration patterns (data-volume obfuscation)
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

import numpy as np

from utils.constants import (
    FEATURE_DIM,
    FEATURE_NAMES,
    MALICIOUS_EVENT_TYPES,
    MALICIOUS_PROCESSES,
    PROTOCOL_MAP,
    EVENT_TYPE_MAP,
    GEO_LOCATIONS,
)
from utils.logger import log
from utils.schemas import FeatureVector, SecurityEvent


# ─── Mutation Types ───────────────────────────────────────────────────────────

class MutationType(str, Enum):
    POLYMORPHIC       = "polymorphic"
    STEALTH           = "stealth"
    PROTOCOL_ABUSE    = "protocol_abuse"
    BEHAVIOURAL_DRIFT = "behavioural_drift"
    INSIDER_THREAT    = "insider_threat"
    LATERAL_MOVEMENT  = "lateral_movement"
    EXFILTRATION      = "exfiltration"


@dataclass
class MutationResult:
    mutation_id:     str
    mutation_type:   MutationType
    feature_vector:  np.ndarray          # shape (FEATURE_DIM,)
    raw_event:       dict
    evasion_score:   float               # 0=obvious, 1=perfectly stealthy
    expected_bypass: bool                # predicted to bypass detection
    description:     str
    created_at:      datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "mutation_id":     self.mutation_id,
            "mutation_type":   self.mutation_type.value,
            "evasion_score":   round(self.evasion_score, 4),
            "expected_bypass": self.expected_bypass,
            "description":     self.description,
            "created_at":      self.created_at.isoformat(),
            "feature_vector":  self.feature_vector.tolist(),
        }


# ─── Mutation Engine ──────────────────────────────────────────────────────────

class MutationEngine:
    """
    Generates synthetic zero-day attack mutations for pipeline stress testing.

    Usage::

        engine = MutationEngine(anomaly_threshold=0.55, faiss_threshold=25.0)
        mutations = engine.generate_batch(n=50)
        for m in mutations:
            if m.expected_bypass:
                log.warning("Blind spot candidate", mutation_id=m.mutation_id)
    """

    # Typical baseline feature ranges (from StreamEngine normal traffic)
    _NORMAL_RANGES: dict[str, tuple[float, float]] = {
        "src_bytes":           (500.0,    5_000.0),
        "dst_bytes":           (200.0,    3_000.0),
        "duration":            (0.1,      5.0),
        "packet_rate":         (10.0,     200.0),
        "connection_count":    (1.0,      20.0),
        "failed_logins":       (0.0,      1.0),
        "event_frequency":     (0.5,      3.0),
        "event_interval":      (0.3,      2.0),
        "protocol_encoding":   (0.0,      5.0),
        "event_type_encoding": (0.0,      5.0),
    }

    _ATTACK_RANGES: dict[str, tuple[float, float]] = {
        "src_bytes":           (50_000.0, 500_000.0),
        "dst_bytes":           (100.0,    500.0),
        "duration":            (0.001,    0.05),
        "packet_rate":         (500.0,    5_000.0),
        "connection_count":    (50.0,     500.0),
        "failed_logins":       (5.0,      50.0),
        "event_frequency":     (10.0,     100.0),
        "event_interval":      (0.001,    0.05),
        "protocol_encoding":   (6.0,      7.0),
        "event_type_encoding": (10.0,     51.0),
    }

    def __init__(
        self,
        anomaly_threshold: float = 0.55,
        faiss_threshold:   float = 25.0,
        seed:              Optional[int] = None,
    ) -> None:
        self._anomaly_threshold = anomaly_threshold
        self._faiss_threshold   = faiss_threshold
        self._rng               = random.Random(seed)
        self._np_rng            = np.random.default_rng(seed)
        self._mutation_count    = 0
        log.info(
            "MutationEngine initialised",
            anomaly_threshold=anomaly_threshold,
            faiss_threshold=faiss_threshold,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_batch(
        self,
        n: int = 50,
        mutation_types: Optional[list[MutationType]] = None,
    ) -> list[MutationResult]:
        """Generate n synthetic attack mutations."""
        types = mutation_types or list(MutationType)
        results = []
        for _ in range(n):
            mtype = self._rng.choice(types)
            result = self._generate_single(mtype)
            results.append(result)
            self._mutation_count += 1
        log.info("MutationEngine batch generated", n=n, types=[t.value for t in types])
        return results

    def generate_single(self, mutation_type: MutationType) -> MutationResult:
        self._mutation_count += 1
        return self._generate_single(mutation_type)

    def stats(self) -> dict:
        return {"total_mutations_generated": self._mutation_count}

    # ── Internal Generators ───────────────────────────────────────────────────

    def _generate_single(self, mtype: MutationType) -> MutationResult:
        dispatch = {
            MutationType.POLYMORPHIC:       self._polymorphic,
            MutationType.STEALTH:           self._stealth,
            MutationType.PROTOCOL_ABUSE:    self._protocol_abuse,
            MutationType.BEHAVIOURAL_DRIFT: self._behavioural_drift,
            MutationType.INSIDER_THREAT:    self._insider_threat,
            MutationType.LATERAL_MOVEMENT:  self._lateral_movement,
            MutationType.EXFILTRATION:      self._exfiltration,
        }
        return dispatch[mtype]()

    def _make_id(self) -> str:
        return f"MUT-{uuid.uuid4().hex[:12].upper()}"

    def _lerp(self, lo: float, hi: float, t: float) -> float:
        return lo + (hi - lo) * t

    def _blend_features(self, normal_weight: float) -> np.ndarray:
        """Blend normal and attack feature ranges by weight (0=pure attack, 1=pure normal)."""
        vec = np.zeros(FEATURE_DIM, dtype=np.float32)
        for i, name in enumerate(FEATURE_NAMES):
            nlo, nhi = self._NORMAL_RANGES[name]
            alo, ahi = self._ATTACK_RANGES[name]
            n_val = self._np_rng.uniform(nlo, nhi)
            a_val = self._np_rng.uniform(alo, ahi)
            vec[i] = float(normal_weight * n_val + (1 - normal_weight) * a_val)
        return vec

    def _evasion_score(self, normal_weight: float, noise: float = 0.0) -> float:
        return float(np.clip(normal_weight + self._np_rng.normal(0, noise), 0.0, 1.0))

    def _fake_ip(self) -> str:
        return f"{self._rng.randint(1,254)}.{self._rng.randint(0,254)}.{self._rng.randint(0,254)}.{self._rng.randint(1,254)}"

    def _fake_hash(self) -> str:
        return self._np_rng.bytes(32).hex()

    def _polymorphic(self) -> MutationResult:
        """Polymorphic: attack features randomised per mutation to evade signature matching."""
        # Random perturbation on classic attack pattern
        base = self._blend_features(normal_weight=0.1)
        # Add random noise to each feature independently
        noise = self._np_rng.normal(0, 0.15, size=FEATURE_DIM).astype(np.float32)
        vec = np.abs(base + base * noise)
        evasion = self._evasion_score(0.15, noise=0.1)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.POLYMORPHIC,
            feature_vector=vec,
            raw_event=self._make_raw_event("Port_Scan", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.4,
            description="Polymorphic port-scan with randomised inter-feature noise",
        )

    def _stealth(self) -> MutationResult:
        """Stealth: carefully crafted to sit just below detection thresholds."""
        # Mostly normal, tiny attack signal
        vec = self._blend_features(normal_weight=0.78)
        # Nudge key attack indicators just below threshold
        vec[FEATURE_NAMES.index("failed_logins")]    = float(self._np_rng.uniform(1.5, 2.5))
        vec[FEATURE_NAMES.index("connection_count")] = float(self._np_rng.uniform(18.0, 24.0))
        evasion = self._evasion_score(0.78, noise=0.05)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.STEALTH,
            feature_vector=vec,
            raw_event=self._make_raw_event("Brute_Force_Login", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.5,
            description="Sub-threshold stealth brute-force with minimal telemetry deviation",
        )

    def _protocol_abuse(self) -> MutationResult:
        """Protocol abuse: unusual protocol/port combinations to confuse normalisation."""
        vec = self._blend_features(normal_weight=0.45)
        # Force unusual protocol encodings (covert channel via DNS/ICMP)
        vec[FEATURE_NAMES.index("protocol_encoding")]   = float(self._rng.choice([2, 5]))  # ICMP or DNS
        vec[FEATURE_NAMES.index("event_type_encoding")] = float(EVENT_TYPE_MAP.get("DNS_Tunneling", 51))
        vec[FEATURE_NAMES.index("dst_bytes")]            = float(self._np_rng.uniform(4000, 8000))
        evasion = self._evasion_score(0.4, noise=0.12)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.PROTOCOL_ABUSE,
            feature_vector=vec,
            raw_event=self._make_raw_event("DNS_Tunneling", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.35,
            description="DNS-over-ICMP covert channel with high dst_bytes exfil pattern",
        )

    def _behavioural_drift(self) -> MutationResult:
        """Behavioural drift: slow timing/frequency deviation over extended window."""
        vec = self._blend_features(normal_weight=0.6)
        # Slowly increasing frequency and connection count
        drift_factor = float(self._np_rng.uniform(1.3, 2.5))
        vec[FEATURE_NAMES.index("event_frequency")]  *= drift_factor
        vec[FEATURE_NAMES.index("connection_count")] *= drift_factor
        vec[FEATURE_NAMES.index("event_interval")]    = float(self._np_rng.uniform(0.05, 0.2))
        evasion = self._evasion_score(0.55, noise=0.08)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.BEHAVIOURAL_DRIFT,
            feature_vector=vec,
            raw_event=self._make_raw_event("Network_Sweep", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.45,
            description=f"Slow-drift network sweep with {drift_factor:.1f}x frequency increase",
        )

    def _insider_threat(self) -> MutationResult:
        """Insider threat: legitimate user behaviour with subtle exfil indicators."""
        vec = self._blend_features(normal_weight=0.85)
        # Insider has normal login behaviour but unusual data transfer
        vec[FEATURE_NAMES.index("src_bytes")]         = float(self._np_rng.uniform(50_000, 200_000))
        vec[FEATURE_NAMES.index("failed_logins")]     = 0.0
        vec[FEATURE_NAMES.index("event_type_encoding")] = float(EVENT_TYPE_MAP.get("File_Access", 1))
        evasion = self._evasion_score(0.82, noise=0.06)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.INSIDER_THREAT,
            feature_vector=vec,
            raw_event=self._make_raw_event("Data_Exfiltration", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.6,
            description="Insider threat: normal auth pattern with anomalous bulk file transfer",
        )

    def _lateral_movement(self) -> MutationResult:
        """Lateral movement: sequential low-volume connections to multiple targets."""
        vec = self._blend_features(normal_weight=0.4)
        # Many short connections to diverse destinations
        vec[FEATURE_NAMES.index("connection_count")] = float(self._np_rng.uniform(40, 120))
        vec[FEATURE_NAMES.index("duration")]          = float(self._np_rng.uniform(0.01, 0.3))
        vec[FEATURE_NAMES.index("src_bytes")]         = float(self._np_rng.uniform(200, 800))
        vec[FEATURE_NAMES.index("event_type_encoding")] = float(EVENT_TYPE_MAP.get("PowerShell_Execution", 30))
        evasion = self._evasion_score(0.38, noise=0.1)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.LATERAL_MOVEMENT,
            feature_vector=vec,
            raw_event=self._make_raw_event("PowerShell_Execution", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.3,
            description="WMI-based lateral movement: many short PowerShell sessions",
        )

    def _exfiltration(self) -> MutationResult:
        """Adaptive exfiltration: data split across many small transfers."""
        vec = self._blend_features(normal_weight=0.5)
        # Split high-volume exfil into many small packets
        n_chunks = self._rng.randint(10, 50)
        per_chunk = float(self._np_rng.uniform(500, 2000))
        vec[FEATURE_NAMES.index("src_bytes")]         = per_chunk
        vec[FEATURE_NAMES.index("connection_count")]  = float(n_chunks)
        vec[FEATURE_NAMES.index("packet_rate")]        = float(self._np_rng.uniform(5, 30))
        vec[FEATURE_NAMES.index("event_type_encoding")] = float(EVENT_TYPE_MAP.get("Data_Exfiltration", 50))
        evasion = self._evasion_score(0.52, noise=0.09)
        return MutationResult(
            mutation_id=self._make_id(),
            mutation_type=MutationType.EXFILTRATION,
            feature_vector=vec,
            raw_event=self._make_raw_event("Data_Exfiltration", vec),
            evasion_score=evasion,
            expected_bypass=evasion > 0.42,
            description=f"Chunked exfil: {n_chunks} transfers of ~{per_chunk:.0f}B each",
        )

    def _make_raw_event(self, event_type: str, vec: np.ndarray) -> dict:
        return {
            "timestamp":       datetime.utcnow().isoformat(),
            "src_ip":          self._fake_ip(),
            "dst_ip":          self._fake_ip(),
            "src_port":        self._rng.randint(1024, 65535),
            "dst_port":        self._rng.randint(1, 1024),
            "protocol":        self._rng.choice(list(PROTOCOL_MAP.keys())),
            "user_id":         f"SYN_USER_{self._rng.randint(100, 999)}",
            "process_name":    self._rng.choice(MALICIOUS_PROCESSES),
            "process_hash":    self._fake_hash(),
            "event_type":      event_type,
            "src_bytes":       int(vec[0]),
            "dst_bytes":       int(vec[1]),
            "duration":        float(vec[2]),
            "packet_rate":     float(vec[3]),
            "connection_count": int(vec[4]),
            "failed_logins":   int(vec[5]),
            "geo_location":    self._rng.choice(GEO_LOCATIONS),
            "asset_criticality": self._rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        }
