"""
IMMUNEX Data Schemas
Pydantic v2 models representing all data flowing through the Innate Immunity Layer.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime
from typing import Optional, Literal

import numpy as np
from pydantic import BaseModel, Field, field_validator, model_validator


# ─── Raw Security Event ───────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    """
    Represents a single raw security event as ingested from SIEM/EDR sources.
    Schema inspired by NSL-KDD and UNSW-NB15 datasets.
    """
    model_config = {"arbitrary_types_allowed": True}

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    user_id: str
    process_name: str
    process_hash: str
    event_type: str
    src_bytes: int = Field(ge=0)
    dst_bytes: int = Field(ge=0)
    duration: float = Field(ge=0.0)
    failed_logins: int = Field(ge=0)
    connection_count: int = Field(ge=0)
    packet_rate: float = Field(ge=0.0)
    geo_location: str
    asset_criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @field_validator("process_hash")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError(f"process_hash must be a 64-char SHA-256 hex string, got length {len(v)}")
        return v.lower()

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address: {v}")
        for part in parts:
            if not (0 <= int(part) <= 255):
                raise ValueError(f"IP octet out of range: {part}")
        return v

    def to_dict(self) -> dict:
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ─── Normalised Feature Vector ────────────────────────────────────────────────

class FeatureVector(BaseModel):
    """
    Fixed-size 10-dimensional feature vector derived from a SecurityEvent.
    Used as input to the IsolationForest and FAISS engines.
    """
    model_config = {"arbitrary_types_allowed": True}

    event_id: str
    timestamp: datetime
    src_bytes: float
    dst_bytes: float
    duration: float
    packet_rate: float
    connection_count: float
    failed_logins: float
    event_frequency: float
    event_interval: float
    protocol_encoding: float
    event_type_encoding: float

    def to_numpy(self) -> np.ndarray:
        """Return the feature values as a float32 numpy array (shape: [10])."""
        return np.array(
            [
                self.src_bytes,
                self.dst_bytes,
                self.duration,
                self.packet_rate,
                self.connection_count,
                self.failed_logins,
                self.event_frequency,
                self.event_interval,
                self.protocol_encoding,
                self.event_type_encoding,
            ],
            dtype=np.float32,
        )


# ─── Anomaly Detection Result ─────────────────────────────────────────────────

class AnomalyResult(BaseModel):
    """Output from the IsolationForest scoring pipeline."""
    event_id: str
    anomaly_score: float = Field(ge=0.0, le=1.0)
    anomaly_label: int = Field(description="-1=anomaly, 1=normal (sklearn convention)")
    confidence_score: float = Field(ge=0.0, le=1.0)
    threshold_breached: bool

    @property
    def is_anomaly(self) -> bool:
        return self.anomaly_label == -1


# ─── FAISS Query Result ───────────────────────────────────────────────────────

class FAISSResult(BaseModel):
    """Output from the FAISS nearest-neighbour lookup."""
    event_id: str
    nearest_distance: float = Field(ge=0.0)
    distances: list[float]
    threshold_breached: bool


# ─── Combined Detection Decision ─────────────────────────────────────────────

class DetectionDecision(BaseModel):
    """
    Final routing decision after combining IsolationForest and FAISS signals.
    """
    event_id: str
    timestamp: datetime
    event_type: str
    src_ip: str
    dst_ip: str
    asset_criticality: str
    anomaly_score: float
    faiss_distance: float
    confidence_score: float
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    is_high_confidence_anomaly: bool
    detection_reason: str
    # Raw event reference
    raw_event: Optional[SecurityEvent] = None

    # Phase 3 & 4 Additive Fields
    consensus_score: Optional[float] = None
    mitre_tactic: Optional[str] = None
    predicted_attack_chain: Optional[list[str]] = None
    confidence_breakdown: Optional[dict[str, float]] = None
    suppression_reason: Optional[str] = None
    recommended_mitigation: Optional[str] = None
    blast_radius_estimate: Optional[float] = None

    attack_path: Optional[list[str]] = None
    crown_jewel_target: Optional[str] = None
    blast_radius_score: Optional[float] = None
    privilege_risk_score: Optional[float] = None
    lateral_movement_probability: Optional[float] = None
    graph_risk_score: Optional[float] = None

    def to_display_row(self) -> dict:
        return {
            "timestamp": self.timestamp.strftime("%H:%M:%S.%f")[:-3],
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "anomaly_score": f"{self.anomaly_score:.4f}",
            "faiss_distance": f"{self.faiss_distance:.4f}",
            "severity": self.severity,
            "detection_reason": self.detection_reason,
        }


# ─── Attack Chain Context ─────────────────────────────────────────────────────

class AttackChain(BaseModel):
    """Represents a multi-stage attack chain being generated by the simulator."""
    chain_id: str
    attacker_ip: str
    target_ip: str
    stage: int = Field(default=0, ge=0, le=4)
    stages_completed: list[str] = Field(default_factory=list)
    active: bool = True

    def advance(self, stage_name: str) -> None:
        self.stages_completed.append(stage_name)
        self.stage += 1
        if self.stage >= 5:
            self.active = False
