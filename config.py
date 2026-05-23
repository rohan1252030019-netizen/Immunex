"""
IMMUNEX Configuration Module
Centralizes all runtime parameters for all four layers.
"""

from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional


BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
MODELS_DIR  = DATA_DIR / "models"
LOGS_DIR    = DATA_DIR / "logs"
VECTORS_DIR = DATA_DIR / "baseline_vectors"
MEMORY_DIR  = DATA_DIR / "memory"
DRIFT_DIR   = DATA_DIR / "drift"
RETRAIN_DIR = DATA_DIR / "retrain_archive"

for _d in [DATA_DIR, MODELS_DIR, LOGS_DIR, VECTORS_DIR, MEMORY_DIR, DRIFT_DIR, RETRAIN_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


class StreamConfig(BaseModel):
    events_per_second:  float        = Field(default=5.0,  ge=0.1, le=1000.0)
    malicious_ratio:    float        = Field(default=0.15, ge=0.0, le=1.0)
    burst_probability:  float        = Field(default=0.05, ge=0.0, le=1.0)
    burst_multiplier:   int          = Field(default=10,   ge=1,   le=100)
    seed:               Optional[int] = Field(default=42)


class AnomalyEngineConfig(BaseModel):
    n_estimators:            int        = Field(default=200,  ge=50,  le=1000)
    contamination:           float      = Field(default=0.1,  ge=0.01, le=0.5)
    max_samples:             str | int  = Field(default="auto")
    random_state:            int        = Field(default=42)
    anomaly_score_threshold: float      = Field(default=0.55, ge=0.0, le=1.0)
    model_path:              Path       = Field(default=MODELS_DIR / "isolation_forest.joblib")
    warmup_samples:          int        = Field(default=500, ge=100)


class VectorEngineConfig(BaseModel):
    feature_dim:              int   = Field(default=10)
    index_path:               Path  = Field(default=VECTORS_DIR / "faiss_baseline.index")
    baseline_samples:         int   = Field(default=1000, ge=100)
    faiss_distance_threshold: float = Field(default=25.0, ge=0.0)
    top_k:                    int   = Field(default=5,    ge=1, le=100)


class LoggingConfig(BaseModel):
    log_file:    Path = Field(default=LOGS_DIR / "immunex.log")
    rotation:    str  = Field(default="50 MB")
    retention:   str  = Field(default="7 days")
    compression: str  = Field(default="gz")
    level:       str  = Field(default="DEBUG")
    json_logs:   bool = Field(default=True)


class Layer3Config(BaseModel):
    ollama_base_url:        str       = Field(default="http://localhost:11434")
    ollama_timeout_seconds: int       = Field(default=120, ge=10, le=600)
    ollama_max_retries:     int       = Field(default=3,   ge=1,  le=10)
    enable_playbook:        bool      = Field(default=True)
    enable_ollama:          bool      = Field(default=True)
    preferred_models: list[str]       = Field(
        default=[
            "mistral:7b-instruct-q4_K_M",
            "mistral",
            "llama3:8b-instruct-q4_K_M",
            "phi3:mini",
            "deepseek-coder",
        ]
    )


class Layer4Config(BaseModel):
    """Layer 4 — Adaptive Immunization configuration."""
    enable_auto_retrain:       bool  = Field(default=True)
    blind_spot_retrain_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    drift_retrain_threshold:   float = Field(default=0.35, ge=0.0, le=1.0)
    blind_spot_check_every_n_campaigns: int = Field(default=20, ge=1)
    drift_check_every_n_decisions:      int = Field(default=500, ge=50)
    mutation_batch_size:       int   = Field(default=100, ge=10, le=1000)
    n_baseline_training_samples: int = Field(default=1000, ge=100)
    memory_retention_days:     int   = Field(default=90, ge=1)
    api_host:                  str   = Field(default="0.0.0.0")
    api_port:                  int   = Field(default=8080, ge=1024, le=65535)


class IMMUNEXConfig(BaseModel):
    stream:              StreamConfig      = Field(default_factory=StreamConfig)
    anomaly:             AnomalyEngineConfig = Field(default_factory=AnomalyEngineConfig)
    vector:              VectorEngineConfig  = Field(default_factory=VectorEngineConfig)
    logging:             LoggingConfig       = Field(default_factory=LoggingConfig)
    layer3:              Layer3Config        = Field(default_factory=Layer3Config)
    layer4:              Layer4Config        = Field(default_factory=Layer4Config)
    dashboard_refresh_hz: float = Field(default=2.0, ge=0.5, le=60.0)
    high_confidence_threshold_combo: bool = Field(default=True)


_CONFIG: Optional[IMMUNEXConfig] = None


def get_config() -> IMMUNEXConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = IMMUNEXConfig()
    return _CONFIG


def override_config(cfg: IMMUNEXConfig) -> None:
    global _CONFIG
    _CONFIG = cfg
