"""
IMMUNEX Advanced AI Reasoning Engine Tests
=========================================
Verifies all sub-engines (Transformer, LSTM, GNN, ConfidenceFusion, FP Suppressor,
and ThresholdTuner), PyTorch incremental training, and backward compatibility.
"""

from __future__ import annotations

import pytest
from datetime import datetime

from utils.schemas import SecurityEvent, FeatureVector, DetectionDecision
from cyber_reasoning import (
    EnsembleReasoningSystem,
    TransformerThreatAnalyzer,
    LSTMSequenceAnalyzer,
    GNNAttackGraphClassifier,
    ConfidenceFusionEngine,
    FalsePositiveSuppressor,
    AdaptiveThresholdTuner,
)
from twin_engine import DigitalTwinEngine
from graph_analytics import AttackGraphAnalytics


# ─── Mock Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def sample_event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.utcnow(),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=4444,
        dst_port=80,
        protocol="TCP",
        user_id="john_doe",
        process_name="powershell.exe",
        process_hash="d2ba860475aa7e4e1a06707328905391a329cd55a90184b2e88a0bc72cd6e866",
        event_type="PowerShell_Execution",
        src_bytes=1024,
        dst_bytes=2048,
        duration=1.5,
        failed_logins=0,
        connection_count=5,
        packet_rate=12.5,
        geo_location="US-NY",
        asset_criticality="MEDIUM"
    )

@pytest.fixture
def sample_fv() -> FeatureVector:
    return FeatureVector(
        event_id="test_event_123",
        timestamp=datetime.utcnow(),
        src_bytes=0.8,
        dst_bytes=0.6,
        duration=0.5,
        packet_rate=0.7,
        connection_count=0.4,
        failed_logins=0.0,
        event_frequency=0.9,
        event_interval=0.2,
        protocol_encoding=0.3,
        event_type_encoding=0.8
    )


# ─── Sub-Engine Unit Tests ───────────────────────────────────────────────────

def test_transformer_threat_analyzer(sample_event):
    analyzer = TransformerThreatAnalyzer()
    
    # Benign execution
    benign_res = analyzer.classify_behavior("notepad.exe")
    assert benign_res["score"] == 0.0
    
    # Malicious Powershell with encoded payload
    malicious_cmd = "powershell.exe -NoP -NonI -W Hidden -Enc a2VlcF9ncm93aW5nX25ldHdvcmtzaF9pbl9wc3g="
    malicious_res = analyzer.classify_behavior(malicious_cmd)
    
    assert malicious_res["score"] >= 0.8
    assert "POWER_SHELL_ABUSE" in malicious_res["patterns"]
    assert "ENCODED_PAYLOAD" in malicious_res["patterns"]

    # Ransomware command
    ransom_res = analyzer.classify_behavior("vssadmin.exe delete shadows /all /quiet")
    assert ransom_res["score"] >= 0.9
    assert "RANSOMWARE_BEHAVIORS" in ransom_res["patterns"]

    # Sequence Scoring
    seq_score = analyzer.score_sequence(["whoami /priv", "powershell.exe -enc XXX", "vssadmin.exe delete shadows"])
    assert seq_score > 0.5


def test_lstm_sequence_analyzer(sample_fv):
    analyzer = LSTMSequenceAnalyzer()
    
    # Observe sequence window
    analyzer.observe_sequence(sample_fv)
    assert len(analyzer.event_window) == 1
    
    # Prediction on single window
    pred_res = analyzer.predict_next_stage()
    assert pred_res["predicted_next_stage"] in analyzer.stages
    assert 0.0 <= pred_res["confidence"] <= 1.0
    
    # Incremental training update directly on CPU
    loss = analyzer.train_incrementally([sample_fv, sample_fv], "Lateral_Movement")
    assert isinstance(loss, float)
    assert loss >= 0.0


def test_gnn_attack_graph_classifier(sample_event):
    twin = DigitalTwinEngine()
    analytics = AttackGraphAnalytics()
    gnn = GNNAttackGraphClassifier(twin, analytics)
    
    # Ingest event and update graph
    gnn.build_graph([sample_event])
    assert "192.168.1.10" in twin.graph
    
    # Path score to crown jewels
    path_res = gnn.calculate_attack_path_score("192.168.1.10")
    assert "blast_radius_score" in path_res
    assert "graph_risk_score" in path_res
    assert 0.0 <= path_res["graph_risk_score"] <= 1.0

    # Subgraph centrality scoring
    subgraph_score = gnn.classify_subgraph("192.168.1.10")
    assert 0.0 <= subgraph_score <= 1.0


def test_confidence_fusion_engine():
    engine = ConfidenceFusionEngine()
    
    scores = {
        "isolation_forest": 0.85,
        "faiss": 0.75,
        "transformer": 0.90,
        "lstm": 0.80,
        "gnn": 0.85,
        "markov": 0.70,
        "rl": 0.65
    }
    
    # Normal Fusion
    res = engine.fuse(scores, asset_criticality="MEDIUM")
    assert 0.0 <= res["consensus_score"] <= 1.0
    assert res["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    
    # High Criticality Amplification
    high_res = engine.fuse(scores, asset_criticality="CRITICAL")
    assert high_res["consensus_score"] >= res["consensus_score"]

    # Drift-aware Weight Adjustments
    drift_res = engine.fuse(scores, asset_criticality="MEDIUM", drift_metric=0.6)
    assert 0.0 <= drift_res["consensus_score"] <= 1.0


def test_false_positive_suppressor(sample_event):
    suppressor = FalsePositiveSuppressor()
    
    # Suppression on whitelisted user
    sample_event.user_id = "admin_maint"
    res = suppressor.should_suppress(sample_event, consensus_score=0.9)
    assert res["suppressed"] is True
    assert "maintenance" in res["reason"]
    
    # Suppression on trusted process
    sample_event.user_id = "john_doe"
    sample_event.process_name = "splunkd.exe"
    res2 = suppressor.should_suppress(sample_event, consensus_score=0.95)
    assert res2["suppressed"] is True

    # Benign event learning and cooldown logic
    sample_event.process_name = "explorer.exe"
    sample_event.event_type = "Normal_Connection"
    res3 = suppressor.should_suppress(sample_event, consensus_score=0.2)
    assert res3["suppressed"] is False
    
    # Deduplication cooldown check
    res4 = suppressor.should_suppress(sample_event, consensus_score=0.2)
    assert res4["suppressed"] is True
    assert "cooldown" in res4["reason"]


def test_adaptive_threshold_tuner():
    tuner = AdaptiveThresholdTuner()
    
    # Standard threshold configuration
    assert tuner.anomaly_threshold == 0.50
    
    # Flood tuning during alert storm
    new_t = tuner.auto_tune(alert_rate_per_min=120.0, drift_metric=0.1)
    assert new_t > 0.50

    # Fine-tuning during drift
    drift_t = tuner.auto_tune(alert_rate_per_min=10.0, drift_metric=0.8)
    assert drift_t > 0.50


# ─── Integrated Ensemble Test ─────────────────────────────────────────────────

def test_ensemble_reasoning_system(sample_event, sample_fv):
    system = EnsembleReasoningSystem()
    
    reason_res = system.reason(
        event=sample_event,
        fv=sample_fv,
        anomaly_score=0.85,
        faiss_distance=4.5,
        markov_score=0.75,
        rl_score=0.70
    )
    
    assert "consensus_score" in reason_res
    assert "mitre_tactic" in reason_res
    assert "recommended_mitigation" in reason_res
    assert 0.0 <= reason_res["consensus_score"] <= 1.0
    assert 0.0 <= reason_res["blast_radius_score"] <= 1.0
    assert 0.0 <= reason_res["graph_risk_score"] <= 1.0


# ─── Backward Compatibility Schema Test ───────────────────────────────────────

def test_backwards_compatibility(sample_event):
    # Tests that instantiating a DetectionDecision using only the baseline fields succeeds perfectly
    decision = DetectionDecision(
        event_id="dec_456",
        timestamp=datetime.utcnow(),
        event_type=sample_event.event_type,
        src_ip=sample_event.src_ip,
        dst_ip=sample_event.dst_ip,
        asset_criticality=sample_event.asset_criticality,
        anomaly_score=0.72,
        faiss_distance=3.2,
        confidence_score=0.8,
        severity="HIGH",
        is_high_confidence_anomaly=True,
        detection_reason="IsolationForest_Score_Exceeded",
        raw_event=sample_event
    )
    
    # Baseline checks
    assert decision.consensus_score is None
    assert decision.attack_path is None
    
    # Enriched checks after adding custom values
    decision.consensus_score = 0.84
    decision.attack_path = ["WORKSTATION-22", "DB-01"]
    
    serialized = decision.model_dump()
    assert serialized["consensus_score"] == 0.84
    assert serialized["attack_path"] == ["WORKSTATION-22", "DB-01"]
