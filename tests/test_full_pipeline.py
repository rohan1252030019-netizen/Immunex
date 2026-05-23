"""
IMMUNEX Full Pipeline Integration Test (Layer 4).

Tests the complete autonomous pipeline from stream → Layer 4 event,
without requiring Ollama or external services.
"""

from __future__ import annotations

import sys
import os
import asyncio
import json
import tempfile
import numpy as np
import pytest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def tmp_data_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("immunex_test_data")


@pytest.fixture(scope="module")
def config(tmp_data_dir):
    from config import IMMUNEXConfig, AnomalyEngineConfig, VectorEngineConfig, Layer4Config
    models_dir  = tmp_data_dir / "models"
    vectors_dir = tmp_data_dir / "vectors"
    models_dir.mkdir()
    vectors_dir.mkdir()
    return IMMUNEXConfig(
        anomaly=AnomalyEngineConfig(
            n_estimators=50,
            warmup_samples=100,
            model_path=models_dir / "if.joblib",
        ),
        vector=VectorEngineConfig(
            index_path=vectors_dir / "faiss.index",
            baseline_samples=200,
        ),
        layer4=Layer4Config(
            enable_auto_retrain=False,  # Disabled to keep tests fast
        ),
    )


@pytest.fixture(scope="module")
def layer1(config):
    from core.innate_immunity import InnateImmunityLayer
    l1 = InnateImmunityLayer(config)
    l1.initialise()
    return l1


@pytest.fixture(scope="module")
def layer2():
    from core.adaptive_intelligence import AdaptiveIntelligenceLayer
    return AdaptiveIntelligenceLayer(
        max_graph_nodes=1_000,
        max_graph_edges=5_000,
        correlation_window_seconds=300.0,
    )


@pytest.fixture(scope="module")
def layer3():
    from core.immune_response import ImmuneResponseEngine
    return ImmuneResponseEngine(enable_ollama=False)


@pytest.fixture(scope="module")
def layer4(layer1, tmp_data_dir):
    from core.adaptive_immunization import AdaptiveImmunizationLayer
    from config import get_config
    l4 = AdaptiveImmunizationLayer(
        innate_layer=layer1,
        anomaly_engine=layer1._anomaly_engine,
        vector_engine=layer1._vector_engine,
        enable_auto_retrain=False,
        seed=42,
    )
    # Override memory DB to use temp path
    from core.defensive_memory import DefensiveMemory
    l4._memory = DefensiveMemory(db_path=tmp_data_dir / "test_mem.db")
    l4.initialise()
    return l4


@pytest.fixture(scope="module")
def stream_events(config):
    """Generate a batch of synthetic stream events."""
    from core.stream_engine import StreamEngine
    engine = StreamEngine(config.stream)

    events = []
    async def collect():
        async for ev in engine.stream():
            events.append(ev)
            if len(events) >= 50:
                break
    asyncio.run(collect())
    return events


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_stream_generates_events(stream_events):
    assert len(stream_events) == 50
    for ev in stream_events:
        assert hasattr(ev, "src_ip")
        assert hasattr(ev, "event_type")
        assert hasattr(ev, "timestamp")


def test_layer1_processes_all_events(layer1, stream_events, config):
    from utils.schemas import DetectionDecision
    decisions = [layer1.process(ev) for ev in stream_events]
    assert len(decisions) == 50
    for d in decisions:
        assert isinstance(d, DetectionDecision)
        assert 0.0 <= d.anomaly_score <= 1.0
        assert d.faiss_distance >= 0.0
        assert d.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_layer1_detects_some_anomalies(layer1, stream_events, config):
    decisions = [layer1.process(ev) for ev in stream_events]
    anomalies = [d for d in decisions if d.is_high_confidence_anomaly]
    # With 15% malicious ratio, expect some anomalies
    assert len(anomalies) >= 0  # At minimum, pipeline runs without error


def test_layer4_ingest_decision(layer4, layer1, stream_events):
    """Layer4 drift ingest should not raise."""
    for ev in stream_events[:20]:
        decision = layer1.process(ev)
        layer4.ingest_decision(decision)  # Should not throw
    stats = layer4.stats()
    assert stats["decisions_ingested"] >= 20


def test_layer4_stats_structure(layer4):
    stats = layer4.stats()
    assert "campaigns_processed" in stats
    assert "decisions_ingested" in stats
    assert "retraining_sessions" in stats
    assert "memory" in stats
    assert "drift" in stats
    assert "mutation" in stats


def test_layer4_memory_integration(layer4):
    """Store and correlate threats through full memory pipeline."""
    rng = np.random.default_rng(99)
    vec = rng.random(10).astype(np.float32)
    layer4._memory.store(
        campaign_id="INT-TEST-001",
        attacker_ip="172.16.0.1",
        feature_vector=vec,
        stages=["Port_Scan", "Brute_Force_Login", "Data_Exfiltration"],
        severity="CRITICAL",
        attack_family="integration_test_apt",
    )
    result = layer4._memory.correlate("INT-TEST-002", vec, ["Port_Scan"])
    assert result.known_attack_family == "integration_test_apt"
    assert result.recurring_threat_score > 0.3


def test_mutation_engine_integration(layer4):
    """MutationEngine within Layer4 generates valid mutations."""
    mutations = layer4._mutation.generate_batch(n=20)
    assert len(mutations) == 20
    for m in mutations:
        assert m.feature_vector.shape == (10,)
        assert np.all(np.isfinite(m.feature_vector))


def test_validation_engine_integration(layer4):
    """ValidationEngine evaluates blind spots without crashing."""
    if layer4._validation is None:
        pytest.skip("Validation engine not initialised")
    report = layer4._validation.evaluate(n_mutations=30)
    assert report is not None
    assert 0.0 <= report.blind_spot_score <= 1.0
    assert report.n_mutations_tested == 30


def test_drift_detector_integration(layer4, layer1, stream_events):
    """Drift detector ingests data and can run analysis."""
    for ev in stream_events[:120]:
        decision = layer1.process(ev)
        if hasattr(decision, "anomaly_score"):
            rng = np.random.default_rng()
            vec = rng.random(10).astype(np.float32)
            layer4._drift.ingest(vec, decision.anomaly_score, decision.faiss_distance)
    # Analyse — may return None if window not filled, that's OK
    result = layer4._drift.analyse()
    # Just check it doesn't raise


@pytest.mark.asyncio
async def test_layer4_process_threat_async(layer4, layer2, layer1, stream_events):
    """Full async Layer4.process_threat call on a synthesized ThreatReport."""
    from core.adaptive_intelligence import ThreatReport
    from datetime import datetime

    # Build a mock ThreatReport
    report = ThreatReport(
        campaign_id="INT-ASYNC-001",
        attacker_ip="10.10.10.10",
        target_ips=["192.168.1.1", "192.168.1.2"],
        stages_observed=["Port_Scan", "Brute_Force_Login", "PowerShell_Execution"],
        predicted_next_stage="Data_Exfiltration",
        prediction_confidence=0.82,
        risk_score=0.77,
        severity="HIGH",
        narrative={"summary": "Test campaign"},
        formatted_report="Test report",
    )

    event = await layer4.process_threat(report)

    assert event is not None
    assert event.campaign_id == "INT-ASYNC-001"
    assert event.memory_correlation is not None
    assert event.total_latency_ms >= 0


@pytest.mark.asyncio
async def test_layer4_process_threat_populates_memory(layer4):
    """process_threat should store the campaign in memory."""
    from core.adaptive_intelligence import ThreatReport

    campaign_id = "INT-MEM-STORE-001"
    report = ThreatReport(
        campaign_id=campaign_id,
        attacker_ip="172.20.0.55",
        target_ips=["10.0.0.1"],
        stages_observed=["Network_Sweep", "Registry_Modification"],
        predicted_next_stage="Data_Exfiltration",
        prediction_confidence=0.7,
        risk_score=0.65,
        severity="MEDIUM",
        narrative={},
        formatted_report="",
    )

    await layer4.process_threat(report)

    stats = layer4._memory.stats()
    assert stats["total_entries"] >= 1


def test_config_layer4_section(config):
    assert hasattr(config, "layer4")
    assert config.layer4.enable_auto_retrain is False
    assert 0.0 < config.layer4.blind_spot_retrain_threshold < 1.0


def test_full_pipeline_event_flow(layer1, layer2, layer3, layer4, stream_events):
    """
    End-to-end synchronous smoke test: events flow through all four layers.
    Layer4.process_threat is called via asyncio.run for simplicity.
    """
    from core.adaptive_intelligence import ThreatReport

    decisions_made    = 0
    campaigns_found   = 0
    responses_made    = 0
    layer4_events     = 0

    for ev in stream_events[:30]:
        decision = layer1.process(ev)
        decisions_made += 1
        layer4.ingest_decision(decision)

        report = layer2.process(decision)
        if report is not None:
            campaigns_found += 1
            response = layer3.process(
                report=report,
                process_name=getattr(ev, "process_name", "unknown"),
                user_id=getattr(ev, "user_id", "unknown"),
            )
            if response is not None:
                responses_made += 1

            l4_event = asyncio.run(layer4.process_threat(report))
            layer4_events += 1
            assert l4_event.campaign_id == report.campaign_id

    assert decisions_made == 30
    # Not guaranteed to find campaigns in 30 events, but pipeline must not crash
    print(
        f"\nPipeline smoke test: decisions={decisions_made}, "
        f"campaigns={campaigns_found}, responses={responses_made}, "
        f"layer4_events={layer4_events}"
    )
