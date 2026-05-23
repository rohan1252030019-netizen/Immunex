"""
Tests for core/correlation_engine.py + core/adaptive_intelligence.py
=======================================================================
Validates:
- Single event (no campaign yet) returns None
- Multi-stage events trigger CorrelatedAttack
- AttackerProfile correctly tracks stage sequence
- CorrelatedAttack has all required fields
- NarrativeEngine generates valid narrative
- AdaptiveIntelligenceLayer.process() returns ThreatReport on campaign
- Batch processing collects all reports
- Stats reporting works
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta

import pytest

from core.adaptive_intelligence import AdaptiveIntelligenceLayer, ThreatReport
from core.correlation_engine import (
    AttackerProfile,
    CorrelatedAttack,
    CorrelationEngine,
)
from core.graph_engine import GraphEngine
from core.markov_predictor import MarkovPredictor
from core.narrative_engine import NarrativeEngine
from utils.schemas import DetectionDecision, SecurityEvent


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _sha256_hex(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _make_event(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.10",
    event_type: str = "Port_Scan",
    ts: datetime | None = None,
) -> SecurityEvent:
    ts = ts or datetime.utcnow()
    rng = random.Random(hash(src_ip))
    return SecurityEvent(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=rng.randint(1024, 65535),
        dst_port=rng.randint(1, 1024),
        protocol="TCP",
        user_id="user_test",
        process_name="cmd.exe",
        process_hash=_sha256_hex(f"hash_{src_ip}"),
        event_type=event_type,
        src_bytes=rng.randint(100, 5000),
        dst_bytes=rng.randint(100, 5000),
        duration=rng.uniform(0.1, 5.0),
        failed_logins=rng.randint(0, 10),
        connection_count=rng.randint(1, 100),
        packet_rate=rng.uniform(1.0, 50.0),
        geo_location="US-CA",
        asset_criticality="HIGH",
    )


def _make_decision(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.10",
    event_type: str = "Port_Scan",
    anomaly_score: float = 0.8,
    is_hca: bool = True,
    ts: datetime | None = None,
) -> DetectionDecision:
    ts = ts or datetime.utcnow()
    event = _make_event(src_ip=src_ip, dst_ip=dst_ip, event_type=event_type, ts=ts)
    return DetectionDecision(
        event_id=hashlib.md5(f"{src_ip}{ts}".encode()).hexdigest()[:16],
        timestamp=ts,
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset_criticality="HIGH",
        anomaly_score=anomaly_score,
        faiss_distance=28.0,
        confidence_score=0.85,
        severity="HIGH",
        is_high_confidence_anomaly=is_hca,
        detection_reason="IsolationForest+FAISS_Combined",
        raw_event=event,
    )


@pytest.fixture
def engines():
    graph   = GraphEngine()
    markov  = MarkovPredictor()
    engine  = CorrelationEngine(
        graph_engine=graph,
        markov_predictor=markov,
        correlation_window=300.0,
    )
    return engine, graph, markov


@pytest.fixture
def layer2():
    return AdaptiveIntelligenceLayer(
        correlation_window_seconds=300.0,
    )


# ─── AttackerProfile ─────────────────────────────────────────────────────────

class TestAttackerProfile:
    def test_record_adds_stages(self):
        profile = AttackerProfile("1.2.3.4")
        d = _make_decision(event_type="Port_Scan")
        profile.record(d, "Reconnaissance")
        assert "Reconnaissance" in profile.stages_observed

    def test_no_duplicate_stages(self):
        profile = AttackerProfile("1.2.3.4")
        d = _make_decision(event_type="Port_Scan")
        profile.record(d, "Reconnaissance")
        profile.record(d, "Reconnaissance")
        assert profile.stages_observed.count("Reconnaissance") == 1

    def test_is_multi_stage_false_on_single(self):
        profile = AttackerProfile("1.2.3.4")
        d = _make_decision(event_type="Port_Scan")
        profile.record(d, "Reconnaissance")
        assert not profile.is_multi_stage

    def test_is_multi_stage_true_on_two_stages(self):
        profile = AttackerProfile("1.2.3.4")
        profile.record(_make_decision(event_type="Port_Scan"), "Reconnaissance")
        profile.record(_make_decision(event_type="Brute_Force_Login"), "Credential_Access")
        assert profile.is_multi_stage

    def test_max_risk_returns_highest(self):
        profile = AttackerProfile("1.2.3.4")
        profile.record(_make_decision(anomaly_score=0.5), "Reconnaissance")
        profile.record(_make_decision(anomaly_score=0.9), "Credential_Access")
        assert profile.max_risk == pytest.approx(0.9)

    def test_campaign_id_format(self):
        profile = AttackerProfile("1.2.3.4")
        assert profile.campaign_id.startswith("CMP-")


# ─── CorrelationEngine single event ─────────────────────────────────────────

class TestCorrelationEngineSingle:
    def test_single_event_returns_none(self, engines):
        engine, _, _ = engines
        result = engine.ingest(_make_decision(event_type="Port_Scan"))
        assert result is None

    def test_normal_event_returns_none(self, engines):
        engine, _, _ = engines
        result = engine.ingest(_make_decision(is_hca=False))
        assert result is None

    def test_single_anomaly_no_campaign(self, engines):
        engine, _, _ = engines
        engine.ingest(_make_decision(event_type="Brute_Force_Login"))
        profiles = engine.get_active_profiles()
        src = "10.0.0.1"
        assert src in profiles
        assert not profiles[src]["is_multi_stage"]


# ─── CorrelationEngine multi-stage ───────────────────────────────────────────

class TestCorrelationEngineMultiStage:
    def test_two_stage_returns_correlated_attack(self, engines):
        engine, _, _ = engines
        base_ts = datetime.utcnow()
        engine.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        result = engine.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=30),
            )
        )
        assert isinstance(result, CorrelatedAttack)

    def test_correlated_attack_has_campaign_id(self, engines):
        engine, _, _ = engines
        base_ts = datetime.utcnow()
        engine.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        ca = engine.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=10),
            )
        )
        assert ca is not None
        assert ca.campaign_id.startswith("CMP-")

    def test_correlated_attack_stages(self, engines):
        engine, _, _ = engines
        base_ts = datetime.utcnow()
        engine.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        ca = engine.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=15),
            )
        )
        assert ca is not None
        assert "Reconnaissance" in ca.stages_observed
        assert "Credential_Access" in ca.stages_observed

    def test_correlated_attack_has_prediction(self, engines):
        engine, _, _ = engines
        base_ts = datetime.utcnow()
        engine.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        ca = engine.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=20),
            )
        )
        assert ca is not None
        assert ca.predicted_next_stage in [
            "Reconnaissance", "Credential_Access", "Lateral_Movement",
            "Execution", "Persistence", "Privilege_Escalation", "Exfiltration",
        ]
        assert 0.0 <= ca.prediction_confidence <= 1.0

    def test_correlated_attack_to_dict(self, engines):
        engine, _, _ = engines
        base_ts = datetime.utcnow()
        engine.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        ca = engine.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=5),
            )
        )
        assert ca is not None
        d = ca.to_dict()
        assert "campaign_id" in d
        assert "attacker_ip" in d
        assert "stages_observed" in d

    def test_stats_reports_campaigns(self, engines):
        engine, _, _ = engines
        base_ts = datetime.utcnow()
        engine.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        engine.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=5),
            )
        )
        s = engine.stats()
        assert s["campaigns_detected"] >= 1


# ─── NarrativeEngine ─────────────────────────────────────────────────────────

class TestNarrativeEngine:
    def _make_ca(self) -> CorrelatedAttack:
        from core.graph_engine import GraphEngine
        from core.markov_predictor import MarkovPredictor

        g = GraphEngine()
        m = MarkovPredictor()
        e = CorrelationEngine(g, m)

        base_ts = datetime.utcnow()
        e.ingest(_make_decision(event_type="Port_Scan", ts=base_ts))
        ca = e.ingest(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=20),
            )
        )
        return ca

    def test_narrative_has_all_keys(self):
        na = NarrativeEngine()
        ca = self._make_ca()
        assert ca is not None
        narrative = na.generate(ca)
        for key in [
            "campaign_id", "severity", "executive_summary",
            "attack_story", "timeline", "impacted_assets",
            "countermeasures", "prediction_warning", "raw_stats",
        ]:
            assert key in narrative, f"Missing key: {key}"

    def test_narrative_severity_valid(self):
        na = NarrativeEngine()
        ca = self._make_ca()
        narrative = na.generate(ca)
        assert narrative["severity"] in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_narrative_timeline_ordered(self):
        na = NarrativeEngine()
        ca = self._make_ca()
        narrative = na.generate(ca)
        tl = narrative["timeline"]
        for i in range(1, len(tl)):
            assert tl[i]["timestamp"] >= tl[i - 1]["timestamp"]

    def test_format_text_is_string(self):
        na = NarrativeEngine()
        ca = self._make_ca()
        narrative = na.generate(ca)
        text = na.format_text(narrative)
        assert isinstance(text, str)
        assert "IMMUNEX THREAT INTELLIGENCE REPORT" in text
        assert "EXECUTIVE SUMMARY" in text
        assert "COUNTERMEASURES" in text


# ─── AdaptiveIntelligenceLayer ───────────────────────────────────────────────

class TestAdaptiveIntelligenceLayer:
    def test_single_event_returns_none(self, layer2):
        d = _make_decision(event_type="Port_Scan")
        result = layer2.process(d)
        assert result is None

    def test_multi_stage_returns_threat_report(self, layer2):
        base_ts = datetime.utcnow()
        layer2.process(_make_decision(event_type="Port_Scan", ts=base_ts))
        report = layer2.process(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=10),
            )
        )
        assert isinstance(report, ThreatReport)

    def test_threat_report_has_narrative(self, layer2):
        base_ts = datetime.utcnow()
        layer2.process(_make_decision(event_type="Port_Scan", ts=base_ts))
        report = layer2.process(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=10),
            )
        )
        assert report is not None
        assert isinstance(report.narrative, dict)
        assert isinstance(report.formatted_report, str)

    def test_threat_report_to_dict(self, layer2):
        base_ts = datetime.utcnow()
        layer2.process(_make_decision(event_type="Port_Scan", ts=base_ts))
        report = layer2.process(
            _make_decision(
                event_type="Brute_Force_Login",
                ts=base_ts + timedelta(seconds=10),
            )
        )
        assert report is not None
        d = report.to_dict()
        assert "campaign_id" in d
        assert "severity" in d

    def test_batch_processing(self, layer2):
        base_ts = datetime.utcnow()
        decisions = [
            _make_decision(event_type="Port_Scan", ts=base_ts),
            _make_decision(event_type="Brute_Force_Login", ts=base_ts + timedelta(seconds=5)),
            _make_decision(event_type="PowerShell_Execution", ts=base_ts + timedelta(seconds=10)),
        ]
        reports = layer2.process_batch(decisions)
        assert isinstance(reports, list)
        assert all(isinstance(r, ThreatReport) for r in reports)

    def test_stats_structure(self, layer2):
        s = layer2.stats()
        assert "events_processed" in s
        assert "reports_generated" in s
        assert "uptime_seconds" in s
        assert "correlation" in s

    def test_stats_events_counted(self, layer2):
        for _ in range(5):
            layer2.process(_make_decision())
        assert layer2.stats()["events_processed"] == 5

    def test_predict_next_stage(self, layer2):
        result = layer2.predict_next_stage("Reconnaissance")
        assert "predicted_stage" in result
        assert "confidence_score" in result

    def test_get_active_campaigns(self, layer2):
        layer2.process(_make_decision(event_type="Port_Scan"))
        profiles = layer2.get_active_campaigns()
        assert isinstance(profiles, dict)
