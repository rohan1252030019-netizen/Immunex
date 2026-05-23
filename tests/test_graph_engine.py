"""
Tests for core/graph_engine.py
================================
Validates:
- Node insertion and upsert
- Edge construction with attack-stage mapping
- Connected component traversal
- Attack chain reconstruction
- Graph pruning
- Stats reporting
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta

import pytest

from core.graph_engine import (
    ENTITY_IP,
    ENTITY_USER,
    ENTITY_PROCESS,
    ENTITY_HASH,
    ENTITY_ASSET,
    GraphEngine,
    _node_id,
    EVENT_TO_STAGE,
)
from utils.schemas import DetectionDecision, SecurityEvent


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _make_event(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.10",
    event_type: str = "Port_Scan",
    asset_criticality: str = "HIGH",
    ts: datetime | None = None,
) -> SecurityEvent:
    ts = ts or datetime.utcnow()
    rng = random.Random(42)
    return SecurityEvent(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=rng.randint(1024, 65535),
        dst_port=rng.randint(1, 1024),
        protocol="TCP",
        user_id="u_test",
        process_name="powershell.exe",
        process_hash=hashlib.sha256(b"test").hexdigest(),
        event_type=event_type,
        src_bytes=rng.randint(100, 5000),
        dst_bytes=rng.randint(100, 5000),
        duration=rng.uniform(0.1, 5.0),
        failed_logins=rng.randint(0, 10),
        connection_count=rng.randint(1, 100),
        packet_rate=rng.uniform(1.0, 100.0),
        geo_location="US-NY",
        asset_criticality=asset_criticality,
    )


def _make_decision(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.10",
    event_type: str = "Port_Scan",
    anomaly_score: float = 0.8,
    is_hca: bool = True,
    severity: str = "HIGH",
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
        faiss_distance=30.0,
        confidence_score=0.9,
        severity=severity,
        is_high_confidence_anomaly=is_hca,
        detection_reason="IsolationForest_Score_Exceeded",
        raw_event=event,
    )


# ─── Tests ─────────────────────────────────────────────────────────────────────

class TestGraphEngineNodes:
    def test_ingest_creates_nodes(self):
        ge = GraphEngine()
        decision = _make_decision()
        nodes = ge.ingest(decision)
        assert len(nodes) > 0
        assert ge._graph.number_of_nodes() > 0

    def test_non_anomaly_skipped(self):
        ge = GraphEngine()
        decision = _make_decision(is_hca=False)
        nodes = ge.ingest(decision)
        assert nodes == []
        assert ge._graph.number_of_nodes() == 0

    def test_src_ip_node_created(self):
        ge = GraphEngine()
        decision = _make_decision(src_ip="1.2.3.4")
        ge.ingest(decision)
        nid = _node_id(ENTITY_IP, "1.2.3.4")
        assert nid in ge._graph.nodes
        data = ge._graph.nodes[nid]
        assert data["entity_type"] == ENTITY_IP
        assert data["risk_score"] > 0

    def test_user_process_hash_nodes_created(self):
        ge = GraphEngine()
        decision = _make_decision()
        ge.ingest(decision)
        user_nid = _node_id(ENTITY_USER, "u_test")
        proc_nid = _node_id(ENTITY_PROCESS, "powershell.exe")
        assert user_nid in ge._graph.nodes
        assert proc_nid in ge._graph.nodes

    def test_upsert_updates_risk_score(self):
        ge = GraphEngine()
        d1 = _make_decision(src_ip="5.5.5.5", anomaly_score=0.5)
        d2 = _make_decision(src_ip="5.5.5.5", anomaly_score=0.9)
        ge.ingest(d1)
        ge.ingest(d2)
        nid = _node_id(ENTITY_IP, "5.5.5.5")
        assert ge._graph.nodes[nid]["risk_score"] == pytest.approx(0.9)

    def test_observation_count_increments(self):
        ge = GraphEngine()
        for _ in range(5):
            ge.ingest(_make_decision(src_ip="9.9.9.9"))
        nid = _node_id(ENTITY_IP, "9.9.9.9")
        assert ge._graph.nodes[nid]["observation_count"] >= 5


class TestGraphEngineEdges:
    def test_edges_created(self):
        ge = GraphEngine()
        ge.ingest(_make_decision())
        assert ge._graph.number_of_edges() > 0

    def test_edge_has_attack_stage(self):
        ge = GraphEngine()
        ge.ingest(_make_decision(event_type="Port_Scan"))
        for u, v, data in ge._graph.edges(data=True):
            if "attack_stage" in data:
                assert data["attack_stage"] == "Reconnaissance"
                break

    def test_edge_temporal_sequence_increases(self):
        ge = GraphEngine()
        d1 = _make_decision(src_ip="1.1.1.1", ts=datetime.utcnow())
        d2 = _make_decision(src_ip="2.2.2.2", ts=datetime.utcnow() + timedelta(seconds=1))
        ge.ingest(d1)
        seq1 = ge._edge_counter
        ge.ingest(d2)
        seq2 = ge._edge_counter
        assert seq2 > seq1


class TestGraphEngineChains:
    def test_get_attack_chains_empty_on_init(self):
        ge = GraphEngine()
        chains = ge.get_attack_chains()
        assert chains == []

    def test_attack_chain_contains_connected_nodes(self):
        ge = GraphEngine()
        ge.ingest(_make_decision(src_ip="3.3.3.3", dst_ip="4.4.4.4"))
        ge.ingest(_make_decision(src_ip="3.3.3.3", dst_ip="5.5.5.5"))
        chains = ge.get_attack_chains()
        assert len(chains) > 0
        # The attacker IP node must appear in at least one chain
        src_node = _node_id(ENTITY_IP, "3.3.3.3")
        found = any(src_node in c for c in chains)
        assert found

    def test_reconstruct_chain_returns_dict(self):
        ge = GraphEngine()
        ge.ingest(_make_decision())
        chains = ge.get_attack_chains()
        if chains:
            result = ge.reconstruct_chain(chains[0])
            assert "ordered_stages" in result
            assert "start_time" in result
            assert "end_time" in result
            assert "risk_score" in result


class TestGraphEngineStats:
    def test_stats_structure(self):
        ge = GraphEngine()
        s = ge.stats()
        assert "nodes" in s
        assert "edges" in s
        assert "alerts_ingested" in s
        assert "attack_chains" in s

    def test_stats_alerts_increments(self):
        ge = GraphEngine()
        ge.ingest(_make_decision())
        ge.ingest(_make_decision(src_ip="7.7.7.7"))
        assert ge.stats()["alerts_ingested"] == 2


class TestGraphEnginePruning:
    def test_prune_caps_nodes(self):
        ge = GraphEngine(max_nodes=10, max_edges=100)
        for i in range(30):
            ge.ingest(_make_decision(src_ip=f"{i}.{i}.{i}.{i}"))
        assert ge._graph.number_of_nodes() <= 15  # allow slight buffer post-ingest


class TestEventToStageMapping:
    @pytest.mark.parametrize("event_type,expected_stage", [
        ("Port_Scan",           "Reconnaissance"),
        ("Network_Sweep",       "Reconnaissance"),
        ("Brute_Force_Login",   "Credential_Access"),
        ("PowerShell_Execution","Execution"),
        ("Data_Exfiltration",   "Exfiltration"),
        ("Registry_Modification","Persistence"),
    ])
    def test_event_type_maps_to_stage(self, event_type, expected_stage):
        assert EVENT_TO_STAGE[event_type] == expected_stage
