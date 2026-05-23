"""
IMMUNEX Digital Twin & Attack Graph Engine Tests
================================================
Verifies asset/identity/network graphs, ransomware propagation, crown jewels discovery,
lateral movements, privilege escalation chains, shortest paths, and Neo4j fallbacks.
"""

from __future__ import annotations

import pytest
import json
from datetime import datetime
import networkx as nx

from utils.schemas import SecurityEvent
from twin_engine import (
    DigitalTwinEngine,
    NODE_HOST,
    NODE_USER,
    NODE_IP,
    EDGE_CONNECTED_TO,
    EDGE_COMMUNICATED_WITH,
    EDGE_PRIV_ESC_TO,
)
from graph_analytics import AttackGraphAnalytics


# ─── Mock Fixture ─────────────────────────────────────────────────────────────

@pytest.fixture
def twin() -> DigitalTwinEngine:
    return DigitalTwinEngine()

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
        src_bytes=5000,
        dst_bytes=10000,
        duration=2.5,
        failed_logins=0,
        connection_count=10,
        packet_rate=50.0,
        geo_location="US-CA",
        asset_criticality="HIGH"
    )


# ─── Digital Twin Graph Tests ────────────────────────────────────────────────

def test_graph_creation_and_ingestion(twin, sample_event):
    # Verify bootstrapped topology
    assert "HOST-01" in twin.graph
    assert "DB-01" in twin.graph
    assert twin.graph.nodes["DB-01"]["type"] == NODE_HOST
    assert twin.graph.nodes["DB-01"]["criticality"] == "CRITICAL"
    
    # Ingest new live telemetry event
    twin.ingest_event(sample_event)
    
    # Check updated nodes
    assert "192.168.1.10" in twin.graph
    assert "10.0.0.5" in twin.graph
    assert "john_doe" in twin.graph
    assert twin.graph.nodes["john_doe"]["type"] == NODE_USER
    
    # Check process tracking execution node
    proc_node = "proc::powershell.exe@192.168.1.10"
    assert proc_node in twin.graph
    assert twin.graph.has_edge("192.168.1.10", proc_node)


def test_blast_radius_simulator(twin):
    simulator = twin.blast_radius_simulator
    
    # Calculate blast radius from starting point
    res = simulator.calculate_blast_radius("HOST-01")
    assert "blast_radius_score" in res
    assert res["estimated_hosts_impacted"] > 0
    assert 0.0 <= res["blast_radius_score"] <= 1.0

    # Test propagation speed metrics
    speed = simulator.estimate_propagation_speed("FILESERVER-01")
    assert 0.0 <= speed <= 10.0


def test_crown_jewel_analyzer(twin):
    analyzer = twin.crown_jewel_analyzer
    
    # Discover crown-jewel assets
    jewels = analyzer.identify_crown_jewels()
    assert len(jewels) > 0
    assert "DB-01" in jewels or "DC-01" in jewels

    # Retrieve asset criticality levels
    criticality = analyzer.calculate_asset_criticality("DB-01")
    assert criticality == 1.0
    
    # Ranked asset lists
    ranked = analyzer.rank_assets()
    assert ranked[0]["criticality_score"] == 1.0


def test_lateral_movement_predictor(twin):
    predictor = twin.lateral_movement_predictor
    
    # Predict next hops from source point
    prediction = predictor.predict_next_hop("HOST-01")
    assert prediction["source"] == "HOST-01"
    assert prediction["target"] in twin.graph.nodes
    assert 0.0 <= prediction["probability"] <= 1.0

    # Calculate lateral probability on specific edges
    prob = predictor.calculate_lateral_probability("HOST-01", "FILESERVER-01")
    assert prob > 0.0

    # Enumerate lateral path sequences
    paths = predictor.enumerate_attack_paths("HOST-01", "DB-01")
    assert len(paths) > 0
    assert "FILESERVER-01" in paths[0]


def test_privilege_escalation_tracker(twin):
    tracker = twin.privilege_escalation_tracker
    
    # Trace user privilege ascending paths
    chain = tracker.trace_privilege_chain("john_doe")
    assert len(chain) > 1
    assert "john_doe" in chain
    assert "domain_admin" in chain  # john_doe -> admin_user -> domain_admin

    # Privilege escalation risk score
    risk = tracker.score_privilege_risk("john_doe")
    assert 0.0 <= risk <= 1.0
    
    # Detect escalation structures
    paths = tracker.detect_escalation_paths("john_doe")
    assert len(paths) > 0


def test_attack_path_predictor(twin):
    predictor = twin.attack_path_predictor
    
    # Shortest path to crown jewels
    path_res = predictor.find_path_to_crown_jewel("HOST-01")
    assert "path" in path_res
    assert len(path_res["path"]) > 0
    assert path_res["path"][-1] in ("DB-01", "DC-01")
    assert 0.0 <= path_res["risk_score"] <= 1.0

    # Multi-jewel routes enumeration
    routes = predictor.enumerate_compromise_routes("HOST-01")
    assert len(routes) > 0


# ─── Graph Analytics & Fallbacks Tests ────────────────────────────────────────

def test_attack_graph_analytics(twin):
    # Neo4j fallback test (unconfigured connections should fallback safely without exceptions)
    analytics = AttackGraphAnalytics(neo4j_uri="bolt://localhost:7687", neo4j_password="wrong_password")
    assert analytics.neo4j_enabled is False
    
    g = analytics.build_relationship_graph(twin.graph)
    assert g.number_of_nodes() > 0

    # Centralities PageRank scoring
    centralities = analytics.calculate_centrality(g)
    assert "DB-01" in centralities
    assert 0.0 <= centralities["DB-01"] <= 1.0

    # Community clusters
    clusters = analytics.detect_attack_clusters(g)
    assert len(clusters) > 0

    # Graph embeddings
    embeddings = analytics.compute_graph_embeddings(g)
    assert "DB-01" in embeddings
    assert len(embeddings["DB-01"]) == 8

    # JSON export Cytoscape format verification
    json_str = analytics.export_graph_json(g)
    data = json.loads(json_str)
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0
