"""
Tests for IMMUNEX FastAPI Layer 4 endpoints.
Uses httpx.AsyncClient for async endpoint testing.
"""

from __future__ import annotations

import sys
import os
import time
import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Test Client Setup ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def test_state():
    """Minimal shared state for API testing (no full pipeline required)."""
    return {
        "start_time":         time.time(),
        "pipeline_stats":     {"total_events": 42, "total_alerts": 7, "total_responses": 3},
        "recent_alerts":      [
            {
                "campaign_id":    "CAM-TEST-001",
                "attacker_ip":    "10.0.0.99",
                "severity":       "HIGH",
                "stages":         ["Port_Scan", "Brute_Force_Login"],
                "risk_score":     0.82,
                "predicted_next": "Data_Exfiltration",
                "confidence":     0.75,
                "detected_at":    "2024-01-01T12:00:00",
            }
        ],
        "recent_mitigations": [
            {
                "campaign_id":            "CAM-TEST-001",
                "final_action":           "BLOCK_IP",
                "verdict":                "APPROVED",
                "reward_score":           0.91,
                "containment_confidence": 0.88,
                "commands":               ["iptables -A INPUT -s 10.0.0.99 -j DROP"],
                "latency_ms":             45.2,
            }
        ],
        "top_attackers":      [{"ip": "10.0.0.99", "campaigns": 3}],
        "layer2":             None,
        "layer3":             None,
        "layer4":             None,
        "scheduler":          None,
        "anomaly_engine":     None,
        "vector_engine":      None,
        "ollama_status":      "unavailable",
    }


@pytest.fixture(scope="module")
def test_app(test_state):
    from api.api_server import create_app
    return create_app(immunex_state=test_state)


@pytest.fixture(scope="module")
def client(test_app):
    from fastapi.testclient import TestClient
    return TestClient(test_app)


# ─── Health Endpoint ─────────────────────────────────────────────────────────

def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_response_structure(client):
    resp = client.get("/health")
    data = resp.json()
    assert "status" in data
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "version" in data
    assert "uptime_s" in data
    assert "components" in data
    assert isinstance(data["components"], dict)


def test_health_version_layer4(client):
    resp = client.get("/health")
    data = resp.json()
    assert "LAYER4" in data["version"] or "4" in data["version"]


# ─── Stream Endpoint ─────────────────────────────────────────────────────────

def test_stream_returns_200(client):
    resp = client.get("/stream")
    assert resp.status_code == 200


def test_stream_response_structure(client):
    resp = client.get("/stream")
    data = resp.json()
    required = {"events_per_second", "total_events", "total_alerts",
                "total_responses", "alert_rate_pct", "uptime_s"}
    assert required.issubset(set(data.keys()))
    assert data["total_events"] == 42
    assert data["total_alerts"] == 7


# ─── Alerts Endpoint ──────────────────────────────────────────────────────────

def test_alerts_returns_200(client):
    resp = client.get("/alerts")
    assert resp.status_code == 200


def test_alerts_response_structure(client):
    resp = client.get("/alerts")
    data = resp.json()
    assert "total" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_alerts_n_parameter(client):
    resp = client.get("/alerts?n=1")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["alerts"]) <= 1


def test_alerts_contains_expected_fields(client):
    resp = client.get("/alerts")
    data = resp.json()
    if data["alerts"]:
        alert = data["alerts"][0]
        assert "campaign_id" in alert
        assert "severity" in alert
        assert "risk_score" in alert


# ─── Graph Endpoint ───────────────────────────────────────────────────────────

def test_graph_returns_503_without_layer2(client):
    # layer2=None in test state → should return 503
    resp = client.get("/graph")
    assert resp.status_code == 503


# ─── Mitigation Endpoint ──────────────────────────────────────────────────────

def test_mitigation_returns_200(client):
    resp = client.get("/mitigation")
    assert resp.status_code == 200


def test_mitigation_response_is_list(client):
    resp = client.get("/mitigation")
    data = resp.json()
    assert isinstance(data, list)


def test_mitigation_n_parameter(client):
    resp = client.get("/mitigation?n=5")
    assert resp.status_code == 200


# ─── Retrain Endpoint ─────────────────────────────────────────────────────────

def test_retrain_returns_503_without_layer4(client):
    resp = client.post("/retrain", json={"triggered_by": "manual", "force": False})
    assert resp.status_code == 503


# ─── Metrics Endpoint ─────────────────────────────────────────────────────────

def test_metrics_returns_200(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200


def test_metrics_response_structure(client):
    resp = client.get("/metrics")
    data = resp.json()
    assert "uptime_seconds" in data
    assert "layer4_stats" in data
    assert "scheduler_metrics" in data


# ─── Threat Memory Endpoints ──────────────────────────────────────────────────

def test_threat_memory_returns_503_without_layer4(client):
    resp = client.get("/threat-memory")
    assert resp.status_code == 503


def test_threat_memory_correlate_returns_503_without_layer4(client):
    payload = {
        "campaign_id":    "CAM-TEST",
        "attacker_ip":    "10.0.0.1",
        "feature_vector": [0.0] * 10,
        "stages":         ["Port_Scan"],
    }
    resp = client.post("/threat-memory/correlate", json=payload)
    assert resp.status_code == 503


# ─── Middleware Tests ─────────────────────────────────────────────────────────

def test_response_time_header_present(client):
    resp = client.get("/health")
    assert "x-response-time" in resp.headers or "X-Response-Time" in resp.headers


def test_request_id_header_present(client):
    resp = client.get("/health")
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    assert "x-request-id" in headers_lower


def test_404_returns_json(client):
    resp = client.get("/nonexistent-endpoint")
    assert resp.status_code == 404
    data = resp.json()
    assert "error" in data
    assert data["code"] == 404


# ─── Rate Limiter (basic) ─────────────────────────────────────────────────────

def test_rate_limit_not_triggered_on_few_requests(client):
    # A handful of requests should not trigger rate limiting
    for _ in range(5):
        resp = client.get("/health")
        assert resp.status_code == 200


# ─── Playbook Endpoint ────────────────────────────────────────────────────────

def test_playbook_returns_503_without_layer3(client):
    payload = {
        "campaign_id": "CAM-PLAY-001",
        "severity":    "HIGH",
        "attacker_ip": "10.0.0.1",
        "stages":      ["Port_Scan", "Brute_Force_Login"],
        "target_ips":  ["192.168.1.10"],
    }
    resp = client.post("/playbook", json=payload)
    assert resp.status_code == 503


def test_playbook_invalid_severity_rejected(client):
    payload = {
        "campaign_id": "CAM-PLAY-002",
        "severity":    "EXTREME",   # invalid
        "attacker_ip": "10.0.0.1",
    }
    resp = client.post("/playbook", json=payload)
    assert resp.status_code == 422  # Pydantic validation error


# ─── OpenAPI Docs ─────────────────────────────────────────────────────────────

def test_openapi_schema_accessible(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    assert schema["info"]["title"] == "IMMUNEX Autonomous SOC API"


def test_docs_ui_accessible(client):
    resp = client.get("/docs")
    assert resp.status_code == 200
