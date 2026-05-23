import pytest
import time
from soc.analytics_engine import AnalyticsEngine
from soc.severity_engine import SeverityEngine
from soc.alert_manager import AlertManager
from soc.escalation_engine import EscalationEngine
from soc.dashboard_engine import DashboardEngine
from soc.case_management import CaseManagement
from storage.incident_store import IncidentStore
from pathlib import Path

def test_analytics_engine():
    engine = AnalyticsEngine()
    
    # Empty incidents
    res = engine.compute_stats([])
    assert res["total_incidents"] == 0
    
    # Active incidents
    incidents = [
        {
            "campaign_id": "c1",
            "attacker_ip": "10.0.0.1",
            "severity": "CRITICAL",
            "risk_score": 90.0,
            "status": "RESOLVED",
            "detected_at": 1000.0,
            "updated_at": 1600.0,
            "notes": [],
            "timeline": [],
            "mitigations": [],
            "stages": ["Execution"]
        },
        {
            "campaign_id": "c2",
            "attacker_ip": "10.0.0.2",
            "severity": "MEDIUM",
            "risk_score": 50.0,
            "status": "OPEN",
            "detected_at": 2000.0,
            "updated_at": 2100.0,
            "notes": [],
            "timeline": [],
            "mitigations": [],
            "stages": ["Discovery"]
        }
    ]
    
    res = engine.compute_stats(incidents)
    assert res["total_incidents"] == 2
    assert res["resolved_incidents"] == 1
    # 600 seconds resolved difference / 60 = 10 minutes MTTR
    assert res["mttr_minutes"] == 10.0
    assert res["severity_distribution"]["CRITICAL"] == 1

def test_severity_engine():
    score_details = SeverityEngine.calculate_score(
        anomaly_score=0.9,
        faiss_distance=15.0,
        recurring_threat_score=0.8,
        asset_tier="TIER_1"
    )
    assert score_details["score"] > 0.0
    assert score_details["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_alert_manager():
    # Deduplication and queueing checks
    manager = AlertManager()
    alert1 = {"campaign_id": "camp1", "src_ip": "192.168.1.10", "signature": "powershell"}
    alert2 = {"campaign_id": "camp1", "src_ip": "192.168.1.10", "signature": "powershell"} # duplicate
    
    assert manager.queue_alert(alert1) is True
    assert manager.queue_alert(alert2) is False # Duplicate filtered
    
    active = manager.get_active_alerts()
    assert len(active) == 1

def test_escalation_engine():
    store = IncidentStore(Path("data/logs/incidents_test.db"))
    inc = {
        "campaign_id": "escalate_test",
        "attacker_ip": "1.2.3.4",
        "severity": "HIGH",
        "risk_score": 80.0,
        "status": "OPEN",
        "detected_at": time.time() - 4000, # stagnating
        "updated_at": time.time() - 4000,
        "notes": [],
        "timeline": [],
        "mitigations": [],
        "stages": ["Execution"]
    }
    store.upsert_incident(inc)
    
    engine = EscalationEngine(store, age_threshold_seconds=1800)
    engine.check_and_escalate()
    
    updated = store.get_incident("escalate_test")
    assert updated["severity"] == "CRITICAL"
    
    # Cleanup DB file
    if Path("data/logs/incidents_test.db").exists():
        try:
            Path("data/logs/incidents_test.db").unlink()
        except Exception:
            pass

def test_dashboard_engine_kpis():
    engine = DashboardEngine()
    incidents = [
        {"severity": "CRITICAL", "status": "OPEN", "detected_at": 100, "updated_at": 200},
        {"severity": "HIGH", "status": "RESOLVED", "detected_at": 100, "updated_at": 160}
    ]
    kpis = engine.compile_kpis(incidents)
    assert kpis["active_threats_count"] == 1
    assert kpis["corporate_risk_index"] >= 0.0
