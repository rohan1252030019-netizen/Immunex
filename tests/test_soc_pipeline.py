import pytest
import time
from pathlib import Path
from storage.incident_store import IncidentStore
from soc.severity_engine import SeverityEngine
from soc.incident_manager import IncidentManager
from soc.investigation_timeline import InvestigationTimeline
from soc.analytics_engine import AnalyticsEngine

def test_full_soc_operations_pipeline():
    db_path = Path("data/logs/incidents_soc_test.db")
    if db_path.exists():
        db_path.unlink()
        
    store = IncidentStore(db_path)
    
    # 1. Alert occurs -> Evaluate dynamic severity and risk score
    sev_data = SeverityEngine.calculate_score(
        anomaly_score=0.88,
        faiss_distance=25.0,
        recurring_threat_score=0.75,
        asset_tier="TIER_1"
    )
    assert sev_data["severity"] in ["HIGH", "CRITICAL"]
    assert sev_data["score"] > 6.0
    
    # 2. Case generation and tracking in SQLite store
    inc_manager = IncidentManager(store)
    campaign_id = "test_campaign_soc"
    
    inc_manager.create_incident_case(
        campaign_id=campaign_id,
        attacker_ip="185.112.144.5",
        severity=sev_data["severity"],
        risk_score=sev_data["score"] * 10.0, # scale to 100
        stages=["Execution"]
    )
    
    # Verify case details
    case = store.get_incident(campaign_id)
    assert case is not None
    assert case["status"] == "OPEN"
    assert case["risk_score"] == sev_data["score"] * 10.0
    
    # 3. Add timeline and analyst notes
    store.upsert_incident(case)
    
    inc_manager.add_note(campaign_id, "analyst_john", "Suspicious credential dumping observed.")
    inc_manager.log_timeline_event(campaign_id, "Credential dumping activity logged", "Credential Access")
    
    # 4. Mitigation action applied
    inc_manager.log_mitigation_action(campaign_id, "BLOCK_IP", "global", "SUCCESS")
    
    # Close case
    inc_manager.update_status(campaign_id, "RESOLVED")
    
    # Verify closed status and timeline chain
    updated_case = store.get_incident(campaign_id)
    assert updated_case["status"] == "RESOLVED"
    assert len(updated_case["notes"]) == 1
    assert len(updated_case["mitigations"]) == 1
    
    # 5. Timeline Reconstruction
    timeline_engine = InvestigationTimeline()
    chronological = timeline_engine.reconstruct_chronology(updated_case["timeline"])
    assert len(chronological) > 0
    
    # 6. Analytics MTTR calculation
    analytics = AnalyticsEngine()
    stats = analytics.compute_stats([updated_case])
    assert stats["total_incidents"] == 1
    assert stats["resolved_incidents"] == 1
    assert stats["mttr_minutes"] >= 0.0
    
    # Cleanup
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
