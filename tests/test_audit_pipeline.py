import pytest
import time
from storage.audit_store import AuditStore
from audit.immutable_event_store import ImmutableEventStore
from audit.audit_logger import AuditLogger
from audit.forensic_recorder import ForensicRecorder
from audit.retention_manager import RetentionManager
from audit.compliance_engine import ComplianceEngine
from pathlib import Path

def test_immutable_event_store_cryptographic_chain():
    db_path = Path("data/logs/audit_test_pipeline.db")
    if db_path.exists():
        db_path.unlink()
        
    store = AuditStore(db_path)
    immutable = ImmutableEventStore(store)
    
    # Assert initial empty hash is standard "0" * 64
    assert store.get_latest_hash() == "0" * 64
    
    # Add first event
    block1 = immutable.append_event(
        user_identity="admin",
        action_type="LOGOUT",
        api_endpoint="/auth/logout",
        details={"session_id": "sess_1"}
    )
    assert block1["block_hash"] != "0" * 64
    assert block1["previous_hash"] == "0" * 64
    
    # Add second event
    block2 = immutable.append_event(
        user_identity="analyst",
        action_type="CLOSE_CASE",
        api_endpoint="/soc/cases/close",
        details={"case_id": "c1"}
    )
    assert block2["previous_hash"] == block1["block_hash"]
    
    # Verify complete blockchain integrity
    assert immutable.verify_integrity() is True
    
    # Tamper with the database manually to verify detection!
    with store.db_path.open("r+b") as f:
        # Just write some corrupted bytes into the database
        f.seek(100)
        f.write(b"TAMPERED_DETAILS_BYTES")
        
    # Validation should now detect corruption and return False!
    assert immutable.verify_integrity() is False
    
    # Clean up DB
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

def test_forensic_recorder():
    recorder = ForensicRecorder()
    snapshot = recorder.capture_snapshot(
        host_id="agent_01",
        trigger_reason="High Confidence Anomaly",
        active_processes=["powershell.exe", "cmd.exe"]
    )
    assert snapshot["host_id"] == "agent_01"
    assert "active_processes" in snapshot["context_captured"]

def test_retention_manager_pruning():
    db_path = Path("data/logs/audit_retention_test.db")
    if db_path.exists():
        db_path.unlink()
        
    store = AuditStore(db_path)
    # Log an extremely old event manually
    timestamp_95_days_ago = time.time() - (95 * 24 * 3600)
    store.log_event(
        timestamp=timestamp_95_days_ago,
        user_identity="old_user",
        action_type="ARCHIVE",
        api_endpoint="manual",
        details={"old": "data"},
        prev_hash="0" * 64,
        block_hash="xyz_hash"
    )
    
    # Log a fresh event
    store.log_event(
        timestamp=time.time(),
        user_identity="new_user",
        action_type="FRESH",
        api_endpoint="manual2",
        details={"fresh": "data"},
        prev_hash="xyz_hash",
        block_hash="abc_hash"
    )
    
    assert store.count_logs() == 2
    
    # Run retention pruning
    retention = RetentionManager(store, max_age_days=90)
    retention.prune_logs()
    
    # Old log should be pruned, leaving 1 log
    assert store.count_logs() == 1
    
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

def test_compliance_engine():
    db_path = Path("data/logs/audit_compliance_test.db")
    if db_path.exists():
        db_path.unlink()
    store = AuditStore(db_path)
    engine = ComplianceEngine(store)
    
    # Empty logs evaluation
    res = engine.evaluate_compliance()
    assert res["SOC2_CC6_Control_Status"] == "PARTIALLY_COMPLIANT"
    
    # Add retrain and privilege actions
    store.log_event(time.time(), "admin", "RETRAIN_MODEL", "api", {"ok": True}, "0"*64, "1"*64)
    store.log_event(time.time(), "admin", "UPDATE_PRIVILEGES", "api", {"ok": True}, "1"*64, "2"*64)
    
    res = engine.evaluate_compliance()
    assert res["SOC2_CC6_Control_Status"] == "COMPLIANT"
    
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
