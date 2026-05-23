import hashlib
import json
import time
from typing import Dict, Any, List
from storage.audit_store import AuditStore

class ImmutableEventStore:
    """
    Guarantees log integrity using block-chaining (SHA-256 signatures of event payload + previous block hash).
    """
    def __init__(self, store: AuditStore) -> None:
        self._store = store

    def append_event(self, user_identity: str, action_type: str, 
                     api_endpoint: str, details: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = time.time()
        prev_hash = self._store.get_latest_hash()
        
        block_data = {
            "timestamp": timestamp,
            "user_identity": user_identity,
            "action_type": action_type,
            "api_endpoint": api_endpoint,
            "details": details,
            "previous_hash": prev_hash
        }
        
        serialized = json.dumps(block_data, sort_keys=True)
        block_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        
        self._store.log_event(
            timestamp=timestamp,
            user_identity=user_identity,
            action_type=action_type,
            api_endpoint=api_endpoint,
            details=details,
            prev_hash=prev_hash,
            block_hash=block_hash
        )
        
        block_data["block_hash"] = block_hash
        return block_data

    def verify_integrity(self) -> bool:
        """
        Walks the database from the beginning and verifies all block hashes and chaining.
        """
        try:
            logs = self._store.get_logs(limit=1000000, offset=0)
        except Exception:
            return False
        logs.reverse()
        
        expected_prev_hash = "0" * 64
        for log in logs:
            if log["previous_hash"] != expected_prev_hash:
                return False
                
            block_data = {
                "timestamp": log["timestamp"],
                "user_identity": log["user_identity"],
                "action_type": log["action_type"],
                "api_endpoint": log["api_endpoint"],
                "details": log["details"],
                "previous_hash": log["previous_hash"]
            }
            serialized = json.dumps(block_data, sort_keys=True)
            calculated_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            
            if log["block_hash"] != calculated_hash:
                return False
                
            expected_prev_hash = log["block_hash"]
            
        return True
