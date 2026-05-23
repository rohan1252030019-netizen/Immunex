import sqlite3
import time
from pathlib import Path
from storage.audit_store import AuditStore

class RetentionManager:
    """
    Governs data archiving and prunes logs based on compliance mandates.
    """
    def __init__(self, audit_store: AuditStore, retention_days: int = 90, max_age_days: int = None) -> None:
        self._store = audit_store
        self.retention_days = max_age_days if max_age_days is not None else retention_days

    def prune_logs(self) -> int:
        """Alias method for test compatibility."""
        return self.enforce_retention()

    def enforce_retention(self) -> int:
        """
        Deletes audit logs older than the retention window.
        Returns the number of pruned log entries.
        """
        now = time.time()
        cutoff = now - (self.retention_days * 86400.0)
        
        with sqlite3.connect(self._store.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE timestamp < ?", (cutoff,))
            pruned_count = cursor.fetchone()[0]
            conn.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,))
            conn.commit()
            return pruned_count
