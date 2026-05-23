from typing import Dict, Any
from audit.immutable_event_store import ImmutableEventStore

class AuditLogger:
    """
    High-level central auditor logs wrapper.
    """
    def __init__(self, store: ImmutableEventStore) -> None:
        self._store = store

    def log_action(self, user: str, action: str, endpoint: str, details: Dict[str, Any]) -> Dict[str, Any]:
        return self._store.append_event(
            user_identity=user,
            action_type=action,
            api_endpoint=endpoint,
            details=details
        )
