import threading
from typing import Dict, Any, Optional

class DistributedStateStore:
    """
    In-memory, thread-safe cache store to hold shared platform state, configuration values,
    session blacklist statuses, and dynamic synchronization flags.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._state: Dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._state[key] = value

    def delete(self, key: str) -> None:
        with self._lock:
            if key in self._state:
                del self._state[key]

    def clear(self) -> None:
        with self._lock:
            self._state.clear()
            
    def get_all(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._state)
