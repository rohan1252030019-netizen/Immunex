import time
import threading
from typing import Dict, Any, List, Optional

class AgentStateCache:
    """
    Thread-safe storage cache tracking distributed endpoints, active heartbeats,
    buffered telemetry, and host-level resource statistics.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._telemetry_buffer: Dict[str, List[Dict[str, Any]]] = {}

    def register_agent(self, agent_id: str, ip: str, hostname: str, os_type: str) -> None:
        with self._lock:
            self._agents[agent_id] = {
                "agent_id": agent_id,
                "ip": ip,
                "hostname": hostname,
                "os": os_type,
                "status": "ACTIVE",
                "last_seen": time.time(),
                "metrics": {}
            }
            if agent_id not in self._telemetry_buffer:
                self._telemetry_buffer[agent_id] = []

    def update_heartbeat(self, agent_id: str, status: str = "ACTIVE", metrics: Optional[Dict[str, Any]] = None) -> bool:
        with self._lock:
            if agent_id in self._agents:
                self._agents[agent_id]["last_seen"] = time.time()
                self._agents[agent_id]["status"] = status
                if metrics:
                    self._agents[agent_id]["metrics"].update(metrics)
                return True
            return False

    def buffer_telemetry(self, agent_id: str, data: Dict[str, Any]) -> None:
        with self._lock:
            if agent_id not in self._telemetry_buffer:
                self._telemetry_buffer[agent_id] = []
            self._telemetry_buffer[agent_id].append(data)
            # Cap buffer size to preserve CPU memory
            if len(self._telemetry_buffer[agent_id]) > 1000:
                self._telemetry_buffer[agent_id] = self._telemetry_buffer[agent_id][-1000:]

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._agents.get(agent_id)

    def list_agents(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._agents.values())

    def get_telemetry(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            buffer = self._telemetry_buffer.get(agent_id, [])
            return buffer[-limit:]
            
    def clear(self) -> None:
        with self._lock:
            self._agents.clear()
            self._telemetry_buffer.clear()
