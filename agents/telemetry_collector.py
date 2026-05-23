from typing import Dict, Any, List
from storage.agent_state_cache import AgentStateCache

class TelemetryCollector:
    """
    Receives and processes incoming multi-host telemetric logs.
    """
    def __init__(self, cache: AgentStateCache) -> None:
        self._cache = cache

    def collect(self, agent_id: str, telemetry_events: List[Dict[str, Any]]) -> None:
        for event in telemetry_events:
            event["agent_id"] = agent_id
            self._cache.buffer_telemetry(agent_id, event)

    def receive_telemetry(self, agent_id: str, event: Dict[str, Any]) -> None:
        self.collect(agent_id, [event])
