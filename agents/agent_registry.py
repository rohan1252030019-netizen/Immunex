import time
from typing import Dict, Any, List, Optional
from storage.agent_state_cache import AgentStateCache

class AgentRegistry:
    """
    Central server registry for keeping track of connected distributed endpoints.
    """
    def __init__(self, cache: AgentStateCache) -> None:
        self._cache = cache

    def register(self, agent_id: str, ip: str, hostname: str, os_type: str) -> None:
        self._cache.register_agent(agent_id, ip, hostname, os_type)

    def list_all(self) -> List[Dict[str, Any]]:
        return self._cache.list_agents()

    def get_by_id(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self._cache.get_agent(agent_id)

    def enroll_agent(self, agent_id: str, ip: str, hostname: str, os_type: str) -> None:
        self.register(agent_id, ip, hostname, os_type)
