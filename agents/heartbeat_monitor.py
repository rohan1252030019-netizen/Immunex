import time
from typing import Dict, Any, List
from storage.agent_state_cache import AgentStateCache

class HeartbeatMonitor:
    """
    Monitors agent health states and flags agents as DEGRADED or OFFLINE
    if their last heartbeat exceeds specific time bounds.
    """
    def __init__(self, cache: AgentStateCache, offline_timeout_seconds: float = 30.0, timeout_seconds: float = None) -> None:
        self._cache = cache
        self.offline_timeout_seconds = timeout_seconds if timeout_seconds is not None else offline_timeout_seconds

    def check_health(self) -> List[Dict[str, Any]]:
        agents = self._cache.list_agents()
        now = time.time()
        degraded_or_offline = []
        for agent in agents:
            elapsed = now - agent["last_seen"]
            old_status = agent["status"]
            if elapsed > self.offline_timeout_seconds:
                new_status = "OFFLINE"
            elif elapsed > (self.offline_timeout_seconds / 2.0):
                new_status = "DEGRADED"
            else:
                new_status = old_status if old_status in ["ONLINE", "ACTIVE"] else "ACTIVE"
            
            if new_status != old_status:
                self._cache.update_heartbeat(agent["agent_id"], status=new_status)
                agent["status"] = new_status
                degraded_or_offline.append(agent)
        return degraded_or_offline

    def scan_and_flag_offline(self) -> List[Dict[str, Any]]:
        return self.check_health()
