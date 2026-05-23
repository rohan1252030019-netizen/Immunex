import pytest
import time
from storage.agent_state_cache import AgentStateCache
from agents.agent_registry import AgentRegistry
from agents.telemetry_collector import TelemetryCollector
from agents.heartbeat_monitor import HeartbeatMonitor
from agents.distributed_dispatcher import DistributedDispatcher

def test_distributed_agents_pipeline():
    cache = AgentStateCache()
    registry = AgentRegistry(cache)
    collector = TelemetryCollector(cache)
    monitor = HeartbeatMonitor(cache, timeout_seconds=2)
    dispatcher = DistributedDispatcher()
    
    # 1. Active hosts register
    registry.enroll_agent("host_alpha", "10.0.0.50", "WS-ALPHA", "Windows")
    registry.enroll_agent("host_beta", "10.0.0.51", "WS-BETA", "Linux")
    
    agents = cache.list_agents()
    assert len(agents) == 2
    
    # 2. Heartbeats received
    cache.update_heartbeat("host_alpha", "ONLINE", {"cpu": 15.0})
    cache.update_heartbeat("host_beta", "ONLINE", {"cpu": 25.0})
    
    # 3. Stream process telemetry
    collector.receive_telemetry("host_alpha", {
        "timestamp": time.time(),
        "event_type": "process_launch",
        "payload": {"process_name": "whoami", "cmdline": "whoami /all"}
    })
    
    collector.receive_telemetry("host_beta", {
        "timestamp": time.time(),
        "event_type": "network_socket",
        "payload": {"dest_ip": "45.227.254.12", "dest_port": 443}
    })
    
    # 4. Heartbeat scan detects online state
    monitor.scan_and_flag_offline()
    assert cache.get_agent("host_alpha")["status"] == "ONLINE"
    assert cache.get_agent("host_beta")["status"] == "ONLINE"
    
    # 5. Dispatch containment command
    res = dispatcher.dispatch_containment("host_beta", "TERMINATE_PID", "4096")
    assert res is True
