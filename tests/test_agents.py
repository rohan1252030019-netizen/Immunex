import pytest
import time
from agents.agent_registry import AgentRegistry
from agents.endpoint_agent import EndpointAgent
from agents.telemetry_collector import TelemetryCollector
from agents.heartbeat_monitor import HeartbeatMonitor
from agents.distributed_dispatcher import DistributedDispatcher
from storage.agent_state_cache import AgentStateCache

def test_endpoint_agent_telemetry_gathering():
    agent = EndpointAgent(
        agent_id="test_agent_123",
        server_url="http://localhost:8080",
        hostname="WS-DEV-99",
        ip="192.168.10.15",
        os_type="Windows"
    )
    
    # Simulate process monitoring
    evt = agent.log_process("powershell.exe", "powershell -nop -w hidden -c Get-Process", 2048)
    assert evt["agent_id"] == "test_agent_123"
    assert evt["process_name"] == "powershell.exe"
    assert len(agent._buffer) == 1

def test_agent_registry_and_cache():
    cache = AgentStateCache()
    registry = AgentRegistry(cache)
    
    registry.enroll_agent("agent_01", "10.0.0.10", "SOC-SERVER-01", "Linux")
    
    active_agent = cache.get_agent("agent_01")
    assert active_agent is not None
    assert active_agent["hostname"] == "SOC-SERVER-01"
    assert active_agent["status"] == "ACTIVE"

def test_telemetry_collector():
    cache = AgentStateCache()
    collector = TelemetryCollector(cache)
    
    event_packet = {
        "timestamp": time.time(),
        "event_type": "network_socket",
        "payload": {"dest_ip": "8.8.8.8", "dest_port": 53}
    }
    
    collector.receive_telemetry("agent_01", event_packet)
    stored = cache.get_telemetry("agent_01", limit=1)
    assert len(stored) == 1
    assert stored[0]["event_type"] == "network_socket"

def test_heartbeat_monitor():
    cache = AgentStateCache()
    monitor = HeartbeatMonitor(cache, timeout_seconds=1)
    
    cache.register_agent("agent_01", "10.0.0.10", "SOC-SERVER-01", "Linux")
    
    # Check status initially
    assert cache.get_agent("agent_01")["status"] == "ACTIVE"
    
    # Wait to trigger timeout and execute monitor scan
    time.sleep(1.1)
    monitor.scan_and_flag_offline()
    
    assert cache.get_agent("agent_01")["status"] == "OFFLINE"

def test_distributed_dispatcher():
    dispatcher = DistributedDispatcher()
    
    # Trigger active host containment command
    res = dispatcher.dispatch_containment("agent_01", "BLOCK_IP", "198.51.100.42")
    assert res is True
