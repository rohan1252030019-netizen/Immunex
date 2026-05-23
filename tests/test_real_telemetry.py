"""
IMMUNEX Real Telemetry Engine — Unit Tests
============================================
Tests the parsing, normalization, ingestion, compression, and replay mechanics.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from telemetry.log_parsers import TelemetryParserRegistry, BaseParser, generate_deterministic_hash
from telemetry.ingestion_pipeline import TelemetryIngestionPipeline, MockBrokerClient
from utils.schemas import SecurityEvent

# ─── Mock Log Samples ───

MOCK_WINDOWS_LOG = {
    "EventID": 4624,
    "TimeCreated": "2026-05-20T23:56:55Z",
    "EventData": {
        "TargetUserName": "admin_test",
        "IpAddress": "192.168.1.100",
        "TargetIpAddress": "10.0.0.5",
        "ProcessName": "C:\\Windows\\System32\\lsass.exe"
    }
}

MOCK_SYSMON_LOG = {
    "EventID": 1,
    "UtcTime": "2026-05-20 23:57:12.456",
    "EventData": {
        "User": "tester",
        "SourceIp": "192.168.2.5",
        "DestinationIp": "10.10.10.2",
        "SourcePort": "50432",
        "DestinationPort": "443",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "Hashes": "SHA256=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
    }
}

MOCK_AUDITD_LOG = {
    "type": "EXECVE",
    "timestamp": "2026-05-20T23:58:00Z",
    "uid": "1000",
    "argc0": "/usr/bin/python3"
}

MOCK_DNS_LOG = {
    "timestamp": "2026-05-20T23:59:00Z",
    "query": "malicious-dns-tunneling-encoded-payload-segment-abcdef1234567890abcdef1234567890.attacker-infra-tunneling-dns.com",
    "client_ip": "192.168.10.12",
    "server_ip": "8.8.8.8"
}

MOCK_NETFLOW_LOG = {
    "timestamp": "2026-05-21T00:00:00Z",
    "protocol": 6,
    "src_bytes": 12000000,
    "dst_bytes": 500,
    "src_ip": "10.0.0.4",
    "dst_ip": "185.220.101.4",
    "src_port": 51234,
    "dst_port": 443,
    "packets": 8000,
    "duration": 5.2
}

MOCK_ZEEK_CONN = {
    "_path": "conn",
    "ts": "2026-05-21T00:01:00Z",
    "id.orig_h": "192.168.1.15",
    "id.resp_h": "8.8.8.8",
    "id.orig_p": 54321,
    "id.resp_p": 53,
    "proto": "udp",
    "orig_bytes": 64,
    "resp_bytes": 128,
    "duration": 0.05
}

MOCK_SURICATA_ALERT = {
    "timestamp": "2026-05-21T00:02:00Z",
    "alert": {
        "signature": "ET EXPLOIT Suspicious Command Exec",
        "severity": 1
    },
    "src_ip": "10.1.2.3",
    "dest_ip": "192.168.100.5",
    "proto": "TCP",
    "src_port": 12345,
    "dest_port": 8080
}

# ─── Tests ───

def test_telemetry_registry_parsers():
    """Verify that all standard parsers successfully ingest, validate and output SecurityEvents."""
    registry = TelemetryParserRegistry()
    
    # 1. Windows Event Parser
    event_win = registry.parse_log("windows", MOCK_WINDOWS_LOG)
    assert event_win is not None
    assert isinstance(event_win, SecurityEvent)
    assert event_win.user_id == "admin_test"
    assert event_win.src_ip == "192.168.1.100"
    assert event_win.process_name == "lsass.exe"

    # 2. Sysmon Parser
    event_sysmon = registry.parse_log("sysmon", MOCK_SYSMON_LOG)
    assert event_sysmon is not None
    assert event_sysmon.process_name == "cmd.exe"
    assert event_sysmon.process_hash == "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
    assert event_sysmon.dst_port == 443

    # 3. Linux auditd Parser
    event_audit = registry.parse_log("auditd", MOCK_AUDITD_LOG)
    assert event_audit is not None
    assert event_audit.process_name == "python3"
    assert event_audit.event_type == "Suspicious_Process_Spawn"

    # 4. DNS Parser
    event_dns = registry.parse_log("dns", MOCK_DNS_LOG)
    assert event_dns is not None
    assert event_dns.event_type == "DNS_Tunneling"
    assert event_dns.dst_port == 53

    # 5. NetFlow Parser
    event_netflow = registry.parse_log("netflow", MOCK_NETFLOW_LOG)
    assert event_netflow is not None
    assert event_netflow.event_type == "Data_Exfiltration"
    assert event_netflow.src_bytes == 12000000

    # 6. Zeek Parser
    event_zeek = registry.parse_log("zeek", MOCK_ZEEK_CONN)
    assert event_zeek is not None
    assert event_zeek.src_ip == "192.168.1.15"
    assert event_zeek.dst_bytes == 128

    # 7. Suricata Parser
    event_suri = registry.parse_log("suricata", MOCK_SURICATA_ALERT)
    assert event_suri is not None
    assert event_suri.asset_criticality == "CRITICAL"


@pytest.mark.asyncio
async def test_ingestion_pipeline_end_to_end():
    """Verify end-to-end telemetry pipeline: parse -> compress -> broker -> consume."""
    pipeline = TelemetryIngestionPipeline(use_kafka_broker=False)
    
    # Ingest 3 real-world telemetry logs
    assert await pipeline.ingest_raw_log("windows", MOCK_WINDOWS_LOG) is True
    assert await pipeline.ingest_raw_log("sysmon", MOCK_SYSMON_LOG) is True
    assert await pipeline.ingest_raw_log("auditd", MOCK_AUDITD_LOG) is True

    # Check that events exist in the consumer queue
    consumed_events = await pipeline.consume_batch(limit=10)
    assert len(consumed_events) == 3
    
    # Check correct type deserialization
    assert all(isinstance(e, SecurityEvent) for e in consumed_events)
    assert consumed_events[0].user_id == "admin_test"
    assert consumed_events[1].process_name == "cmd.exe"
    assert consumed_events[2].process_name == "python3"


@pytest.mark.asyncio
async def test_historical_replay_pipeline():
    """Verify that historical logging works for simulation and forensic audits."""
    pipeline = TelemetryIngestionPipeline(use_kafka_broker=False)
    
    # Ingest logs
    await pipeline.ingest_raw_log("sysmon", MOCK_SYSMON_LOG)
    await pipeline.ingest_raw_log("dns", MOCK_DNS_LOG)
    
    # Consume active queue (leaves active queue empty)
    await pipeline.consume_batch(limit=10)
    
    # Replay historical records
    replayed = []
    await pipeline.replay_history(speed_multiplier=10.0, callback=lambda e: replayed.append(e))
    
    assert len(replayed) == 2
    assert replayed[0].process_name == "cmd.exe"
    assert replayed[1].event_type == "DNS_Tunneling"


def test_base_parser_fallback_safeguards():
    """Test BaseParser fallback mechanics against malformed logs to guarantee stability."""
    class DummyParser(BaseParser):
        def _normalize(self, raw_log: dict):
            # Missing almost all keys deliberately
            return {"user_id": "test_dummy"}
            
    parser = DummyParser()
    res = parser.parse({})
    
    assert res is not None
    assert isinstance(res, SecurityEvent)
    assert res.user_id == "test_dummy"
    assert res.src_ip == "127.0.0.1"  # fallback
    assert res.process_name == "unknown"  # fallback
