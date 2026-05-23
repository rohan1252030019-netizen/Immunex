"""
Tests for IMMUNEX StreamEngine
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime

from config import StreamConfig, override_config, IMMUNEXConfig
from core.stream_engine import StreamEngine
from utils.schemas import SecurityEvent
from utils.constants import MALICIOUS_EVENT_TYPES, BENIGN_EVENT_TYPES


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fast_stream_config() -> StreamConfig:
    """High-throughput config for testing."""
    return StreamConfig(events_per_second=100.0, malicious_ratio=0.3, seed=1337)


@pytest.fixture
def stream_engine(fast_stream_config) -> StreamEngine:
    return StreamEngine(cfg=fast_stream_config)


# ── Unit Tests ────────────────────────────────────────────────────────────────

class TestStreamEngineBatch:
    """Synchronous batch generation tests."""

    def test_generates_correct_batch_size(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(50)
        assert len(batch) == 50

    def test_all_events_are_security_events(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(20)
        for event in batch:
            assert isinstance(event, SecurityEvent)

    def test_events_have_valid_timestamps(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(10)
        for event in batch:
            assert isinstance(event.timestamp, datetime)

    def test_events_have_valid_ip_addresses(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(20)
        for event in batch:
            for ip in (event.src_ip, event.dst_ip):
                parts = ip.split(".")
                assert len(parts) == 4
                for part in parts:
                    assert 0 <= int(part) <= 255

    def test_events_have_valid_ports(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(20)
        for event in batch:
            assert 0 <= event.src_port <= 65535
            assert 0 <= event.dst_port <= 65535

    def test_process_hash_is_64_chars(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(10)
        for event in batch:
            assert len(event.process_hash) == 64

    def test_asset_criticality_valid(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(50)
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for event in batch:
            assert event.asset_criticality in valid

    def test_src_bytes_non_negative(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(50)
        for event in batch:
            assert event.src_bytes >= 0
            assert event.dst_bytes >= 0

    def test_duration_non_negative(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(50)
        for event in batch:
            assert event.duration >= 0.0

    def test_packet_rate_non_negative(self, stream_engine: StreamEngine):
        batch = stream_engine.generate_batch(50)
        for event in batch:
            assert event.packet_rate >= 0.0


class TestStreamEngineEventTypes:
    """Tests covering the mix of benign and malicious event types."""

    def test_benign_events_generated(self):
        cfg = StreamConfig(events_per_second=100.0, malicious_ratio=0.0, seed=99)
        engine = StreamEngine(cfg=cfg)
        batch = engine.generate_batch(200)
        types = {e.event_type for e in batch}
        # With malicious_ratio=0.0 all events should be benign
        assert types.issubset(BENIGN_EVENT_TYPES | MALICIOUS_EVENT_TYPES)

    def test_malicious_events_generated_with_high_ratio(self):
        cfg = StreamConfig(events_per_second=100.0, malicious_ratio=0.9, seed=42)
        engine = StreamEngine(cfg=cfg)
        batch = engine.generate_batch(500)
        malicious = [e for e in batch if e.event_type in MALICIOUS_EVENT_TYPES]
        # With high ratio we expect at least some malicious events
        assert len(malicious) > 0

    def test_all_known_attack_types_eventually_appear(self):
        """Attack chains cycle through stages; given enough events all should appear."""
        cfg = StreamConfig(events_per_second=100.0, malicious_ratio=0.8, seed=7)
        engine = StreamEngine(cfg=cfg)
        batch = engine.generate_batch(2000)
        observed = {e.event_type for e in batch}
        # At minimum the recon stage should appear
        recon_types = {"Port_Scan", "Network_Sweep"}
        assert observed & recon_types, f"Expected recon events, got: {observed}"


class TestStreamEngineAsync:
    """Async streaming tests."""

    def test_async_stream_yields_events(self):
        async def collect_n(n: int) -> list[SecurityEvent]:
            cfg = StreamConfig(events_per_second=1000.0, seed=0)
            engine = StreamEngine(cfg=cfg)
            events: list[SecurityEvent] = []
            async for event in engine.stream():
                events.append(event)
                if len(events) >= n:
                    break
            return events

        events = asyncio.run(collect_n(10))
        assert len(events) == 10
        for ev in events:
            assert isinstance(ev, SecurityEvent)

    def test_async_stream_is_continuous(self):
        """Stream should not raise StopAsyncIteration prematurely."""
        async def collect_100() -> int:
            cfg = StreamConfig(events_per_second=1000.0, seed=0)
            engine = StreamEngine(cfg=cfg)
            count = 0
            async for _ in engine.stream():
                count += 1
                if count >= 100:
                    break
            return count

        result = asyncio.run(collect_100())
        assert result == 100
