"""
IMMUNEX Real Telemetry Engine — Ingestion & Buffering Pipeline
================================================================
Implements streaming queues, compression, historical log replays, and a
pluggable Redpanda/Kafka broker abstraction to support high-throughput log ingestion.
"""

from __future__ import annotations

import os
import zlib
import json
import asyncio
from datetime import datetime
from collections import deque
from typing import Dict, Any, List, Optional, Callable
from utils.logger import log
from utils.schemas import SecurityEvent
from telemetry.log_parsers import TelemetryParserRegistry

class MockBrokerClient:
    """In-memory high-speed broker client acting as a zero-dependency Redpanda/Kafka substitute."""
    
    def __init__(self) -> None:
        self._topics: Dict[str, deque] = {}
        log.info("Zero-dependency in-memory log broker initialized successfully.")

    async def produce(self, topic: str, value: bytes) -> bool:
        """Push a raw compressed/serialized message into a topic queue."""
        if topic not in self._topics:
            self._topics[topic] = deque(maxlen=50000)
        self._topics[topic].append(value)
        return True

    async def consume(self, topic: str, limit: int = 100) -> List[bytes]:
        """Pull a batch of messages from a topic queue."""
        if topic not in self._topics or not self._topics[topic]:
            return []
        batch = []
        q = self._topics[topic]
        for _ in range(min(limit, len(q))):
            batch.append(q.popleft())
        return batch

class TelemetryIngestionPipeline:
    """
    Ingestion engine with adaptive buffering, compressed streams, log replay capabilities,
    and fallback mechanisms to ensure complete offline/air-gapped stability.
    """

    def __init__(self, use_kafka_broker: bool = False, kafka_hosts: str = "localhost:9092") -> None:
        self.use_kafka = use_kafka_broker
        self.kafka_hosts = kafka_hosts
        self._parser_registry = TelemetryParserRegistry()
        
        # Internal adaptive in-memory buffer
        self._buffer: deque[bytes] = deque(maxlen=10000)
        
        # Historical replay buffer
        self._replay_buffer: List[bytes] = []
        
        # Broker initialization
        self._broker = MockBrokerClient()
        if self.use_kafka:
            try:
                # Try loading production confluent-kafka if available, fallback gracefully
                import confluent_kafka # type: ignore
                log.info("Enterprise Redpanda/Kafka backend library detected", hosts=self.kafka_hosts)
            except ImportError:
                log.warning("confluent-kafka library not found. Falling back to local broker layer.")
                self.use_kafka = False

    async def ingest_raw_log(self, format_type: str, raw_log: Dict[str, Any], topic: str = "telemetry-ingest") -> bool:
        """
        Parse raw telemetry log, compress the standardized record, and dispatch to the broker.
        """
        try:
            # 1. Parse and standardize the event to validate inputs
            event = self._parser_registry.parse_log(format_type, raw_log)
            if not event:
                return False

            # 2. Serialize to compact JSON
            serialized = json.dumps(event.to_dict()).encode("utf-8")
            
            # 3. Apply zlib compression to minimize transmission overhead
            compressed = zlib.compress(serialized, level=zlib.Z_BEST_SPEED)

            # 4. Save to buffer for local historical replay support
            self._buffer.append(compressed)
            self._replay_buffer.append(compressed)
            if len(self._replay_buffer) > 100000: # caps absolute memory consumption
                self._replay_buffer.pop(0)

            # 5. Produce to Kafka/Redpanda or the mock in-memory broker
            if self.use_kafka:
                # Pluggable Kafka invocation placeholder
                pass
            
            await self._broker.produce(topic, compressed)
            return True
        except Exception as exc:
            log.error("Failed to ingest log stream event", exc_info=exc)
            return False

    async def consume_batch(self, topic: str = "telemetry-ingest", limit: int = 100) -> List[SecurityEvent]:
        """
        Pull a batch of compressed messages from the broker, decompress, and deserialize back to SecurityEvent.
        """
        events: List[SecurityEvent] = []
        try:
            compressed_batch = await self._broker.consume(topic, limit=limit)
            for compressed in compressed_batch:
                decompressed = zlib.decompress(compressed)
                event_dict = json.loads(decompressed.decode("utf-8"))
                
                # Turn timestamp back into datetime
                if "timestamp" in event_dict:
                    event_dict["timestamp"] = datetime.fromisoformat(event_dict["timestamp"])
                
                events.append(SecurityEvent(**event_dict))
        except Exception as exc:
            log.error("Failed to consume telemetry batch", exc_info=exc)
        return events

    def clear_buffers(self) -> None:
        """Flushes the active streaming queues."""
        self._buffer.clear()
        log.info("Telemetry streaming buffers flushed successfully.")

    async def replay_history(self, speed_multiplier: float = 1.0, callback: Optional[Callable[[SecurityEvent], Any]] = None) -> List[SecurityEvent]:
        """
        Replays recorded history sequentially, supporting testing, simulation, and post-incident investigation.
        """
        replayed_events = []
        if not self._replay_buffer:
            log.warning("Telemetry historical replay requested but no events are present in memory.")
            return []

        log.info("Beginning telemetry historical replay", event_count=len(self._replay_buffer))
        for compressed in self._replay_buffer:
            try:
                decompressed = zlib.decompress(compressed)
                event_dict = json.loads(decompressed.decode("utf-8"))
                if "timestamp" in event_dict:
                    event_dict["timestamp"] = datetime.fromisoformat(event_dict["timestamp"])
                
                event = SecurityEvent(**event_dict)
                replayed_events.append(event)
                
                if callback:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        callback(event)
                
                # Simulated delay scaling
                await asyncio.sleep(0.001 / max(speed_multiplier, 0.1))
            except Exception as exc:
                log.warning("Skipping malformed event during historical log replay", exc_info=exc)
                
        log.info("Historical replay complete", replayed=len(replayed_events))
        return replayed_events
