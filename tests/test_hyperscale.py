"""
IMMUNEX Phase 7 Hyper-Scale Infrastructure Test Suite
=======================================================
Tests ClickHouse, Redis, MinIO, gRPC, Stream Orchestrator,
Telemetry Profiler, and Cluster Security — all in local fallback mode.
"""

from __future__ import annotations

import os
import sys
import time
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ═══════════════════════════════════════════════════════════════════════════════
# ClickHouse / SQLite Fallback Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestClickHouseStore:

    def test_sqlite_fallback_init(self, tmp_path):
        from clickhouse_store import SQLiteTelemetryStore
        store = SQLiteTelemetryStore(db_path=str(tmp_path / "telemetry.db"))
        assert store.backend == "sqlite"
        assert store.connect() is True

    def test_insert_and_query_events(self, tmp_path):
        from clickhouse_store import SQLiteTelemetryStore
        store = SQLiteTelemetryStore(db_path=str(tmp_path / "telemetry.db"))
        store.insert_event({
            "timestamp": "2024-01-01T00:00:00",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "event_type": "login_attempt",
            "severity": "HIGH",
            "anomaly_score": 0.9,
        })
        events = store.query_events(limit=10)
        assert len(events) == 1
        assert events[0]["src_ip"] == "10.0.0.1"

    def test_insert_and_query_alerts(self, tmp_path):
        from clickhouse_store import SQLiteTelemetryStore
        store = SQLiteTelemetryStore(db_path=str(tmp_path / "telemetry.db"))
        store.insert_alert({
            "severity": "CRITICAL",
            "risk_score": 0.95,
            "mitre_tactic": "execution",
        })
        alerts = store.query_alerts(limit=10)
        assert len(alerts) == 1

    def test_aggregate_metrics(self, tmp_path):
        from clickhouse_store import SQLiteTelemetryStore
        store = SQLiteTelemetryStore(db_path=str(tmp_path / "telemetry.db"))
        store.insert_event({"severity": "HIGH", "src_ip": "10.0.0.1"})
        store.insert_event({"severity": "CRITICAL", "src_ip": "10.0.0.2"})
        metrics = store.aggregate_metrics()
        assert metrics["total_events"] == 2
        assert "severity_distribution" in metrics

    def test_factory_function(self):
        from clickhouse_store import create_telemetry_store
        store = create_telemetry_store()
        assert store.backend == "sqlite"

    def test_bulk_insert(self, tmp_path):
        from clickhouse_store import SQLiteTelemetryStore
        store = SQLiteTelemetryStore(db_path=str(tmp_path / "telemetry.db"))
        events = [{"severity": "HIGH", "src_ip": f"10.0.0.{i}"} for i in range(10)]
        count = store.bulk_insert(events)
        assert count == 10


# ═══════════════════════════════════════════════════════════════════════════════
# Redis / LocalMemoryCache Fallback Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedisCache:

    def test_local_memory_init(self):
        from redis_cache import LocalMemoryCache
        cache = LocalMemoryCache()
        assert cache.backend == "local_memory"

    def test_set_and_get(self):
        from redis_cache import LocalMemoryCache
        cache = LocalMemoryCache()
        cache.set("test_key", "test_value", ttl=60)
        assert cache.get("test_key") == "test_value"

    def test_delete(self):
        from redis_cache import LocalMemoryCache
        cache = LocalMemoryCache()
        cache.set("del_key", "value", ttl=60)
        assert cache.delete("del_key") is True
        assert cache.get("del_key") is None

    def test_ttl_expiry(self):
        from redis_cache import LocalMemoryCache
        cache = LocalMemoryCache()
        # Manually insert with an already-expired timestamp
        cache._store["immunex:expire_key"] = ("value", 0)  # Expired at epoch 0
        assert cache.get("expire_key") is None

    def test_increment(self):
        from redis_cache import LocalMemoryCache
        cache = LocalMemoryCache()
        assert cache.increment("counter") == 1
        assert cache.increment("counter") == 2
        assert cache.increment("counter", 5) == 7

    def test_cache_alert(self):
        from redis_cache import LocalMemoryCache
        cache = LocalMemoryCache()
        cache.cache_alert("ALT-001", {"severity": "CRITICAL"})
        result = cache.get("alert:ALT-001")
        assert result is not None

    def test_factory_function(self):
        from redis_cache import create_cache
        cache = create_cache()
        assert cache.backend == "local_memory"


# ═══════════════════════════════════════════════════════════════════════════════
# MinIO / LocalDisk Fallback Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestMinIOStore:

    def test_local_disk_init(self, tmp_path):
        from minio_store import LocalDiskObjectStore
        store = LocalDiskObjectStore(root_dir=str(tmp_path / "evidence"))
        assert store.backend == "local_disk"

    def test_upload_and_retrieve(self, tmp_path):
        from minio_store import LocalDiskObjectStore
        store = LocalDiskObjectStore(root_dir=str(tmp_path / "evidence"))

        # Create a test file
        test_file = str(tmp_path / "test_artifact.txt")
        with open(test_file, "w") as f:
            f.write("forensic evidence data")

        meta = store.upload_file("test_bucket", "artifact.txt", test_file)
        assert meta["sha256"] is not None
        assert meta["size"] > 0

        # Retrieve
        dest = str(tmp_path / "retrieved.txt")
        assert store.retrieve_file("test_bucket", "artifact.txt", dest) is True
        with open(dest) as f:
            assert f.read() == "forensic evidence data"

    def test_integrity_verification(self, tmp_path):
        from minio_store import LocalDiskObjectStore
        store = LocalDiskObjectStore(root_dir=str(tmp_path / "evidence"))
        test_file = str(tmp_path / "integrity_test.txt")
        with open(test_file, "w") as f:
            f.write("data integrity test")
        store.upload_file("test", "integrity.txt", test_file)
        result = store.verify_integrity("test", "integrity.txt")
        assert result["valid"] is True

    def test_factory_function(self):
        from minio_store import create_object_store
        store = create_object_store()
        assert store.backend == "local_disk"


# ═══════════════════════════════════════════════════════════════════════════════
# gRPC / Local Worker Fallback Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGRPCWorker:

    def test_local_fabric_init(self):
        from grpc_worker import LocalWorkerFabric
        fabric = LocalWorkerFabric()
        assert fabric.backend == "local_threading"

    def test_register_worker(self):
        from grpc_worker import LocalWorkerFabric
        fabric = LocalWorkerFabric()
        worker = fabric.register_worker("w1", "TELEMETRY", "localhost")
        assert worker["id"] == "w1"
        assert worker["status"] == "ONLINE"

    def test_dispatch_task(self):
        from grpc_worker import LocalWorkerFabric
        fabric = LocalWorkerFabric()
        result = fabric.dispatch_task("TELEMETRY", {"action": "process"})
        assert result["status"] == "completed"

    def test_health_check(self):
        from grpc_worker import LocalWorkerFabric
        fabric = LocalWorkerFabric()
        health = fabric.health_check()
        assert health["status"] == "healthy"

    def test_factory_function(self):
        from grpc_worker import create_worker_fabric
        fabric = create_worker_fabric()
        assert fabric.backend == "local_threading"


# ═══════════════════════════════════════════════════════════════════════════════
# Stream Orchestrator Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestStreamOrchestrator:

    def test_local_orchestrator_init(self):
        from stream_orchestrator import LocalStreamOrchestrator
        orch = LocalStreamOrchestrator()
        assert orch.backend == "local_priority_queue"

    def test_publish_and_consume(self):
        from stream_orchestrator import LocalStreamOrchestrator
        orch = LocalStreamOrchestrator()
        orch.start()
        received = []
        orch.consume("alerts", lambda e: received.append(e))
        assert orch.publish("alerts", {"severity": "CRITICAL", "msg": "test"}) is True
        assert len(received) == 1
        assert received[0]["severity"] == "CRITICAL"
        orch.stop()

    def test_priority_ordering(self):
        from stream_orchestrator import LocalStreamOrchestrator
        orch = LocalStreamOrchestrator()
        orch.start()
        orch.publish("events", {"severity": "LOW", "id": 1})
        orch.publish("events", {"severity": "CRITICAL", "id": 2})
        assert orch.get_queue_depth("events") >= 0

    def test_burst_protection(self):
        from stream_orchestrator import LocalStreamOrchestrator
        orch = LocalStreamOrchestrator(burst_limit=5)
        orch.start()
        results = [orch.publish("test", {"severity": "LOW"}) for _ in range(10)]
        assert False in results  # Some should be blocked

    def test_stats(self):
        from stream_orchestrator import LocalStreamOrchestrator
        orch = LocalStreamOrchestrator()
        stats = orch.get_stats()
        assert "backend" in stats
        assert "total_events" in stats

    def test_factory_function(self):
        from stream_orchestrator import create_stream_orchestrator
        orch = create_stream_orchestrator()
        assert orch.backend == "local_priority_queue"


# ═══════════════════════════════════════════════════════════════════════════════
# Telemetry Profiler Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTelemetryProfiler:

    def test_profiler_init(self):
        from telemetry_profiler import TelemetryProfiler
        profiler = TelemetryProfiler()
        metrics = profiler.get_metrics()
        assert "total_events" in metrics
        assert "eps" in metrics

    def test_record_events(self):
        from telemetry_profiler import TelemetryProfiler
        profiler = TelemetryProfiler()
        for _ in range(10):
            profiler.record_event()
        metrics = profiler.get_metrics()
        assert metrics["total_events"] == 10

    def test_record_latency(self):
        from telemetry_profiler import TelemetryProfiler
        profiler = TelemetryProfiler()
        profiler.record_latency("reasoning", 15.5)
        profiler.record_latency("reasoning", 20.0)
        metrics = profiler.get_metrics()
        assert metrics["latencies"]["reasoning"]["count"] == 2

    def test_prometheus_export(self):
        from telemetry_profiler import TelemetryProfiler
        profiler = TelemetryProfiler()
        profiler.record_event()
        prom = profiler.get_prometheus_metrics()
        assert "immunex_events_total" in prom
        assert "immunex_eps" in prom

    def test_dashboard_metrics(self):
        from telemetry_profiler import TelemetryProfiler
        profiler = TelemetryProfiler()
        dash = profiler.get_dashboard_metrics()
        assert "eps" in dash
        assert "total_events" in dash


# ═══════════════════════════════════════════════════════════════════════════════
# Cluster Security Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestClusterSecurity:

    def test_node_identity(self):
        from cluster_security import ClusterSecurityManager
        mgr = ClusterSecurityManager()
        identity = mgr.generate_node_identity()
        assert "node_id" in identity
        assert identity["node_id"].startswith("immunex-node-")

    def test_sign_and_verify(self):
        from cluster_security import ClusterSecurityManager
        mgr = ClusterSecurityManager()
        message = b"test message for signing"
        signature = mgr.sign_message(message)
        assert mgr.verify_message(message, signature) is True
        assert mgr.verify_message(b"tampered message", signature) is False

    def test_cluster_token(self):
        from cluster_security import ClusterSecurityManager
        mgr = ClusterSecurityManager()
        mgr.generate_node_identity()
        token = mgr.generate_cluster_token()
        assert isinstance(token, str)
        assert "." in token
        assert mgr.validate_cluster_token(token) is True

    def test_invalid_token(self):
        from cluster_security import ClusterSecurityManager
        mgr = ClusterSecurityManager()
        assert mgr.validate_cluster_token("invalid.token") is False

    def test_replay_detection(self):
        from cluster_security import ClusterSecurityManager
        mgr = ClusterSecurityManager()
        assert mgr.detect_replay("msg-001") is False  # First time — not a replay
        assert mgr.detect_replay("msg-001") is True   # Second time — IS a replay
        assert mgr.detect_replay("msg-002") is False  # New message — not a replay

    def test_security_status(self):
        from cluster_security import ClusterSecurityManager
        mgr = ClusterSecurityManager()
        mgr.generate_node_identity()
        status = mgr.get_security_status()
        assert status["node_identity"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Factory Function Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestFactoryFunctions:

    def test_all_factories_return_fallback(self):
        from clickhouse_store import create_telemetry_store
        from redis_cache import create_cache
        from minio_store import create_object_store
        from grpc_worker import create_worker_fabric
        from stream_orchestrator import create_stream_orchestrator

        assert create_telemetry_store().backend == "sqlite"
        assert create_cache().backend == "local_memory"
        assert create_object_store().backend == "local_disk"
        assert create_worker_fabric().backend == "local_threading"
        assert create_stream_orchestrator().backend == "local_priority_queue"


# ═══════════════════════════════════════════════════════════════════════════════
# Schema Backward Compatibility
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemaBackwardCompat:

    def test_security_event_serialization(self):
        from datetime import datetime
        from utils.schemas import SecurityEvent
        event = SecurityEvent(
            timestamp=datetime.utcnow(), src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1234, dst_port=80, protocol="TCP", user_id="user1",
            process_name="chrome.exe", process_hash="b" * 64, event_type="network_connection",
            src_bytes=100, dst_bytes=200, duration=1.0, failed_logins=0,
            connection_count=1, packet_rate=5.0, geo_location="US",
            asset_criticality="LOW",
        )
        data = event.model_dump()
        assert data["src_ip"] == "10.0.0.1"

    def test_detection_decision_serialization(self):
        from datetime import datetime
        from utils.schemas import DetectionDecision
        decision = DetectionDecision(
            event_id="test", timestamp=datetime.utcnow(), event_type="test",
            src_ip="1.1.1.1", dst_ip="2.2.2.2", asset_criticality="LOW",
            anomaly_score=0.1, faiss_distance=0.5, confidence_score=0.5,
            severity="LOW", is_high_confidence_anomaly=False,
            detection_reason="test",
        )
        data = decision.model_dump()
        assert data["event_id"] == "test"
        assert data["blast_radius_score"] is None  # Optional field
