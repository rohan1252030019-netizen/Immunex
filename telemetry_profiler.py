"""
IMMUNEX Telemetry Profiler
=============================
Phase 7 — Internal observability engine: latency profiling, throughput metrics,
CPU/RAM monitoring, Prometheus-compatible exports.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from utils.logger import log

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class TelemetryProfiler:
    """Enterprise observability engine for IMMUNEX internals."""

    def __init__(self):
        self._lock = threading.Lock()
        self._event_count = 0
        self._start_time = time.time()

        # Rolling windows for latency tracking (deque of (timestamp, value_ms))
        self._latencies: dict[str, deque] = {
            "reasoning": deque(maxlen=1000),
            "graph_traversal": deque(maxlen=1000),
            "copilot": deque(maxlen=1000),
            "websocket": deque(maxlen=1000),
            "mitigation": deque(maxlen=1000),
            "ingestion": deque(maxlen=1000),
        }

        # EPS tracking
        self._eps_window = deque(maxlen=60)  # 1-minute window of per-second counts
        self._current_second_count = 0
        self._current_second = int(time.time())

        log.info("TelemetryProfiler initialized", psutil=_PSUTIL_AVAILABLE)

    def record_event(self) -> None:
        """Record a single event for EPS calculation."""
        with self._lock:
            self._event_count += 1
            now_sec = int(time.time())
            if now_sec != self._current_second:
                self._eps_window.append(self._current_second_count)
                self._current_second_count = 0
                self._current_second = now_sec
            self._current_second_count += 1

    def record_latency(self, operation: str, ms: float) -> None:
        """Record a latency measurement for an operation."""
        if operation in self._latencies:
            self._latencies[operation].append((time.time(), ms))

    def get_metrics(self) -> dict:
        """Get all current metrics."""
        with self._lock:
            uptime = time.time() - self._start_time
            metrics = {
                "uptime_seconds": round(uptime, 2),
                "total_events": self._event_count,
                "eps": self._calculate_eps(),
                "latencies": self._calculate_latencies(),
            }

            if _PSUTIL_AVAILABLE:
                try:
                    metrics["cpu_percent"] = psutil.cpu_percent(interval=0)
                    mem = psutil.virtual_memory()
                    metrics["memory_percent"] = mem.percent
                    metrics["memory_used_mb"] = round(mem.used / (1024 * 1024), 1)
                except Exception:
                    metrics["cpu_percent"] = 0.0
                    metrics["memory_percent"] = 0.0
            else:
                metrics["cpu_percent"] = 0.0
                metrics["memory_percent"] = 0.0

            return metrics

    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus text format."""
        m = self.get_metrics()
        lines = [
            "# HELP immunex_events_total Total events processed",
            "# TYPE immunex_events_total counter",
            f'immunex_events_total {m["total_events"]}',
            "# HELP immunex_eps Events per second",
            "# TYPE immunex_eps gauge",
            f'immunex_eps {m["eps"]:.2f}',
            "# HELP immunex_uptime_seconds Uptime in seconds",
            "# TYPE immunex_uptime_seconds gauge",
            f'immunex_uptime_seconds {m["uptime_seconds"]:.2f}',
            "# HELP immunex_cpu_percent CPU utilization",
            "# TYPE immunex_cpu_percent gauge",
            f'immunex_cpu_percent {m.get("cpu_percent", 0):.1f}',
            "# HELP immunex_memory_percent Memory utilization",
            "# TYPE immunex_memory_percent gauge",
            f'immunex_memory_percent {m.get("memory_percent", 0):.1f}',
        ]
        for op, lat in m.get("latencies", {}).items():
            lines.append(f'# HELP immunex_{op}_latency_ms Average latency in ms')
            lines.append(f'# TYPE immunex_{op}_latency_ms gauge')
            lines.append(f'immunex_{op}_latency_ms {lat.get("avg_ms", 0):.2f}')
        return "\n".join(lines) + "\n"

    def get_dashboard_metrics(self) -> dict:
        """Get metrics formatted for dashboard consumption."""
        m = self.get_metrics()
        return {
            "eps": round(m["eps"], 1),
            "total_events": m["total_events"],
            "uptime": m["uptime_seconds"],
            "cpu": m.get("cpu_percent", 0),
            "memory": m.get("memory_percent", 0),
            "latencies": {op: lat.get("avg_ms", 0) for op, lat in m.get("latencies", {}).items()},
        }

    def _calculate_eps(self) -> float:
        if not self._eps_window:
            return 0.0
        return sum(self._eps_window) / max(len(self._eps_window), 1)

    def _calculate_latencies(self) -> dict:
        result = {}
        now = time.time()
        for op, dq in self._latencies.items():
            # Only consider last 60 seconds
            recent = [(ts, ms) for ts, ms in dq if now - ts < 60]
            if recent:
                values = [ms for _, ms in recent]
                result[op] = {
                    "avg_ms": round(sum(values) / len(values), 2),
                    "min_ms": round(min(values), 2),
                    "max_ms": round(max(values), 2),
                    "count": len(values),
                }
            else:
                result[op] = {"avg_ms": 0, "min_ms": 0, "max_ms": 0, "count": 0}
        return result
