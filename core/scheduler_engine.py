"""
IMMUNEX Scheduler Engine
=========================
Layer 4: Autonomous background task scheduler.

Manages periodic execution of:
  - Drift analysis
  - Mutation generation and testing
  - Health monitoring
  - Memory cleanup
  - Metrics aggregation
  - Scheduled retraining

Uses APScheduler with asyncio backend for non-blocking execution.
Falls back to pure asyncio if APScheduler is unavailable.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Callable, Optional, TYPE_CHECKING

from utils.logger import log

if TYPE_CHECKING:
    from core.adaptive_immunization import AdaptiveImmunizationLayer


# ─── Metrics Store ────────────────────────────────────────────────────────────

class MetricsStore:
    """Lightweight in-process metrics aggregation."""

    def __init__(self) -> None:
        self._data: dict[str, list] = {}
        self._start_time = time.time()

    def record(self, metric: str, value: float) -> None:
        if metric not in self._data:
            self._data[metric] = []
        self._data[metric].append((time.time(), value))
        # Keep last 1000 samples per metric
        if len(self._data[metric]) > 1000:
            self._data[metric].pop(0)

    def latest(self, metric: str, default: float = 0.0) -> float:
        pts = self._data.get(metric, [])
        return pts[-1][1] if pts else default

    def summary(self) -> dict:
        import numpy as np
        result = {
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "metrics":        {},
        }
        for name, pts in self._data.items():
            vals = [p[1] for p in pts[-100:]]
            result["metrics"][name] = {
                "latest": round(vals[-1], 4)   if vals else 0.0,
                "mean":   round(float(np.mean(vals)), 4)   if vals else 0.0,
                "max":    round(float(np.max(vals)),  4)   if vals else 0.0,
                "count":  len(vals),
            }
        return result


# ─── Scheduler Engine ─────────────────────────────────────────────────────────

class SchedulerEngine:
    """
    Autonomous background scheduler for IMMUNEX Layer 4 tasks.

    Usage::

        scheduler = SchedulerEngine(layer4)
        await scheduler.start()
        # ... pipeline runs ...
        await scheduler.stop()
    """

    def __init__(
        self,
        layer4: "AdaptiveImmunizationLayer",
        drift_interval_seconds:     int = 300,    # 5 minutes
        mutation_interval_seconds:  int = 600,    # 10 minutes
        health_interval_seconds:    int = 60,     # 1 minute
        memory_cleanup_interval_s:  int = 86400,  # 24 hours
        metrics_interval_seconds:   int = 30,     # 30 seconds
        retrain_interval_seconds:   int = 3600,   # 1 hour (scheduled retrain)
    ) -> None:
        self._layer4    = layer4
        self._intervals = {
            "drift":          drift_interval_seconds,
            "mutation_test":  mutation_interval_seconds,
            "health":         health_interval_seconds,
            "memory_cleanup": memory_cleanup_interval_s,
            "metrics":        metrics_interval_seconds,
            "scheduled_retrain": retrain_interval_seconds,
        }
        self._metrics   = MetricsStore()
        self._running   = False
        self._tasks:     list[asyncio.Task] = []
        self._last_run:  dict[str, float]   = {}
        log.info("SchedulerEngine initialised", intervals=self._intervals)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        log.info("SchedulerEngine starting background tasks")

        # Try APScheduler first
        try:
            await self._start_apscheduler()
        except ImportError:
            log.info("APScheduler not available — using asyncio task loop")
            await self._start_asyncio_loop()

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        log.info("SchedulerEngine stopped")

    def metrics(self) -> dict:
        return self._metrics.summary()

    # ── APScheduler Backend ───────────────────────────────────────────────────

    async def _start_apscheduler(self) -> None:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        self._scheduler = AsyncIOScheduler()
        self._scheduler.add_job(
            self._job_drift_analysis, "interval",
            seconds=self._intervals["drift"], id="drift", misfire_grace_time=30
        )
        self._scheduler.add_job(
            self._job_mutation_test, "interval",
            seconds=self._intervals["mutation_test"], id="mutation", misfire_grace_time=60
        )
        self._scheduler.add_job(
            self._job_health_check, "interval",
            seconds=self._intervals["health"], id="health", misfire_grace_time=10
        )
        self._scheduler.add_job(
            self._job_memory_cleanup, "interval",
            seconds=self._intervals["memory_cleanup"], id="memory_cleanup", misfire_grace_time=3600
        )
        self._scheduler.add_job(
            self._job_metrics_aggregation, "interval",
            seconds=self._intervals["metrics"], id="metrics", misfire_grace_time=10
        )
        self._scheduler.add_job(
            self._job_scheduled_retrain, "interval",
            seconds=self._intervals["scheduled_retrain"], id="scheduled_retrain", misfire_grace_time=300
        )
        self._scheduler.start()
        log.info("SchedulerEngine started with APScheduler backend")

    # ── asyncio Fallback Backend ──────────────────────────────────────────────

    async def _start_asyncio_loop(self) -> None:
        for name, interval in self._intervals.items():
            handler = getattr(self, f"_job_{name}", None)
            if handler:
                task = asyncio.create_task(
                    self._periodic_task(name, interval, handler),
                    name=f"immunex_scheduler_{name}",
                )
                self._tasks.append(task)
        log.info("SchedulerEngine started with asyncio fallback backend")

    async def _periodic_task(
        self,
        name:     str,
        interval: int,
        coro_fn:  Callable,
    ) -> None:
        """Run coro_fn every `interval` seconds until stopped."""
        while self._running:
            await asyncio.sleep(interval)
            if not self._running:
                break
            try:
                await coro_fn()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error(f"Scheduler job '{name}' failed", exc_info=exc)

    # ── Jobs ──────────────────────────────────────────────────────────────────

    async def _job_drift_analysis(self) -> None:
        t0 = time.perf_counter()
        log.debug("Scheduler: drift analysis job started")
        try:
            drift_report = await asyncio.get_event_loop().run_in_executor(
                None, self._layer4._drift.analyse
            )
            if drift_report:
                self._metrics.record("drift_score", drift_report.overall_drift_score)
                self._metrics.record("drift_retrain_recommended",
                                     1.0 if drift_report.retrain_recommended else 0.0)
                log.info(
                    "Scheduler: drift analysis complete",
                    drift_id=drift_report.drift_id,
                    score=round(drift_report.overall_drift_score, 3),
                    retrain=drift_report.retrain_recommended,
                )
        except Exception as exc:
            log.error("Scheduler: drift analysis failed", exc_info=exc)
        finally:
            self._metrics.record("job_drift_latency_ms", (time.perf_counter() - t0) * 1000)
            self._last_run["drift"] = time.time()

    async def _job_mutation_test(self) -> None:
        t0 = time.perf_counter()
        log.debug("Scheduler: mutation test job started")
        try:
            if self._layer4._validation:
                report = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._layer4._validation.evaluate(n_mutations=50)
                )
                self._metrics.record("blind_spot_score", report.blind_spot_score)
                self._metrics.record("mutation_detection_coverage",
                                     1.0 - report.false_negative_rate)
                log.info(
                    "Scheduler: mutation test complete",
                    blind_spot=round(report.blind_spot_score, 3),
                    false_negatives=round(report.false_negative_rate, 3),
                )
        except Exception as exc:
            log.error("Scheduler: mutation test failed", exc_info=exc)
        finally:
            self._metrics.record("job_mutation_latency_ms", (time.perf_counter() - t0) * 1000)
            self._last_run["mutation_test"] = time.time()

    async def _job_health_check(self) -> None:
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            self._metrics.record("cpu_percent", cpu)
            self._metrics.record("memory_percent", mem)
        except ImportError:
            pass

        stats = self._layer4.stats()
        self._metrics.record("campaigns_processed", float(stats.get("campaigns_processed", 0)))
        self._metrics.record("decisions_ingested",  float(stats.get("decisions_ingested", 0)))
        self._metrics.record("memory_entries",
                             float(stats.get("memory", {}).get("total_entries", 0)))
        self._last_run["health"] = time.time()

    async def _job_memory_cleanup(self) -> None:
        t0 = time.perf_counter()
        try:
            deleted = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._layer4._memory.cleanup_old_entries(days=90)
            )
            self._metrics.record("memory_cleanup_deleted", float(deleted))
            log.info("Scheduler: memory cleanup complete", deleted=deleted)
        except Exception as exc:
            log.error("Scheduler: memory cleanup failed", exc_info=exc)
        finally:
            self._metrics.record("job_memory_cleanup_latency_ms", (time.perf_counter() - t0) * 1000)
            self._last_run["memory_cleanup"] = time.time()

    async def _job_metrics_aggregation(self) -> None:
        """Snapshot current metrics for observability endpoints."""
        try:
            stats = self._layer4.stats()
            self._metrics.record("retrain_sessions",
                                 float(stats.get("retraining_sessions", 0)))
            self._metrics.record("memory_cached",
                                 float(stats.get("memory", {}).get("cached_vectors", 0)))
            self._metrics.record("drift_retrain_triggers",
                                 float(stats.get("drift", {}).get("retrain_triggers", 0)))
        except Exception as exc:
            log.debug("Scheduler: metrics aggregation error", exc_info=exc)
        self._last_run["metrics"] = time.time()

    async def _job_scheduled_retrain(self) -> None:
        """Scheduled retraining — runs validation first, retrains only if needed."""
        t0 = time.perf_counter()
        log.info("Scheduler: evaluating scheduled retraining")
        try:
            if self._layer4._validation and self._layer4._retrain:
                report = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._layer4._validation.evaluate(n_mutations=80)
                )
                if report.blind_spot_score > 0.20:
                    log.info(
                        "Scheduler: blind spots warrant retraining",
                        score=report.blind_spot_score,
                    )
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: self._layer4._retrain.retrain(triggered_by="scheduled")
                    )
                    self._metrics.record("scheduled_retrain_improvement", result.improvement)
                    self._metrics.record("scheduled_retrain_success", 1.0 if result.success else 0.0)
                else:
                    log.info(
                        "Scheduler: models healthy — no retraining needed",
                        blind_spot=report.blind_spot_score,
                    )
        except Exception as exc:
            log.error("Scheduler: scheduled retraining failed", exc_info=exc)
        finally:
            self._metrics.record("job_retrain_latency_ms", (time.perf_counter() - t0) * 1000)
            self._last_run["scheduled_retrain"] = time.time()
