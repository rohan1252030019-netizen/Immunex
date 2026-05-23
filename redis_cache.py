"""
IMMUNEX Redis Threat Cache
=============================
Phase 7 — Hot alert cache, session management, pub/sub with LocalMemoryCache fallback.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Optional

from utils.logger import log

_REDIS_AVAILABLE = False
try:
    import redis
    _REDIS_AVAILABLE = True
except ImportError:
    pass


class LocalMemoryCache:
    """Thread-safe in-memory cache with TTL support. Always available."""

    def __init__(self):
        self._store: dict[str, tuple[Any, float]] = {}  # key → (value, expiry_ts)
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[Callable]] = {}
        self._counters: dict[str, int] = {}
        self.backend = "local_memory"
        log.info("LocalMemoryCache initialized")

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        with self._lock:
            expiry = time.time() + ttl if ttl > 0 else float("inf")
            self._store[f"immunex:{key}"] = (value, expiry)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            full_key = f"immunex:{key}"
            entry = self._store.get(full_key)
            if entry is None:
                return None
            value, expiry = entry
            if time.time() > expiry:
                del self._store[full_key]
                return None
            return value

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(f"immunex:{key}", None) is not None

    def increment(self, key: str, amount: int = 1) -> int:
        with self._lock:
            full_key = f"immunex:{key}"
            entry = self._store.get(full_key)
            current = 0
            if entry and time.time() <= entry[1]:
                current = int(entry[0]) if entry[0] else 0
            new_val = current + amount
            self._store[full_key] = (new_val, float("inf"))
            return new_val

    def publish(self, channel: str, message: Any) -> int:
        """Publish message to local subscribers."""
        callbacks = self._subscribers.get(channel, [])
        for cb in callbacks:
            try:
                cb(message)
            except Exception:
                pass
        return len(callbacks)

    def subscribe(self, channel: str, callback: Callable) -> None:
        """Subscribe to a channel with a callback."""
        if channel not in self._subscribers:
            self._subscribers[channel] = []
        self._subscribers[channel].append(callback)

    def cache_alert(self, alert_id: str, data: dict, ttl: int = 3600) -> None:
        self.set(f"alert:{alert_id}", json.dumps(data), ttl=ttl)

    def cache_incident(self, incident_id: str, data: dict, ttl: int = 7200) -> None:
        self.set(f"incident:{incident_id}", json.dumps(data), ttl=ttl)

    def cache_agent_state(self, agent_id: str, state: dict, ttl: int = 300) -> None:
        self.set(f"agent:{agent_id}", json.dumps(state), ttl=ttl)

    def get_stats(self) -> dict:
        with self._lock:
            self._cleanup_expired()
            return {"total_keys": len(self._store), "subscribers": {k: len(v) for k, v in self._subscribers.items()},
                    "backend": self.backend}

    def _cleanup_expired(self) -> None:
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]


class RedisThreatCache(LocalMemoryCache):
    """Redis-backed cache. Falls back to LocalMemoryCache parent."""

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        super().__init__()
        self._redis = None
        if _REDIS_AVAILABLE:
            try:
                self._redis = redis.Redis(host=host, port=port, db=db, decode_responses=True, socket_timeout=2)
                self._redis.ping()
                self.backend = "redis"
                log.info("Redis connection established", host=host, port=port)
            except Exception as exc:
                log.warning("Redis unavailable, using local memory", error=str(exc))
                self._redis = None

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        if self._redis:
            try:
                self._redis.setex(f"immunex:{key}", ttl, json.dumps(value) if not isinstance(value, str) else value)
                return
            except Exception:
                pass
        super().set(key, value, ttl)

    def get(self, key: str) -> Optional[Any]:
        if self._redis:
            try:
                val = self._redis.get(f"immunex:{key}")
                if val:
                    try:
                        return json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        return val
                return None
            except Exception:
                pass
        return super().get(key)


def create_cache(host: str = "localhost", port: int = 6379) -> LocalMemoryCache:
    """Factory: returns Redis or LocalMemoryCache based on availability."""
    if _REDIS_AVAILABLE:
        cache = RedisThreatCache(host=host, port=port)
        if cache.backend == "redis":
            return cache
    return LocalMemoryCache()
