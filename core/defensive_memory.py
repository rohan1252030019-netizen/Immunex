"""
IMMUNEX Defensive Memory
=========================
Layer 4: Persistent threat memory for historical attack correlation.

Stores:
  - Attack embeddings (feature vectors) with metadata
  - Attack graph signatures (campaign fingerprints)
  - Recurring attacker behaviour profiles

Provides:
  - Vector similarity search for threat matching
  - Recurring threat scoring
  - Historical match probability
  - Known attack family identification

Storage: SQLite (lightweight, offline, no external deps)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, Optional

import numpy as np

from utils.logger import log

_MEMORY_DB = Path(__file__).parent.parent / "data" / "memory" / "threat_memory.db"
_MEMORY_DB.parent.mkdir(parents=True, exist_ok=True)


# ─── Memory Models ────────────────────────────────────────────────────────────

@dataclass
class ThreatMemoryEntry:
    entry_id:        str
    campaign_id:     str
    attacker_ip:     str
    attack_family:   str           # e.g. "APT29", "ransomware_wave", "insider"
    feature_vector:  np.ndarray   # shape (FEATURE_DIM,)
    graph_signature: str          # SHA-256 of attack graph structure
    stages:          list[str]
    severity:        str
    seen_at:         datetime
    seen_count:      int = 1

    def to_dict(self) -> dict:
        return {
            "entry_id":       self.entry_id,
            "campaign_id":    self.campaign_id,
            "attacker_ip":    self.attacker_ip,
            "attack_family":  self.attack_family,
            "graph_signature": self.graph_signature,
            "stages":         self.stages,
            "severity":       self.severity,
            "seen_at":        self.seen_at.isoformat(),
            "seen_count":     self.seen_count,
        }


@dataclass
class MemoryCorrelationResult:
    query_campaign_id:         str
    recurring_threat_score:    float   # 0=new, 1=exact historical match
    historical_match_probability: float
    known_attack_family:       str
    closest_match_id:          Optional[str]
    closest_similarity:        float
    n_similar_incidents:       int
    time_since_last_seen:      Optional[str]
    recommendation:            str
    correlated_at:             datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "query_campaign_id":          self.query_campaign_id,
            "recurring_threat_score":     round(self.recurring_threat_score, 4),
            "historical_match_probability": round(self.historical_match_probability, 4),
            "known_attack_family":        self.known_attack_family,
            "closest_match_id":           self.closest_match_id,
            "closest_similarity":         round(self.closest_similarity, 4),
            "n_similar_incidents":        self.n_similar_incidents,
            "time_since_last_seen":       self.time_since_last_seen,
            "recommendation":             self.recommendation,
            "correlated_at":              self.correlated_at.isoformat(),
        }


# ─── Defensive Memory ─────────────────────────────────────────────────────────

class DefensiveMemory:
    """
    Persistent threat intelligence memory backed by SQLite.

    On startup it loads all historical embeddings into an in-memory numpy
    array for fast cosine-similarity search without external dependencies.

    Usage::

        memory = DefensiveMemory()
        memory.store(campaign_id, attacker_ip, feature_vector, stages, severity)
        result = memory.correlate(campaign_id, feature_vector, stages)
        log.info("Threat match", family=result.known_attack_family)
    """

    _SIMILARITY_THRESHOLD = 0.85   # cosine similarity to count as "same family"
    _MAX_ENTRIES          = 50_000  # soft cap on stored entries

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _MEMORY_DB
        self._init_db()

        # In-memory cache for fast similarity search
        self._cache_vectors:   list[np.ndarray] = []
        self._cache_entries:   list[dict]        = []
        self._load_cache()

        log.info(
            "DefensiveMemory initialised",
            db=str(self._db_path),
            cached_entries=len(self._cache_entries),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def store(
        self,
        campaign_id:    str,
        attacker_ip:    str,
        feature_vector: np.ndarray,
        stages:         list[str],
        severity:       str,
        attack_family:  str = "unknown",
    ) -> str:
        """Store a threat observation. Returns the entry_id."""
        entry_id    = self._make_entry_id(campaign_id, feature_vector)
        graph_sig   = self._graph_signature(stages)
        now         = datetime.utcnow()
        vec_bytes   = feature_vector.astype(np.float32).tobytes()
        stages_json = json.dumps(stages)

        with self._db() as conn:
            # Upsert — increment seen_count if same entry_id seen again
            existing = conn.execute(
                "SELECT seen_count FROM threat_memory WHERE entry_id = ?", (entry_id,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE threat_memory SET seen_count = ?, last_seen_at = ? WHERE entry_id = ?",
                    (existing[0] + 1, now.isoformat(), entry_id),
                )
            else:
                conn.execute(
                    """INSERT INTO threat_memory
                       (entry_id, campaign_id, attacker_ip, attack_family,
                        feature_vector_blob, graph_signature, stages_json,
                        severity, seen_at, last_seen_at, seen_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        entry_id, campaign_id, attacker_ip, attack_family,
                        vec_bytes, graph_sig, stages_json,
                        severity, now.isoformat(), now.isoformat(),
                    ),
                )
                # Add to cache
                self._cache_vectors.append(feature_vector.astype(np.float32))
                self._cache_entries.append({
                    "entry_id":      entry_id,
                    "campaign_id":   campaign_id,
                    "attacker_ip":   attacker_ip,
                    "attack_family": attack_family,
                    "stages":        stages,
                    "severity":      severity,
                    "seen_at":       now.isoformat(),
                    "seen_count":    1,
                })

        return entry_id

    def correlate(
        self,
        campaign_id:    str,
        feature_vector: np.ndarray,
        stages:         list[str],
    ) -> MemoryCorrelationResult:
        """
        Compare current incident against historical threat memory.
        Returns a MemoryCorrelationResult with match probability and family.
        """
        if len(self._cache_vectors) == 0:
            return MemoryCorrelationResult(
                query_campaign_id=campaign_id,
                recurring_threat_score=0.0,
                historical_match_probability=0.0,
                known_attack_family="no_history",
                closest_match_id=None,
                closest_similarity=0.0,
                n_similar_incidents=0,
                time_since_last_seen=None,
                recommendation="No historical data. First-time threat — proceed with full investigation.",
            )

        qvec = feature_vector.astype(np.float32)
        similarities = [self._cosine_sim(qvec, v) for v in self._cache_vectors]
        sims_arr = np.array(similarities, dtype=np.float32)

        top_idx = int(np.argmax(sims_arr))
        closest_sim = float(sims_arr[top_idx])
        n_similar = int(np.sum(sims_arr >= self._SIMILARITY_THRESHOLD))

        closest = self._cache_entries[top_idx] if self._cache_entries else None
        closest_id     = closest["entry_id"]     if closest else None
        attack_family  = closest["attack_family"] if closest else "unknown"
        seen_at_str    = closest["seen_at"]       if closest else None

        # Time since last seen
        time_since = None
        if seen_at_str:
            try:
                seen_dt   = datetime.fromisoformat(seen_at_str)
                delta     = datetime.utcnow() - seen_dt
                time_since = self._format_timedelta(delta)
            except Exception:
                pass

        # Recurring threat score: blend of similarity and frequency
        seen_count = closest["seen_count"] if closest else 0
        frequency_bonus = min(seen_count / 10.0, 0.3)
        recurring_score = float(np.clip(closest_sim * 0.7 + frequency_bonus, 0.0, 1.0))

        # Historical match probability (how likely this is the same threat actor)
        stage_overlap = self._stage_overlap(stages, closest["stages"] if closest else [])
        match_prob = float(np.clip(0.6 * closest_sim + 0.4 * stage_overlap, 0.0, 1.0))

        recommendation = self._build_recommendation(
            recurring_score, match_prob, attack_family, n_similar, time_since
        )

        return MemoryCorrelationResult(
            query_campaign_id=campaign_id,
            recurring_threat_score=recurring_score,
            historical_match_probability=match_prob,
            known_attack_family=attack_family,
            closest_match_id=closest_id,
            closest_similarity=closest_sim,
            n_similar_incidents=n_similar,
            time_since_last_seen=time_since,
            recommendation=recommendation,
        )

    def list_recent(self, n: int = 20) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT entry_id, campaign_id, attacker_ip, attack_family, severity, seen_at, seen_count "
                "FROM threat_memory ORDER BY seen_at DESC LIMIT ?",
                (n,),
            ).fetchall()
        return [
            {
                "entry_id":      r[0], "campaign_id": r[1], "attacker_ip":   r[2],
                "attack_family": r[3], "severity":    r[4], "seen_at":       r[5],
                "seen_count":    r[6],
            }
            for r in rows
        ]

    def cleanup_old_entries(self, days: int = 90) -> int:
        """Remove entries older than `days`. Returns count deleted."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        with self._db() as conn:
            n = conn.execute(
                "DELETE FROM threat_memory WHERE last_seen_at < ?", (cutoff,)
            ).rowcount
        if n > 0:
            self._load_cache()   # Refresh in-memory cache
            log.info("DefensiveMemory: cleaned old entries", deleted=n, cutoff_days=days)
        return n

    def stats(self) -> dict:
        with self._db() as conn:
            total    = conn.execute("SELECT COUNT(*) FROM threat_memory").fetchone()[0]
            families = conn.execute(
                "SELECT attack_family, COUNT(*) FROM threat_memory GROUP BY attack_family"
            ).fetchall()
        return {
            "total_entries":      total,
            "cached_vectors":     len(self._cache_vectors),
            "attack_families":    {f[0]: f[1] for f in families},
        }

    # ── Database ──────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_memory (
                    entry_id            TEXT PRIMARY KEY,
                    campaign_id         TEXT NOT NULL,
                    attacker_ip         TEXT NOT NULL,
                    attack_family       TEXT NOT NULL DEFAULT 'unknown',
                    feature_vector_blob BLOB NOT NULL,
                    graph_signature     TEXT NOT NULL,
                    stages_json         TEXT NOT NULL,
                    severity            TEXT NOT NULL,
                    seen_at             TEXT NOT NULL,
                    last_seen_at        TEXT NOT NULL,
                    seen_count          INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_seen_at ON threat_memory(seen_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_family ON threat_memory(attack_family)")

    def _load_cache(self) -> None:
        self._cache_vectors = []
        self._cache_entries = []
        with self._db() as conn:
            rows = conn.execute(
                "SELECT entry_id, campaign_id, attacker_ip, attack_family, "
                "feature_vector_blob, stages_json, severity, seen_at, seen_count "
                "FROM threat_memory ORDER BY seen_at DESC LIMIT ?",
                (self._MAX_ENTRIES,),
            ).fetchall()
        for r in rows:
            try:
                vec = np.frombuffer(r[4], dtype=np.float32).copy()
                self._cache_vectors.append(vec)
                self._cache_entries.append({
                    "entry_id":      r[0],
                    "campaign_id":   r[1],
                    "attacker_ip":   r[2],
                    "attack_family": r[3],
                    "stages":        json.loads(r[5]),
                    "severity":      r[6],
                    "seen_at":       r[7],
                    "seen_count":    r[8],
                })
            except Exception:
                pass

    @contextmanager
    def _db(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
        na, nb = np.linalg.norm(a), np.linalg.norm(b)
        if na < 1e-8 or nb < 1e-8:
            return 0.0
        return float(np.clip(np.dot(a, b) / (na * nb), 0.0, 1.0))

    @staticmethod
    def _make_entry_id(campaign_id: str, vec: np.ndarray) -> str:
        payload = campaign_id + vec.tobytes().hex()[:32]
        return hashlib.sha256(payload.encode()).hexdigest()[:24]

    @staticmethod
    def _graph_signature(stages: list[str]) -> str:
        return hashlib.sha256("→".join(sorted(stages)).encode()).hexdigest()[:16]

    @staticmethod
    def _stage_overlap(a: list[str], b: list[str]) -> float:
        if not a or not b:
            return 0.0
        sa, sb = set(a), set(b)
        return len(sa & sb) / len(sa | sb)

    @staticmethod
    def _format_timedelta(delta: timedelta) -> str:
        secs = int(delta.total_seconds())
        if secs < 60:
            return f"{secs}s ago"
        elif secs < 3600:
            return f"{secs // 60}m ago"
        elif secs < 86400:
            return f"{secs // 3600}h ago"
        else:
            return f"{secs // 86400}d ago"

    def _build_recommendation(
        self,
        recurring_score: float,
        match_prob:      float,
        family:          str,
        n_similar:       int,
        time_since:      Optional[str],
    ) -> str:
        if recurring_score > 0.85:
            return (
                f"HIGH CONFIDENCE recurring threat from family '{family}'. "
                f"{n_similar} similar incidents found. Last seen: {time_since}. "
                "Apply pre-computed countermeasures immediately."
            )
        elif recurring_score > 0.6:
            return (
                f"Probable recurring threat (family: '{family}', match: {match_prob:.0%}). "
                f"Cross-reference {n_similar} historical incidents. Escalate to Tier 2."
            )
        elif recurring_score > 0.3:
            return (
                f"Possible variant of known threat '{family}'. "
                "Partial pattern match — investigate behavioural deviations."
            )
        else:
            return "Novel threat pattern — no strong historical match. Full investigation required."
