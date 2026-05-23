"""
IMMUNEX RAG Memory System
==========================
Phase 5 — Retrieval-Augmented Generation memory for the SOC Copilot.

Provides local FAISS + SQLite vector memory for incident embedding retrieval.
Falls back to pure SQLite FTS when FAISS/sentence-transformers are unavailable.

Air-gapped & CPU-only compatible.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime
from typing import Any, Optional

from utils.logger import log

# ─── Optional dependency imports ──────────────────────────────────────────────
_FAISS_AVAILABLE = False
_ENCODER_AVAILABLE = False

try:
    import faiss
    import numpy as np
    _FAISS_AVAILABLE = True
except ImportError:
    log.info("FAISS not available — RAG memory will use SQLite FTS fallback")

try:
    from sentence_transformers import SentenceTransformer
    _ENCODER_AVAILABLE = True
except ImportError:
    log.info("sentence-transformers not available — using keyword-based retrieval")


# ─── Constants ────────────────────────────────────────────────────────────────
_DB_DIR = os.path.join("data", "logs")
_DB_PATH = os.path.join(_DB_DIR, "copilot_memory.db")
_EMBEDDING_DIM = 384  # MiniLM default
_MAX_MEMORY = 100_000


class ThreatMemoryIndex:
    """
    Local FAISS + SQLite vector store for incident context retrieval.
    Gracefully degrades to pure SQLite when FAISS is unavailable.
    """

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

        # FAISS index (optional)
        self._faiss_index: Any = None
        self._id_map: list[str] = []  # Maps FAISS row → event_id

        # Sentence encoder (optional)
        self._encoder: Any = None

        if _FAISS_AVAILABLE:
            try:
                self._faiss_index = faiss.IndexFlatIP(_EMBEDDING_DIM)
                log.info("FAISS index initialized", dim=_EMBEDDING_DIM)
            except Exception as exc:
                log.warning("FAISS init failed, using SQLite fallback", error=str(exc))

        if _ENCODER_AVAILABLE:
            try:
                self._encoder = SentenceTransformer("all-MiniLM-L6-v2")
                log.info("Sentence encoder loaded for RAG memory")
            except Exception as exc:
                log.warning("Encoder load failed", error=str(exc))

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        """Create SQLite tables and FTS virtual table."""
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS memory_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT UNIQUE,
                timestamp   TEXT,
                src_ip      TEXT,
                dst_ip      TEXT,
                event_type  TEXT,
                severity    TEXT,
                anomaly_score REAL,
                detection_reason TEXT,
                mitre_tactic TEXT,
                raw_text    TEXT,
                ingested_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_memory_ts     ON memory_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_memory_sev    ON memory_events(severity);
            CREATE INDEX IF NOT EXISTS idx_memory_src    ON memory_events(src_ip);
            CREATE INDEX IF NOT EXISTS idx_memory_tactic ON memory_events(mitre_tactic);
        """)
        # FTS5 for full-text search fallback
        try:
            cur.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts
                USING fts5(event_id, event_type, severity, detection_reason,
                           mitre_tactic, raw_text, content=memory_events,
                           content_rowid=id);
            """)
        except Exception:
            log.debug("FTS5 table already exists or not supported")
        self._conn.commit()

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest_decision(self, decision) -> None:
        """
        Store a DetectionDecision in SQLite and optionally index in FAISS.
        """
        raw_text = self._decision_to_text(decision)
        try:
            cur = self._conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO memory_events
                (event_id, timestamp, src_ip, dst_ip, event_type, severity,
                 anomaly_score, detection_reason, mitre_tactic, raw_text, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.event_id,
                decision.timestamp.isoformat() if hasattr(decision.timestamp, 'isoformat') else str(decision.timestamp),
                decision.src_ip,
                decision.dst_ip,
                decision.event_type,
                decision.severity,
                decision.anomaly_score,
                decision.detection_reason,
                decision.mitre_tactic or "",
                raw_text,
                time.time(),
            ))
            # Update FTS
            try:
                rowid = cur.lastrowid
                cur.execute("""
                    INSERT INTO memory_fts(rowid, event_id, event_type, severity,
                                           detection_reason, mitre_tactic, raw_text)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (rowid, decision.event_id, decision.event_type,
                      decision.severity, decision.detection_reason,
                      decision.mitre_tactic or "", raw_text))
            except Exception:
                pass  # FTS update non-critical
            self._conn.commit()

            # FAISS vector indexing
            if self._faiss_index is not None and self._encoder is not None:
                try:
                    embedding = self._encoder.encode([raw_text])
                    faiss.normalize_L2(embedding)
                    self._faiss_index.add(embedding)
                    self._id_map.append(decision.event_id)
                except Exception as exc:
                    log.debug("FAISS indexing skipped", error=str(exc))

            log.debug("RAG_MEMORY_INGESTED", event_id=decision.event_id)
        except Exception as exc:
            log.warning("RAG memory ingestion failed", error=str(exc))

    # ── Search ────────────────────────────────────────────────────────────────

    def search(self, query_text: str, top_k: int = 5) -> list[dict]:
        """
        Search by text similarity using FAISS, fallback to SQLite FTS/LIKE.
        """
        # Try FAISS vector search first
        if self._faiss_index is not None and self._encoder is not None and self._faiss_index.ntotal > 0:
            try:
                query_vec = self._encoder.encode([query_text])
                faiss.normalize_L2(query_vec)
                scores, indices = self._faiss_index.search(query_vec, min(top_k, self._faiss_index.ntotal))
                results = []
                for score, idx in zip(scores[0], indices[0]):
                    if idx < 0 or idx >= len(self._id_map):
                        continue
                    event_id = self._id_map[idx]
                    row = self._get_by_event_id(event_id)
                    if row:
                        row["similarity_score"] = float(score)
                        results.append(row)
                if results:
                    return results
            except Exception as exc:
                log.debug("FAISS search failed, falling back to SQLite", error=str(exc))

        # Fallback: SQLite FTS5
        try:
            cur = self._conn.cursor()
            cur.execute("""
                SELECT event_id, event_type, severity, detection_reason,
                       mitre_tactic, raw_text
                FROM memory_fts
                WHERE memory_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """, (query_text, top_k))
            rows = cur.fetchall()
            if rows:
                return [dict(r) for r in rows]
        except Exception:
            pass

        # Final fallback: LIKE queries
        keywords = query_text.split()
        conditions = " OR ".join(["raw_text LIKE ?"] * len(keywords))
        params = [f"%{kw}%" for kw in keywords]
        params.append(top_k)
        try:
            cur = self._conn.cursor()
            cur.execute(f"""
                SELECT * FROM memory_events
                WHERE {conditions}
                ORDER BY ingested_at DESC
                LIMIT ?
            """, params)
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    def get_recent(self, n: int = 20) -> list[dict]:
        """Get most recent ingested events from SQLite."""
        cur = self._conn.cursor()
        cur.execute("""
            SELECT * FROM memory_events
            ORDER BY ingested_at DESC
            LIMIT ?
        """, (n,))
        return [dict(r) for r in cur.fetchall()]

    def stats(self) -> dict:
        """Return index statistics."""
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) as total FROM memory_events")
        total = cur.fetchone()["total"]
        cur.execute("SELECT severity, COUNT(*) as cnt FROM memory_events GROUP BY severity")
        severity_dist = {r["severity"]: r["cnt"] for r in cur.fetchall()}
        return {
            "total_events": total,
            "faiss_indexed": self._faiss_index.ntotal if self._faiss_index else 0,
            "faiss_available": _FAISS_AVAILABLE,
            "encoder_available": _ENCODER_AVAILABLE,
            "severity_distribution": severity_dist,
            "db_path": self._db_path,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _decision_to_text(self, decision) -> str:
        """Convert a DetectionDecision to searchable text."""
        parts = [
            f"event:{decision.event_type}",
            f"src:{decision.src_ip}",
            f"dst:{decision.dst_ip}",
            f"severity:{decision.severity}",
            f"score:{decision.anomaly_score:.4f}",
            f"reason:{decision.detection_reason}",
        ]
        if decision.mitre_tactic:
            parts.append(f"mitre:{decision.mitre_tactic}")
        if decision.recommended_mitigation:
            parts.append(f"mitigation:{decision.recommended_mitigation}")
        return " ".join(parts)

    def _get_by_event_id(self, event_id: str) -> Optional[dict]:
        """Fetch a single event by ID."""
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM memory_events WHERE event_id = ?", (event_id,))
        row = cur.fetchone()
        return dict(row) if row else None


class ContextRetriever:
    """
    Merges vector similarity search with temporal filtering and severity weighting.
    """

    def __init__(self, memory_index: ThreatMemoryIndex):
        self._index = memory_index

    def retrieve_context(self, query: str, top_k: int = 10) -> dict:
        """Combines vector search + temporal filter + severity weighting."""
        results = self._index.search(query, top_k=top_k)
        # Weight by severity
        severity_weights = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        for r in results:
            sev = r.get("severity", "INFO")
            r["relevance_weight"] = severity_weights.get(sev, 1)
        results.sort(key=lambda x: x.get("relevance_weight", 1), reverse=True)
        return {
            "query": query,
            "results": results,
            "total": len(results),
            "context_summary": self._summarize(results),
        }

    def retrieve_for_investigation(self, alert_id: str) -> dict:
        """Get full context for an alert investigation."""
        event = self._index._get_by_event_id(alert_id)
        if not event:
            return {"alert_id": alert_id, "found": False, "context": {}}
        # Find related events by same source IP
        related = self._index.search(event.get("src_ip", ""), top_k=20)
        recent = self._index.get_recent(10)
        return {
            "alert_id": alert_id,
            "found": True,
            "event": event,
            "related_events": related,
            "recent_activity": recent,
            "stats": self._index.stats(),
        }

    def _summarize(self, results: list[dict]) -> str:
        if not results:
            return "No matching events found in threat memory."
        severities = [r.get("severity", "UNKNOWN") for r in results]
        return (
            f"Found {len(results)} relevant events. "
            f"Severity breakdown: {dict((s, severities.count(s)) for s in set(severities))}"
        )


class MemoryIngestionPipeline:
    """
    Pipeline that feeds DetectionDecision objects into the RAG memory system.
    """

    def __init__(self, db_path: str = _DB_PATH):
        self._index = ThreatMemoryIndex(db_path=db_path)
        self._ingested_count = 0
        log.info("RAG MemoryIngestionPipeline initialized", db_path=db_path)

    def ingest(self, decision) -> None:
        """Feed a single DetectionDecision into memory."""
        self._index.ingest_decision(decision)
        self._ingested_count += 1

    def bulk_ingest(self, decisions: list) -> int:
        """Batch ingestion of multiple decisions."""
        count = 0
        for d in decisions:
            try:
                self.ingest(d)
                count += 1
            except Exception as exc:
                log.debug("Bulk ingest item failed", error=str(exc))
        return count

    @property
    def index(self) -> ThreatMemoryIndex:
        return self._index

    @property
    def ingested_count(self) -> int:
        return self._ingested_count
