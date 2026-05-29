import os
import time
from typing import List, Dict, Any

from utils.logger import log

class ClickHouseTelemetryLogger:
    """Production ClickHouse client with resilient local SQLite metrics auditing fallback."""
    
    def __init__(self) -> None:
        self.host = os.getenv("CLICKHOUSE_HOST", "localhost")
        self.port = int(os.getenv("CLICKHOUSE_PORT", "8123"))
        self.client: Any = None
        self.backend = "local_sqlite"
        
        try:
            import clickhouse_connect
            # Fast, native HTTP ClickHouse client
            self.client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                username="default",
                password="",
                database="default",
                connect_timeout=5
            )
            self.backend = "clickhouse"
            log.info("ClickHouse Client connected successfully for high-throughput logging")
        except Exception:
            log.warning("ClickHouse unavailable. Falling back to local transactional SQLite metrics logs")

    def log_telemetry_event(self, event_data: Dict[str, Any]) -> bool:
        """Logs a transaction telemetry event asynchronously."""
        if self.backend == "clickhouse" and self.client:
            try:
                # Structure telemetry values into partition schema list
                row = [
                    event_data.get("event_id", f"EVT-{int(time.time())}"),
                    event_data.get("account_number", "unknown"),
                    event_data.get("src_ip", "0.0.0.0"),
                    event_data.get("dst_ip", "0.0.0.0"),
                    event_data.get("channel", "MOBILE_BANKING"),
                    event_data.get("event_type", "transaction_execution"),
                    float(event_data.get("transaction_amount", 0.0)),
                    float(event_data.get("transfer_velocity", 0.0)),
                    float(event_data.get("typing_speed_wpm", 0.0)),
                    float(event_data.get("key_latency_ms", 0.0)),
                    int(event_data.get("forgery_score", 0)),
                    event_data.get("underwriting_verdict", "MANUAL_REVIEW")
                ]
                self.client.insert("system_telemetry", [row], column_names=[
                    "event_id", "account_number", "src_ip", "dst_ip", "channel",
                    "event_type", "transaction_amount", "transfer_velocity",
                    "typing_speed_wpm", "key_latency_ms", "forgery_score",
                    "underwriting_verdict"
                ])
                return True
            except Exception as exc:
                log.error("ClickHouse insert failed. Redirecting to SQLite fallback", exc_info=exc)
                
        # Write to SQLite / JSON logs fallback
        return self._write_sqlite_fallback(event_data)

    def _write_sqlite_fallback(self, event_data: Dict[str, Any]) -> bool:
        """Saves telemetry event to local SQLite cache table."""
        try:
            import sqlite3
            db_path = "data/logs/telemetry_fallback.db"
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS telemetry_logs (
                        event_id TEXT PRIMARY KEY,
                        account_number TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        channel TEXT,
                        event_type TEXT,
                        transaction_amount REAL,
                        transfer_velocity REAL,
                        typing_speed_wpm REAL,
                        key_latency_ms REAL,
                        forgery_score INTEGER,
                        underwriting_verdict TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("""
                    INSERT INTO telemetry_logs (
                        event_id, account_number, src_ip, dst_ip, channel,
                        event_type, transaction_amount, transfer_velocity,
                        typing_speed_wpm, key_latency_ms, forgery_score,
                        underwriting_verdict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_data.get("event_id", f"EVT-{int(time.time())}"),
                    event_data.get("account_number", "unknown"),
                    event_data.get("src_ip", "0.0.0.0"),
                    event_data.get("dst_ip", "0.0.0.0"),
                    event_data.get("channel", "MOBILE_BANKING"),
                    event_data.get("event_type", "transaction_execution"),
                    float(event_data.get("transaction_amount", 0.0)),
                    float(event_data.get("transfer_velocity", 0.0)),
                    float(event_data.get("typing_speed_wpm", 0.0)),
                    float(event_data.get("key_latency_ms", 0.0)),
                    int(event_data.get("forgery_score", 0)),
                    event_data.get("underwriting_verdict", "MANUAL_REVIEW")
                ))
                conn.commit()
            return True
        except Exception as exc:
            log.critical("Total telemetry persistence system failure!", exc_info=exc)
            return False
