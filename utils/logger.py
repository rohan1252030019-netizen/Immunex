"""
IMMUNEX Structured Logger
Production-grade logging using loguru with JSON output, rotation, and console sink.
"""

import sys
import json
from pathlib import Path
from loguru import logger as _loguru_logger
from config import get_config


def _json_serializer(record: dict) -> str:
    """Custom JSON serialization for loguru records."""
    subset = {
        "timestamp": record["time"].isoformat(),
        "level": record["level"].name,
        "module": record["module"],
        "function": record["function"],
        "line": record["line"],
        "message": record["message"],
    }
    if record["extra"]:
        subset["extra"] = record["extra"]
    if record["exception"]:
        subset["exception"] = str(record["exception"])
    return json.dumps(subset)


def _json_sink(message) -> None:  # type: ignore[type-arg]
    """Write JSON-serialised log records to a file."""
    cfg = get_config().logging
    log_path: Path = cfg.log_file
    with open(log_path, "a", encoding="utf-8") as fh:
        serialized = _json_serializer(message.record)
        fh.write(serialized + "\n")


def setup_logger() -> None:
    """
    Configure loguru:
    - Console sink with human-readable coloured output
    - Rotating JSON file sink
    """
    cfg = get_config().logging

    # Remove the default loguru handler
    _loguru_logger.remove()

    # ── Console sink ──────────────────────────────────────────────────────────
    _loguru_logger.add(
        sys.stderr,
        level=cfg.level,
        colorize=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{module}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        backtrace=True,
        diagnose=True,
    )

    # ── Rotating file sink (plain text with JSON records) ─────────────────────
    _loguru_logger.add(
        str(cfg.log_file),
        level=cfg.level,
        rotation=cfg.rotation,
        retention=cfg.retention,
        compression=cfg.compression,
        serialize=True,          # loguru built-in JSON mode
        backtrace=True,
        diagnose=True,
        encoding="utf-8",
    )

    _loguru_logger.info("IMMUNEX logger initialised", subsystem="logger")


# Re-export loguru's logger so all modules import from this single entry point
get_logger = lambda: _loguru_logger  # noqa: E731

# Convenience alias used throughout the project
log = _loguru_logger
