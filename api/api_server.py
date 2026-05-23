"""
IMMUNEX API Server
===================
Production FastAPI application for IMMUNEX Layer 4.

Run:
    uvicorn api.api_server:app --host 0.0.0.0 --port 8080 --workers 1

Or integrated via:
    python main.py --api
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.middleware import LoggingTimingMiddleware, RateLimitMiddleware
from api.routes import router
from utils.logger import log, setup_logger


# ─── Shared State ─────────────────────────────────────────────────────────────

_SHARED_STATE: dict[str, Any] = {
    "start_time":         time.time(),
    "pipeline_stats":     {"total_events": 0, "total_alerts": 0, "total_responses": 0},
    "recent_alerts":      [],
    "recent_mitigations": [],
    "top_attackers":      [],
    "layer2":             None,
    "layer3":             None,
    "layer4":             None,
    "scheduler":          None,
    "anomaly_engine":     None,
    "vector_engine":      None,
    "ollama_status":      "unknown",
}


def get_shared_state() -> dict:
    return _SHARED_STATE


def update_state(**kwargs) -> None:
    _SHARED_STATE.update(kwargs)


def record_alert(alert_dict: dict) -> None:
    _SHARED_STATE["recent_alerts"].append(alert_dict)
    if len(_SHARED_STATE["recent_alerts"]) > 500:
        _SHARED_STATE["recent_alerts"] = _SHARED_STATE["recent_alerts"][-500:]
    _SHARED_STATE["pipeline_stats"]["total_alerts"] += 1


def record_mitigation(mitigation_dict: dict) -> None:
    _SHARED_STATE["recent_mitigations"].append(mitigation_dict)
    if len(_SHARED_STATE["recent_mitigations"]) > 200:
        _SHARED_STATE["recent_mitigations"] = _SHARED_STATE["recent_mitigations"][-200:]
    _SHARED_STATE["pipeline_stats"]["total_responses"] += 1


def increment_events() -> None:
    _SHARED_STATE["pipeline_stats"]["total_events"] += 1


# ─── Application Factory ──────────────────────────────────────────────────────

def create_app(immunex_state: dict | None = None) -> FastAPI:
    """
    Create and configure the IMMUNEX FastAPI application.

    Args:
        immunex_state: Pre-populated state dict. If not provided, uses the
                       module-level shared state.
    """
    state_to_use = immunex_state if immunex_state is not None else _SHARED_STATE

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        setup_logger()
        log.info("IMMUNEX API server starting", version="5.0.0-LAYER5")
        # Always set state from both lifespan AND at creation time
        app.state.immunex = state_to_use
        yield
        log.info("IMMUNEX API server shutting down")

    app = FastAPI(
        title="IMMUNEX Autonomous SOC API",
        description=(
            "Layer 5 — Enterprise Zero-Trust Operations & Full System Orchestration.\n\n"
            "Enterprise-grade autonomous cyber-defense REST API. "
            "CPU-only, air-gapped deployment compatible."
        ),
        version="5.0.0-LAYER5",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Eagerly attach state so TestClient (which skips lifespan) also works
    app.state.immunex = state_to_use

    # ── Middleware ────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RateLimitMiddleware, default_rate=60, heavy_rate=5)
    app.add_middleware(LoggingTimingMiddleware)

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(router, prefix="")

    # ── Phase 5: WebSocket Copilot Endpoint ──────────────────────────────────
    try:
        from websocket_server import WebSocketConnectionManager, copilot_websocket_endpoint
        ws_manager = WebSocketConnectionManager()
        state_to_use["ws_manager"] = ws_manager

        @app.websocket("/ws/copilot")
        async def ws_copilot(websocket):
            await copilot_websocket_endpoint(websocket, ws_manager)

        log.info("WebSocket copilot endpoint mounted at /ws/copilot")
    except ImportError:
        log.info("WebSocket server not available, skipping WS mount")

    # ── Exception Handlers ────────────────────────────────────────────────────
    @app.exception_handler(404)
    async def not_found(request, exc):
        return JSONResponse(
            status_code=404,
            content={
                "error":  "Not found",
                "detail": f"Path '{request.url.path}' does not exist",
                "code":   404,
                "path":   request.url.path,
            },
        )

    @app.exception_handler(500)
    async def server_error(request, exc):
        log.error("Unhandled 500", path=request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={
                "error":  "Internal server error",
                "detail": str(exc),
                "code":   500,
                "path":   request.url.path,
            },
        )

    return app


# ── Singleton app instance ─────────────────────────────────────────────────────
app = create_app()


def run_server(host: str = "0.0.0.0", port: int = 8080, reload: bool = False) -> None:
    uvicorn.run(
        "api.api_server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
        access_log=False,
        workers=1,
    )


if __name__ == "__main__":
    run_server()
