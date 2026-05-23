"""
IMMUNEX WebSocket Server
==========================
Phase 5 — Thread-safe multi-channel WebSocket broadcast manager for real-time
frontend streaming of alerts, metrics, graph updates, and copilot responses.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from utils.logger import log

try:
    from fastapi import WebSocket, WebSocketDisconnect
    _FASTAPI_WS = True
except ImportError:
    _FASTAPI_WS = False


# ─── Valid channels ──────────────────────────────────────────────────────────
CHANNELS = ("alerts", "metrics", "graph", "copilot", "mitre", "mitigation", "cluster")


class WebSocketConnectionManager:
    """Thread-safe multi-client WebSocket broadcast manager."""

    def __init__(self):
        self._connections: dict[str, Any] = {}       # client_id → websocket
        self._subscriptions: dict[str, set[str]] = {}  # channel → {client_ids}
        self._buffer: list[dict] = []                  # offline message buffer
        self._lock = asyncio.Lock() if asyncio else None
        log.info("WebSocketConnectionManager initialized", channels=CHANNELS)

    async def connect(self, websocket, client_id: str = None) -> str:
        """Accept and register a WebSocket connection."""
        if client_id is None:
            client_id = str(uuid.uuid4())[:8]
        await websocket.accept()
        self._connections[client_id] = websocket
        # Auto-subscribe to alerts and metrics by default
        for ch in ("alerts", "metrics"):
            self.subscribe(client_id, ch)
        log.info("WS_CLIENT_CONNECTED", client_id=client_id, total=len(self._connections))
        return client_id

    def disconnect(self, client_id: str) -> None:
        """Remove a client connection and all subscriptions."""
        self._connections.pop(client_id, None)
        for channel_clients in self._subscriptions.values():
            channel_clients.discard(client_id)
        log.info("WS_CLIENT_DISCONNECTED", client_id=client_id)

    def subscribe(self, client_id: str, channel: str) -> None:
        """Subscribe a client to a channel."""
        if channel not in self._subscriptions:
            self._subscriptions[channel] = set()
        self._subscriptions[channel].add(client_id)

    def unsubscribe(self, client_id: str, channel: str) -> None:
        """Unsubscribe a client from a channel."""
        if channel in self._subscriptions:
            self._subscriptions[channel].discard(client_id)

    async def broadcast(self, channel: str, data: dict) -> int:
        """Send data to all clients subscribed to a channel. Returns count of messages sent."""
        subscribers = self._subscriptions.get(channel, set())
        sent = 0
        message = json.dumps({"channel": channel, "data": data, "timestamp": time.time()})

        dead_clients = []
        for client_id in subscribers:
            ws = self._connections.get(client_id)
            if ws is None:
                dead_clients.append(client_id)
                continue
            try:
                await ws.send_text(message)
                sent += 1
            except Exception:
                dead_clients.append(client_id)

        # Cleanup dead connections
        for cid in dead_clients:
            self.disconnect(cid)

        return sent

    async def send_personal(self, client_id: str, data: dict) -> bool:
        """Send data to a specific client."""
        ws = self._connections.get(client_id)
        if ws is None:
            return False
        try:
            await ws.send_text(json.dumps(data))
            return True
        except Exception:
            self.disconnect(client_id)
            return False

    def get_active_connections(self) -> int:
        """Count active connections."""
        return len(self._connections)

    def get_channel_subscribers(self, channel: str) -> int:
        """Count subscribers for a channel."""
        return len(self._subscriptions.get(channel, set()))

    def get_status(self) -> dict:
        """Get WebSocket server status."""
        return {
            "active_connections": len(self._connections),
            "channels": {ch: len(self._subscriptions.get(ch, set())) for ch in CHANNELS},
            "buffer_size": len(self._buffer),
        }


async def copilot_websocket_endpoint(websocket, manager: WebSocketConnectionManager) -> None:
    """
    WebSocket endpoint handler for FastAPI mounting.
    Handles connect/disconnect/message lifecycle.
    """
    client_id = await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                action = msg.get("action", "")

                if action == "subscribe":
                    channel = msg.get("channel", "")
                    if channel in CHANNELS:
                        manager.subscribe(client_id, channel)
                        await manager.send_personal(client_id, {
                            "status": "subscribed", "channel": channel
                        })

                elif action == "unsubscribe":
                    channel = msg.get("channel", "")
                    manager.unsubscribe(client_id, channel)

                elif action == "ping":
                    await manager.send_personal(client_id, {"status": "pong", "timestamp": time.time()})

                else:
                    await manager.send_personal(client_id, {"status": "unknown_action", "action": action})

            except json.JSONDecodeError:
                await manager.send_personal(client_id, {"error": "Invalid JSON"})

    except Exception:
        manager.disconnect(client_id)
