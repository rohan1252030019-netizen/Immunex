"""
IMMUNEX Cluster Security Manager
===================================
Phase 7 — Mutual TLS, node identity, signed packets, replay prevention,
cluster token validation. Uses only stdlib (hashlib, hmac, secrets).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any, Optional

from utils.logger import log


class ClusterSecurityManager:
    """
    Provides cryptographic security primitives for distributed cluster operations.
    Uses only Python stdlib — no external dependencies.
    """

    def __init__(self, cluster_secret: str = None):
        self._cluster_secret = cluster_secret or secrets.token_hex(32)
        self._node_identity: Optional[dict] = None
        self._seen_messages: dict[str, float] = {}  # msg_id → timestamp
        self._replay_window = 300  # 5-minute replay window
        self._token_ttl = 3600    # 1-hour token lifetime
        log.info("ClusterSecurityManager initialized")

    def generate_node_identity(self) -> dict:
        """Create unique node ID + signing key."""
        self._node_identity = {
            "node_id": f"immunex-node-{uuid.uuid4().hex[:12]}",
            "signing_key": secrets.token_hex(32),
            "created_at": time.time(),
            "fingerprint": hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16],
        }
        log.info("NODE_IDENTITY_GENERATED", node_id=self._node_identity["node_id"])
        return {
            "node_id": self._node_identity["node_id"],
            "fingerprint": self._node_identity["fingerprint"],
            "created_at": self._node_identity["created_at"],
        }

    def sign_message(self, message: bytes) -> str:
        """HMAC-SHA256 sign a message using the cluster secret."""
        signature = hmac.new(
            self._cluster_secret.encode("utf-8"),
            message if isinstance(message, bytes) else message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return signature

    def verify_message(self, message: bytes, signature: str) -> bool:
        """Verify an HMAC-SHA256 message signature."""
        expected = self.sign_message(message)
        return hmac.compare_digest(expected, signature)

    def generate_cluster_token(self) -> str:
        """Create a time-limited authentication token."""
        payload = {
            "token_id": uuid.uuid4().hex[:16],
            "issued_at": time.time(),
            "expires_at": time.time() + self._token_ttl,
            "issuer": self._node_identity["node_id"] if self._node_identity else "unknown",
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = self.sign_message(payload_bytes)
        # Token format: base64(payload).signature
        import base64
        encoded = base64.b64encode(payload_bytes).decode("utf-8")
        token = f"{encoded}.{signature}"
        log.debug("CLUSTER_TOKEN_GENERATED", token_id=payload["token_id"])
        return token

    def validate_cluster_token(self, token: str) -> bool:
        """Validate a cluster authentication token."""
        import base64
        try:
            parts = token.rsplit(".", 1)
            if len(parts) != 2:
                return False
            encoded, signature = parts
            payload_bytes = base64.b64decode(encoded)
            # Verify signature
            if not self.verify_message(payload_bytes, signature):
                return False
            # Check expiry
            payload = json.loads(payload_bytes)
            if time.time() > payload.get("expires_at", 0):
                return False
            return True
        except Exception:
            return False

    def detect_replay(self, message_id: str) -> bool:
        """
        Track seen message IDs to prevent replay attacks.
        Returns True if this is a replay (message already seen).
        """
        now = time.time()
        # Cleanup old entries
        expired = [mid for mid, ts in self._seen_messages.items() if now - ts > self._replay_window]
        for mid in expired:
            del self._seen_messages[mid]

        if message_id in self._seen_messages:
            log.warning("REPLAY_ATTACK_DETECTED", message_id=message_id)
            return True  # Replay detected

        self._seen_messages[message_id] = now
        return False  # Not a replay

    def get_security_status(self) -> dict:
        """Get cluster security status."""
        return {
            "node_identity": self._node_identity["node_id"] if self._node_identity else None,
            "tracked_messages": len(self._seen_messages),
            "replay_window_seconds": self._replay_window,
            "token_ttl_seconds": self._token_ttl,
        }
