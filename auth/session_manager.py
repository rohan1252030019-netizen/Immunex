import time
from typing import Set

class SessionManager:
    """
    Stateful token tracking manager. Supports blacklisting revoked tokens (logouts).
    """
    def __init__(self):
        self._revoked_tokens: Set[str] = set()

    def revoke_token(self, token: str) -> None:
        self._revoked_tokens.add(token)

    def is_token_revoked(self, token: str) -> bool:
        return token in self._revoked_tokens

    def clean_expired(self) -> None:
        # Self-governed cleanup; for pure in-memory cache, simple set operations are low cost.
        pass
