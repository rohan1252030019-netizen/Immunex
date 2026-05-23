import jwt
import time
from typing import Dict, Any, Optional

SECRET_KEY = "IMMUNEX_ENTERPRISE_SOC_SUPER_SECRET_KEY_2026"
ALGORITHM = "HS256"
DEFAULT_EXPIRY_SECONDS = 3600

class JWTManager:
    """
    Standard JWT operations manager using PyJWT.
    """
    @staticmethod
    def generate_token(username: str, role: str, expires_in: int = DEFAULT_EXPIRY_SECONDS) -> str:
        payload = {
            "sub": username,
            "role": role,
            "exp": time.time() + expires_in,
            "iat": time.time()
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.PyJWTError:
            return None
