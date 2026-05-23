import pytest
import time
from auth.rbac_engine import RBACEngine, Permission
from auth.jwt_manager import JWTManager
from auth.access_policy_engine import AccessPolicyEngine
from auth.session_manager import SessionManager

def test_rbac_engine_permissions():
    assert RBACEngine.has_permission("ADMINISTRATOR", Permission.VIEW_AUDIT) is True
    assert RBACEngine.has_permission("SOC_ANALYST", Permission.VIEW_AUDIT) is False
    assert RBACEngine.has_permission("AUDITOR", Permission.VIEW_AUDIT) is True
    assert "ADMINISTRATOR" in RBACEngine.list_roles()

def test_jwt_generation_and_verification():
    username = "test_analyst"
    role = "SOC_ANALYST"
    token = JWTManager.generate_token(username, role, expires_in=10)
    
    payload = JWTManager.verify_token(token)
    assert payload is not None
    assert payload["sub"] == username
    assert payload["role"] == role
    assert payload["exp"] > time.time()

def test_jwt_invalid_token():
    payload = JWTManager.verify_token("invalid.token.signature")
    assert payload is None

def test_session_revocation():
    session_manager = SessionManager()
    token = "some_valid_jwt_token_string"
    
    assert session_manager.is_token_revoked(token) is False
    session_manager.revoke_token(token)
    assert session_manager.is_token_revoked(token) is True

def test_zero_trust_policy_engine():
    policy = AccessPolicyEngine()
    
    # Standard context check
    context = {
        "client_ip": "192.168.1.50",
        "time_of_day": "14:00",
        "mfa_verified": True
    }
    
    # Allow admin from standard subnet
    verdict, reason = policy.evaluate_access("ADMINISTRATOR", context)
    assert verdict is True
    
    # Deny auditor outside business window if policy enforcer is strict
    malicious_context = {
        "client_ip": "10.0.0.99",
        "time_of_day": "03:00",
        "mfa_verified": False
    }
    verdict, reason = policy.evaluate_access("AUDITOR", malicious_context)
    assert verdict is False
