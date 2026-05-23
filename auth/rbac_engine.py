from typing import Set, Dict

class Permission:
    VIEW_ALERTS = "alerts:view"
    VIEW_GRAPH = "graph:view"
    VIEW_DASHBOARD = "dashboard:view"
    VIEW_METRICS = "metrics:view"
    MANAGE_INCIDENTS = "incidents:manage"
    RETRAIN_MODELS = "models:retrain"
    MANAGE_POLICIES = "policies:manage"
    VIEW_AUDIT = "audit:view"
    MANAGE_AGENTS = "agents:manage"
    COPILOT_ACCESS = "copilot:access"
    CLUSTER_VIEW = "cluster:view"

class RBACEngine:
    """
    Standard Role-Based Access Control engine determining if a user's role
    grants them specific permissions to interact with IMMUNEX endpoints.
    """
    ROLE_PERMISSIONS: Dict[str, Set[str]] = {
        "SOC_ANALYST": {
            Permission.VIEW_ALERTS,
            Permission.VIEW_GRAPH,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_METRICS,
            Permission.COPILOT_ACCESS
        },
        "INCIDENT_RESPONDER": {
            Permission.VIEW_ALERTS,
            Permission.VIEW_GRAPH,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_METRICS,
            Permission.MANAGE_INCIDENTS,
            Permission.COPILOT_ACCESS
        },
        "SECURITY_ENGINEER": {
            Permission.VIEW_ALERTS,
            Permission.VIEW_GRAPH,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_METRICS,
            Permission.RETRAIN_MODELS,
            Permission.MANAGE_POLICIES,
            Permission.MANAGE_AGENTS,
            Permission.CLUSTER_VIEW
        },
        "THREAT_HUNTER": {
            Permission.VIEW_ALERTS,
            Permission.VIEW_GRAPH,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_METRICS,
            Permission.MANAGE_INCIDENTS,
            Permission.COPILOT_ACCESS
        },
        "AUDITOR": {
            Permission.VIEW_AUDIT,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_METRICS
        },
        "ADMINISTRATOR": {
            Permission.VIEW_ALERTS,
            Permission.VIEW_GRAPH,
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_METRICS,
            Permission.MANAGE_INCIDENTS,
            Permission.RETRAIN_MODELS,
            Permission.MANAGE_POLICIES,
            Permission.VIEW_AUDIT,
            Permission.MANAGE_AGENTS,
            Permission.COPILOT_ACCESS,
            Permission.CLUSTER_VIEW
        }
    }

    @classmethod
    def has_permission(cls, role: str, permission: str) -> bool:
        permissions = cls.ROLE_PERMISSIONS.get(role, set())
        return permission in permissions
        
    @classmethod
    def list_roles(cls) -> list[str]:
        return list(cls.ROLE_PERMISSIONS.keys())
