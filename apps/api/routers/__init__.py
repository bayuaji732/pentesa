"""API routers package."""

from apps.api.routers.auth import router as auth_router
from apps.api.routers.users import router as users_router
from apps.api.routers.projects import router as projects_router
from apps.api.routers.scope import router as scope_router
from apps.api.routers.audit import router as audit_router
from apps.api.routers.discovery import router as discovery_router
from apps.api.routers.health import router as health_router
from apps.api.routers.wstg import router as wstg_router
from apps.api.routers.tools import router as tools_router
from apps.api.routers.findings import router as findings_router
from apps.api.routers.agents import router as agents_router

__all__ = [
    "auth_router",
    "users_router",
    "projects_router",
    "scope_router",
    "audit_router",
    "discovery_router",
    "health_router",
    "wstg_router",
    "tools_router",
    "findings_router",
    "agents_router"
]


