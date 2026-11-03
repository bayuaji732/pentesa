"""API routers package."""

from apps.api.routers.auth import router as auth_router
from apps.api.routers.users import router as users_router
from apps.api.routers.projects import router as projects_router
from apps.api.routers.scope import router as scope_router
from apps.api.routers.audit import router as audit_router
from apps.api.routers.health import router as health_router

__all__ = [
    "auth_router",
    "users_router",
    "projects_router",
    "scope_router",
    "audit_router",
    "health_router"
]
