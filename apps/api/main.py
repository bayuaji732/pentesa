"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from apps.api.routers import (
    agents_router,
    auth_router,
    audit_router,
    discovery_router,
    findings_router,
    health_router,
    projects_router,
    reports_router,
    scope_router,
    tools_router,
    users_router,
    wstg_router
)
from database.session import AsyncSessionLocal, close_db, init_db
from database.seeds.seed_data import seed_initial_data
from packages.common.config import settings
from packages.common.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    PentesaError,
    ProjectAuthorizationExpiredError,
    ResourceNotFoundError,
    ScopeViolationError
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events: initialize database schema and seed initial data."""
    await init_db()
    async with AsyncSessionLocal() as session:
        await seed_initial_data(session)
    yield
    await close_db()


app = FastAPI(
    title="Pentesa Security Operations API",
    description="Autonomous Web Application Penetration Testing Platform API",
    version="0.1.0",
    lifespan=lifespan
)

logger = logging.getLogger(__name__)


class _UnhandledExceptionMiddleware:
    """Catch unhandled route exceptions inside CORSMiddleware so 500 responses preserve CORS headers."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def _guarded_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, _guarded_send)
        except Exception as exc:
            logger.exception(
                "Unhandled API exception on %s %s",
                scope.get("method", "UNKNOWN"),
                scope.get("path", ""),
            )
            if response_started:
                raise
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected internal server error occurred.",
                    "detail": str(exc) if settings.debug else "Internal server error",
                },
            )
            await response(scope, receive, send)


# Last middleware added runs outermost: register UnhandledExceptionMiddleware first, then CORSMiddleware
app.add_middleware(_UnhandledExceptionMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Register Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(projects_router)
app.include_router(scope_router)
app.include_router(discovery_router)
app.include_router(wstg_router)
app.include_router(tools_router)
app.include_router(findings_router)
app.include_router(agents_router)
app.include_router(reports_router)
app.include_router(audit_router)


# Global Exception Handlers
@app.exception_handler(ScopeViolationError)
async def scope_violation_handler(request: Request, exc: ScopeViolationError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"error": "SCOPE_VIOLATION", "message": exc.message, "details": exc.details}
    )


@app.exception_handler(AuthenticationError)
async def auth_error_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "AUTHENTICATION_FAILED", "message": exc.message, "details": exc.details},
        headers={"WWW-Authenticate": "Bearer"}
    )


@app.exception_handler(AuthorizationError)
async def authorization_error_handler(request: Request, exc: AuthorizationError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"error": "FORBIDDEN", "message": exc.message, "details": exc.details}
    )


@app.exception_handler(ResourceNotFoundError)
async def not_found_handler(request: Request, exc: ResourceNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": "NOT_FOUND", "message": exc.message, "details": exc.details}
    )


@app.exception_handler(ConflictError)
async def conflict_handler(request: Request, exc: ConflictError):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"error": "CONFLICT", "message": exc.message, "details": exc.details}
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Ensure unhandled exceptions return structured JSON inside CORSMiddleware."""
    logger.exception("Unhandled API exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected internal server error occurred.",
            "detail": str(exc) if settings.debug else "Internal server error",
        },
    )

