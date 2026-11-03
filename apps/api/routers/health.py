"""Health, liveness, and readiness check router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database.session import get_db

router = APIRouter(tags=["Health"])


@router.get("/healthz", status_code=status.HTTP_200_OK)
async def health_check():
    """Liveness probe indicating API server is running."""
    return {"status": "ok", "service": "pentesa-api"}


@router.get("/readyz", status_code=status.HTTP_200_OK)
async def readiness_check(session: AsyncSession = Depends(get_db)):
    """Readiness probe checking database connectivity."""
    try:
        await session.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        return {"status": "unready", "database": "disconnected", "error": str(e)}
