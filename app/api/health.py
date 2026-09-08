"""
BuildOS Auth Service
Health and readiness endpoints.
"""

from typing import Any

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.integrations.user_service import UserService

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe – is the process running?"""
    return {
        "status": "ok",
        "service": settings.service_name,
    }


@router.get("/ready")
def readiness() -> JSONResponse:
    """
    Readiness probe – can this instance accept traffic?

    Checks connectivity to the User Service.
    """
    checks: dict[str, str] = {
        "user_service": "unknown",
    }

    try:
        with UserService() as user_service:
            if user_service.check_health(timeout=3.0):
                checks["user_service"] = "ok"
            else:
                checks["user_service"] = "unhealthy"
    except (ConnectionError, OSError, TimeoutError) as exc:
        checks["user_service"] = f"error: {type(exc).__name__}"

    all_ok = all(value == "ok" for value in checks.values())

    payload: dict[str, Any] = {
        "status": "ready" if all_ok else "not_ready",
        "service": settings.service_name,
        "checks": checks,
    }

    return JSONResponse(
        status_code=(
            status.HTTP_200_OK
            if all_ok
            else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        content=payload,
    )
