"""
BuildOS Auth Service
Application Entry Point
"""

from fastapi import FastAPI

from app.api.v1.router import router as api_router
from app.core.config import settings
from app.core.logging import configure_logging


def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.
    """

    configure_logging()

    application = FastAPI(
        title="BuildOS Authentication Service",
        description=(
            "Authentication and security service for the BuildOS platform."
        ),
        version="0.1.0",
        debug=settings.debug,
    )

    application.include_router(
        api_router,
        prefix="/api",
    )

    @application.get(
        "/health",
        tags=["health"],
    )
    def health_check() -> dict[str, str]:
        """
        Basic service health check.
        """

        return {
            "status": "ok",
            "service": settings.service_name,
        }

    return application


app = create_application()