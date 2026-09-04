"""
BuildOS Auth Service
Application Entry Point
"""

from fastapi import FastAPI

from app.api.v1 import auth, password, security, token
from app.core.config import settings
from app.core.logging import configure_logging
from app.core.rate_limit import setup_rate_limiting


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
        auth.router,
        prefix="/api/v1/auth",
        tags=["authentication"],
    )

    application.include_router(
        password.router,
        prefix="/api/v1/password",
        tags=["password"],
    )

    application.include_router(
        security.router,
        prefix="/api/v1/security",
        tags=["security"],
    )

    application.include_router(
        token.router,
        prefix="/api/v1/token",
        tags=["token"],
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
setup_rate_limiting(app)
