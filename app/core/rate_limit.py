"""
BuildOS Auth Service
Rate Limiting Configuration
"""

from fastapi import FastAPI, Request
from fastapi.responses import Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Create a limiter that uses the client's IP address as the key
limiter = Limiter(key_func=get_remote_address)

# Default rate limits (adjust as needed)
REGISTER_RATE = "5/minute"
LOGIN_RATE = "10/minute"
PASSWORD_RESET_RATE = "3/minute"
AVAILABILITY_RATE = "30/minute"


def _rate_limit_handler(
    request: Request,
    exc: Exception,
) -> Response:
    """Adapt SlowAPI's handler to FastAPI's exception-handler type."""

    if not isinstance(exc, RateLimitExceeded):
        raise exc

    return _rate_limit_exceeded_handler(request, exc)


def setup_rate_limiting(app: FastAPI) -> None:
    """Configure SlowAPI rate limiting for the FastAPI application."""

    app.state.limiter = limiter
    app.add_exception_handler(
        RateLimitExceeded,
        _rate_limit_handler,
    )
