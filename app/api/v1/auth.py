"""
BuildOS Auth Service
Authentication API
"""

from fastapi import APIRouter, HTTPException, Request, status

from app.api.dependencies import LoginServiceDependency
from app.core.exceptions import AuthenticationError, IntegrationError
from app.schemas.auth import LoginRequest, LoginResponse

router = APIRouter()


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    payload: LoginRequest,
    request: Request,
    login_service: LoginServiceDependency,
) -> LoginResponse:
    """
    Authenticate a BuildOS user.

    User identity is resolved by the canonical User Service.
    Credential verification is performed by the Auth Service.
    """

    try:
        result = login_service.login(
            identifier=payload.identifier,
            password=payload.password,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        ) from exc
    except IntegrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User identity service is unavailable.",
        ) from exc

    if not result.authentication.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    user_id = result.authentication.user_id

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication completed without a user identity.",
        )

    return LoginResponse(
        authenticated=True,
        user_id=user_id,
    )
