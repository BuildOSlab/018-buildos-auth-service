"""
BuildOS Auth Service
Authentication API
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.dependencies import (
    LoginServiceDependency,
    LogoutServiceDependency,
    RegistrationServiceDependency,
    TokenServiceDependency,
    get_user_service,
)
from app.core.exceptions import (
    AuthenticationError,
    ExpiredTokenError,
    IdempotencyConflictError,
    IntegrationError,
    InvalidTokenError,
    RevokedTokenError,
    UserAlreadyExistsError,
    ValidationError,
)
from app.core.rate_limit import (
    AVAILABILITY_RATE,
    LOGIN_RATE,
    REGISTER_RATE,
    limiter,
)
from app.integrations.user_service import UserService
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)
from app.schemas.token import TokenRefreshRequest, TokenRevokeResponse

router = APIRouter()


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(REGISTER_RATE)
def register(
    payload: RegisterRequest,
    request: Request,
    registration_service: RegistrationServiceDependency,
) -> RegisterResponse:
    """Register a new BuildOS user."""

    idempotency_key = request.headers.get("Idempotency-Key")

    if not idempotency_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Idempotency-Key header is required.",
        )

    try:
        result = registration_service.register(
            idempotency_key=idempotency_key,
            email=payload.email,
            phone=payload.phone,
            username=payload.username,
            password=payload.password,
            first_name=payload.first_name,
            last_name=payload.last_name,
            display_name=payload.display_name,
            country=payload.country,
            timezone=payload.timezone,
            language=payload.language,
            ip_address=(
                request.client.host
                if request.client
                else None
            ),
            user_agent=request.headers.get("user-agent"),
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except IdempotencyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except IntegrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User registration service is unavailable.",
        ) from exc

    return RegisterResponse(
        registered=True,
        user_id=result.user.user_id,
        public_id=result.user.public_id,
        access_token=result.tokens.access_token,
        refresh_token=result.tokens.refresh_token,
        token_type=result.tokens.token_type,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit(LOGIN_RATE)
def login(
    payload: LoginRequest,
    request: Request,  # pylint: disable=unused-argument
    login_service: LoginServiceDependency,
    token_service: TokenServiceDependency,
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
            ip_address=(
                request.client.host
                if request.client
                else None
            ),
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

    token_pair = token_service.issue_tokens(
        user_id=user_id,
        context_type="PERSONAL",
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
        user_agent=request.headers.get("user-agent"),
    )

    return LoginResponse(
        authenticated=True,
        user_id=user_id,
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        token_type=token_pair.token_type,
    )


@router.post(
    "/logout",
    response_model=TokenRevokeResponse,
    status_code=status.HTTP_200_OK,
)
def logout(
    payload: TokenRefreshRequest,
    request: Request,  # pylint: disable=unused-argument
    logout_service: LogoutServiceDependency,
) -> TokenRevokeResponse:
    """
    Log out the current session by revoking its refresh token
    """

    try:
        logout_service.logout(
            refresh_token=payload.refresh_token,
            ip_address=(
                request.client.host
                if request.client
                else None
            ),
            user_agent=request.headers.get("user-agent"),
        )
    except ExpiredTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
        ) from exc
    except RevokedTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has already been revoked.",
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        ) from exc

    return TokenRevokeResponse(
        revoked=True,
    )


@router.get(
    "/check-availability",
    status_code=status.HTTP_200_OK,
)
@limiter.limit(AVAILABILITY_RATE)
def check_availability(
    request: Request,  # pylint: disable=unused-argument
    email: str | None = None,
    username: str | None = None,
    user_service: UserService = Depends(get_user_service),  # noqa: B008
) -> dict[str, bool]:
    """
    Check if an email or username is already registered in the User Service.

    This endpoint is used by the frontend to perform real-time validation
    during registration, reducing duplicate submission errors.
    """
    if not email and not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either email or username must be provided.",
        )

    user_id = None

    try:
        if email:
            user_id = user_service.resolve_identifier(
                identifier=email,
            )

        if not user_id and username:
            user_id = user_service.resolve_identifier(
                identifier=username,
            )

    except IntegrationError as exc:
        # If the User Service is unavailable, we cannot determine availability.
        # Return a 503 so the frontend can treat it as "unknown" and not block
        # the user from submitting, or show a warning.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="User identity service is temporarily unavailable.",
        ) from exc

    available = user_id is None

    return {"available": available}
