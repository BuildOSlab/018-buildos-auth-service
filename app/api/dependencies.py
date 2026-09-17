"""
BuildOS Auth Service
API Dependencies
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.constants import CONTEXT_PERSONAL
from app.core.exceptions import ExpiredTokenError, InvalidTokenError
from app.database.dependencies import get_db
from app.integrations.session_service import SessionService
from app.integrations.user_service import UserService
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.repositories.login_attempt_repository import LoginAttemptRepository
from app.repositories.password_reset_repository import PasswordResetRepository
from app.repositories.token_repository import TokenRepository
from app.schemas.token import TokenUserContext
from app.security.token_validation import validate_access_token
from app.services.authentication_service import AuthenticationService
from app.services.login_service import LoginService
from app.services.logout_service import LogoutService
from app.services.password_service import PasswordService
from app.services.registration_service import RegistrationService
from app.services.token_service import TokenService

DatabaseSession = Annotated[Session, Depends(get_db)]


# ------------------------------------------------------------------
# Internal service authentication
# ------------------------------------------------------------------

internal_api_key_header = APIKeyHeader(
    name="Authorization",
    auto_error=False,
)


async def verify_internal_service(
    api_key: str | None = Security(internal_api_key_header),
    service_id: str | None = Header(
        default=None,
        alias="X-Service-ID",
    ),
) -> bool:
    """
    Verify service-to-service authentication for internal endpoints.

    Internal requests must provide:
    - Authorization: Bearer <internal API key>
    - X-Service-ID: calling service identifier
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key.",
        )

    if not service_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing service identity.",
        )

    if api_key.startswith("Bearer "):
        api_key = api_key.removeprefix("Bearer ").strip()

    settings = get_settings()

    if api_key != settings.internal_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    return True


# ------------------------------------------------------------------
# User Service
# ------------------------------------------------------------------


def get_user_service() -> UserService:
    """
    Provide the canonical User Service integration.
    """
    return UserService()


# ------------------------------------------------------------------
# Session Service
# ------------------------------------------------------------------


def get_session_service() -> SessionService:
    """Provide the internal Session Service integration."""
    return SessionService()


SessionServiceDependency = Annotated[
    SessionService,
    Depends(get_session_service),
]


# ------------------------------------------------------------------
# Authentication Service
# ------------------------------------------------------------------


def get_authentication_service(
    db: DatabaseSession,
) -> AuthenticationService:
    """
    Build the authentication domain service with its repositories.
    """
    credential_repository = CredentialRepository(db)
    login_attempt_repository = LoginAttemptRepository(db)
    event_repository = EventRepository(db)

    return AuthenticationService(
        credential_repository=credential_repository,
        login_attempt_repository=login_attempt_repository,
        event_repository=event_repository,
    )


# ------------------------------------------------------------------
# Login Service
# ------------------------------------------------------------------


def get_login_service(
    db: DatabaseSession,
) -> LoginService:
    """
    Build the login orchestration service.
    """
    return LoginService(
        user_service=get_user_service(),
        authentication_service=get_authentication_service(db),
    )


LoginServiceDependency = Annotated[
    LoginService,
    Depends(get_login_service),
]


# ------------------------------------------------------------------
# Password Service
# ------------------------------------------------------------------


def get_password_service(
    db: DatabaseSession,
) -> PasswordService:
    """
    Build the password-management service with its repositories.
    """
    return PasswordService(
        user_service=get_user_service(),
        credential_repository=CredentialRepository(db),
        password_reset_repository=PasswordResetRepository(db),
        token_repository=TokenRepository(db),
        event_repository=EventRepository(db),
    )


PasswordServiceDependency = Annotated[
    PasswordService,
    Depends(get_password_service),
]


# ------------------------------------------------------------------
# Token Service
# ------------------------------------------------------------------


def get_token_service(
    db: DatabaseSession,
) -> TokenService:
    """
    Build the token lifecycle service with its repositories.
    """
    return TokenService(
        token_repository=TokenRepository(db),
        event_repository=EventRepository(db),
    )


TokenServiceDependency = Annotated[
    TokenService,
    Depends(get_token_service),
]


# ------------------------------------------------------------------
# Logout Service
# ------------------------------------------------------------------


def get_logout_service(
    db: DatabaseSession,
) -> LogoutService:
    """
    Build the logout orchestration service.
    """
    return LogoutService(
        token_service=get_token_service(db),
    )


LogoutServiceDependency = Annotated[
    LogoutService,
    Depends(get_logout_service),
]


# ------------------------------------------------------------------
# Current User
# ------------------------------------------------------------------

bearer_scheme = HTTPBearer()


def get_current_user_context(
    credentials: HTTPAuthorizationCredentials = Depends(  # noqa: B008
        bearer_scheme,
    ),
) -> TokenUserContext:
    """
    Resolve the authenticated user context from an access token.
    """
    try:
        payload = validate_access_token(credentials.credentials)
    except ExpiredTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    subject = payload.get("sub")

    if not isinstance(subject, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = UUID(subject)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    context_type = payload.get(
        "context_type",
        CONTEXT_PERSONAL,
    )

    if not isinstance(context_type, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token context.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    organization_id = _optional_uuid_claim(
        payload,
        "organization_id",
    )

    membership_id = _optional_uuid_claim(
        payload,
        "membership_id",
    )

    return TokenUserContext(
        user_id=user_id,
        context_type=context_type,
        organization_id=organization_id,
        membership_id=membership_id,
    )


CurrentUserContextDependency = Annotated[
    TokenUserContext,
    Depends(get_current_user_context),
]


def _optional_uuid_claim(
    payload: dict[str, object],
    claim_name: str,
) -> UUID | None:
    """
    Parse an optional UUID claim from an access-token payload.
    """
    value = payload.get(claim_name)

    if value is None:
        return None

    if not isinstance(value, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token context.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return UUID(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token context.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ------------------------------------------------------------------
# Registration Service
# ------------------------------------------------------------------


def get_registration_service(
    db: DatabaseSession,
) -> RegistrationService:
    """Build the registration orchestration service."""
    return RegistrationService(
        user_service=get_user_service(),
        credential_repository=CredentialRepository(db),
        event_repository=EventRepository(db),
        token_service=get_token_service(db),
    )


RegistrationServiceDependency = Annotated[
    RegistrationService,
    Depends(get_registration_service),
]


__all__ = [
    "CurrentUserContextDependency",
    "DatabaseSession",
    "LoginServiceDependency",
    "LogoutServiceDependency",
    "PasswordServiceDependency",
    "RegistrationServiceDependency",
    "TokenServiceDependency",
    "get_authentication_service",
    "get_current_user_context",
    "get_db",
    "get_login_service",
    "get_logout_service",
    "get_password_service",
    "get_registration_service",
    "get_token_service",
    "get_user_service",
    "verify_internal_service",
]
