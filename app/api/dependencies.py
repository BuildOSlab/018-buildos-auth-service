"""
BuildOS Auth Service
API Dependencies
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.constants import CONTEXT_PERSONAL
from app.core.exceptions import ExpiredTokenError, InvalidTokenError
from app.database.dependencies import get_db
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
from app.services.password_service import PasswordService
from app.services.token_service import TokenService

DatabaseSession = Annotated[Session, Depends(get_db)]


def get_user_service() -> UserService:
    """
    Provide the canonical User Service integration.
    """

    return UserService()


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


bearer_scheme = HTTPBearer()


def get_current_user_context(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),  # noqa: B008
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


__all__ = [
    "CurrentUserContextDependency",
    "DatabaseSession",
    "LoginServiceDependency",
    "PasswordServiceDependency",
    "TokenServiceDependency",
    "get_authentication_service",
    "get_current_user_context",
    "get_db",
    "get_login_service",
    "get_password_service",
    "get_token_service",
    "get_user_service",
]
