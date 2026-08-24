"""
BuildOS Auth Service
JWT Token Signing
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt

from app.core.config import get_settings
from app.core.constants import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH


def create_access_token(
    *,
    user_id: UUID,
    context_type: str = "PERSONAL",
    organization_id: UUID | None = None,
    membership_id: UUID | None = None,
    now: datetime | None = None,
) -> str:
    """
    Create a signed JWT access token.

    The token contains only authentication/context claims.
    No sensitive user information is embedded in the JWT.
    """
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    payload: dict[str, object] = {
        "sub": str(user_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": issued_at,
        "exp": expires_at,
        "jti": str(uuid4()),
        "token_type": TOKEN_TYPE_ACCESS,
        "context_type": context_type,
    }

    if organization_id is not None:
        payload["organization_id"] = str(organization_id)

    if membership_id is not None:
        payload["membership_id"] = str(membership_id)

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(
    *,
    user_id: UUID,
    context_type: str = "PERSONAL",
    organization_id: UUID | None = None,
    membership_id: UUID | None = None,
    now: datetime | None = None,
) -> str:
    """
    Create a signed JWT refresh token.

    The token contains only authentication/context claims.
    No sensitive user information is embedded in the JWT.
    """
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + timedelta(
        days=settings.refresh_token_expire_days
    )

    payload: dict[str, object] = {
        "sub": str(user_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": issued_at,
        "exp": expires_at,
        "jti": str(uuid4()),
        "token_type": TOKEN_TYPE_REFRESH,
        "context_type": context_type,
    }

    if organization_id is not None:
        payload["organization_id"] = str(organization_id)

    if membership_id is not None:
        payload["membership_id"] = str(membership_id)

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
