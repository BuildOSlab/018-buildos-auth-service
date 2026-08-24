"""
BuildOS Auth Service
JWT Token Validation
"""

from uuid import UUID

import jwt

from app.core.config import get_settings
from app.core.constants import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH
from app.core.exceptions import ExpiredTokenError, InvalidTokenError


def validate_access_token(token: str) -> dict[str, object]:
    """
    Validate and decode an access token.

    Signature, issuer, audience, expiration, and token type
    are all validated before claims are returned.
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "jti",
                    "token_type",
                ]
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredTokenError("Access token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError("Invalid access token.") from exc

    if payload.get("token_type") != TOKEN_TYPE_ACCESS:
        raise InvalidTokenError("Invalid token type.")

    subject = payload.get("sub")

    if not isinstance(subject, str):
        raise InvalidTokenError("Token subject is invalid.")

    try:
        UUID(subject)
    except ValueError as exc:
        raise InvalidTokenError("Token subject is invalid.") from exc

    return payload


def validate_refresh_token(token: str) -> dict[str, object]:
    """
    Validate and decode a refresh token.

    Signature, issuer, audience, expiration, and token type
    are all validated before claims are returned.
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "jti",
                    "token_type",
                ]
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredTokenError("Refresh token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError("Invalid refresh token.") from exc

    if payload.get("token_type") != TOKEN_TYPE_REFRESH:
        raise InvalidTokenError("Invalid token type.")

    subject = payload.get("sub")

    if not isinstance(subject, str):
        raise InvalidTokenError("Token subject is invalid.")

    try:
        UUID(subject)
    except ValueError as exc:
        raise InvalidTokenError("Token subject is invalid.") from exc

    return payload
