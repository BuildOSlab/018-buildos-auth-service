"""
Tests for JWT token signing and validation.
"""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
import pytest

from app.core.config import get_settings
from app.core.constants import TOKEN_TYPE_REFRESH
from app.core.exceptions import ExpiredTokenError, InvalidTokenError
from app.security.token_signing import create_access_token, create_refresh_token
from app.security.token_validation import validate_access_token, validate_refresh_token


@pytest.fixture(autouse=True)
def test_settings(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Configure test JWT settings and clear the settings cache."""
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://user:pass@localhost/db",
    )
    monkeypatch.setenv(
        "JWT_SECRET_KEY",
        "test-secret-key-for-buildos-auth-service-32bytes",
    )

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_create_refresh_token_basic() -> None:
    """Test that a refresh token can be created and decoded."""
    user_id = UUID("12345678-1234-1234-1234-123456789012")
    token = create_refresh_token(user_id=user_id)

    assert token

    payload = jwt.decode(
        token,
        options={"verify_signature": False},
    )

    assert payload["sub"] == str(user_id)
    assert payload["token_type"] == TOKEN_TYPE_REFRESH


def test_create_refresh_token_contains_correct_user_id() -> None:
    """Test that a refresh token contains the correct user ID."""
    user_id = UUID("12345678-1234-1234-1234-123456789012")
    token = create_refresh_token(user_id=user_id)

    validated = validate_refresh_token(token)

    assert validated["sub"] == str(user_id)


def test_create_refresh_token_token_type() -> None:
    """Test that a refresh token contains the correct token type."""
    token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
    )

    validated = validate_refresh_token(token)

    assert validated["token_type"] == TOKEN_TYPE_REFRESH


def test_create_refresh_token_issuer_audience() -> None:
    """Test that a refresh token contains the configured issuer and audience."""
    settings = get_settings()

    token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
    )

    validated = validate_refresh_token(token)

    assert validated["iss"] == settings.jwt_issuer
    assert validated["aud"] == settings.jwt_audience


def test_create_refresh_token_context_type_defaults_to_personal() -> None:
    """Test that refresh tokens default to personal context."""
    token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
    )

    validated = validate_refresh_token(token)

    assert validated.get("context_type") == "PERSONAL"


def test_create_refresh_token_jti_exists() -> None:
    """Test that a refresh token contains a JTI claim."""
    token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
    )

    validated = validate_refresh_token(token)

    assert "jti" in validated
    assert isinstance(validated["jti"], str)


def test_validate_refresh_token_valid() -> None:
    """Test that a valid refresh token is successfully validated."""
    user_id = UUID("12345678-1234-1234-1234-123456789012")
    token = create_refresh_token(user_id=user_id)

    payload = validate_refresh_token(token)

    assert payload["sub"] == str(user_id)
    assert payload["token_type"] == TOKEN_TYPE_REFRESH


def test_validate_access_token_rejects_refresh_token() -> None:
    """Test that access-token validation rejects refresh tokens."""
    refresh_token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
    )

    with pytest.raises(InvalidTokenError, match="Invalid token type."):
        validate_access_token(refresh_token)


def test_validate_refresh_token_rejects_access_token() -> None:
    """Test that refresh-token validation rejects access tokens."""
    access_token = create_access_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
    )

    with pytest.raises(InvalidTokenError, match="Invalid token type."):
        validate_refresh_token(access_token)


def test_validate_refresh_token_malformed() -> None:
    """Test that malformed tokens are rejected."""
    with pytest.raises(InvalidTokenError):
        validate_refresh_token("not.a.jwt.token")


def test_validate_refresh_token_invalid_token_type() -> None:
    """Test that refresh-token validation rejects an invalid token type."""
    settings = get_settings()

    payload = {
        "sub": str(UUID("12345678-1234-1234-1234-123456789012")),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=15),
        "jti": "test-jti",
        "token_type": "invalid",
        "context_type": "PERSONAL",
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(InvalidTokenError, match="Invalid token type."):
        validate_refresh_token(token)


def test_create_refresh_token_organization_context() -> None:
    """Test that refresh tokens support organization context."""
    user_id = UUID("12345678-1234-1234-1234-123456789012")
    org_id = UUID("87654321-4321-4321-4321-210987654321")
    membership_id = UUID("11111111-1111-1111-1111-111111111111")

    token = create_refresh_token(
        user_id=user_id,
        organization_id=org_id,
        membership_id=membership_id,
    )

    validated = validate_refresh_token(token)

    assert validated["organization_id"] == str(org_id)
    assert validated["membership_id"] == str(membership_id)


def test_validate_refresh_token_expired() -> None:
    """Test that an expired refresh token is rejected."""
    settings = get_settings()

    past = datetime.now(UTC) - timedelta(
        days=settings.refresh_token_expire_days + 1,
    )

    token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
        now=past,
    )

    with pytest.raises(
        ExpiredTokenError,
        match="Refresh token has expired.",
    ):
        validate_refresh_token(token)


def test_create_refresh_token_context_type_explicit() -> None:
    """Test that an explicit organization context is preserved."""
    token = create_refresh_token(
        user_id=UUID("12345678-1234-1234-1234-123456789012"),
        context_type="ORGANIZATION",
    )

    validated = validate_refresh_token(token)

    assert validated["context_type"] == "ORGANIZATION"
