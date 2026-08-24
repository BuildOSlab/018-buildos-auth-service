"""
Tests for the refresh-token repository.
"""

# pylint: disable=redefined-outer-name
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.refresh_token import RefreshToken
from app.repositories.token_repository import TokenRepository


@pytest.fixture(scope="module")
def engine() -> Generator[Engine, None, None]:
    """Create a PostgreSQL engine for repository tests."""
    settings = get_settings()

    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
    )

    yield engine

    engine.dispose()


@pytest.fixture
def db(engine: Engine) -> Generator[Session, None, None]:
    """Provide a clean database session for each repository test."""
    with Session(engine) as session:
        yield session
        session.rollback()


@pytest.fixture
def repository(db: Session) -> TokenRepository:
    """Provide a TokenRepository."""
    return TokenRepository(db)


@pytest.fixture
def user_id() -> UUID:
    """Return a test user ID."""
    return uuid4()


@pytest.fixture
def now() -> datetime:
    """Return a timezone-aware test timestamp."""
    return datetime.now(UTC)


@pytest.fixture
def cleanup_tokens(engine: Engine) -> Generator[list[UUID], None, None]:
    """
    Remove refresh tokens created during the test.

    The repository tests operate against the real PostgreSQL schema,
    so test-created rows must be cleaned up explicitly.
    """
    created_ids: list[UUID] = []

    yield created_ids

    with Session(engine) as session:
        if created_ids:
            session.execute(
                delete(RefreshToken).where(
                    RefreshToken.id.in_(created_ids),
                ),
            )
            session.commit()


@dataclass
class TokenOptions:
    """Optional configuration for creating a refresh token in tests."""

    user_id: UUID | None = None
    token_hash: str | None = None
    expires_at: datetime | None = None
    context_type: str = "PERSONAL"
    organization_id: UUID | None = None
    membership_id: UUID | None = None


def create_token(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    options: TokenOptions | None = None,
) -> RefreshToken:
    """Create and register a refresh token for a test."""
    options = options or TokenOptions()

    token = repository.create(
        user_id=options.user_id or uuid4(),
        token_hash=options.token_hash or f"hash-{uuid4()}",
        expires_at=(
            options.expires_at
            or datetime.now(UTC) + timedelta(days=30)
        ),
        context_type=options.context_type,
        organization_id=options.organization_id,
        membership_id=options.membership_id,
    )

    cleanup_tokens.append(token.id)
    return token


def test_create_token(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
    now: datetime,
) -> None:
    """Test creating a refresh token."""
    token = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            expires_at=now + timedelta(days=30),
        ),
    )

    assert token.id is not None
    assert token.user_id == user_id
    assert token.context_type == "PERSONAL"
    assert token.is_revoked is False
    assert token.revoked_at is None
    assert token.last_used_at is None


def test_get_by_token_hash(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
) -> None:
    """Test retrieving a refresh token by hash."""
    token_hash = f"hash-{uuid4()}"

    token = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            token_hash=token_hash,
        ),
    )

    result = repository.get_by_token_hash(token_hash)

    assert result is not None
    assert result.id == token.id
    assert result.user_id == user_id


def test_get_by_token_hash_returns_none_for_unknown_hash(
    repository: TokenRepository,
) -> None:
    """Test unknown token hashes return None."""
    result = repository.get_by_token_hash(
        f"unknown-{uuid4()}",
    )

    assert result is None


def test_get_active_by_token_hash_returns_active_token(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    now: datetime,
) -> None:
    """Test retrieving an active refresh token."""
    token_hash = f"hash-{uuid4()}"

    token = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            token_hash=token_hash,
            expires_at=now + timedelta(days=30),
        ),
    )

    result = repository.get_active_by_token_hash(
        token_hash=token_hash,
        now=now,
    )

    assert result is not None
    assert result.id == token.id


def test_get_active_by_token_hash_rejects_revoked_token(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    now: datetime,
) -> None:
    """Test revoked tokens are not returned as active."""
    token_hash = f"hash-{uuid4()}"

    token = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            token_hash=token_hash,
            expires_at=now + timedelta(days=30),
        ),
    )

    repository.revoke(
        token,
        revoked_at=now,
    )

    result = repository.get_active_by_token_hash(
        token_hash=token_hash,
        now=now,
    )

    assert result is None


def test_get_active_by_token_hash_rejects_expired_token(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    now: datetime,
) -> None:
    """Test expired tokens are not returned as active."""
    token_hash = f"hash-{uuid4()}"

    create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            token_hash=token_hash,
            expires_at=now - timedelta(seconds=1),
        ),
    )

    result = repository.get_active_by_token_hash(
        token_hash=token_hash,
        now=now,
    )

    assert result is None


def test_get_active_by_user(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
) -> None:
    """Test retrieving all active tokens belonging to a user."""
    first = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(user_id=user_id),
    )

    second = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(user_id=user_id),
    )

    result = repository.get_active_by_user(
        user_id=user_id,
    )

    result_ids = {token.id for token in result}

    assert first.id in result_ids
    assert second.id in result_ids


def test_get_active_by_user_filters_context(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
) -> None:
    """Test filtering active tokens by authentication context."""
    organization_id = uuid4()
    membership_id = uuid4()

    personal = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="PERSONAL",
        ),
    )

    organization = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="ORGANIZATION",
            organization_id=organization_id,
            membership_id=membership_id,
        ),
    )

    result = repository.get_active_by_user(
        user_id=user_id,
        context_type="ORGANIZATION",
    )

    result_ids = {token.id for token in result}

    assert organization.id in result_ids
    assert personal.id not in result_ids


def test_get_active_by_user_filters_organization(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
) -> None:
    """Test filtering active tokens by organization."""
    organization_a = uuid4()
    organization_b = uuid4()

    token_a = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="ORGANIZATION",
            organization_id=organization_a,
        ),
    )

    token_b = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="ORGANIZATION",
            organization_id=organization_b,
        ),
    )

    result = repository.get_active_by_user(
        user_id=user_id,
        context_type="ORGANIZATION",
        organization_id=organization_a,
    )

    result_ids = {token.id for token in result}

    assert token_a.id in result_ids
    assert token_b.id not in result_ids


def test_get_active_by_user_filters_membership(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
) -> None:
    """Test filtering active tokens by membership."""
    organization_id = uuid4()
    membership_a = uuid4()
    membership_b = uuid4()

    token_a = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="ORGANIZATION",
            organization_id=organization_id,
            membership_id=membership_a,
        ),
    )

    token_b = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="ORGANIZATION",
            organization_id=organization_id,
            membership_id=membership_b,
        ),
    )

    result = repository.get_active_by_user(
        user_id=user_id,
        context_type="ORGANIZATION",
        organization_id=organization_id,
        membership_id=membership_a,
    )

    result_ids = {token.id for token in result}

    assert token_a.id in result_ids
    assert token_b.id not in result_ids


def test_revoke(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    now: datetime,
) -> None:
    """Test revoking one refresh token."""
    token = create_token(
        repository,
        cleanup_tokens,
    )

    result = repository.revoke(
        token,
        revoked_at=now,
    )

    assert result.is_revoked is True
    assert result.revoked_at == now


def test_revoke_all_for_user(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
    now: datetime,
) -> None:
    """Test revoking all active tokens for a user."""
    first = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(user_id=user_id),
    )

    second = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(user_id=user_id),
    )

    revoked_count = repository.revoke_all_for_user(
        user_id=user_id,
        revoked_at=now,
    )

    assert revoked_count >= 2
    assert first.is_revoked is True
    assert second.is_revoked is True


def test_revoke_all_for_user_scoped_to_context(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    user_id: UUID,
    now: datetime,
) -> None:
    """Test scoped bulk revocation."""
    organization_id = uuid4()

    personal = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="PERSONAL",
        ),
    )

    organization = create_token(
        repository,
        cleanup_tokens,
        TokenOptions(
            user_id=user_id,
            context_type="ORGANIZATION",
            organization_id=organization_id,
        ),
    )

    revoked_count = repository.revoke_all_for_user(
        user_id=user_id,
        revoked_at=now,
        context_type="ORGANIZATION",
        organization_id=organization_id,
    )

    assert revoked_count == 1
    assert personal.is_revoked is False
    assert organization.is_revoked is True


def test_mark_used(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    now: datetime,
) -> None:
    """Test recording token usage."""
    token = create_token(
        repository,
        cleanup_tokens,
    )

    result = repository.mark_used(
        token,
        used_at=now,
    )

    assert result.last_used_at == now


def test_rotate(
    repository: TokenRepository,
    cleanup_tokens: list[UUID],
    now: datetime,
) -> None:
    """Test refresh-token rotation."""
    original = create_token(
        repository,
        cleanup_tokens,
    )

    replacement = create_token(
        repository,
        cleanup_tokens,
    )

    result = repository.rotate(
        original,
        replacement_token_id=replacement.id,
        revoked_at=now,
    )

    assert result.is_revoked is True
    assert result.revoked_at == now
    assert result.replaced_by_token_id == replacement.id
