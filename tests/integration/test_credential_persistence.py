"""
Integration tests for credential persistence against PostgreSQL.
These tests verify that the repository and transaction lifecycle actually persist data.
"""

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.repositories.credential_repository import CredentialRepository
from app.security.password_hashing import hash_password, verify_password

# pylint: disable=redefined-outer-name


@pytest.fixture(scope="session")
def engine() -> Generator[Engine, None, None]:
    """Create a PostgreSQL engine for integration tests."""
    settings = get_settings()
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Generator[Session, None, None]:
    """
    Provide a clean database session for each test.

    The session rolls back after the test to keep the database clean.
    """
    session = Session(bind=engine)

    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def repo(db_session: Session) -> CredentialRepository:
    """Provide a CredentialRepository instance."""
    return CredentialRepository(db_session)


@pytest.fixture
def user_id() -> UUID:
    """Return a random user ID for testing."""
    return uuid4()


def test_create_and_retrieve_credential(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Create a credential and verify it can be retrieved."""
    password = "SecureP@ssw0rd!"
    password_hash = hash_password(password)

    _credential = repo.create(user_id=user_id, password_hash=password_hash)
    db_session.flush()

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert retrieved.user_id == user_id
    assert retrieved.password_hash == password_hash
    assert retrieved.is_active is True
    assert retrieved.is_locked is False
    assert retrieved.failed_login_count == 0
    assert retrieved.created_at is not None
    assert retrieved.updated_at is not None

    assert verify_password(password, retrieved.password_hash) is True


def test_password_verification(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test correct and incorrect password verification."""
    password = "CorrectP@ss"
    wrong = "WrongP@ss"
    password_hash = hash_password(password)

    _credential = repo.create(user_id=user_id, password_hash=password_hash)
    db_session.flush()

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert verify_password(password, retrieved.password_hash) is True
    assert verify_password(wrong, retrieved.password_hash) is False


def test_update_password(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test changing the password hash."""
    old_password = "OldP@ss"
    new_password = "NewP@ss"
    old_hash = hash_password(old_password)
    credential = repo.create(user_id=user_id, password_hash=old_hash)
    db_session.flush()

    now = datetime.now(UTC)
    new_hash = hash_password(new_password)
    repo.update_password(credential, password_hash=new_hash, changed_at=now)
    db_session.flush()

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert verify_password(old_password, retrieved.password_hash) is False
    assert verify_password(new_password, retrieved.password_hash) is True
    assert retrieved.password_changed_at == now


def test_failed_login_increment(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test that failed_login_count increments."""
    password = "P@ss"
    password_hash = hash_password(password)
    credential = repo.create(user_id=user_id, password_hash=password_hash)
    db_session.flush()

    repo.record_failed_login(credential)
    db_session.flush()
    assert credential.failed_login_count == 1

    repo.record_failed_login(credential)
    db_session.flush()
    assert credential.failed_login_count == 2

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert retrieved.failed_login_count == 2


def test_reset_failed_count_on_successful_login(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test that successful login resets failed count and unlocks."""
    password = "P@ss"
    password_hash = hash_password(password)
    credential = repo.create(user_id=user_id, password_hash=password_hash)
    credential.failed_login_count = 3
    credential.is_locked = True
    db_session.flush()

    now = datetime.now(UTC)
    repo.record_successful_login(credential, login_at=now)
    db_session.flush()

    assert credential.failed_login_count == 0
    assert credential.is_locked is False
    assert credential.locked_until is None
    assert credential.last_login_at == now

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert retrieved.failed_login_count == 0
    assert retrieved.is_locked is False


def test_lock_account(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test locking the account."""
    password = "P@ss"
    password_hash = hash_password(password)
    credential = repo.create(user_id=user_id, password_hash=password_hash)
    db_session.flush()

    lock_until = datetime.now(UTC) + timedelta(minutes=15)
    repo.lock(credential, locked_until=lock_until)
    db_session.flush()

    assert credential.is_locked is True
    assert credential.locked_until == lock_until

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert retrieved.is_locked is True
    assert retrieved.locked_until == lock_until


def test_unlock_account(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test unlocking the account."""
    password = "P@ss"
    password_hash = hash_password(password)
    credential = repo.create(user_id=user_id, password_hash=password_hash)
    credential.is_locked = True
    credential.locked_until = datetime.now(UTC) + timedelta(minutes=15)
    db_session.flush()

    repo.unlock(credential)
    db_session.flush()

    assert credential.is_locked is False
    assert credential.locked_until is None
    assert credential.failed_login_count == 0

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert retrieved.is_locked is False
    assert retrieved.locked_until is None
    assert retrieved.failed_login_count == 0


def test_update_last_login_timestamp(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """Test updating last_login_at."""
    password = "P@ss"
    password_hash = hash_password(password)
    credential = repo.create(user_id=user_id, password_hash=password_hash)
    db_session.flush()

    now = datetime.now(UTC)
    repo.record_successful_login(credential, login_at=now)
    db_session.flush()

    assert credential.last_login_at == now

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is not None
    assert retrieved.last_login_at == now


def test_transaction_rollback(
    repo: CredentialRepository,
    db_session: Session,
    user_id: UUID,
) -> None:
    """
    Test that an exception rolls back the transaction and no credential
    is persisted.
    """
    password = "P@ss"
    password_hash = hash_password(password)

    _credential = repo.create(
        user_id=user_id,
        password_hash=password_hash,
    )
    db_session.flush()

    # Force a unique-constraint violation.
    with pytest.raises(IntegrityError):
        repo.create(
            user_id=user_id,
            password_hash=hash_password("another"),
        )
        db_session.flush()

    # SQLAlchemy marks the session as failed after a flush exception.
    # Explicit rollback restores the session and rolls back the entire
    # transaction, including the first credential.
    db_session.rollback()

    retrieved = repo.get_by_user_id(user_id)
    assert retrieved is None, "Credential should not exist after rollback"
