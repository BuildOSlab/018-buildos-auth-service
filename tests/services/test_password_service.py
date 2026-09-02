"""
BuildOS Auth Service
Password Service Tests
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import ANY, Mock
from uuid import UUID, uuid4

import pytest

from app.core.constants import (
    EVENT_PASSWORD_CHANGED,
    EVENT_PASSWORD_RESET_COMPLETED,
    EVENT_PASSWORD_RESET_REQUESTED,
)
from app.core.exceptions import InvalidCredentialsError, PasswordResetError
from app.integrations.user_service import UserService
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.repositories.password_reset_repository import PasswordResetRepository
from app.repositories.token_repository import TokenRepository
from app.services.password_service import PasswordService


def build_service(
    *,
    credential: Any = None,
    resolved_user_id: UUID | None = None,
    reset: Any = None,
) -> tuple[
    PasswordService,
    Mock,
    Mock,
    Mock,
    Mock,
    Mock,
]:
    """Build a password service with typed repository mocks."""

    user_service = Mock(spec=UserService)
    credential_repository = Mock(spec=CredentialRepository)
    password_reset_repository = Mock(spec=PasswordResetRepository)
    token_repository = Mock(spec=TokenRepository)
    event_repository = Mock(spec=EventRepository)

    user_service.resolve_identifier.return_value = resolved_user_id
    credential_repository.get_by_user_id.return_value = credential

    def update_password(
        credential_object: Any,
        *,
        password_hash: str,
        changed_at: datetime,
    ) -> Any:
        """Update the test credential and return it."""
        credential_object.password_hash = password_hash
        credential_object.password_changed_at = changed_at
        return credential_object

    credential_repository.update_password.side_effect = update_password

    def create_reset(**kwargs: Any) -> Any:
        """Create a test password-reset record."""
        return SimpleNamespace(
            user_id=kwargs["user_id"],
            token_hash=kwargs["token_hash"],
            expires_at=kwargs["expires_at"],
            is_used=False,
            used_at=None,
        )

    password_reset_repository.create.side_effect = create_reset
    password_reset_repository.get_active_by_token_hash.return_value = reset

    def mark_used(
        reset_object: Any,
        *,
        used_at: datetime,
    ) -> Any:
        """Mark the test reset record as used."""
        reset_object.is_used = True
        reset_object.used_at = used_at
        return reset_object

    password_reset_repository.mark_used.side_effect = mark_used
    token_repository.revoke_all_for_user.return_value = 1

    def create_security_event(**kwargs: Any) -> Any:
        """Create a test security event."""
        return SimpleNamespace(**kwargs)

    event_repository.create_security_event.side_effect = create_security_event

    service = PasswordService(
        user_service=cast(UserService, user_service),
        credential_repository=cast(
            CredentialRepository,
            credential_repository,
        ),
        password_reset_repository=cast(
            PasswordResetRepository,
            password_reset_repository,
        ),
        token_repository=cast(
            TokenRepository,
            token_repository,
        ),
        event_repository=cast(
            EventRepository,
            event_repository,
        ),
    )

    return (
        service,
        user_service,
        credential_repository,
        password_reset_repository,
        token_repository,
        event_repository,
    )


def test_change_password_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Change an active user's password successfully."""
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = SimpleNamespace(
        user_id=user_id,
        password_hash="old-hash",
        is_active=True,
        password_changed_at=now,
    )

    (
        service,
        _user_service,
        credential_repository,
        _password_reset_repository,
        token_repository,
        event_repository,
    ) = build_service(credential=credential)

    def verify_password(
        password: str,
        password_hash: str,
    ) -> bool:
        """Verify the expected test password."""
        return password == "OldPassword123" and password_hash == "old-hash"

    def hash_password(password: str) -> str:
        """Return a deterministic test password hash."""
        return f"hash:{password}"

    monkeypatch.setattr(
        "app.services.password_service.verify_password",
        verify_password,
    )
    monkeypatch.setattr(
        "app.services.password_service.hash_password",
        hash_password,
    )

    result = service.change_password(
        user_id=user_id,
        current_password="OldPassword123",
        new_password="NewPassword123",
        now=now,
    )

    assert result.changed is True
    assert result.user_id == user_id
    assert credential.password_hash == "hash:NewPassword123"
    assert credential.password_changed_at == now

    credential_repository.update_password.assert_called_once()

    token_repository.revoke_all_for_user.assert_called_once_with(
        user_id=user_id,
        revoked_at=now,
        context_type="PERSONAL",
        organization_id=None,
        membership_id=None,
    )

    event_repository.create_security_event.assert_called_once()

    event_call = event_repository.create_security_event.call_args.kwargs
    assert event_call["user_id"] == user_id
    assert event_call["event_type"] == EVENT_PASSWORD_CHANGED


def test_change_password_rejects_invalid_current_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a password change when the current password is invalid."""
    user_id = uuid4()

    credential = SimpleNamespace(
        user_id=user_id,
        password_hash="old-hash",
        is_active=True,
        password_changed_at=datetime.now(UTC),
    )

    service, _user_service, *_repositories = build_service(
        credential=credential,
    )

    def verify_password(
        _password: str,
        _password_hash: str,
    ) -> bool:
        """Always reject the supplied current password."""
        return False

    monkeypatch.setattr(
        "app.services.password_service.verify_password",
        verify_password,
    )

    with pytest.raises(InvalidCredentialsError):
        service.change_password(
            user_id=user_id,
            current_password="wrong",
            new_password="NewPassword123",
        )


def test_change_password_rejects_missing_credential() -> None:
    """Reject a password change when no credential exists."""
    service, _user_service, *_repositories = build_service(
        credential=None,
    )

    with pytest.raises(InvalidCredentialsError):
        service.change_password(
            user_id=uuid4(),
            current_password="OldPassword123",
            new_password="NewPassword123",
        )


def test_change_password_rejects_inactive_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a password change for an inactive credential."""
    credential = SimpleNamespace(
        password_hash="old-hash",
        is_active=False,
        password_changed_at=datetime.now(UTC),
    )

    service, _user_service, *_repositories = build_service(
        credential=credential,
    )

    def verify_password(
        _password: str,
        _password_hash: str,
    ) -> bool:
        """Return true so the inactive check is exercised."""
        return True

    monkeypatch.setattr(
        "app.services.password_service.verify_password",
        verify_password,
    )

    with pytest.raises(InvalidCredentialsError):
        service.change_password(
            user_id=uuid4(),
            current_password="OldPassword123",
            new_password="NewPassword123",
        )


def test_change_password_rejects_same_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a password change when both passwords are identical."""
    credential = SimpleNamespace(
        password_hash="old-hash",
        is_active=True,
        password_changed_at=datetime.now(UTC),
    )

    service, _user_service, *_repositories = build_service(
        credential=credential,
    )

    def verify_password(
        _password: str,
        _password_hash: str,
    ) -> bool:
        """Return true so the same-password check is exercised."""
        return True

    monkeypatch.setattr(
        "app.services.password_service.verify_password",
        verify_password,
    )

    with pytest.raises(InvalidCredentialsError):
        service.change_password(
            user_id=uuid4(),
            current_password="SamePassword123",
            new_password="SamePassword123",
        )


def test_hash_reset_token_is_deterministic() -> None:
    """Hashing the same reset token produces the same digest."""
    token = "example-reset-token"

    first = PasswordService.hash_reset_token(token)
    second = PasswordService.hash_reset_token(token)

    assert first == second
    assert first != token
    assert len(first) == 64


def test_request_reset_unknown_identifier_does_not_create_token() -> None:
    """Do not generate a reset token for an unknown identifier."""
    (
        service,
        user_service,
        _credential_repository,
        password_reset_repository,
        _token_repository,
        event_repository,
    ) = build_service(resolved_user_id=None)

    result = service.request_reset(
        identifier="unknown@example.com",
    )

    assert result.requested is True
    assert result.reset_token is None

    user_service.resolve_identifier.assert_called_once_with(
        identifier="unknown@example.com",
    )
    password_reset_repository.create.assert_not_called()
    event_repository.create_security_event.assert_not_called()


def test_request_reset_known_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create a reset request for a known identifier."""
    user_id = uuid4()

    (
        service,
        _user_service,
        _credential_repository,
        password_reset_repository,
        _token_repository,
        event_repository,
    ) = build_service(
        resolved_user_id=user_id,
    )

    def token_urlsafe(_length: int) -> str:
        """Return a deterministic reset token for testing."""
        return "raw-reset-token"

    monkeypatch.setattr(
        "app.services.password_service.token_urlsafe",
        token_urlsafe,
    )

    result = service.request_reset(
        identifier="known@example.com",
    )

    assert result.requested is True
    assert result.reset_token == "raw-reset-token"

    password_reset_repository.create.assert_called_once()

    create_call = password_reset_repository.create.call_args.kwargs
    assert create_call["user_id"] == user_id
    assert create_call["token_hash"] == (PasswordService.hash_reset_token("raw-reset-token"))

    event_repository.create_security_event.assert_called_once()

    event_call = event_repository.create_security_event.call_args.kwargs
    assert event_call["user_id"] == user_id
    assert event_call["event_type"] == EVENT_PASSWORD_RESET_REQUESTED


def test_confirm_reset_rejects_invalid_token() -> None:
    """Reject a password reset when the reset token is invalid."""
    (
        service,
        _user_service,
        _credential_repository,
        password_reset_repository,
        _token_repository,
        _event_repository,
    ) = build_service(reset=None)

    with pytest.raises(PasswordResetError):
        service.confirm_reset(
            reset_token="invalid-token",
            new_password="NewPassword123",
        )

    password_reset_repository.get_active_by_token_hash.assert_called_once_with(
        token_hash=PasswordService.hash_reset_token("invalid-token"),
        now=ANY,
    )


def test_confirm_reset_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete a valid password reset successfully."""
    user_id = uuid4()
    now = datetime.now(UTC)

    reset = SimpleNamespace(
        user_id=user_id,
        is_used=False,
        used_at=None,
    )

    credential = SimpleNamespace(
        user_id=user_id,
        password_hash="old-hash",
        is_active=True,
        password_changed_at=now,
    )

    (
        service,
        _user_service,
        credential_repository,
        password_reset_repository,
        token_repository,
        event_repository,
    ) = build_service(
        credential=credential,
        reset=reset,
    )

    def hash_password(password: str) -> str:
        """Return a deterministic test password hash."""
        return f"hash:{password}"

    monkeypatch.setattr(
        "app.services.password_service.hash_password",
        hash_password,
    )

    result = service.confirm_reset(
        reset_token="valid-token",
        new_password="NewPassword123",
        now=now,
    )

    assert result.reset is True
    assert result.user_id == user_id
    assert reset.is_used is True
    assert reset.used_at == now
    assert credential.password_hash == "hash:NewPassword123"
    assert credential.password_changed_at == now

    credential_repository.update_password.assert_called_once()

    password_reset_repository.mark_used.assert_called_once_with(
        reset,
        used_at=now,
    )

    token_repository.revoke_all_for_user.assert_called_once_with(
        user_id=user_id,
        revoked_at=now,
        context_type="PERSONAL",
        organization_id=None,
        membership_id=None,
    )

    event_repository.create_security_event.assert_called_once()

    event_call = event_repository.create_security_event.call_args.kwargs
    assert event_call["user_id"] == user_id
    assert event_call["event_type"] == EVENT_PASSWORD_RESET_COMPLETED


def test_confirm_reset_rejects_missing_credential() -> None:
    """Reject a password reset when the user has no credential."""
    user_id = uuid4()

    reset = SimpleNamespace(
        user_id=user_id,
        is_used=False,
        used_at=None,
    )

    (
        service,
        _user_service,
        credential_repository,
        password_reset_repository,
        token_repository,
        event_repository,
    ) = build_service(
        credential=None,
        reset=reset,
    )

    with pytest.raises(PasswordResetError):
        service.confirm_reset(
            reset_token="valid-token",
            new_password="NewPassword123",
        )

    credential_repository.update_password.assert_not_called()
    password_reset_repository.mark_used.assert_not_called()
    token_repository.revoke_all_for_user.assert_not_called()
    event_repository.create_security_event.assert_not_called()
