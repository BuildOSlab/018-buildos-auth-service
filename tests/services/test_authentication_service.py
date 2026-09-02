"""
BuildOS Auth Service
Authentication Service Behavioral Tests
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

from app.models.auth_credential import AuthCredential
from app.services.authentication_service import AuthenticationService


def build_service(
    credential: AuthCredential | None,
) -> tuple[AuthenticationService, Mock, Mock, Mock]:
    credential_repository = Mock()
    login_attempt_repository = Mock()
    event_repository = Mock()

    credential_repository.get_by_user_id.return_value = credential

    service = AuthenticationService(
        credential_repository=credential_repository,
        login_attempt_repository=login_attempt_repository,
        event_repository=event_repository,
    )

    return (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    )


def build_credential(
    *,
    user_id: UUID | None = None,
    password_hash: str = "correct-password-hash",
    is_active: bool = True,
    is_locked: bool = False,
    failed_login_count: int = 0,
    locked_until: datetime | None = None,
) -> AuthCredential:
    return AuthCredential(
        user_id=user_id or uuid4(),
        password_hash=password_hash,
        is_active=is_active,
        is_locked=is_locked,
        failed_login_count=failed_login_count,
        locked_until=locked_until,
    )


def test_successful_authentication() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(user_id=user_id)

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is True
    assert result.user_id == user_id
    assert result.credential is credential
    assert result.failure_reason is None

    credential_repository.record_successful_login.assert_called_once_with(
        credential,
        login_at=now,
    )

    login_attempt_repository.create.assert_called_once()

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["identifier"] == "user@example.com"
    assert attempt["user_id"] == user_id
    assert attempt["successful"] is True

    event_repository.create_auth_event.assert_called_once()

    event = event_repository.create_auth_event.call_args.kwargs

    assert event["event_type"] == "LOGIN_SUCCESS"


def test_invalid_password_records_failed_attempt() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(user_id=user_id)

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    def record_failed_login(
        current_credential: AuthCredential,
    ) -> AuthCredential:
        current_credential.failed_login_count += 1
        return current_credential

    credential_repository.record_failed_login.side_effect = record_failed_login

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=False,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="wrong-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is False
    assert result.user_id == user_id
    assert result.failure_reason == "INVALID_CREDENTIALS"
    assert result.credential is credential
    assert credential.failed_login_count == 1

    credential_repository.record_failed_login.assert_called_once_with(
        credential,
    )

    login_attempt_repository.create.assert_called_once()

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["successful"] is False
    assert attempt["failure_reason"] == "INVALID_CREDENTIALS"

    event_repository.create_auth_event.assert_called_once()

    event = event_repository.create_auth_event.call_args.kwargs

    assert event["event_type"] == "LOGIN_FAILURE"


def test_fifth_failed_attempt_locks_account() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        failed_login_count=4,
    )

    (
        service,
        credential_repository,
        _,
        event_repository,
    ) = build_service(credential)

    def record_failed_login(
        current_credential: AuthCredential,
    ) -> AuthCredential:
        current_credential.failed_login_count += 1
        return current_credential

    def lock_credential(
        current_credential: AuthCredential,
        *,
        locked_until: datetime | None,
    ) -> AuthCredential:
        current_credential.is_locked = True
        current_credential.locked_until = locked_until
        return current_credential

    credential_repository.record_failed_login.side_effect = record_failed_login
    credential_repository.lock.side_effect = lock_credential

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=False,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="wrong-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is False
    assert result.failure_reason == "ACCOUNT_LOCKED"
    assert result.credential is credential
    assert credential.failed_login_count == 5
    assert credential.is_locked is True

    credential_repository.record_failed_login.assert_called_once_with(
        credential,
    )

    credential_repository.lock.assert_called_once()

    lock_kwargs = credential_repository.lock.call_args.kwargs

    assert lock_kwargs["locked_until"] is not None
    assert lock_kwargs["locked_until"] > now

    event_repository.create_security_event.assert_called_once()

    event = event_repository.create_security_event.call_args.kwargs

    assert event["event_type"] == "ACCOUNT_LOCKED"
    assert event["severity"] == "warning"


def test_locked_account_cannot_authenticate() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        is_locked=True,
        locked_until=now + timedelta(minutes=15),
    )

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is False
    assert result.failure_reason == "ACCOUNT_LOCKED"
    assert result.user_id == user_id
    assert result.credential is credential

    credential_repository.record_successful_login.assert_not_called()

    login_attempt_repository.create.assert_called_once()

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["identifier"] == "user@example.com"
    assert attempt["user_id"] == user_id
    assert attempt["successful"] is False
    assert attempt["failure_reason"] == "ACCOUNT_LOCKED"

    event_repository.create_auth_event.assert_called_once()

    event = event_repository.create_auth_event.call_args.kwargs

    assert event["event_type"] == "LOGIN_FAILURE"


def test_expired_lock_allows_authentication() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        is_locked=True,
        locked_until=now - timedelta(minutes=1),
    )

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is True
    assert result.failure_reason is None

    credential_repository.record_successful_login.assert_called_once_with(
        credential,
        login_at=now,
    )

    login_attempt_repository.create.assert_called_once()

    event_repository.create_auth_event.assert_called_once()


def test_successful_login_resets_failed_login_state() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        failed_login_count=4,
    )

    service, credential_repository, _, _ = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is True

    credential_repository.record_successful_login.assert_called_once_with(
        credential,
        login_at=now,
    )


def test_inactive_credential_cannot_authenticate() -> None:
    user_id = uuid4()

    credential = build_credential(
        user_id=user_id,
        is_active=False,
    )

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
        )

    assert result.authenticated is False
    assert result.failure_reason == "CREDENTIAL_INACTIVE"

    credential_repository.record_successful_login.assert_not_called()

    login_attempt_repository.create.assert_called_once()

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["failure_reason"] == "CREDENTIAL_INACTIVE"

    event_repository.create_auth_event.assert_called_once()


def test_missing_credential_returns_invalid_credentials() -> None:
    user_id = uuid4()

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(None)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
        )

    assert result.authenticated is False
    assert result.user_id is None
    assert result.credential is None
    assert result.failure_reason == "INVALID_CREDENTIALS"

    credential_repository.record_successful_login.assert_not_called()

    login_attempt_repository.create.assert_called_once()

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["user_id"] is None
    assert attempt["failure_reason"] == "INVALID_CREDENTIALS"

    event_repository.create_auth_event.assert_called_once()


def test_locked_account_does_not_verify_password() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        is_locked=True,
        locked_until=now + timedelta(minutes=15),
    )

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
    ) as verify_password:
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is False
    assert result.failure_reason == "ACCOUNT_LOCKED"

    verify_password.assert_not_called()
    credential_repository.record_successful_login.assert_not_called()

    login_attempt_repository.create.assert_called_once()
    event_repository.create_auth_event.assert_called_once()


def test_inactive_credential_does_not_verify_password() -> None:
    user_id = uuid4()

    credential = build_credential(
        user_id=user_id,
        is_active=False,
    )

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
    ) as verify_password:
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
        )

    assert result.authenticated is False
    assert result.failure_reason == "CREDENTIAL_INACTIVE"

    verify_password.assert_not_called()
    credential_repository.record_successful_login.assert_not_called()

    login_attempt_repository.create.assert_called_once()
    event_repository.create_auth_event.assert_called_once()


def test_fifth_failed_attempt_uses_configured_lock_duration() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        failed_login_count=4,
    )

    (
        service,
        credential_repository,
        _,
        event_repository,
    ) = build_service(credential)

    def record_failed_login(
        current_credential: AuthCredential,
    ) -> AuthCredential:
        current_credential.failed_login_count += 1
        return current_credential

    def lock_credential(
        current_credential: AuthCredential,
        *,
        locked_until: datetime | None,
    ) -> AuthCredential:
        current_credential.is_locked = True
        current_credential.locked_until = locked_until
        return current_credential

    credential_repository.record_failed_login.side_effect = record_failed_login
    credential_repository.lock.side_effect = lock_credential

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=False,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="wrong-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.authenticated is False
    assert result.failure_reason == "ACCOUNT_LOCKED"

    lock_kwargs = credential_repository.lock.call_args.kwargs
    locked_until = lock_kwargs["locked_until"]

    assert locked_until is not None
    assert locked_until > now

    expected_duration = timedelta(
        minutes=15,
    )

    assert locked_until == now + expected_duration

    event_repository.create_security_event.assert_called_once()


def test_successful_authentication_preserves_context() -> None:
    user_id = uuid4()
    organization_id = uuid4()
    membership_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(user_id=user_id)

    (
        service,
        _,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=True,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="correct-password",
            identifier="user@example.com",
            context_type="ORGANIZATION",
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address="127.0.0.1",
            user_agent="BuildOS-Test",
            now=now,
        )

    assert result.authenticated is True

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["context_type"] == "ORGANIZATION"
    assert attempt["organization_id"] == organization_id
    assert attempt["membership_id"] == membership_id
    assert attempt["ip_address"] == "127.0.0.1"
    assert attempt["user_agent"] == "BuildOS-Test"

    event = event_repository.create_auth_event.call_args.kwargs

    assert event["context_type"] == "ORGANIZATION"
    assert event["organization_id"] == organization_id
    assert event["membership_id"] == membership_id
    assert event["ip_address"] == "127.0.0.1"
    assert event["user_agent"] == "BuildOS-Test"


def test_lock_records_failed_attempt_and_security_event() -> None:
    user_id = uuid4()
    now = datetime.now(UTC)

    credential = build_credential(
        user_id=user_id,
        failed_login_count=4,
    )

    (
        service,
        credential_repository,
        login_attempt_repository,
        event_repository,
    ) = build_service(credential)

    def record_failed_login(
        current_credential: AuthCredential,
    ) -> AuthCredential:
        current_credential.failed_login_count += 1
        return current_credential

    def lock_credential(
        current_credential: AuthCredential,
        *,
        locked_until: datetime | None,
    ) -> AuthCredential:
        current_credential.is_locked = True
        current_credential.locked_until = locked_until
        return current_credential

    credential_repository.record_failed_login.side_effect = record_failed_login
    credential_repository.lock.side_effect = lock_credential

    with patch(
        "app.services.authentication_service.verify_password",
        return_value=False,
    ):
        result = service.authenticate(
            user_id=user_id,
            password="wrong-password",
            identifier="user@example.com",
            now=now,
        )

    assert result.failure_reason == "ACCOUNT_LOCKED"

    login_attempt_repository.create.assert_called_once()

    attempt = login_attempt_repository.create.call_args.kwargs

    assert attempt["identifier"] == "user@example.com"
    assert attempt["user_id"] == user_id
    assert attempt["successful"] is False
    assert attempt["failure_reason"] == "INVALID_CREDENTIALS"

    event_repository.create_security_event.assert_called_once()

    event = event_repository.create_security_event.call_args.kwargs

    assert event["user_id"] == user_id
    assert event["event_type"] == "ACCOUNT_LOCKED"
    assert event["severity"] == "warning"
