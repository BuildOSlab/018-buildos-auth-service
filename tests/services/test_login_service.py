"""
BuildOS LoginService lifecycle tests.
"""

from unittest.mock import Mock
from uuid import uuid4

import pytest

from app.core.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    UserDeletedError,
)
from app.integrations.user_service import UserStatus
from app.services.authentication_service import AuthenticationResult
from app.services.login_service import LoginService


def build_login_service(
    *,
    status: str,
    is_active: bool = True,
    authentication_result: AuthenticationResult | None = None,
) -> tuple[LoginService, Mock, Mock]:
    """Build a LoginService with mocked user and authentication services."""
    user_service = Mock()
    authentication_service = Mock()

    user_id = uuid4()

    user_service.resolve_identifier.return_value = user_id

    user_service.get_user_status.return_value = UserStatus(
        user_id=user_id,
        status=status,
        is_active=is_active,
        status_changed_at=None,
        verification={},
    )

    if authentication_result is None:
        authentication_result = AuthenticationResult(
            authenticated=True,
            user_id=user_id,
            credential=None,
            failure_reason=None,
        )

    authentication_service.authenticate.return_value = (
        authentication_result
    )

    service = LoginService(
        user_service=user_service,
        authentication_service=authentication_service,
    )

    return service, user_service, authentication_service


def test_active_user_can_login() -> None:
    """Active users can authenticate successfully."""
    service, _, authentication_service = build_login_service(
        status="active",
    )

    result = service.login(
        identifier="user@example.com",
        password="correct-password",
    )

    assert result.authentication.authenticated is True

    authentication_service.authenticate.assert_called_once()


@pytest.mark.parametrize(
    "status",
    [
        "suspended",
        "restricted",
        "deactivated",
    ],
)
def test_blocked_user_statuses_are_rejected(
    status: str,
) -> None:
    """Blocked account statuses prevent authentication."""
    service, _, authentication_service = build_login_service(
        status=status,
    )

    with pytest.raises(AccountLockedError):
        service.login(
            identifier="user@example.com",
            password="correct-password",
        )

    authentication_service.authenticate.assert_not_called()


def test_deleted_user_is_rejected() -> None:
    """Deleted users are rejected before authentication."""
    service, user_service, _ = build_login_service(
        status="deleted",
    )

    with pytest.raises(UserDeletedError):
        service.login(
            identifier="user@example.com",
            password="correct-password",
        )

    user_service.get_user_status.assert_called_once()


@pytest.mark.parametrize(
    "status",
    [
        "pending",
        "verification_pending",
    ],
)
def test_pending_statuses_follow_current_policy(
    status: str,
) -> None:
    """Pending statuses currently remain eligible for authentication."""
    service, _, authentication_service = build_login_service(
        status=status,
    )

    result = service.login(
        identifier="user@example.com",
        password="correct-password",
    )

    assert result.authentication.authenticated is True
    authentication_service.authenticate.assert_called_once()


def test_unknown_identifier_is_rejected() -> None:
    """Unknown identifiers are rejected without authentication."""
    service, user_service, authentication_service = (
        build_login_service(status="active")
    )

    user_service.resolve_identifier.return_value = None

    with pytest.raises(InvalidCredentialsError):
        service.login(
            identifier="unknown@example.com",
            password="wrong-password",
        )

    authentication_service.authenticate.assert_not_called()


def test_authentication_failure_is_rejected() -> None:
    """Failed credential authentication produces invalid credentials."""
    failed_result = AuthenticationResult(
        authenticated=False,
        user_id=uuid4(),
        credential=None,
        failure_reason="INVALID_CREDENTIALS",
    )

    service, _, authentication_service = build_login_service(
        status="active",
        authentication_result=failed_result,
    )

    with pytest.raises(InvalidCredentialsError):
        service.login(
            identifier="user@example.com",
            password="wrong-password",
        )

    authentication_service.authenticate.assert_called_once()


def test_locked_credential_is_rejected() -> None:
    """Locked credentials are rejected by the login service."""
    failed_result = AuthenticationResult(
        authenticated=False,
        user_id=uuid4(),
        credential=None,
        failure_reason="ACCOUNT_LOCKED",
    )

    service, _, _ = build_login_service(
        status="active",
        authentication_result=failed_result,
    )

    with pytest.raises(InvalidCredentialsError):
        service.login(
            identifier="user@example.com",
            password="correct-password",
        )


def test_inactive_credential_is_rejected() -> None:
    """Inactive credentials are rejected by the login service."""
    failed_result = AuthenticationResult(
        authenticated=False,
        user_id=uuid4(),
        credential=None,
        failure_reason="CREDENTIAL_INACTIVE",
    )

    service, _, _ = build_login_service(
        status="active",
        authentication_result=failed_result,
    )

    with pytest.raises(InvalidCredentialsError):
        service.login(
            identifier="user@example.com",
            password="correct-password",
        )
