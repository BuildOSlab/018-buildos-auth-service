"""
Integration-style tests for the Auth Service -> User Service HTTP boundary.

These tests mock the HTTP transport so they verify request construction,
response handling, and error mapping without requiring the User Service
process to be running.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

import httpx
import pytest

from app.core.exceptions import IntegrationError, UserAlreadyExistsError
from app.integrations.user_service import UserService

TEST_USER_ID = UUID("82298225-a2af-4691-bc47-1514be4ceb88")


def make_transport(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    """Build an HTTP mock transport from a request handler."""
    return httpx.MockTransport(handler)


def make_service(
    transport: httpx.MockTransport,
) -> UserService:
    """Build a UserService using the supplied mock transport."""
    client = httpx.Client(
        transport=transport,
        base_url="http://testserver",
    )
    service = UserService(client=client)
    service.base_url = "http://testserver"
    return service


def test_resolve_identifier_success() -> None:
    """Resolve an identifier into the canonical user UUID."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/internal/v1/users/resolve"
        assert request.headers["Authorization"].startswith("Bearer ")
        assert request.headers["X-Service-ID"] == "buildos-auth-service"
        assert json.loads(request.content) == {
            "identifier": "gerald.test001@example.com",
            "type": "email",
        }

        return httpx.Response(
            200,
            json={
                "user_id": str(TEST_USER_ID),
                "status": "pending",
                "identities": [],
            },
        )

    with make_service(make_transport(handler)) as service:
        result = service.resolve_identifier(
            identifier="gerald.test001@example.com",
        )

    assert result == TEST_USER_ID


@pytest.mark.parametrize(
    ("identifier", "expected_type"),
    [
        ("gerald.test001@example.com", "email"),
        ("+2348012345001", "phone"),
        ("gerald_test001", "username"),
    ],
)
def test_resolve_identifier_classifies_types(
    identifier: str,
    expected_type: str,
) -> None:
    """Send the correct identity type to the User Service."""

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)

        assert payload["identifier"] == identifier
        assert payload["type"] == expected_type

        return httpx.Response(
            200,
            json={
                "user_id": str(TEST_USER_ID),
                "status": "pending",
                "identities": [],
            },
        )

    with make_service(make_transport(handler)) as service:
        result = service.resolve_identifier(identifier=identifier)

    assert result == TEST_USER_ID


@pytest.mark.parametrize("status_code", [404, 410])
def test_resolve_identifier_not_found_returns_none(
    status_code: int,
) -> None:
    """Map missing or deleted users to None."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code)

    with make_service(make_transport(handler)) as service:
        result = service.resolve_identifier(
            identifier="missing@example.com",
        )

    assert result is None


def test_resolve_identifier_transport_error() -> None:
    """Map transport failures to IntegrationError."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed")

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="User Service transport failed",
    ):
        service.resolve_identifier(
            identifier="gerald.test001@example.com",
        )


def test_resolve_identifier_unexpected_status() -> None:
    """Reject unexpected User Service responses."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            json={"detail": "server error"},
        )

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="failed to resolve the user identity",
    ):
        service.resolve_identifier(
            identifier="gerald.test001@example.com",
        )


def test_resolve_identifier_malformed_response() -> None:
    """Reject responses without a valid user UUID."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "pending",
                "identities": [],
            },
        )

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="invalid identity response",
    ):
        service.resolve_identifier(
            identifier="gerald.test001@example.com",
        )


def test_create_user_success() -> None:
    """Create a canonical user and parse the response."""
    created_at = datetime.now(UTC).isoformat()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/internal/v1/users/create"
        assert request.headers["Idempotency-Key"] == "registration-test-001"

        payload = json.loads(request.content)

        assert payload["email"] == "new@example.com"
        assert payload["first_name"] == "Test"
        assert payload["last_name"] == "User"

        return httpx.Response(
            201,
            json={
                "user_id": str(TEST_USER_ID),
                "public_id": "usr_test001",
                "status": "pending",
                "created_at": created_at,
            },
        )

    with make_service(make_transport(handler)) as service:
        result = service.create_user(
            idempotency_key="registration-test-001",
            email="new@example.com",
            first_name="Test",
            last_name="User",
        )

    assert result.user_id == TEST_USER_ID
    assert result.public_id == "usr_test001"
    assert result.status == "pending"


def test_create_user_conflict() -> None:
    """Map an existing identity to UserAlreadyExistsError."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "detail": {
                    "code": "IDENTITY_ALREADY_EXISTS",
                },
            },
        )

    with make_service(make_transport(handler)) as service, pytest.raises(
        UserAlreadyExistsError,
        match="account with this email already exists",
    ):
        service.create_user(
            idempotency_key="registration-test-002",
            email="existing@example.com",
        )


def test_create_user_malformed_response() -> None:
    """Reject malformed user creation responses."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json={
                "public_id": "usr_test001",
                "status": "pending",
            },
        )

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="invalid user creation response",
    ):
        service.create_user(
            idempotency_key="registration-test-003",
            email="new@example.com",
        )


def test_get_user_status_success() -> None:
    """Retrieve and parse canonical user status."""
    changed_at = datetime.now(UTC).isoformat()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == (
            f"/internal/v1/users/{TEST_USER_ID}/status"
        )

        return httpx.Response(
            200,
            json={
                "user_id": str(TEST_USER_ID),
                "status": "pending",
                "is_active": False,
                "status_changed_at": changed_at,
                "verification": {
                    "status": "unverified",
                    "method": "none",
                },
            },
        )

    with make_service(make_transport(handler)) as service:
        result = service.get_user_status(user_id=TEST_USER_ID)

    assert result.user_id == TEST_USER_ID
    assert result.status == "pending"
    assert result.is_active is False
    assert result.status_changed_at is not None
    assert result.verification["status"] == "unverified"


def test_get_user_status_not_found() -> None:
    """Map a missing user status to IntegrationError."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="could not find the user",
    ):
        service.get_user_status(user_id=TEST_USER_ID)


def test_get_user_status_transport_error() -> None:
    """Map status transport failures to IntegrationError."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed")

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="User Service transport failed",
    ):
        service.get_user_status(user_id=TEST_USER_ID)


def test_get_user_status_malformed_response() -> None:
    """Reject malformed status responses."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "user_id": str(TEST_USER_ID),
                "status": "pending",
            },
        )

    with make_service(make_transport(handler)) as service, pytest.raises(
        IntegrationError,
        match="invalid status response",
    ):
        service.get_user_status(user_id=TEST_USER_ID)
