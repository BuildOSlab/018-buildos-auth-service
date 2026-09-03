from unittest.mock import Mock

from fastapi.testclient import TestClient

from app.api.dependencies import get_registration_service
from app.core.exceptions import IntegrationError, UserAlreadyExistsError
from app.main import app
from app.services.registration_service import RegistrationResult

client = TestClient(app)


def build_registration_result() -> RegistrationResult:
    """Build a valid mocked registration result."""
    user = Mock()
    user.user_id = "11111111-1111-1111-1111-111111111111"
    user.public_id = "USR_TEST_001"

    tokens = Mock()
    tokens.access_token = "access-token"
    tokens.refresh_token = "refresh-token"
    tokens.token_type = "bearer"

    return RegistrationResult(
        user=user,
        tokens=tokens,
    )


def override_registration_service(
    registration_service: Mock,
) -> None:
    """Override the registration dependency for API tests."""
    app.dependency_overrides[get_registration_service] = (
        lambda: registration_service
    )


def clear_overrides() -> None:
    """Clear FastAPI dependency overrides after each test."""
    app.dependency_overrides.clear()


def test_register_success() -> None:
    """A valid registration returns created user and tokens."""
    registration_service = Mock()
    registration_service.register.return_value = build_registration_result()

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-success",
            },
            json={
                "email": "new-user@example.com",
                "display_name": "New User",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 201

        payload = response.json()

        assert payload["registered"] is True
        assert payload["user_id"] == "11111111-1111-1111-1111-111111111111"
        assert payload["public_id"] == "USR_TEST_001"
        assert payload["access_token"] == "access-token"
        assert payload["refresh_token"] == "refresh-token"
        assert payload["token_type"] == "bearer"

        registration_service.register.assert_called_once_with(
            idempotency_key="test-registration-success",
            email="new-user@example.com",
            phone=None,
            username=None,
            password="TestPassword123!",
            first_name=None,
            last_name=None,
            display_name="New User",
            country=None,
            timezone="Africa/Lagos",
            language="en",
            ip_address="testclient",
            user_agent="testclient",
        )
    finally:
        clear_overrides()


def test_register_rejects_missing_idempotency_key() -> None:
    """Registration requires an Idempotency-Key header."""
    registration_service = Mock()

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "missing-key@example.com",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 400
        assert "Idempotency-Key" in response.json()["detail"]
        registration_service.register.assert_not_called()
    finally:
        clear_overrides()


def test_register_duplicate_user_returns_409() -> None:
    """An existing identity is returned as HTTP 409."""
    registration_service = Mock()
    registration_service.register.side_effect = UserAlreadyExistsError(
        "An account with this email already exists.",
    )

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-duplicate",
            },
            json={
                "email": "existing@example.com",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 409
        assert response.json()["detail"] == (
            "An account with this email already exists."
        )
    finally:
        clear_overrides()


def test_register_user_service_unavailable_returns_503() -> None:
    """A User Service integration failure returns HTTP 503."""
    registration_service = Mock()
    registration_service.register.side_effect = IntegrationError(
        "User Service unavailable.",
    )

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-unavailable",
            },
            json={
                "email": "service-error@example.com",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 503
        assert response.json()["detail"] == (
            "User registration service is unavailable."
        )
    finally:
        clear_overrides()


def test_register_rejects_short_password() -> None:
    """Passwords shorter than eight characters are rejected."""
    registration_service = Mock()

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-short-password",
            },
            json={
                "email": "short-password@example.com",
                "password": "short",
            },
        )

        assert response.status_code == 422
        registration_service.register.assert_not_called()
    finally:
        clear_overrides()


def test_register_rejects_extra_fields() -> None:
    """Unknown registration fields are rejected."""
    registration_service = Mock()

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-extra-field",
            },
            json={
                "email": "extra-field@example.com",
                "password": "TestPassword123!",
                "unexpected_field": "not-allowed",
            },
        )

        assert response.status_code == 422
        registration_service.register.assert_not_called()
    finally:
        clear_overrides()


def test_register_accepts_phone_identity() -> None:
    """Phone-only registration is accepted by the API schema."""
    registration_service = Mock()
    registration_service.register.return_value = build_registration_result()

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-phone",
            },
            json={
                "phone": "+2348012345678",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 201
        registration_service.register.assert_called_once()
        assert registration_service.register.call_args.kwargs["phone"] == (
            "+2348012345678"
        )
    finally:
        clear_overrides()


def test_register_accepts_username_identity() -> None:
    """Username-only registration is accepted by the API schema."""
    registration_service = Mock()
    registration_service.register.return_value = build_registration_result()

    override_registration_service(registration_service)

    try:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "test-registration-username",
            },
            json={
                "username": "new_username",
                "password": "TestPassword123!",
            },
        )

        assert response.status_code == 201
        registration_service.register.assert_called_once()
        assert registration_service.register.call_args.kwargs["username"] == (
            "new_username"
        )
    finally:
        clear_overrides()