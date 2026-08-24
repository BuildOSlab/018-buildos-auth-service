"""
BuildOS Auth Service
Authentication API Integration Tests
"""

from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.dependencies import get_login_service
from app.core.exceptions import IntegrationError, InvalidCredentialsError
from app.main import app
from app.services.authentication_service import AuthenticationResult
from app.services.login_service import LoginResult


def build_authenticated_result() -> LoginResult:
    """Build a successful authentication result for API integration tests."""
    return LoginResult(
        authentication=AuthenticationResult(
            authenticated=True,
            user_id=uuid4(),
            credential=None,
            failure_reason=None,
        )
    )


def test_login_success() -> None:
    login_service = Mock()
    result = build_authenticated_result()
    login_service.login.return_value = result

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "correct-password",
            },
        )

        assert response.status_code == 200

        body = response.json()

        assert body["authenticated"] is True
        assert body["user_id"] == str(result.authentication.user_id)
        assert body["access_token"] is None
        assert body["refresh_token"] is None
        assert body["token_type"] == "bearer"

        login_service.login.assert_called_once_with(
            identifier="user@example.com",
            password="correct-password",
            ip_address="testclient",
            user_agent="testclient",
        )
    finally:
        app.dependency_overrides.clear()


def test_login_invalid_credentials_returns_401() -> None:
    login_service = Mock()
    login_service.login.side_effect = InvalidCredentialsError(
        "Invalid credentials."
    )

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "wrong-password",
            },
        )

        assert response.status_code == 401
        assert response.json() == {
            "detail": "Invalid credentials.",
        }
    finally:
        app.dependency_overrides.clear()


def test_login_user_service_unavailable_returns_503() -> None:
    login_service = Mock()
    login_service.login.side_effect = IntegrationError(
        "User Service integration transport is not configured."
    )

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "correct-password",
            },
        )

        assert response.status_code == 503
        assert response.json() == {
            "detail": "User identity service is unavailable.",
        }
    finally:
        app.dependency_overrides.clear()


def test_login_rejects_missing_identifier() -> None:
    login_service = Mock()

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "password": "correct-password",
            },
        )

        assert response.status_code == 422
        login_service.login.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_login_rejects_missing_password() -> None:
    login_service = Mock()

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "user@example.com",
            },
        )

        assert response.status_code == 422
        login_service.login.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_login_rejects_empty_identifier() -> None:
    login_service = Mock()

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "",
                "password": "correct-password",
            },
        )

        assert response.status_code == 422
        login_service.login.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_login_rejects_empty_password() -> None:
    login_service = Mock()

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "",
            },
        )

        assert response.status_code == 422
        login_service.login.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_login_rejects_unknown_fields() -> None:
    login_service = Mock()

    app.dependency_overrides[get_login_service] = lambda: login_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/login",
            json={
                "identifier": "user@example.com",
                "password": "correct-password",
                "unexpected": "value",
            },
        )

        assert response.status_code == 422
        login_service.login.assert_not_called()
    finally:
        app.dependency_overrides.clear()
