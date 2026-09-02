"""
BuildOS Auth Service
Authentication API Integration Tests
"""

from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.dependencies import get_login_service, get_token_service
from app.core.exceptions import IntegrationError, InvalidCredentialsError
from app.main import app
from app.services.authentication_service import AuthenticationResult
from app.services.login_service import LoginResult
from app.services.token_service import TokenPair


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


def build_token_pair() -> TokenPair:
    """Build a deterministic token pair for API integration tests."""
    return TokenPair(
        access_token="test-access-token",
        refresh_token="test-refresh-token",
        token_type="bearer",
    )


def test_login_success() -> None:
    login_service = Mock()
    token_service = Mock()

    result = build_authenticated_result()
    token_pair = build_token_pair()

    login_service.login.return_value = result
    token_service.issue_tokens.return_value = token_pair

    app.dependency_overrides[get_login_service] = lambda: login_service
    app.dependency_overrides[get_token_service] = lambda: token_service

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
        assert body["access_token"] == "test-access-token"
        assert body["refresh_token"] == "test-refresh-token"
        assert body["token_type"] == "bearer"

        login_service.login.assert_called_once_with(
            identifier="user@example.com",
            password="correct-password",
            ip_address="testclient",
            user_agent="testclient",
        )

        token_service.issue_tokens.assert_called_once_with(
            user_id=result.authentication.user_id,
            context_type="PERSONAL",
            ip_address="testclient",
            user_agent="testclient",
        )
    finally:
        app.dependency_overrides.clear()


def test_login_invalid_credentials_returns_401() -> None:
    login_service = Mock()
    login_service.login.side_effect = InvalidCredentialsError(
        "Invalid credentials.",
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
        "User Service integration transport is not configured.",
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
