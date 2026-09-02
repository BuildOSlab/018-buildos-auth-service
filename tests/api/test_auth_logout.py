"""
BuildOS Auth Service
Authentication Logout API Integration Tests
"""

from unittest.mock import Mock

from fastapi.testclient import TestClient

from app.api.dependencies import get_logout_service
from app.core.exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    RevokedTokenError,
)
from app.main import app
from app.services.logout_service import LogoutResult


def test_logout_success() -> None:
    logout_service = Mock()
    logout_service.logout.return_value = LogoutResult(logged_out=True)

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": "test-refresh-token",
            },
        )

        assert response.status_code == 200
        assert response.json() == {
            "revoked": True,
        }

        logout_service.logout.assert_called_once_with(
            refresh_token="test-refresh-token",
            ip_address="testclient",
            user_agent="testclient",
        )
    finally:
        app.dependency_overrides.clear()


def test_logout_expired_token_returns_401() -> None:
    logout_service = Mock()
    logout_service.logout.side_effect = ExpiredTokenError(
        "Refresh token has expired.",
    )

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": "expired-refresh-token",
            },
        )

        assert response.status_code == 401
        assert response.json() == {
            "detail": "Refresh token has expired.",
        }
    finally:
        app.dependency_overrides.clear()


def test_logout_revoked_token_returns_401() -> None:
    logout_service = Mock()
    logout_service.logout.side_effect = RevokedTokenError(
        "Refresh token has already been revoked.",
    )

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": "revoked-refresh-token",
            },
        )

        assert response.status_code == 401
        assert response.json() == {
            "detail": "Refresh token has already been revoked.",
        }
    finally:
        app.dependency_overrides.clear()


def test_logout_invalid_token_returns_401() -> None:
    logout_service = Mock()
    logout_service.logout.side_effect = InvalidTokenError(
        "Invalid refresh token.",
    )

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": "invalid-refresh-token",
            },
        )

        assert response.status_code == 401
        assert response.json() == {
            "detail": "Invalid refresh token.",
        }
    finally:
        app.dependency_overrides.clear()


def test_logout_rejects_missing_refresh_token() -> None:
    logout_service = Mock()

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={},
        )

        assert response.status_code == 422
        logout_service.logout.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_logout_rejects_empty_refresh_token() -> None:
    logout_service = Mock()

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": "",
            },
        )

        assert response.status_code == 422
        logout_service.logout.assert_not_called()
    finally:
        app.dependency_overrides.clear()


def test_logout_rejects_unknown_fields() -> None:
    logout_service = Mock()

    app.dependency_overrides[get_logout_service] = lambda: logout_service

    try:
        client = TestClient(app)

        response = client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": "test-refresh-token",
                "unexpected": "value",
            },
        )

        assert response.status_code == 422
        logout_service.logout.assert_not_called()
    finally:
        app.dependency_overrides.clear()
