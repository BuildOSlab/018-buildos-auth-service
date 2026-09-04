"""
Real 018 -> 019 registration integration tests.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from _pytest.monkeypatch import MonkeyPatch

from app.integrations.user_service import UserService
from app.main import app


@pytest.mark.usefixtures("configure_user_service_url")
def test_successful_registration_through_real_user_service(
    integration_registration_payload: dict[str, str],
) -> None:
    """018 registration creates the canonical user in real 019."""
    payload = integration_registration_payload.copy()
    password = payload.pop("password")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": (
                    f"cross-service-{payload['username']}"
                ),
            },
            json={
                **payload,
                "password": password,
            },
        )

    assert response.status_code == 201

    body = response.json()

    assert body["registered"] is True
    assert body["user_id"]
    assert body["public_id"]
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


@pytest.mark.usefixtures("configure_user_service_url")
def test_duplicate_identity_propagates_409(
    integration_registration_payload: dict[str, str],
) -> None:
    """A second registration with the same identity is rejected."""
    payload = integration_registration_payload.copy()
    key = f"duplicate-{payload['username']}"

    with TestClient(app) as client:
        first = client.post(
            "/api/v1/auth/register",
            headers={"Idempotency-Key": key},
            json=payload,
        )

        assert first.status_code == 201

        second = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": f"{key}-different",
            },
            json=payload,
        )

    assert second.status_code == 409


@pytest.mark.usefixtures("configure_user_service_url")
def test_missing_identity_is_rejected_by_auth_service() -> None:
    """018 rejects a registration without any identity."""
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/register",
            headers={
                "Idempotency-Key": "missing-identity-test",
            },
            json={
                "password": "TestPassword123!",
            },
        )

    # The UserService integration boundary requires an identity.
    assert response.status_code in {400, 422}


def _unavailable_user_service_settings() -> SimpleNamespace:
    """Return settings pointing to an intentionally unavailable service."""
    return SimpleNamespace(
        user_service_url="http://127.0.0.1:1",
        user_service_api_key="test-key",
        user_service_id="buildos-auth-service",
        user_service_timeout=0.2,
    )


def test_user_service_network_failure_returns_503(
    monkeypatch: MonkeyPatch,
) -> None:
    """An unavailable 019 service becomes HTTP 503 from 018."""
    monkeypatch.setattr(
        "app.integrations.user_service.get_settings",
        _unavailable_user_service_settings,
    )

    service = UserService()

    try:
        with (
            TestClient(app) as client,
            patch(
                "app.api.dependencies.get_user_service",
                return_value=service,
            ),
        ):
            response = client.post(
                "/api/v1/auth/register",
                headers={
                    "Idempotency-Key": "network-failure-test",
                },
                json={
                    "email": "network-failure@example.com",
                    "password": "TestPassword123!",
                },
            )

        assert response.status_code == 503
    finally:
        service.close()


@pytest.mark.usefixtures("configure_user_service_url")
def test_user_service_client_can_reach_real_019(
    integration_registration_payload: dict[str, str],
) -> None:
    """Verify the 018 integration client can directly reach real 019."""
    payload = integration_registration_payload.copy()
    payload.pop("password")

    service = UserService()

    try:
        response = service.create_user(
            idempotency_key=(
                f"direct-client-{payload['username']}"
            ),
            **payload,
        )

        assert response.user_id
        assert response.public_id.startswith("usr_")
        assert response.status == "pending"
        assert response.created_at is not None
    finally:
        service.close()
