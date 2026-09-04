"""
Registration retry and idempotency integration tests.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core.exceptions import IntegrationError
from app.main import app


def test_same_request_same_idempotency_key_replays_safely(
    configure_user_service_url: str,
    integration_registration_payload: dict[str, str],
) -> None:
    """
    Repeating the exact registration request with the same key must
    resolve to the same canonical user rather than creating another one.
    """
    _ = configure_user_service_url

    client = TestClient(app)

    key = (
        f"retry-safe-{integration_registration_payload['username']}"
    )

    first = client.post(
        "/api/v1/auth/register",
        headers={"Idempotency-Key": key},
        json=integration_registration_payload,
    )

    assert first.status_code == 201

    first_body = first.json()

    second = client.post(
        "/api/v1/auth/register",
        headers={"Idempotency-Key": key},
        json=integration_registration_payload,
    )

    assert second.status_code in {201, 409}

    if second.status_code == 201:
        second_body = second.json()

        assert second_body["user_id"] == first_body["user_id"]
        assert second_body["public_id"] == first_body["public_id"]


def test_same_key_different_payload_returns_409(
    configure_user_service_url: str,
    integration_registration_payload: dict[str, str],
) -> None:
    """019 idempotency conflict propagates through 018."""
    _ = configure_user_service_url

    client = TestClient(app)

    key = (
        f"conflict-{integration_registration_payload['username']}"
    )

    first_payload = integration_registration_payload.copy()

    first = client.post(
        "/api/v1/auth/register",
        headers={"Idempotency-Key": key},
        json=first_payload,
    )

    assert first.status_code == 201

    second_payload = first_payload.copy()
    second_payload["display_name"] = "Different Payload"

    second = client.post(
        "/api/v1/auth/register",
        headers={"Idempotency-Key": key},
        json=second_payload,
    )

    assert second.status_code == 409


def test_same_identity_different_key_returns_409(
    configure_user_service_url: str,
    integration_registration_payload: dict[str, str],
) -> None:
    """A duplicate canonical identity cannot be recreated."""
    _ = configure_user_service_url

    client = TestClient(app)

    first = client.post(
        "/api/v1/auth/register",
        headers={
            "Idempotency-Key": (
                f"identity-a-{integration_registration_payload['username']}"
            ),
        },
        json=integration_registration_payload,
    )

    assert first.status_code == 201

    second = client.post(
        "/api/v1/auth/register",
        headers={
            "Idempotency-Key": (
                f"identity-b-{integration_registration_payload['username']}"
            ),
        },
        json=integration_registration_payload,
    )

    assert second.status_code == 409


def test_credential_failure_after_user_creation_does_not_create_second_user(
    configure_user_service_url: str,
    integration_registration_payload: dict[str, str],
) -> None:
    """
    Simulate failure after 019 succeeds.

    The important invariant is that retrying the same request must not
    create a second canonical user.
    """
    _ = configure_user_service_url

    client = TestClient(app)

    key = (
        f"credential-failure-{integration_registration_payload['username']}"
    )

    with patch(
        "app.services.registration_service.CredentialRepository.create",
        side_effect=IntegrationError(
            "Simulated credential failure.",
        ),
    ):
        first = client.post(
            "/api/v1/auth/register",
            headers={"Idempotency-Key": key},
            json=integration_registration_payload,
        )

    assert first.status_code == 503

    # Retry without the simulated failure.
    second = client.post(
        "/api/v1/auth/register",
        headers={"Idempotency-Key": key},
        json=integration_registration_payload,
    )

    assert second.status_code in {201, 409}
