"""
BuildOS Auth Service
User Service Integration
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Self
from uuid import UUID

import httpx

from app.core.config import get_settings
from app.core.exceptions import IntegrationError


@dataclass(frozen=True)
class CreatedUser:
    """Canonical user created by the User Service."""

    user_id: UUID
    public_id: str
    status: str
    created_at: datetime


@dataclass(frozen=True)
class UserStatus:
    """Canonical user status returned by the User Service."""

    user_id: UUID
    status: str
    is_active: bool
    status_changed_at: datetime | None
    verification: dict[str, str]


class UserService:
    """
    Integration boundary for the canonical BuildOS User Service.

    The Auth Service does not own canonical user identity records.

    The User Service remains authoritative for user identity and
    account records. Auth communicates with it through the internal
    HTTP API.
    """

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        settings = get_settings()

        self.base_url = settings.user_service_url.rstrip("/")
        self.api_key = settings.user_service_api_key
        self.service_id = settings.user_service_id
        self.timeout = settings.user_service_timeout

        self._client = client or httpx.Client(
            timeout=self.timeout,
        )
        self._owns_client = client is None

    def close(self) -> None:
        """Close the HTTP client when Auth owns it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        """Build internal service authentication headers."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Service-ID": self.service_id,
            "Accept": "application/json",
        }

    @staticmethod
    def _detect_identifier_type(identifier: str) -> str:
        """
        Determine the identity type.

        Normalization remains the responsibility of the User Service.
        """
        value = identifier.strip()

        if "@" in value:
            return "email"

        compact = (
            value.replace(" ", "")
            .replace("-", "")
            .replace("(", "")
            .replace(")", "")
        )

        if value.startswith("+") or compact.isdigit():
            return "phone"

        return "username"

    @staticmethod
    def _extract_data(response: httpx.Response) -> dict[str, Any]:
        """
        Extract endpoint data from the standard API envelope or
        the previous raw response contract.
        """
        try:
            payload = response.json()
        except ValueError as exc:
            raise IntegrationError(
                "User Service returned invalid JSON.",
            ) from exc

        if not isinstance(payload, dict):
            raise IntegrationError(
                "User Service returned an invalid response.",
            )

        # Standard envelope:
        # {
        #   "success": true,
        #   "data": {...},
        #   "meta": {...}
        # }
        if payload.get("success") is True:
            data = payload.get("data")

            if not isinstance(data, dict):
                raise IntegrationError(
                    "User Service returned an invalid data payload.",
                )

            return data

        # Backward compatibility with the previous raw response contract.
        return payload

    def resolve_identifier(
        self,
        *,
        identifier: str,
    ) -> UUID | None:
        """
        Resolve an authentication identifier through the User Service.

        Returns None when the identity does not exist.
        """
        normalized_identifier = identifier.strip()

        if not normalized_identifier:
            return None

        identity_type = self._detect_identifier_type(
            normalized_identifier,
        )

        url = f"{self.base_url}/internal/v1/users/resolve"

        payload = {
            "identifier": normalized_identifier,
            "type": identity_type,
        }

        try:
            response = self._client.post(
                url,
                json=payload,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise IntegrationError(
                "User Service transport failed.",
            ) from exc

        if response.status_code in {404, 410}:
            return None

        if response.status_code != 200:
            raise IntegrationError(
                "User Service failed to resolve the user identity.",
            )

        data = self._extract_data(response)
        user_id = data.get("user_id")

        if not isinstance(user_id, str):
            raise IntegrationError(
                "User Service returned an invalid identity response.",
            )

        try:
            return UUID(user_id)
        except ValueError as exc:
            raise IntegrationError(
                "User Service returned an invalid identity response.",
            ) from exc

    def create_user(
        self,
        *,
        idempotency_key: str,
        email: str | None = None,
        phone: str | None = None,
        username: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        display_name: str | None = None,
        country: str | None = None,
        timezone: str = "Africa/Lagos",
        language: str = "en",
    ) -> CreatedUser:
        """Create a canonical user through the User Service."""
        normalized_idempotency_key = idempotency_key.strip()

        if not normalized_idempotency_key:
            raise IntegrationError(
                "User creation requires an idempotency key.",
            )

        identities = (email, phone, username)

        if not any(
            value is not None and value.strip()
            for value in identities
        ):
            raise IntegrationError(
                "User creation requires at least one identity.",
            )

        url = f"{self.base_url}/internal/v1/users/create"

        payload = {
            "email": email,
            "phone": phone,
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "display_name": display_name,
            "country": country,
            "timezone": timezone,
            "language": language,
        }

        headers = self._headers()
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = normalized_idempotency_key

        try:
            response = self._client.post(
                url,
                json=payload,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise IntegrationError(
                "User Service transport failed.",
            ) from exc

        if response.status_code not in {200, 201}:
            raise IntegrationError(
                "User Service failed to create the user.",
            )

        data = self._extract_data(response)

        user_id = data.get("user_id")
        public_id = data.get("public_id")
        status = data.get("status")
        created_at = data.get("created_at")

        if not isinstance(user_id, str):
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            )

        if not isinstance(public_id, str):
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            )

        if not isinstance(status, str):
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            )

        if not isinstance(created_at, str):
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            )

        try:
            parsed_user_id = UUID(user_id)
        except ValueError as exc:
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            ) from exc

        try:
            parsed_created_at = datetime.fromisoformat(created_at)
        except ValueError as exc:
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            ) from exc

        return CreatedUser(
            user_id=parsed_user_id,
            public_id=public_id,
            status=status,
            created_at=parsed_created_at,
        )

    def get_user_status(
        self,
        *,
        user_id: UUID,
    ) -> UserStatus:
        """Retrieve canonical user status from the User Service."""
        url = (
            f"{self.base_url}/internal/v1/users/"
            f"{user_id}/status"
        )

        try:
            response = self._client.get(
                url,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise IntegrationError(
                "User Service transport failed.",
            ) from exc

        if response.status_code == 404:
            raise IntegrationError(
                "User Service could not find the user.",
            )

        if response.status_code != 200:
            raise IntegrationError(
                "User Service failed to retrieve user status.",
            )

        data = self._extract_data(response)

        response_user_id = data.get("user_id")
        status = data.get("status")
        is_active = data.get("is_active")
        status_changed_at = data.get("status_changed_at")
        verification = data.get("verification")

        if not isinstance(response_user_id, str):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )

        if not isinstance(status, str):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )

        if not isinstance(is_active, bool):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )

        if verification is not None and not isinstance(
            verification,
            dict,
        ):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )

        parsed_verification: dict[str, str] = {}

        if isinstance(verification, dict):
            for key, value in verification.items():
                if not isinstance(key, str):
                    raise IntegrationError(
                        "User Service returned an invalid status response.",
                    )

                if not isinstance(value, str):
                    raise IntegrationError(
                        "User Service returned an invalid status response.",
                    )

                parsed_verification[key] = value

        parsed_status_changed_at: datetime | None = None

        if status_changed_at is not None:
            if not isinstance(status_changed_at, str):
                raise IntegrationError(
                    "User Service returned an invalid status response.",
                )

            try:
                parsed_status_changed_at = datetime.fromisoformat(
                    status_changed_at,
                )
            except ValueError as exc:
                raise IntegrationError(
                    "User Service returned an invalid status response.",
                ) from exc

        try:
            parsed_user_id = UUID(response_user_id)
        except ValueError as exc:
            raise IntegrationError(
                "User Service returned an invalid status response.",
            ) from exc

        return UserStatus(
            user_id=parsed_user_id,
            status=status,
            is_active=is_active,
            status_changed_at=parsed_status_changed_at,
            verification=parsed_verification,
        )
    