"""
BuildOS Auth Service
User Service Integration
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Self
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

        try:
            data = response.json()
            return UUID(data["user_id"])
        except (KeyError, TypeError, ValueError) as exc:
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
        headers["Idempotency-Key"] = idempotency_key

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

        try:
            data = response.json()

            return CreatedUser(
                user_id=UUID(data["user_id"]),
                public_id=data["public_id"],
                status=data["status"],
                created_at=datetime.fromisoformat(
                    data["created_at"],
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            ) from exc

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

        try:
            data = response.json()

            status_changed_at = data.get("status_changed_at")

            return UserStatus(
                user_id=UUID(data["user_id"]),
                status=data["status"],
                is_active=data["is_active"],
                status_changed_at=(
                    datetime.fromisoformat(status_changed_at)
                    if status_changed_at
                    else None
                ),
                verification=data["verification"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrationError(
                "User Service returned an invalid status response.",
            ) from exc
