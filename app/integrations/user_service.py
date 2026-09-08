"""
BuildOS Auth Service
User Service Integration
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Self
from uuid import UUID

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import get_settings
from app.core.exceptions import (
    IdempotencyConflictError,
    IntegrationError,
    UserAlreadyExistsError,
    UserDeletedError,
    UserNotFoundError,
    ValidationError,
)

logger = logging.getLogger(__name__)


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
        if not self.api_key:
            raise IntegrationError(
                "USER_SERVICE_API_KEY is not configured.",
            )

        if not self.service_id:
            raise IntegrationError(
                "USER_SERVICE_ID is not configured.",
            )

        # Prefer the standard Bearer format
        auth_value = self.api_key
        if not auth_value.lower().startswith("bearer "):
            auth_value = f"Bearer {auth_value}"

        return {
            "Authorization": auth_value,
            "X-Service-ID": self.service_id,
            "Accept": "application/json",
        }

    def _log_request(self, method: str, url: str, **extra: Any) -> None:
        logger.info(
            "User Service request",
            extra={
                "event": "user_service_request",
                "method": method,
                "url": url,
                "service_id": self.service_id,
                **extra,
            },
        )

    def _log_response(
        self,
        method: str,
        url: str,
        status_code: int,
        duration_ms: float,
        **extra: Any,
    ) -> None:
        level = logging.INFO if status_code < 400 else logging.WARNING
        logger.log(
            level,
            "User Service response",
            extra={
                "event": "user_service_response",
                "method": method,
                "url": url,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 1),
                "service_id": self.service_id,
                **extra,
            },
        )

    def _log_transport_error(
        self,
        method: str,
        url: str,
        duration_ms: float,
        error: Exception,
    ) -> None:
        logger.warning(
            "User Service transport error",
            extra={
                "event": "user_service_transport_error",
                "method": method,
                "url": url,
                "duration_ms": round(duration_ms, 1),
                "error": str(error),
                "service_id": self.service_id,
            },
        )

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

    @staticmethod
    def _parse_error_payload(
        response: httpx.Response,
    ) -> dict[str, Any]:
        """
        Extract a structured error payload when the User Service
        returns one.
        """
        try:
            payload = response.json()
        except (ValueError, TypeError):
            return {}

        if not isinstance(payload, dict):
            return {}

        detail = payload.get("detail")

        if isinstance(detail, dict):
            return detail

        return payload

    def _parse_error_detail(
        self,
        response: httpx.Response,
    ) -> str | None:
        """Extract human-readable error detail from the User Service."""
        try:
            payload = response.json()

            if not isinstance(payload, dict):
                return None

            detail = payload.get("detail")

            if isinstance(detail, str):
                return detail

            if isinstance(detail, dict):
                message = detail.get("message")

                if isinstance(message, str):
                    return message

                return None

            if detail is not None:
                return str(detail)

        except (ValueError, AttributeError, TypeError):
            pass

        return None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type(httpx.HTTPError),
        reraise=True,
    )
    def resolve_identifier(
        self,
        *,
        identifier: str,
    ) -> UUID | None:
        """
        Resolve an authentication identifier through the User Service.

        Returns None when the identity does not exist or has been
        deleted and is therefore no longer resolvable.
        """
        normalized_identifier = identifier.strip()

        if not normalized_identifier:
            return None

        identity_type = self._detect_identifier_type(normalized_identifier)
        url = f"{self.base_url}/internal/v1/users/resolve"

        payload = {
            "identifier": normalized_identifier,
            "type": identity_type,
        }

        self._log_request("POST", url, identity_type=identity_type)

        start = time.perf_counter()
        try:
            response = self._client.post(
                url,
                json=payload,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            self._log_transport_error("POST", url, duration_ms, exc)
            raise IntegrationError(
                "User Service transport failed.",
            ) from exc

        duration_ms = (time.perf_counter() - start) * 1000
        self._log_response("POST", url, response.status_code, duration_ms)

        error_detail = self._parse_error_detail(response)

        if response.status_code in {404, 410}:
            return None

        if response.status_code == 422:
            raise ValidationError(
                error_detail or "Validation error in identifier resolution.",
            )

        if response.status_code != 200:
            raise IntegrationError(
                "User Service failed to resolve the user identity: "
                f"{response.status_code} – {error_detail}"
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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type(httpx.HTTPError),
        reraise=True,
    )
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

        if not any(value is not None and value.strip() for value in identities):
            raise ValidationError(
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

        # Truncate idempotency key in logs for safety
        safe_key = normalized_idempotency_key[:16] + "..." if len(normalized_idempotency_key) > 16 else normalized_idempotency_key

        self._log_request(
            "POST",
            url,
            idempotency_key=safe_key,
            has_email=bool(email),
            has_phone=bool(phone),
            has_username=bool(username),
        )

        start = time.perf_counter()
        try:
            response = self._client.post(
                url,
                json=payload,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            self._log_transport_error("POST", url, duration_ms, exc)
            raise IntegrationError(
                "User Service transport failed.",
            ) from exc

        duration_ms = (time.perf_counter() - start) * 1000
        self._log_response("POST", url, response.status_code, duration_ms)

        error_detail = self._parse_error_detail(response)

        if response.status_code == 409:
            error_payload = self._parse_error_payload(response)
            error_code = error_payload.get("code")

            if error_code == "IDENTITY_ALREADY_EXISTS":
                if email is not None and email.strip():
                    message = "An account with this email already exists."
                elif phone is not None and phone.strip():
                    message = "An account with this phone number already exists."
                elif username is not None and username.strip():
                    message = "An account with this username already exists."
                else:
                    message = "An account with this identity already exists."

                raise UserAlreadyExistsError(message)

            if error_code == "IDEMPOTENCY_CONFLICT":
                raise IdempotencyConflictError(
                    error_detail or "Idempotency key was used with different data.",
                )

            if error_detail is not None and "idempotency" in error_detail.lower():
                raise IdempotencyConflictError(
                    error_detail or "Idempotency key was used with different data.",
                )

            raise UserAlreadyExistsError(
                error_detail or "An account with this identity already exists.",
            )

        if response.status_code == 422:
            raise ValidationError(
                error_detail or "Validation error in user creation.",
            )

        if response.status_code == 404:
            raise UserNotFoundError(
                error_detail or "User not found.",
            )

        if response.status_code == 410:
            raise UserDeletedError(
                error_detail or "User account has been deleted.",
            )

        if response.status_code not in {200, 201}:
            raise IntegrationError(
                "User Service failed to create the user: "
                f"{response.status_code} – {error_detail}"
            )

        data = self._extract_data(response)

        user_id = data.get("user_id")
        public_id = data.get("public_id")
        user_status = data.get("status")
        created_at = data.get("created_at")

        if not isinstance(user_id, str):
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            )
        if not isinstance(public_id, str):
            raise IntegrationError(
                "User Service returned an invalid user creation response.",
            )
        if not isinstance(user_status, str):
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

        logger.info(
            "User created successfully via User Service",
            extra={
                "event": "user_service_user_created",
                "user_id": str(parsed_user_id),
                "public_id": public_id,
                "status": user_status,
            },
        )

        return CreatedUser(
            user_id=parsed_user_id,
            public_id=public_id,
            status=user_status,
            created_at=parsed_created_at,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type(httpx.HTTPError),
        reraise=True,
    )
    def get_user_status(
        self,
        *,
        user_id: UUID,
    ) -> UserStatus:
        """Retrieve canonical user status from the User Service."""
        url = f"{self.base_url}/internal/v1/users/{user_id}/status"

        self._log_request("GET", url, user_id=str(user_id))

        start = time.perf_counter()
        try:
            response = self._client.get(
                url,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            self._log_transport_error("GET", url, duration_ms, exc)
            raise IntegrationError(
                "User Service transport failed.",
            ) from exc

        duration_ms = (time.perf_counter() - start) * 1000
        self._log_response("GET", url, response.status_code, duration_ms)

        error_detail = self._parse_error_detail(response)

        if response.status_code == 404:
            raise IntegrationError(
                error_detail or "could not find the user.",
            )

        if response.status_code == 410:
            raise UserDeletedError(
                error_detail or "User account has been deleted.",
            )

        if response.status_code == 422:
            raise ValidationError(
                error_detail or "Validation error in status request.",
            )

        if response.status_code != 200:
            raise IntegrationError(
                "User Service failed to retrieve user status: "
                f"{response.status_code} – {error_detail}"
            )

        data = self._extract_data(response)

        response_user_id = data.get("user_id")
        user_status = data.get("status")
        is_active = data.get("is_active")
        status_changed_at = data.get("status_changed_at")
        verification = data.get("verification")

        if not isinstance(response_user_id, str):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )
        if not isinstance(user_status, str):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )
        if not isinstance(is_active, bool):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )
        if verification is not None and not isinstance(verification, dict):
            raise IntegrationError(
                "User Service returned an invalid status response.",
            )

        parsed_verification: dict[str, str] = {}
        if isinstance(verification, dict):
            for key, value in verification.items():
                if not isinstance(key, str) or not isinstance(value, str):
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
                parsed_status_changed_at = datetime.fromisoformat(status_changed_at)
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
            status=user_status,
            is_active=is_active,
            status_changed_at=parsed_status_changed_at,
            verification=parsed_verification,
        )
    