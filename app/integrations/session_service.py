"""HTTP integration boundary for the BuildOS Session Service (022)."""

import json
import logging
import time
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

from app.core.config import get_settings
from app.core.exceptions import IntegrationError

logger = logging.getLogger(__name__)


class SessionService:
    """Integration client for the BuildOS Session Service."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = settings.session_service_url.rstrip("/")
        self.api_key = settings.session_service_api_key
        self.service_id = settings.session_service_id
        self.timeout = settings.session_service_timeout
        self._client = client or httpx.Client(timeout=self.timeout)
        self._owns_client = client is None

    def close(self) -> None:
        """Close the HTTP client when the service owns it."""
        if self._owns_client:
            self._client.close()

    def _headers(self) -> dict[str, str]:
        """Build internal service authentication headers."""
        if not self.api_key:
            raise IntegrationError("SESSION_SERVICE_API_KEY is not configured.")
        if not self.service_id:
            raise IntegrationError("SESSION_SERVICE_ID is not configured.")

        auth_value = self.api_key
        if not auth_value.lower().startswith("bearer "):
            auth_value = f"Bearer {auth_value}"

        return {
            "Authorization": auth_value,
            "X-Service-ID": self.service_id,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _log_request(self, method: str, url: str, **extra: Any) -> None:
        logger.info(
            "Session Service request",
            extra={
                "event": "session_service_request",
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
            "Session Service response",
            extra={
                "event": "session_service_response",
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
            "Session Service transport error",
            extra={
                "event": "session_service_transport_error",
                "method": method,
                "url": url,
                "duration_ms": round(duration_ms, 1),
                "error": str(error),
                "service_id": self.service_id,
            },
        )

    def create_session(
        self,
        *,
        user_id: UUID,
        device_id: UUID,
        expires_at: datetime,
    ) -> UUID:
        """Create a server-side session in the BuildOS Session Service."""
        if not self.base_url:
            raise IntegrationError("SESSION_SERVICE_URL is not configured.")

        url = f"{self.base_url}/api/v1/sessions"
        payload = {
            "user_id": str(user_id),
            "device_id": str(device_id),
            "expires_at": expires_at.isoformat(),
        }

        self._log_request("POST", url, user_id=str(user_id), device_id=str(device_id))

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
            raise IntegrationError("Session Service transport failed.") from exc

        duration_ms = (time.perf_counter() - start) * 1000
        self._log_response("POST", url, response.status_code, duration_ms)

        if response.status_code >= 400:
            detail = response.text.strip() or "Session Service request failed."
            raise IntegrationError(
                f"Session Service rejected session creation: {response.status_code} – {detail}"
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise IntegrationError("Session Service returned invalid JSON.") from exc

        if not isinstance(body, dict):
            raise IntegrationError("Session Service returned an invalid response.")

        session_id = body.get("session_id")
        if not isinstance(session_id, str):
            raise IntegrationError("Session Service returned an invalid session ID.")

        try:
            return UUID(session_id)
        except ValueError as exc:
            raise IntegrationError("Session Service returned an invalid session ID.") from exc
