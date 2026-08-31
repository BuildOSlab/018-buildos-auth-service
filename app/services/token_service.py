"""
BuildOS Auth Service
Token Lifecycle Service
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from app.core.config import get_settings
from app.core.constants import (
    CONTEXT_PERSONAL,
    EVENT_TOKEN_REFRESH,
    EVENT_TOKEN_REVOKED,
)
from app.core.exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    RevokedTokenError,
)
from app.repositories.event_repository import EventRepository
from app.repositories.token_repository import TokenRepository
from app.security.token_signing import (
    create_access_token,
    create_refresh_token,
)
from app.security.token_validation import validate_refresh_token


@dataclass(frozen=True)
class TokenPair:
    """Issued access and refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenService:
    """
    Orchestrates JWT issuance and persisted refresh-token lifecycle.

    JWT signing and validation remain delegated to the security layer.
    Database persistence remains delegated to repositories.
    """

    def __init__(
        self,
        *,
        token_repository: TokenRepository,
        event_repository: EventRepository,
    ) -> None:
        self.token_repository = token_repository
        self.event_repository = event_repository

    @staticmethod
    def hash_refresh_token(token: str) -> str:
        """
        Hash a refresh token for database persistence.

        The raw refresh token is never persisted.
        """
        return sha256(token.encode("utf-8")).hexdigest()

    def issue_tokens(
        self,
        *,
        user_id: UUID,
        context_type: str = CONTEXT_PERSONAL,
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        now: datetime | None = None,
    ) -> TokenPair:
        """
        Issue a new access/refresh token pair and persist refresh state.
        """
        settings = get_settings()
        issued_at = now or datetime.now(UTC)

        access_token = create_access_token(
            user_id=user_id,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            now=issued_at,
        )

        refresh_token = create_refresh_token(
            user_id=user_id,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            now=issued_at,
        )

        expires_at = issued_at + timedelta(
            days=settings.refresh_token_expire_days,
        )

        self.token_repository.create(
            user_id=user_id,
            token_hash=self.hash_refresh_token(refresh_token),
            expires_at=expires_at,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def refresh(
        self,
        *,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        now: datetime | None = None,
    ) -> TokenPair:
        """
        Validate, rotate, and replace a refresh token.

        The presented refresh token must be:
        - cryptographically valid
        - unexpired
        - the correct token type
        - present in the database
        - active and not revoked
        """
        current_time = now or datetime.now(UTC)

        payload = validate_refresh_token(refresh_token)

        subject = payload.get("sub")

        if not isinstance(subject, str):
            raise InvalidTokenError("Token subject is invalid.")

        try:
            user_id = UUID(subject)
        except ValueError as exc:
            raise InvalidTokenError("Token subject is invalid.") from exc

        token_hash = self.hash_refresh_token(refresh_token)

        stored_token = self.token_repository.get_by_token_hash(
            token_hash,
        )

        if stored_token is None:
            raise InvalidTokenError("Refresh token is not recognized.")

        if stored_token.is_revoked:
            raise RevokedTokenError("Refresh token has been revoked.")

        if stored_token.expires_at <= current_time:
            raise ExpiredTokenError("Refresh token has expired.")

        if stored_token.user_id != user_id:
            raise InvalidTokenError("Refresh token subject does not match.")

        context_type = payload.get("context_type", CONTEXT_PERSONAL)

        if not isinstance(context_type, str):
            raise InvalidTokenError("Token context is invalid.")

        organization_id = self._optional_uuid_claim(
            payload,
            "organization_id",
        )
        membership_id = self._optional_uuid_claim(
            payload,
            "membership_id",
        )

        replacement = self.issue_tokens(
            user_id=user_id,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address=ip_address,
            user_agent=user_agent,
            now=current_time,
        )

        replacement_id = self._get_replacement_token_id(
            replacement.refresh_token,
        )

        self.token_repository.rotate(
            stored_token,
            replacement_token_id=replacement_id,
            revoked_at=current_time,
        )

        self.token_repository.mark_used(
            stored_token,
            used_at=current_time,
        )

        self.event_repository.create_auth_event(
            user_id=user_id,
            context_type=context_type,
            event_type=EVENT_TOKEN_REFRESH,
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return replacement

    def revoke(
        self,
        *,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """
        Revoke one persisted refresh token.
        """
        current_time = now or datetime.now(UTC)

        payload = validate_refresh_token(refresh_token)

        subject = payload.get("sub")

        if not isinstance(subject, str):
            raise InvalidTokenError("Token subject is invalid.")

        try:
            user_id = UUID(subject)
        except ValueError as exc:
            raise InvalidTokenError("Token subject is invalid.") from exc

        token_hash = self.hash_refresh_token(refresh_token)

        stored_token = self.token_repository.get_by_token_hash(
            token_hash,
        )

        if stored_token is None:
            raise InvalidTokenError("Refresh token is not recognized.")

        if stored_token.is_revoked:
            raise RevokedTokenError("Refresh token has already been revoked.")

        self.token_repository.revoke(
            stored_token,
            revoked_at=current_time,
        )

        context_type = payload.get("context_type", CONTEXT_PERSONAL)

        if not isinstance(context_type, str):
            context_type = CONTEXT_PERSONAL

        organization_id = self._optional_uuid_claim(
            payload,
            "organization_id",
        )
        membership_id = self._optional_uuid_claim(
            payload,
            "membership_id",
        )

        self.event_repository.create_auth_event(
            user_id=user_id,
            context_type=context_type,
            event_type=EVENT_TOKEN_REVOKED,
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def revoke_all(
        self,
        *,
        user_id: UUID,
        context_type: str | None = None,
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        revoked_at: datetime | None = None,
    ) -> int:
        """
        Revoke all active refresh tokens belonging to a user.

        Context filtering will be added when the repository exposes
        context-specific bulk revocation.
        """
        current_time = revoked_at or datetime.now(UTC)

        return self.token_repository.revoke_all_for_user(
            user_id=user_id,
            revoked_at=current_time,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
        )
    def _get_replacement_token_id(
        self,
        refresh_token: str,
    ) -> UUID:
        """
        Resolve the persisted ID of a newly issued refresh token.
        """
        token_hash = self.hash_refresh_token(refresh_token)

        replacement = self.token_repository.get_by_token_hash(
            token_hash,
        )

        if replacement is None:
            raise InvalidTokenError(
                "Replacement refresh token could not be persisted.",
            )

        return replacement.id

    @staticmethod
    def _optional_uuid_claim(
        payload: dict[str, object],
        claim_name: str,
    ) -> UUID | None:
        """
        Parse an optional UUID claim from JWT payload.
        """
        value = payload.get(claim_name)

        if value is None:
            return None

        if not isinstance(value, str):
            raise InvalidTokenError(
                f"Token claim '{claim_name}' is invalid.",
            )

        try:
            return UUID(value)
        except ValueError as exc:
            raise InvalidTokenError(
                f"Token claim '{claim_name}' is invalid.",
            ) from exc
