"""
BuildOS Auth Service
Password Management Service
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from uuid import UUID

from app.core.config import get_settings
from app.core.constants import (
    CONTEXT_PERSONAL,
    EVENT_PASSWORD_CHANGED,
    EVENT_PASSWORD_RESET_COMPLETED,
    EVENT_PASSWORD_RESET_REQUESTED,
)
from app.core.exceptions import (
    InvalidCredentialsError,
    PasswordResetError,
)
from app.integrations.user_service import UserService
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.repositories.password_reset_repository import PasswordResetRepository
from app.repositories.token_repository import TokenRepository
from app.security.password_hashing import hash_password, verify_password


@dataclass(frozen=True)
class PasswordContext:
    """Security context associated with a password operation."""

    context_type: str = CONTEXT_PERSONAL
    organization_id: UUID | None = None
    membership_id: UUID | None = None
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class PasswordResetRequestResult:
    """Result of a password reset request."""

    requested: bool
    reset_token: str | None = None


@dataclass(frozen=True)
class PasswordChangeResult:
    """Result of a password change."""

    changed: bool
    user_id: UUID


@dataclass(frozen=True)
class PasswordResetResult:
    """Result of a completed password reset."""

    reset: bool
    user_id: UUID


class PasswordService:
    """
    Orchestrates password changes and password reset lifecycle.

    Password hashes are persisted only through the credential repository.
    Reset tokens are persisted only as hashes.
    """

    def __init__(
        self,
        *,
        user_service: UserService,
        credential_repository: CredentialRepository,
        password_reset_repository: PasswordResetRepository,
        token_repository: TokenRepository,
        event_repository: EventRepository,
    ) -> None:
        self.user_service = user_service
        self.credential_repository = credential_repository
        self.password_reset_repository = password_reset_repository
        self.token_repository = token_repository
        self.event_repository = event_repository

    def change_password(
        self,
        *,
        user_id: UUID,
        current_password: str,
        new_password: str,
        context: PasswordContext | None = None,
        now: datetime | None = None,
    ) -> PasswordChangeResult:
        """Change an authenticated user's password."""
        operation_context = context or PasswordContext()
        current_time = now or datetime.now(UTC)

        credential = self.credential_repository.get_by_user_id(user_id)

        if credential is None:
            raise InvalidCredentialsError("Invalid credentials.")

        if not credential.is_active:
            raise InvalidCredentialsError("Invalid credentials.")

        if not verify_password(
            current_password,
            credential.password_hash,
        ):
            raise InvalidCredentialsError("Invalid credentials.")

        if current_password == new_password:
            raise InvalidCredentialsError(
                "New password must differ from the current password."
            )

        updated_credential = self.credential_repository.update_password(
            credential,
            password_hash=hash_password(new_password),
            changed_at=current_time,
        )

        self.token_repository.revoke_all_for_user(
            user_id=user_id,
            revoked_at=current_time,
            context_type=operation_context.context_type,
            organization_id=operation_context.organization_id,
            membership_id=operation_context.membership_id,
        )

        self.event_repository.create_security_event(
            user_id=user_id,
            context_type=operation_context.context_type,
            event_type=EVENT_PASSWORD_CHANGED,
            severity="info",
            description="User password changed successfully.",
            organization_id=operation_context.organization_id,
            membership_id=operation_context.membership_id,
            ip_address=operation_context.ip_address,
            user_agent=operation_context.user_agent,
        )

        return PasswordChangeResult(
            changed=updated_credential.password_changed_at == current_time,
            user_id=user_id,
        )

    def request_reset(
        self,
        *,
        identifier: str,
        ip_address: str | None = None,
        now: datetime | None = None,
    ) -> PasswordResetRequestResult:
        """
        Create a password reset request.

        Unknown identifiers return the same outward result as known
        identifiers to avoid account enumeration.
        """
        current_time = now or datetime.now(UTC)

        user_id = self.user_service.resolve_identifier(
            identifier=identifier,
        )

        if user_id is None:
            return PasswordResetRequestResult(
                requested=True,
                reset_token=None,
            )

        reset_token = token_urlsafe(48)
        token_hash = self.hash_reset_token(reset_token)

        settings = get_settings()
        expires_at = current_time + timedelta(
            minutes=settings.password_reset_expire_minutes,
        )

        self.password_reset_repository.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            requested_ip=ip_address,
        )

        self.event_repository.create_security_event(
            user_id=user_id,
            context_type=CONTEXT_PERSONAL,
            event_type=EVENT_PASSWORD_RESET_REQUESTED,
            severity="info",
            description="Password reset requested.",
            ip_address=ip_address,
        )

        return PasswordResetRequestResult(
            requested=True,
            reset_token=reset_token,
        )

    def confirm_reset(
        self,
        *,
        reset_token: str,
        new_password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        now: datetime | None = None,
    ) -> PasswordResetResult:
        """Complete a password reset using a valid single-use token."""
        current_time = now or datetime.now(UTC)

        reset = self.password_reset_repository.get_active_by_token_hash(
            token_hash=self.hash_reset_token(reset_token),
            now=current_time,
        )

        if reset is None:
            raise PasswordResetError("Invalid or expired reset token.")

        credential = self.credential_repository.get_by_user_id(
            reset.user_id,
        )

        if credential is None:
            raise PasswordResetError("Password reset cannot be completed.")

        self.credential_repository.update_password(
            credential,
            password_hash=hash_password(new_password),
            changed_at=current_time,
        )

        self.password_reset_repository.mark_used(
            reset,
            used_at=current_time,
        )

        self.token_repository.revoke_all_for_user(
            user_id=reset.user_id,
            revoked_at=current_time, 
            context_type=CONTEXT_PERSONAL,
            organization_id=None,
            membership_id=None,
        )

        self.event_repository.create_security_event(
            user_id=reset.user_id,
            context_type=CONTEXT_PERSONAL,
            event_type=EVENT_PASSWORD_RESET_COMPLETED,
            severity="info",
            description="Password reset completed successfully.",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return PasswordResetResult(
            reset=True,
            user_id=reset.user_id,
        )

    @staticmethod
    def hash_reset_token(token: str) -> str:
        """Hash a password reset token before persistence."""
        return sha256(token.encode("utf-8")).hexdigest()
