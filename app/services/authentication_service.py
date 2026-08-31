"""
BuildOS Auth Service
Authentication Service
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.models.auth_credential import AuthCredential
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.repositories.login_attempt_repository import LoginAttemptRepository
from app.security.authentication import is_credential_locked
from app.security.password_hashing import verify_password
from app.security.rate_limiting import (
    get_lock_expiration,
    should_lock_account,
)


@dataclass(frozen=True)
class AuthenticationContext:
    """
    Authentication request context.
    """

    context_type: str = "PERSONAL"
    organization_id: UUID | None = None
    membership_id: UUID | None = None
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class AuthenticationResult:
    """
    Result of an authentication attempt.
    """

    authenticated: bool
    user_id: UUID | None
    credential: AuthCredential | None
    failure_reason: str | None = None


class AuthenticationService:
    """
    Orchestrates authentication against the authentication repository layer.

    This service owns authentication workflow decisions but does not contain
    raw database queries or low-level password hashing/token implementation.
    """

    def __init__(
        self,
        *,
        credential_repository: CredentialRepository,
        login_attempt_repository: LoginAttemptRepository,
        event_repository: EventRepository,
    ) -> None:
        self.credential_repository = credential_repository
        self.login_attempt_repository = login_attempt_repository
        self.event_repository = event_repository

    def authenticate(
        self,
        *,
        user_id: UUID,
        password: str,
        identifier: str,
        context_type: str = "PERSONAL",
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        now: datetime | None = None,
    ) -> AuthenticationResult:
        """
        Authenticate a user using an already-resolved user identity.
        """

        current_time = now or datetime.now(UTC)

        context = AuthenticationContext(
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        credential = self.credential_repository.get_by_user_id(user_id)

        if credential is None:
            self._record_failed_attempt(
                identifier=identifier,
                user_id=None,
                context=context,
                failure_reason="INVALID_CREDENTIALS",
            )

            return AuthenticationResult(
                authenticated=False,
                user_id=None,
                credential=None,
                failure_reason="INVALID_CREDENTIALS",
            )

        if not credential.is_active:
            self._record_failed_attempt(
                identifier=identifier,
                user_id=user_id,
                context=context,
                failure_reason="CREDENTIAL_INACTIVE",
            )

            return AuthenticationResult(
                authenticated=False,
                user_id=user_id,
                credential=credential,
                failure_reason="CREDENTIAL_INACTIVE",
            )

        if is_credential_locked(credential, now=current_time):
            self._record_failed_attempt(
                identifier=identifier,
                user_id=user_id,
                context=context,
                failure_reason="ACCOUNT_LOCKED",
            )

            return AuthenticationResult(
                authenticated=False,
                user_id=user_id,
                credential=credential,
                failure_reason="ACCOUNT_LOCKED",
            )

        if not verify_password(password, credential.password_hash):
            updated_credential = self._handle_failed_password(
                credential=credential,
                identifier=identifier,
                user_id=user_id,
                context=context,
                now=current_time,
            )

            failure_reason = (
                "ACCOUNT_LOCKED"
                if updated_credential.is_locked
                else "INVALID_CREDENTIALS"
            )

            return AuthenticationResult(
                authenticated=False,
                user_id=user_id,
                credential=updated_credential,
                failure_reason=failure_reason,
            )

        self.credential_repository.record_successful_login(
            credential,
            login_at=current_time,
        )

        self.login_attempt_repository.create(
            identifier=identifier,
            user_id=user_id,
            successful=True,
            context_type=context.context_type,
            organization_id=context.organization_id,
            membership_id=context.membership_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
        )

        self.event_repository.create_auth_event(
            user_id=user_id,
            context_type=context.context_type,
            event_type="LOGIN_SUCCESS",
            organization_id=context.organization_id,
            membership_id=context.membership_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
        )

        return AuthenticationResult(
            authenticated=True,
            user_id=user_id,
            credential=credential,
        )

    def _handle_failed_password(
        self,
        *,
        credential: AuthCredential,
        identifier: str,
        user_id: UUID,
        context: AuthenticationContext,
        now: datetime,
    ) -> AuthCredential:
        """
        Record a failed password attempt and apply account lockout when needed.
        """

        credential = self.credential_repository.record_failed_login(
            credential,
        )

        self.login_attempt_repository.create(
            identifier=identifier,
            user_id=user_id,
            successful=False,
            context_type=context.context_type,
            organization_id=context.organization_id,
            membership_id=context.membership_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            failure_reason="INVALID_CREDENTIALS",
        )

        if should_lock_account(credential.failed_login_count):
            credential = self.credential_repository.lock(
                credential,
                locked_until=get_lock_expiration(now=now),
            )

            self.event_repository.create_security_event(
                user_id=user_id,
                context_type=context.context_type,
                event_type="ACCOUNT_LOCKED",
                severity="warning",
                description="Account locked after repeated failed login attempts.",
                organization_id=context.organization_id,
                membership_id=context.membership_id,
                ip_address=context.ip_address,
                user_agent=context.user_agent,
            )

        else:
            self.event_repository.create_auth_event(
                user_id=user_id,
                context_type=context.context_type,
                event_type="LOGIN_FAILURE",
                organization_id=context.organization_id,
                membership_id=context.membership_id,
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                metadata_json='{"reason":"INVALID_CREDENTIALS"}',
            )

        return credential

    def _record_failed_attempt(
        self,
        *,
        identifier: str,
        user_id: UUID | None,
        context: AuthenticationContext,
        failure_reason: str,
    ) -> None:
        """
        Record an authentication failure without exposing sensitive details.
        """

        self.login_attempt_repository.create(
            identifier=identifier,
            user_id=user_id,
            successful=False,
            context_type=context.context_type,
            organization_id=context.organization_id,
            membership_id=context.membership_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            failure_reason=failure_reason,
        )

        self.event_repository.create_auth_event(
            user_id=user_id,
            context_type=context.context_type,
            event_type="LOGIN_FAILURE",
            organization_id=context.organization_id,
            membership_id=context.membership_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            metadata_json=f'{{"reason":"{failure_reason}"}}',
        )