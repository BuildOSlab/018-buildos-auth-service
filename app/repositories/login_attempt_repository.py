"""
BuildOS Auth Service
Login Attempt Repository
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql.functions import count

from app.models.login_attempt import LoginAttempt


@dataclass(frozen=True)
class LoginAttemptOptions:
    """Optional configuration for creating a login attempt."""

    user_id: UUID | None = None
    context_type: str = "PERSONAL"
    organization_id: UUID | None = None
    membership_id: UUID | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    failure_reason: str | None = None


class LoginAttemptRepository:
    """Database access for authentication attempts."""

    def __init__(self, db: Session) -> None:
        """Initialize the repository with a database session."""
        self.db = db

    def create(
        self,
        *,
        identifier: str,
        successful: bool,
        options: LoginAttemptOptions | None = None,
    ) -> LoginAttempt:
        """Create and persist a login attempt."""
        options = options or LoginAttemptOptions()

        attempt = LoginAttempt(
            identifier=identifier,
            successful=successful,
            user_id=options.user_id,
            context_type=options.context_type,
            organization_id=options.organization_id,
            membership_id=options.membership_id,
            ip_address=options.ip_address,
            user_agent=options.user_agent,
            failure_reason=options.failure_reason,
        )

        self.db.add(attempt)
        self.db.flush()
        self.db.refresh(attempt)

        return attempt

    def get_recent_by_identifier(
        self,
        *,
        identifier: str,
        since: datetime,
    ) -> list[LoginAttempt]:
        """Return recent login attempts for an identifier."""
        stmt = (
            select(LoginAttempt)
            .where(
                LoginAttempt.identifier == identifier,
                LoginAttempt.attempted_at >= since,
            )
            .order_by(LoginAttempt.attempted_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def get_recent_by_user(
        self,
        *,
        user_id: UUID,
        since: datetime,
    ) -> list[LoginAttempt]:
        """Return recent login attempts for a user."""
        stmt = (
            select(LoginAttempt)
            .where(
                LoginAttempt.user_id == user_id,
                LoginAttempt.attempted_at >= since,
            )
            .order_by(LoginAttempt.attempted_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def count_failed_by_identifier(
        self,
        *,
        identifier: str,
        since: datetime,
    ) -> int:
        """Count failed login attempts for an identifier."""
        stmt = (
            select(count())
            .select_from(LoginAttempt)
            .where(
                LoginAttempt.identifier == identifier,
                LoginAttempt.successful.is_(False),
                LoginAttempt.attempted_at >= since,
            )
        )

        return int(self.db.scalar(stmt) or 0)

    def count_failed_by_user(
        self,
        *,
        user_id: UUID,
        since: datetime,
    ) -> int:
        """Count failed login attempts for a user."""
        stmt = (
            select(count())
            .select_from(LoginAttempt)
            .where(
                LoginAttempt.user_id == user_id,
                LoginAttempt.successful.is_(False),
                LoginAttempt.attempted_at >= since,
            )
        )

        return int(self.db.scalar(stmt) or 0)
