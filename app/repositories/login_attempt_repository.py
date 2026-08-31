"""
BuildOS Auth Service
Login Attempt Repository
"""

# pylint: disable=too-many-arguments

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.sql.functions import count

from app.models.login_attempt import LoginAttempt


class LoginAttemptRepository:
    """Database access for authentication attempts."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        identifier: str,
        successful: bool,
        user_id: UUID | None = None,
        context_type: str = "PERSONAL",
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        failure_reason: str | None = None,
    ) -> LoginAttempt:
        """Create and persist a login attempt."""
        attempt = LoginAttempt(
            identifier=identifier,
            successful=successful,
            user_id=user_id,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason,
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
