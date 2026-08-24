"""
BuildOS Auth Service
Password Reset Repository
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.password_reset import PasswordReset


class PasswordResetRepository:
    """Database access for password reset records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        requested_ip: str | None = None,
    ) -> PasswordReset:
        reset = PasswordReset(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            requested_ip=requested_ip,
        )

        self.db.add(reset)
        self.db.flush()
        self.db.refresh(reset)

        return reset

    def get_by_token_hash(
        self,
        token_hash: str,
    ) -> PasswordReset | None:
        stmt = select(PasswordReset).where(
            PasswordReset.token_hash == token_hash
        )
        return self.db.scalar(stmt)

    def get_active_by_token_hash(
        self,
        *,
        token_hash: str,
        now: datetime,
    ) -> PasswordReset | None:
        stmt = select(PasswordReset).where(
            PasswordReset.token_hash == token_hash,
            PasswordReset.is_used.is_(False),
            PasswordReset.expires_at > now,
        )

        return self.db.scalar(stmt)

    def get_latest_by_user(
        self,
        *,
        user_id: UUID,
    ) -> PasswordReset | None:
        stmt = (
            select(PasswordReset)
            .where(PasswordReset.user_id == user_id)
            .order_by(PasswordReset.created_at.desc())
            .limit(1)
        )

        return self.db.scalar(stmt)

    def mark_used(
        self,
        reset: PasswordReset,
        *,
        used_at: datetime,
    ) -> PasswordReset:
        reset.is_used = True
        reset.used_at = used_at

        self.db.flush()
        self.db.refresh(reset)

        return reset
