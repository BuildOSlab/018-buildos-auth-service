"""
BuildOS Auth Service
Refresh Token Repository
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken


class TokenRepository:
    """Database access for refresh tokens."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        *,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
        context_type: str = "PERSONAL",
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
    ) -> RefreshToken:
        token = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
        )

        self.db.add(token)
        self.db.flush()
        self.db.refresh(token)

        return token

    def get_by_token_hash(
        self,
        token_hash: str,
    ) -> RefreshToken | None:
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )

        return self.db.scalar(stmt)

    def get_active_by_token_hash(
        self,
        *,
        token_hash: str,
        now: datetime,
    ) -> RefreshToken | None:
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > now,
        )

        return self.db.scalar(stmt)

    def get_active_by_user(
        self,
        *,
        user_id: UUID,
    ) -> list[RefreshToken]:
        stmt = (
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked.is_(False),
            )
            .order_by(RefreshToken.created_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def revoke(
        self,
        token: RefreshToken,
        *,
        revoked_at: datetime,
    ) -> RefreshToken:
        token.is_revoked = True
        token.revoked_at = revoked_at

        self.db.flush()
        self.db.refresh(token)

        return token

    def revoke_all_for_user(
        self,
        *,
        user_id: UUID,
        revoked_at: datetime,
    ) -> int:
        tokens = self.get_active_by_user(user_id=user_id)

        for token in tokens:
            token.is_revoked = True
            token.revoked_at = revoked_at

        self.db.flush()

        return len(tokens)

    def mark_used(
        self,
        token: RefreshToken,
        *,
        used_at: datetime,
    ) -> RefreshToken:
        token.last_used_at = used_at

        self.db.flush()
        self.db.refresh(token)

        return token

    def rotate(
        self,
        token: RefreshToken,
        *,
        replacement_token_id: UUID,
        revoked_at: datetime,
    ) -> RefreshToken:
        token.is_revoked = True
        token.revoked_at = revoked_at
        token.replaced_by_token_id = replacement_token_id

        self.db.flush()
        self.db.refresh(token)

        return token
