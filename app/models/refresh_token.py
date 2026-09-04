"""
BuildOS Auth Service
Refresh Token Model
"""
# pylint: disable=duplicate-code

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class RefreshToken(Base):
    # pylint: disable=too-few-public-methods
    """
    Stores refresh-token state.

    A refresh token belongs to a user, but may represent either:

    1. PERSONAL context
    2. ORGANIZATION context

    The organization and membership IDs are references to records
    owned by other BuildOS services.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    # Canonical Person/User ID.
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # PERSONAL or ORGANIZATION.
    context_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="PERSONAL",
        server_default="PERSONAL",
        index=True,
    )

    # Organization ID when context_type = ORGANIZATION.
    organization_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    # Membership ID authorizing the user to act for the organization.
    membership_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    token_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        unique=True,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(), # pylint: disable=not-callable
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    replaced_by_token_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<RefreshToken "
            f"id={self.id!s} "
            f"user_id={self.user_id!s} "
            f"context_type={self.context_type!r} "
            f"organization_id={self.organization_id!s} "
            f"is_revoked={self.is_revoked}>"
        )
