"""
BuildOS Auth Service
Authentication Event Model
"""
# pylint: disable=duplicate-code

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class AuthEvent(Base):
    # pylint: disable=too-few-public-methods
    """
    Records authentication lifecycle events.

    Examples:
    - login
    - logout
    - token issued
    - token refreshed
    - token revoked
    - authentication failure
    - context switched
    """

    __tablename__ = "auth_events"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    context_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="PERSONAL",
        server_default="PERSONAL",
        index=True,
    )

    organization_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    membership_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    metadata_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(), # pylint: disable=not-callable
    )

    def __repr__(self) -> str:
        return (
            f"<AuthEvent "
            f"id={self.id!s} "
            f"user_id={self.user_id!s} "
            f"context_type={self.context_type!r} "
            f"event_type={self.event_type!r}>"
        )
