"""
BuildOS Auth Service
Login Attempt Model
"""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class LoginAttempt(Base):
    """
    Records authentication attempts.

    A login may establish either:

    - PERSONAL context
    - ORGANIZATION context
    """

    __tablename__ = "login_attempts"

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

    identifier: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
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

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    successful: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    failure_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"<LoginAttempt "
            f"id={self.id!s} "
            f"user_id={self.user_id!s} "
            f"context_type={self.context_type!r} "
            f"successful={self.successful}>"
        )