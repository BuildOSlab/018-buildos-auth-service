"""
BuildOS Auth Service
Authentication and Security Event Repository
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.models.security_event import SecurityEvent


class EventRepository:
    """Database access for authentication and security events."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # pylint: disable=too-many-arguments
    def create_auth_event(
        self,
        *,
        user_id: UUID | None,
        context_type: str,
        event_type: str,
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata_json: str | None = None,
    ) -> AuthEvent:
        """Create and persist an authentication event."""
        event = AuthEvent(
            user_id=user_id,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_json=metadata_json,
        )

        self.db.add(event)
        self.db.flush()
        self.db.refresh(event)

        return event

    # pylint: disable=too-many-arguments
    def create_security_event(
        self,
        *,
        user_id: UUID | None,
        context_type: str,
        event_type: str,
        severity: str = "info",
        description: str | None = None,
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> SecurityEvent:
        """Create and persist a security event."""
        event = SecurityEvent(
            user_id=user_id,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            event_type=event_type,
            severity=severity,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.add(event)
        self.db.flush()
        self.db.refresh(event)

        return event

    def get_auth_events_by_user(
        self,
        user_id: UUID,
    ) -> list[AuthEvent]:
        """Return authentication events belonging to a user."""
        stmt = (
            select(AuthEvent)
            .where(AuthEvent.user_id == user_id)
            .order_by(AuthEvent.occurred_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def get_security_events_by_user(
        self,
        user_id: UUID,
    ) -> list[SecurityEvent]:
        """Return security events belonging to a user."""
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.user_id == user_id)
            .order_by(SecurityEvent.occurred_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def get_auth_events_by_type(
        self,
        event_type: str,
    ) -> list[AuthEvent]:
        """Return authentication events matching an event type."""
        stmt = (
            select(AuthEvent)
            .where(AuthEvent.event_type == event_type)
            .order_by(AuthEvent.occurred_at.desc())
        )

        return list(self.db.scalars(stmt).all())

    def get_security_events_by_type(
        self,
        event_type: str,
    ) -> list[SecurityEvent]:
        """Return security events matching an event type."""
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.event_type == event_type)
            .order_by(SecurityEvent.occurred_at.desc())
        )

        return list(self.db.scalars(stmt).all())
