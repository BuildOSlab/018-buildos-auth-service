"""
BuildOS Auth Service
Authentication Credential Repository
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.auth_credential import AuthCredential


class CredentialRepository:
    """Database access for authentication credentials."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_user_id(self, user_id: UUID) -> AuthCredential | None:
        """Return authentication credentials for a user."""
        stmt = select(AuthCredential).where(AuthCredential.user_id == user_id)
        return self.db.scalar(stmt)

    def create(
        self,
        *,
        user_id: UUID,
        password_hash: str,
    ) -> AuthCredential:
        """Create and persist authentication credentials for a user."""
        credential = AuthCredential(
            user_id=user_id,
            password_hash=password_hash,
        )

        self.db.add(credential)
        self.db.flush()
        self.db.refresh(credential)

        return credential

    def update_password(
        self,
        credential: AuthCredential,
        *,
        password_hash: str,
        changed_at: datetime,
    ) -> AuthCredential:
        """Replace a credential password hash and record the change time."""
        credential.password_hash = password_hash
        credential.password_changed_at = changed_at

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def record_successful_login(
        self,
        credential: AuthCredential,
        *,
        login_at: datetime,
    ) -> AuthCredential:
        """Record a successful login and clear login failure state."""
        credential.failed_login_count = 0
        credential.is_locked = False
        credential.locked_until = None
        credential.last_login_at = login_at

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def record_failed_login(
        self,
        credential: AuthCredential,
    ) -> AuthCredential:
        """Record one failed login attempt for a credential."""
        credential.failed_login_count += 1

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def lock(
        self,
        credential: AuthCredential,
        *,
        locked_until: datetime | None = None,
    ) -> AuthCredential:
        """Lock credentials until the specified time, if provided."""
        credential.is_locked = True
        credential.locked_until = locked_until

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def unlock(
        self,
        credential: AuthCredential,
    ) -> AuthCredential:
        """Unlock credentials and reset the failed login counter."""
        credential.is_locked = False
        credential.locked_until = None
        credential.failed_login_count = 0

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def deactivate(
        self,
        credential: AuthCredential,
    ) -> AuthCredential:
        """Deactivate authentication credentials."""
        credential.is_active = False

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def activate(
        self,
        credential: AuthCredential,
    ) -> AuthCredential:
        """Activate authentication credentials."""
        credential.is_active = True

        self.db.flush()
        self.db.refresh(credential)

        return credential
