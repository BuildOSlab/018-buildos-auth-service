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
        stmt = select(AuthCredential).where(
            AuthCredential.user_id == user_id
        )
        return self.db.scalar(stmt)

    def create(
        self,
        *,
        user_id: UUID,
        password_hash: str,
    ) -> AuthCredential:
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
        credential.is_locked = True
        credential.locked_until = locked_until

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def unlock(
        self,
        credential: AuthCredential,
    ) -> AuthCredential:
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
        credential.is_active = False

        self.db.flush()
        self.db.refresh(credential)

        return credential

    def activate(
        self,
        credential: AuthCredential,
    ) -> AuthCredential:
        credential.is_active = True

        self.db.flush()
        self.db.refresh(credential)

        return credential
