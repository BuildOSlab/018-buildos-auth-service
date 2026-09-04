"""
BuildOS Auth Service
Credential Synchronization Service
"""

from typing import ClassVar
from uuid import UUID

from app.repositories.credential_repository import CredentialRepository


class CredentialSyncService: # pylint: disable=too-few-public-methods
    """
    Handles credential state updates in response to user status changes
    from the User Service.
    """

    # Maps 019 user statuses to the authentication credential state.
    STATUS_TO_ACTIVE: ClassVar[dict[str, bool]] = {
        "pending": True,
        "verification_pending": True,
        "active": True,
        "suspended": False,
        "restricted": False,
        "deactivated": False,
        "deleted": False,
    }

    def __init__(
        self,
        credential_repository: CredentialRepository,
    ) -> None:
        """Initialize the credential synchronization service."""
        self.credential_repository = credential_repository

    def sync_status(
        self,
        user_id: UUID,
        user_status: str,
        is_active: bool,
    ) -> None:
        """
        Synchronize a credential's active state with a user status.

        The user status is authoritative for determining the credential
        state. The is_active value is accepted as part of the internal
        service contract for compatibility with the User Service.
        """
        # The status mapping is authoritative. The incoming is_active
        # value is intentionally not used to override it.
        del is_active

        credential = self.credential_repository.get_by_user_id(user_id)

        if credential is None:
            # A credential may not exist if user registration was not
            # completed. There is nothing to synchronize in that case.
            return

        desired_active = self.STATUS_TO_ACTIVE.get(user_status, False)

        if credential.is_active == desired_active:
            return

        if desired_active:
            self.credential_repository.activate(credential)
        else:
            self.credential_repository.deactivate(credential)
