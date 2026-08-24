"""
BuildOS Auth Service
User Service Integration
"""

from uuid import UUID

from app.core.exceptions import IntegrationError


class UserService:
    """
    Integration boundary for the canonical BuildOS User Service.

    The Auth Service does not own canonical user identity records.

    The User Service remains authoritative for the canonical user record.
    Auth only asks it to resolve an approved authentication identifier
    such as an email address or phone number into a canonical user_id.
    """

    def resolve_identifier(
        self,
        *,
        identifier: str,
    ) -> UUID | None:
        """
        Resolve an authentication identifier to a canonical user ID.

        The transport implementation will be added behind this boundary.
        """

        normalized_identifier = identifier.strip()

        if not normalized_identifier:
            return None

        raise IntegrationError(
            "User Service integration transport is not configured."
        )