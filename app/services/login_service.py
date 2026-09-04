"""
BuildOS Auth Service
Login Orchestration Service
"""

from dataclasses import dataclass
from uuid import UUID

from app.core.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    UserDeletedError,
)
from app.integrations.user_service import UserService
from app.services.authentication_service import (
    AuthenticationResult,
    AuthenticationService,
)

# Statuses that are allowed to authenticate.
ALLOWED_LOGIN_STATUSES = {
    "active",
    "verification_pending",
    "pending",
}

# Pylint's too-few-public-methods warning is not useful for this
# orchestration service because its single public method represents
# the complete login use case.
# pylint: disable=too-few-public-methods


@dataclass(frozen=True)
class LoginResult:
    """
    Result of the login orchestration.
    """

    authentication: AuthenticationResult


class LoginService:
    """
    Orchestrates identifier resolution, user status verification,
    and authentication.

    User identity resolution and status belong to the User Service (019).
    Credential verification belongs to the Auth Service (018).
    """

    def __init__(
        self,
        *,
        user_service: UserService,
        authentication_service: AuthenticationService,
    ) -> None:
        self.user_service = user_service
        self.authentication_service = authentication_service

    # Authentication requires these context parameters for credential,
    # tenancy, membership, audit, and security processing.
    # pylint: disable=too-many-arguments
    def login(
        self,
        *,
        identifier: str,
        password: str,
        context_type: str = "PERSONAL",
        organization_id: UUID | None = None,
        membership_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> LoginResult:
        """
        Resolve the identifier, verify user status, and authenticate
        the corresponding user.
        """

        # Step 1: Resolve user_id from the User Service (019).
        user_id = self.user_service.resolve_identifier(
            identifier=identifier,
        )

        if user_id is None:
            raise InvalidCredentialsError("Invalid credentials.")

        # Step 2: Retrieve the canonical user status from 019.
        user_status = self.user_service.get_user_status(
            user_id=user_id,
        )

        # Step 3: Verify that the user's status permits authentication.
        if user_status.status not in ALLOWED_LOGIN_STATUSES:
            if user_status.status == "deleted":
                raise UserDeletedError(
                    "This account has been deleted."
                )

            if user_status.status in {
                "suspended",
                "restricted",
                "deactivated",
            }:
                raise AccountLockedError(
                    f"Account is {user_status.status}."
                )

            # Any unknown or otherwise disallowed status is treated
            # as inactive and must not authenticate.
            raise InvalidCredentialsError(
                "Account is not active."
            )

        # Step 4: Perform credential-based authentication.
        #
        # AuthenticationService remains responsible for password
        # verification, login attempts, lockout handling, token
        # generation, and related authentication concerns.
        authentication = self.authentication_service.authenticate(
            user_id=user_id,
            password=password,
            identifier=identifier,
            context_type=context_type,
            organization_id=organization_id,
            membership_id=membership_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        if not authentication.authenticated:
            raise InvalidCredentialsError(
                "Invalid credentials."
            )

        return LoginResult(
            authentication=authentication,
        )
