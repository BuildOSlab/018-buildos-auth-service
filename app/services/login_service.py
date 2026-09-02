"""
BuildOS Auth Service
Login Orchestration Service
"""

from dataclasses import dataclass
from uuid import UUID

from app.core.exceptions import InvalidCredentialsError
from app.integrations.user_service import UserService
from app.services.authentication_service import (
    AuthenticationResult,
    AuthenticationService,
)


@dataclass(frozen=True)
class LoginResult:
    """
    Result of the login orchestration.
    """

    authentication: AuthenticationResult


class LoginService:
    """
    Orchestrates identifier resolution and authentication.

    User identity resolution belongs to the User Service.
    Credential verification belongs to the Auth Service.
    """

    def __init__(
        self,
        *,
        user_service: UserService,
        authentication_service: AuthenticationService,
    ) -> None:
        self.user_service = user_service
        self.authentication_service = authentication_service

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
        Resolve the identifier and authenticate the corresponding user.
        """

        user_id = self.user_service.resolve_identifier(
            identifier=identifier,
        )

        if user_id is None:
            raise InvalidCredentialsError("Invalid credentials.")

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
            raise InvalidCredentialsError("Invalid credentials.")

        return LoginResult(
            authentication=authentication,
        )
