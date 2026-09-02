"""
BuildOS Auth Service
Registration Service
"""

from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError

from app.core.exceptions import IntegrationError
from app.integrations.user_service import CreatedUser, UserService
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.security.password_hashing import hash_password
from app.services.token_service import TokenPair, TokenService


@dataclass(frozen=True)
class RegistrationResult:
    """Result of a successful registration."""

    user: CreatedUser
    tokens: TokenPair


class RegistrationService:
    """
    Orchestrates canonical user creation and authentication setup.

    The User Service owns canonical user identity.
    The Auth Service owns authentication credentials and tokens.
    """

    def __init__(
        self,
        *,
        user_service: UserService,
        credential_repository: CredentialRepository,
        event_repository: EventRepository,
        token_service: TokenService,
    ) -> None:
        self.user_service = user_service
        self.credential_repository = credential_repository
        self.event_repository = event_repository
        self.token_service = token_service

    def register(
        self,
        *,
        idempotency_key: str,
        email: str | None = None,
        phone: str | None = None,
        username: str | None = None,
        password: str,
        first_name: str | None = None,
        last_name: str | None = None,
        display_name: str | None = None,
        country: str | None = None,
        timezone: str = "Africa/Lagos",
        language: str = "en",
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> RegistrationResult:
        """
        Register a canonical user and establish authentication.

        User creation is delegated to the User Service.
        Password hashing and authentication credential storage remain
        owned by the Auth Service.
        """

        user = self.user_service.create_user(
            idempotency_key=idempotency_key,
            email=email,
            phone=phone,
            username=username,
            first_name=first_name,
            last_name=last_name,
            display_name=display_name,
            country=country,
            timezone=timezone,
            language=language,
        )

        password_hash = hash_password(password)

        try:
            self.credential_repository.create(
                user_id=user.user_id,
                password_hash=password_hash,
            )
        except IntegrityError as exc:
            raise IntegrationError(
                "Authentication credentials already exist for this user.",
            ) from exc

        self.event_repository.create_auth_event(
            user_id=user.user_id,
            context_type="PERSONAL",
            event_type="REGISTRATION_COMPLETED",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        tokens = self.token_service.issue_tokens(
            user_id=user.user_id,
            context_type="PERSONAL",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return RegistrationResult(
            user=user,
            tokens=tokens,
        )
    