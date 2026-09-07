"""
BuildOS Auth Service
Registration Service
"""

import logging
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError

from app.core.exceptions import IntegrationError
from app.integrations.user_service import CreatedUser, UserService
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.security.password_hashing import hash_password
from app.services.token_service import TokenPair, TokenService

logger = logging.getLogger(__name__)


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

        Repeated requests using the same idempotency key may cause the
        User Service to replay the existing canonical user. In that
        case, existing authentication credentials are reused.
        """
        logger.info(
            "Registration started: email=%s, username=%s, idempotency_key=%s",
            email,
            username,
            idempotency_key[:8] + "...",
        )

        # Step 1: Create the canonical user via User Service
        try:
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
        except Exception:
            logger.exception("User Service call failed")
            raise  # IntegrationError is already raised by UserService

        logger.info("User created: user_id=%s, public_id=%s", user.user_id, user.public_id)

        # Step 2: Hash the password
        password_hash = hash_password(password)
        logger.debug("Password hashed for user_id=%s", user.user_id)

        # Step 3: Ensure authentication credentials exist (idempotent)
        credential = self.credential_repository.get_by_user_id(user.user_id)
        if credential is None:
            try:
                self.credential_repository.create(
                    user_id=user.user_id,
                    password_hash=password_hash,
                )
                logger.info("Credentials created for user_id=%s", user.user_id)
            except IntegrityError as exc:
                # Another request beat us – fetch the now-existing credential
                logger.warning(
                    "IntegrityError while creating credential for user_id=%s – likely duplicate, fetching existing",
                    user.user_id,
                )
                credential = self.credential_repository.get_by_user_id(user.user_id)
                if credential is None:
                    # Unexpected: duplicate key but no record found?
                    logger.exception(
                        "IntegrityError occurred but no credential found for user_id=%s – re-raising",
                        user.user_id,
                    )
                    raise IntegrationError(
                        "Authentication credentials already exist for this user, but could not be retrieved."
                    ) from exc
                # else: credential now exists, we can continue
        else:
            logger.info("Credentials already exist for user_id=%s – skipping creation", user.user_id)

        # Step 4: Log the registration completion event
        self.event_repository.create_auth_event(
            user_id=user.user_id,
            context_type="PERSONAL",
            event_type="REGISTRATION_COMPLETED",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        logger.info("Registration event logged for user_id=%s", user.user_id)

        # Step 5: Issue access/refresh tokens
        tokens = self.token_service.issue_tokens(
            user_id=user.user_id,
            context_type="PERSONAL",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        logger.info("Tokens issued for user_id=%s", user.user_id)

        return RegistrationResult(
            user=user,
            tokens=tokens,
        )
    