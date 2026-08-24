"""
BuildOS Auth Service
API Dependencies
"""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.database.dependencies import get_db
from app.integrations.user_service import UserService
from app.repositories.credential_repository import CredentialRepository
from app.repositories.event_repository import EventRepository
from app.repositories.login_attempt_repository import LoginAttemptRepository
from app.services.authentication_service import AuthenticationService
from app.services.login_service import LoginService

DatabaseSession = Annotated[Session, Depends(get_db)]


def get_user_service() -> UserService:
    """
    Provide the canonical User Service integration.
    """

    return UserService()


def get_authentication_service(
    db: DatabaseSession,
) -> AuthenticationService:
    """
    Build the authentication domain service with its repositories.
    """

    credential_repository = CredentialRepository(db)
    login_attempt_repository = LoginAttemptRepository(db)
    event_repository = EventRepository(db)

    return AuthenticationService(
        credential_repository=credential_repository,
        login_attempt_repository=login_attempt_repository,
        event_repository=event_repository,
    )


def get_login_service(
    db: DatabaseSession,
) -> LoginService:
    """
    Build the login orchestration service.
    """

    return LoginService(
        user_service=get_user_service(),
        authentication_service=get_authentication_service(db),
    )


LoginServiceDependency = Annotated[
    LoginService,
    Depends(get_login_service),
]


__all__ = [
    "DatabaseSession",
    "LoginServiceDependency",
    "get_authentication_service",
    "get_db",
    "get_login_service",
    "get_user_service",
]
