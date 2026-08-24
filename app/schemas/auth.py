"""
BuildOS Auth Service
Authentication Schemas
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    """
    Authentication login request.

    `identifier` may be an email address or phone number.
    """

    model_config = ConfigDict(extra="forbid")

    identifier: str = Field(
        min_length=1,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )


class LoginResponse(BaseModel):
    """
    Authentication result returned after successful login.

    Token fields will be populated when the token service is implemented.
    """

    model_config = ConfigDict(extra="forbid")

    authenticated: bool
    user_id: UUID
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"