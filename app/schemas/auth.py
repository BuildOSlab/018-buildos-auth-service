"""
BuildOS Auth Service
Authentication Schemas
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RegisterRequest(BaseModel):
    """Register a new BuildOS user and authentication credential."""

    model_config = ConfigDict(extra="forbid")

    email: str | None = Field(
        default=None,
        max_length=255,
    )

    phone: str | None = Field(
        default=None,
        max_length=30,
    )

    username: str | None = Field(
        default=None,
        max_length=50,
    )

    password: str = Field(
        min_length=8,
        max_length=1024,
    )

    first_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    last_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    display_name: str | None = Field(
        default=None,
        max_length=100,
    )

    country: str | None = Field(
        default=None,
        min_length=2,
        max_length=2,
    )

    timezone: str = Field(
        default="Africa/Lagos",
        max_length=100,
    )

    language: str = Field(
        default="en",
        max_length=20,
    )


class RegisterResponse(BaseModel):
    """Successful registration response."""

    model_config = ConfigDict(extra="forbid")

    registered: bool
    user_id: UUID
    public_id: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    """
    Authentication login request.

    `identifier` may be an email address, phone number, or username.
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

    device_id: UUID | None = None


class LoginResponse(BaseModel):
    """Authentication result returned after successful login."""

    model_config = ConfigDict(extra="forbid")

    authenticated: bool
    user_id: UUID
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
