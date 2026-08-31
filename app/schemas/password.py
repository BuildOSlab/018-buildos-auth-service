"""
BuildOS Auth Service
Password Management Schemas
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChangePasswordRequest(BaseModel):
    """Request to change the authenticated user's password."""

    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        """Reject passwords consisting only of whitespace."""
        if not value.strip():
            raise ValueError("Password must not be blank.")

        return value


class ChangePasswordResponse(BaseModel):
    """Response returned after a successful password change."""

    changed: bool
    user_id: UUID


class PasswordResetRequest(BaseModel):
    """Request a password reset using email or phone."""

    model_config = ConfigDict(extra="forbid")

    identifier: str = Field(min_length=1, max_length=255)

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        """Reject blank identifiers."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("Identifier must not be blank.")

        return normalized


class PasswordResetRequestResponse(BaseModel):
    """Response for a password-reset request."""

    requested: bool


class PasswordResetConfirmRequest(BaseModel):
    """Complete a password reset with a single-use token."""

    model_config = ConfigDict(extra="forbid")

    reset_token: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("reset_token")
    @classmethod
    def validate_reset_token(cls, value: str) -> str:
        """Reject blank reset tokens."""
        if not value.strip():
            raise ValueError("Reset token must not be blank.")

        return value

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        """Reject passwords consisting only of whitespace."""
        if not value.strip():
            raise ValueError("Password must not be blank.")

        return value


class PasswordResetConfirmResponse(BaseModel):
    """Response returned after completing a password reset."""

    reset: bool
    user_id: UUID
