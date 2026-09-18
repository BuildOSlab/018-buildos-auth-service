"""
BuildOS Auth Service
Token Schemas
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TokenRefreshRequest(BaseModel):
    """
    Request to rotate an existing refresh token.
    """

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(
        min_length=1,
        max_length=4096,
    )


class TokenRefreshResponse(BaseModel):
    """
    Newly issued access and refresh tokens.
    """

    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRevokeRequest(BaseModel):
    """
    Request to revoke a single refresh token.
    """

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(
        min_length=1,
        max_length=4096,
    )


class TokenRevokeResponse(BaseModel):
    """
    Result of a refresh-token revocation.
    """

    model_config = ConfigDict(extra="forbid")

    revoked: bool


class TokenUserContext(BaseModel):
    """
    Authentication context associated with a token.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    context_type: str = "PERSONAL"
    organization_id: UUID | None = None
    membership_id: UUID | None = None


class TokenMeResponse(BaseModel):
    """
    Authenticated identity resolved from an access token.
    """

    model_config = ConfigDict(extra="forbid")

    authenticated: bool = True
    user_id: UUID
    context_type: str = "PERSONAL"
    organization_id: UUID | None = None
    membership_id: UUID | None = None
