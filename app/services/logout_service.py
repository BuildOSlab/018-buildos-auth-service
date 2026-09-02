"""
BuildOS Auth Service
Logout Service
"""

from dataclasses import dataclass

from app.services.token_service import TokenService


@dataclass(frozen=True)
class LogoutResult:
    """Result of a successful logout."""

    logged_out: bool = True


class LogoutService:
    """
    Orchestrates logout by revoking the supplied refresh token.

    The Auth Service owns refresh-token state.
    """

    def __init__(
        self,
        *,
        token_service: TokenService,
    ) -> None:
        self.token_service = token_service

    def logout(
        self,
        *,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> LogoutResult:
        """Revoke the current refresh token."""
        self.token_service.revoke(
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return LogoutResult(logged_out=True)
