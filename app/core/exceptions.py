"""
BuildOS Auth Service
Application Exceptions
"""


class AuthServiceError(Exception):
    """Base exception for the authentication service."""


class AuthenticationError(AuthServiceError):
    """Raised when authentication fails."""


class InvalidCredentialsError(AuthenticationError):
    """Raised when supplied credentials are invalid."""


class AccountLockedError(AuthenticationError):
    """Raised when an account is currently locked."""


class CredentialInactiveError(AuthenticationError):
    """Raised when authentication credentials are inactive."""


class UserNotFoundError(AuthServiceError):
    """Raised when a canonical user cannot be resolved."""


class TokenError(AuthServiceError):
    """Base exception for token-related failures."""


class InvalidTokenError(TokenError):
    """Raised when a token is invalid."""


class ExpiredTokenError(TokenError):
    """Raised when a token has expired."""


class RevokedTokenError(TokenError):
    """Raised when a token has been revoked."""


class PasswordError(AuthServiceError):
    """Base exception for password-related failures."""


class PasswordResetError(PasswordError):
    """Raised when a password reset operation fails."""


class IntegrationError(AuthServiceError):
    """Raised when an external service integration fails."""


class UserAlreadyExistsError(AuthServiceError):
    """Raised when a user identity already exists."""


# ============================================================================
# 018 ↔ 019 integration specific exceptions
# ============================================================================

class ValidationError(IntegrationError):
    """Raised when the User Service returns a validation error (422)."""


class UserDeletedError(IntegrationError):
    """Raised when the User Service indicates that the user is deleted (410)."""


class IdempotencyConflictError(IntegrationError):
    """Raised when an idempotency key was used with different data."""
