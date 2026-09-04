"""
BuildOS Auth Service
Password Hashing Security
"""

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

from app.core.config import get_settings

settings = get_settings()

_password_hasher = PasswordHasher(
    time_cost=settings.password_hash_time_cost,
    memory_cost=settings.password_hash_memory_cost,
    parallelism=settings.password_hash_parallelism,
)


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2.

    The plaintext password must never be persisted.
    """
    return _password_hasher.hash(password)


def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    """
    Verify a plaintext password against an Argon2 password hash.

    Returns False when the password does not match or the stored
    hash cannot be verified.
    """
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """
    Determine whether a stored password hash should be regenerated
    using the current Argon2 parameters.
    """
    return _password_hasher.check_needs_rehash(password_hash)
