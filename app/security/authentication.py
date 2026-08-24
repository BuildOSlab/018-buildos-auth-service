"""
BuildOS Auth Service
Authentication State Security
"""

from datetime import UTC, datetime

from app.models.auth_credential import AuthCredential


def is_credential_active(
    credential: AuthCredential,
) -> bool:
    """
    Return True when the credential belongs to an active account.
    """
    return credential.is_active


def is_credential_locked(
    credential: AuthCredential,
    *,
    now: datetime | None = None,
) -> bool:
    """
    Determine whether a credential is currently locked.

    A permanent lock has no locked_until value.

    A temporary lock remains active until locked_until.
    Once the lock expires, the credential is considered unlocked.
    """
    if not credential.is_locked:
        return False

    if credential.locked_until is None:
        return True

    current_time = now or datetime.now(UTC)

    return credential.locked_until > current_time


def can_authenticate(
    credential: AuthCredential,
    *,
    now: datetime | None = None,
) -> bool:
    """
    Determine whether a credential is currently eligible
    for password authentication.
    """
    if not is_credential_active(credential):
        return False

    return not is_credential_locked(credential, now=now)


def lock_has_expired(
    credential: AuthCredential,
    *,
    now: datetime | None = None,
) -> bool:
    """
    Determine whether a temporary credential lock has expired.
    """
    if not credential.is_locked:
        return False

    if credential.locked_until is None:
        return False

    current_time = now or datetime.now(UTC)

    return credential.locked_until <= current_time


def should_clear_expired_lock(
    credential: AuthCredential,
    *,
    now: datetime | None = None,
) -> bool:
    """
    Determine whether an expired temporary lock should be cleared.
    """
    return lock_has_expired(credential, now=now)
