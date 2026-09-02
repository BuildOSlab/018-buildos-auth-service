"""
BuildOS Auth Service
Authentication Rate Limiting
"""

from datetime import UTC, datetime, timedelta

from app.core.config import settings


def get_attempt_window_start(
    *,
    now: datetime | None = None,
) -> datetime:
    """
    Return the beginning of the rolling login-attempt window.
    """
    current_time = now or datetime.now(UTC)

    return current_time - timedelta(
        minutes=settings.login_rate_limit_window_minutes,
    )


def is_login_rate_limited(
    failed_attempts: int,
) -> bool:
    """
    Determine whether the failed-attempt threshold has been reached.
    """
    return failed_attempts >= settings.max_failed_login_attempts


def should_lock_account(
    failed_attempts: int,
) -> bool:
    """
    Determine whether the account should be temporarily locked.
    """
    return is_login_rate_limited(failed_attempts)


def get_lock_expiration(
    *,
    now: datetime | None = None,
) -> datetime:
    """
    Calculate when a temporary account lock should expire.
    """
    current_time = now or datetime.now(UTC)

    return current_time + timedelta(
        minutes=settings.login_lockout_minutes,
    )
