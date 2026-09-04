"""Pytest configuration for the BuildOS Auth Service test suite."""

import pytest

from app.core.rate_limit import limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """Reset SlowAPI rate-limit state before every test."""
    limiter.reset()
