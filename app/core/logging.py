"""
BuildOS Auth Service
Logging Configuration
"""

import logging
import sys

LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | "
    "%(name)s | %(message)s"
)


def configure_logging(
    *,
    level: int = logging.INFO,
) -> None:
    """
    Configure application-wide logging.

    Configuration is intentionally centralized so the service can later
    integrate structured logging without changing individual modules.
    """

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        stream=sys.stdout,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger for an application module.
    """

    return logging.getLogger(name)