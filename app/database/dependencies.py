"""
BuildOS Auth Service
Database Dependencies
"""

from collections.abc import Generator

from sqlalchemy.orm import Session

from app.database.session import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    Provide a database session for an API request.

    The session is always closed when the request finishes.
    """

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
