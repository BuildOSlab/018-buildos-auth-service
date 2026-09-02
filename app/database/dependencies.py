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

    Commit on successful request completion and rollback on failure.
    """

    db = SessionLocal()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
        