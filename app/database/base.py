"""
BuildOS Auth Service
Database Declarative Base
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Declarative base for all SQLAlchemy models
    owned by the BuildOS Auth Service.
    """