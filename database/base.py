"""Shared SQLAlchemy declarative base used by all ORM models."""

from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    """Base class for every ORM model in the database package."""

    pass
