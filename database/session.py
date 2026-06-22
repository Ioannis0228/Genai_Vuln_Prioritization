"""Database engine and session factory configuration."""

import os
from .base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine)

def create_tables():
    """Create all tables registered on the shared metadata object."""

    Base.metadata.create_all(bind=engine)