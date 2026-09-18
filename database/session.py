"""Database engine and session factory configuration."""

from config import config
from .base import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = config.DATABASE_URL

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine)

def create_tables():
    """Create all tables registered on the shared metadata object."""

    Base.metadata.create_all(bind=engine)