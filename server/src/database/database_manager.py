import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
#
from src.config import DATABASE_URI
from .models import Base


# Suppress SQLAlchemy INFO logs at various levels
sqlalchemy_logger = logging.getLogger('sqlalchemy')
sqlalchemy_logger.handlers.clear()  # Remove any existing handlers to avoid conflicts
sqlalchemy_logger.setLevel(logging.WARNING)

# Create an engine
engine = create_engine(DATABASE_URI, echo=True)  # Set echo=True for SQL query logging

# Create a configured "Session" class
Session = sessionmaker(bind=engine)

# Create a session instance
session = Session()

def initialize_database() -> None:
    """Create all tables in the database."""
    Base.metadata.create_all(engine)

