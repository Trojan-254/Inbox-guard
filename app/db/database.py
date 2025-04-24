from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment variables
SQL_ALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Create SQLAlchemy engine
engine = create_engine('postgresql+psycopg2://inboxuser:39944816@localhost/inboxguard')

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


async def connect():
    """
    Tries to establish a connection to the database.
    Returns True if successful, raises error if not.
    """
    try:
        with engine.connect() as connection:
            pass
        print("Database connection successful")
        return True
    except OperationalError as e:
        print("Database connection failed:", str(e))
        raise


def disconnect():
    """
    Properly closes all database connections and cleans up resources.
    """
    try:
        # Dispose of the engine, which closes all connection pools
        engine.dispose()
        
        # If using scoped sessions, remove the registry
        if 'SessionScoped' in globals():
            SessionScoped.remove()
            
        print("Database disconnected successfully")
        return True
    except DisconnectionError as e:
        print("Error disconnecting from database:", str(e))
        raise
    except Exception as e:
        print("Unexpected error during disconnection:", str(e))
        raise

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Context manager for database operations (alternative to the dependency)
@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

# Create all tables
def create_tables():
    Base.metadata.create_all(bind=engine)