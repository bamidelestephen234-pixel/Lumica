# database/db_manager.py
import os
import uuid
import time
from datetime import datetime
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

# Import your Base and password hashing from existing modules
from database.models import Base
from utils.security import hash_password  # adjust import path if needed

# --- Restart-safe engine ---
@st.cache_resource
def get_engine():
    """
    Create a restart-safe SQLAlchemy engine.
    Reads DATABASE_URL from Streamlit secrets or environment variables.
    """
    try:
        db_url = st.secrets["DATABASE_URL"]
        if not db_url:
            raise ValueError("Empty DATABASE_URL")
    except KeyError:
        raise RuntimeError(
            "❌ DATABASE_URL not found in Streamlit secrets. "
            "Please configure this in your Streamlit Cloud dashboard "
            "under 'Manage app' -> 'Secrets'"
        )

    engine = create_engine(
        db_url.strip(),
        poolclass=NullPool,  # Disable connection pooling to avoid Supabase limits
        connect_args={
            'connect_timeout': 30,  # Increase timeout for slower connections
            'keepalives': 1,  # Enable TCP keepalive
            'keepalives_idle': 30,  # Time between keepalive pings when idle
            'keepalives_interval': 10,  # Time between keepalive retries
            'keepalives_count': 5,  # Number of keepalive retries
            'application_name': 'lumica_app'  # Identify our app in database logs
        }
    )
    
    # Verify we can connect with retries
    max_retries = 3
    retry_delay = 2
    last_error = None
    
    for attempt in range(max_retries):
        try:
            # Test connection
            with engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            return engine
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                print(f"Connection attempt {attempt + 1} failed, retrying in {retry_delay}s: {e}")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
    
    print(f"Database connection failed after {max_retries} attempts: {last_error}")
    raise last_error

class DatabaseManager:
    def __init__(self):
        """Initialize the database manager"""
        self._engine = None
        self._Session = None
        self.connect()

    def connect(self):
        """Establish database connection with retries"""
        max_retries = 3
        retry_delay = 2
        last_error = None

        for attempt in range(max_retries):
            try:
                self._engine = get_engine()
                self._Session = sessionmaker(bind=self._engine)
                # Test connection
                with self._engine.connect() as conn:
                    conn.execute(text('SELECT 1'))
                return True
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
        print(f"Failed to connect to database after {max_retries} attempts: {last_error}")
        return False

    @property
    def engine(self):
        """Get the SQLAlchemy engine, reconnecting if needed"""
        if not self.is_available():
            self.connect()
        return self._engine

    @property
    def Session(self):
        """Get the session maker, reconnecting if needed"""
        if not self.is_available():
            self.connect()
        return self._Session

    def get_session(self):
        """Get a new database session with automatic reconnection"""
        if not self.is_available():
            self.connect()
        return self.Session()

    def close_session(self, session):
        """Safely close a database session"""
        if session:
            try:
                session.close()
            except Exception:
                pass

    def init_db(self):
        """Initialize the database tables with retry logic"""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                Base.metadata.create_all(self.engine)
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"Database initialization attempt {attempt + 1} failed: {e}")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                raise

    def is_available(self):
        """Check if database connection is available and working"""
        if not self._engine:
            return False
        try:
            with self._engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            return True
        except Exception:
            return False

# Create a singleton instance
db_manager = DatabaseManager()
