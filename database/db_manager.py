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

    # Strip any whitespace and parse the URL
    db_url = db_url.strip()
    
    # Add explicit statement_timeout and idle_in_transaction_session_timeout
    if '?' in db_url:
        db_url += '&statement_timeout=60000&idle_in_transaction_session_timeout=60000'
    else:
        db_url += '?statement_timeout=60000&idle_in_transaction_session_timeout=60000'

    engine = create_engine(
        db_url,
        echo=False,  # Disable SQL logging in production
        future=True,
        poolclass=NullPool,  # Use NullPool to force new connections
        connect_args={
            'connect_timeout': 10,
            'application_name': 'lumica_app',
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 3,
            'sslmode': 'require',
            'options': '-c statement_timeout=60000 -c idle_in_transaction_session_timeout=60000'
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
        self._last_connection_attempt = 0
        self._connection_backoff = 1
        self.connect()

    def connect(self):
        """Establish database connection with backoff"""
        current_time = time.time()
        
        # Enforce minimum time between connection attempts
        if current_time - self._last_connection_attempt < self._connection_backoff:
            time.sleep(self._connection_backoff)
        
        try:
            self._engine = get_engine()
            self._Session = sessionmaker(bind=self._engine)
            
            # Test connection
            with self._engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            
            # Success - reset backoff
            self._connection_backoff = 1
            return True
            
        except Exception as e:
            print(f"Database connection failed: {e}")
            # Increase backoff (max 32 seconds)
            self._connection_backoff = min(self._connection_backoff * 2, 32)
            return False
        finally:
            self._last_connection_attempt = time.time()

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
            if not self.connect():
                raise RuntimeError("Unable to establish database connection")
        
        try:
            session = self.Session()
            # Set session timeout
            session.execute(text('SET statement_timeout = 60000'))
            session.execute(text('SET idle_in_transaction_session_timeout = 60000'))
            return session
        except Exception as e:
            print(f"Failed to create session: {e}")
            self._engine = None  # Force reconnect on next attempt
            raise

    def close_session(self, session):
        """Safely close a database session"""
        if session:
            try:
                session.commit()  # Commit any pending changes
            except:
                session.rollback()  # Rollback on error
            finally:
                try:
                    session.close()
                except:
                    pass  # Ignore errors on close

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
