# database/db_manager.py
import os
import uuid
import time
from datetime import datetime
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import SingletonThreadPool

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

    # Strip any whitespace
    db_url = db_url.strip()

    # Create engine with SingletonThreadPool to ensure single connection
    engine = create_engine(
        db_url,
        echo=False,
        future=True,
        poolclass=SingletonThreadPool,
        connect_args={
            'connect_timeout': 30,
            'application_name': 'lumica_app',
            'sslmode': 'require',
            'options': '-c idle_in_transaction_session_timeout=1800000'  # 30 minutes
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
        self._engine = get_engine()
        
        # Create a scoped session factory
        session_factory = sessionmaker(bind=self._engine)
        self._Session = scoped_session(session_factory)
        
        # Verify connection
        self.is_available()

    def connect(self):
        """Establish database connection"""
        try:
            self._engine = get_engine()
            
            # Create new scoped session factory
            session_factory = sessionmaker(bind=self._engine)
            self._Session = scoped_session(session_factory)
            
            return self.is_available()
        except Exception as e:
            print(f"Database connection failed: {e}")
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
        """Get a session from the scoped session registry"""
        if not self.is_available():
            if not self.connect():
                raise RuntimeError("Unable to establish database connection")
        return self._Session()

    def close_session(self, session):
        """Remove session from the scoped session registry"""
        if session:
            try:
                session.commit()
            except:
                session.rollback()
            finally:
                try:
                    # Remove it from the scoped session registry
                    self._Session.remove()
                except:
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
