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
            'connect_timeout': 10,  # 10 second connection timeout
            'application_name': 'lumica_app'  # Identify our app in database logs
        }
    )
    
    # Verify we can connect
    try:
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        return engine
    except Exception as e:
        print(f"Database connection failed: {e}")
        raise

class DatabaseManager:
    def __init__(self):
        """Initialize the database manager"""
        self.engine = get_engine()
        self.Session = sessionmaker(bind=self.engine)
        
    def get_session(self):
        """Get a new database session"""
        return self.Session()
        
    def close_session(self, session):
        """Safely close a database session"""
        if session:
            session.close()

    def init_db(self):
        """Initialize the database tables"""
        Base.metadata.create_all(self.engine)

# Create a singleton instance
db_manager = DatabaseManager()
