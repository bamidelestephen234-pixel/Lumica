# database/db_manager.py
import os
import uuid
from datetime import datetime
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Import your Base and password hashing fr
# om existing modules
from database.models import Base
from utils.security import hash_password  # adjust import path if needed

# --- Restart-safe engine ---
@st.cache_resource
def get_engine():
    """
    Create a restart-safe SQLAlchemy engine with connection recycling.
    Reads DATABASE_URL from Streamlit secrets or environment variables.
    """
    db_url = st.secrets["DATABASE_URL"]
    if not db_url:
        raise RuntimeError("❌ DATABASE_URL not found in Streamlit secrets.")
    return create_engine(
        db_url.strip(),
        pool_pre_ping=True,
        pool_recycle=300,  # Recycle connections every 5 minutes
        pool_size=2,  # Minimal pool size for Supabase
        max_overflow=0,  # No overflow connections
        pool_timeout=10,  # Shorter timeout to fail fast
        pool_use_lifo=True,  # Use last-in-first-out for better connection reuse
        echo_pool=True  # Log pool events for debugging
    )

def get_session():
    """
    Get a new SQLAlchemy session.
    Always close it after use: 
        session = get_session()
        try:
            ...
        finally:
            session.close()
            session.bind.dispose()  # Return connection to the pool immediately
    """
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        session.bind.dispose()

# --- Schema migration ---
def ensure_schema():
    """
    Create all tables and ensure required columns exist.
    """
    engine = get_engine()
    
    # First, create all tables from models
    Base.metadata.create_all(engine)
    
    # Then ensure additional columns exist
    with engine.begin() as conn:
        # Users table additional columns
        try:
            conn.execute(text("""
                ALTER TABLE users
                ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'approved',
                ADD COLUMN IF NOT EXISTS approved_by TEXT NULL,
                ADD COLUMN IF NOT EXISTS approval_date TIMESTAMP NULL,
                ADD COLUMN IF NOT EXISTS registration_notes TEXT NULL,
                ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP NULL,
                ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS two_factor_secret TEXT NULL,
                ADD COLUMN IF NOT EXISTS session_timeout INTEGER DEFAULT 30,
                ADD COLUMN IF NOT EXISTS assigned_classes TEXT NULL,
                ADD COLUMN IF NOT EXISTS departments TEXT NULL,
                ADD COLUMN IF NOT EXISTS custom_features TEXT NULL,
                ADD COLUMN IF NOT EXISTS subjects TEXT NULL;
            """))
        except Exception as e:
            print(f"Note: Some user table columns may already exist: {e}")
        
        # Students table additional columns
        try:
            conn.execute(text("""
                ALTER TABLE students
                ADD COLUMN IF NOT EXISTS class_name TEXT NULL;
            """))
        except Exception as e:
            print(f"Note: Some student table columns may already exist: {e}")

# --- Safe seeding ---
def seed_default_users():
    """
    Insert default users only if they don't already exist.
    Uses ON CONFLICT DO NOTHING to avoid duplicate key errors.
    """
    engine = get_engine()
    default_users = [
        {
            "id": "teacher_eric",  # fixed ID for known account
            "full_name": "Joe Eric",
            "email": "bamidelestephen224",
            "password_hash": hash_password("admin789"),
            "role": "principal",
            "phone": "+234-XXX-XXX-XXXX",
            "is_active": True,
            "created_date": datetime.utcnow(),
            "approval_status": "approved",
            "approved_by": None,
            "approval_date": None,
            "registration_notes": None
        }
    ]
    with engine.begin() as conn:
        for user in default_users:
            conn.execute(text("""
                INSERT INTO users (
                    id, full_name, email, password_hash, role, phone, is_active,
                    created_date, approval_status, approved_by, approval_date, registration_notes
                )
                VALUES (
                    :id, :full_name, :email, :password_hash, :role, :phone, :is_active,
                    :created_date, :approval_status, :approved_by, :approval_date, :registration_notes
                )
                ON CONFLICT (id) DO NOTHING;
            """), user)

# --- Combined init ---
def init_database():
    """
    Run schema checks and seed default users.
    Call this once at app startup.
    """
    ensure_schema()
    seed_default_users()
    st.info("✅ Database schema ensured and default users seeded.")

class DatabaseManager:
    """Simple database manager class to match the app's expected interface"""
    
    def __init__(self):
        self.engine = get_engine()
    
    def get_session(self):
        """Get a new database session"""
        return get_session()
    
    def is_available(self):
        """Check if database connection is available"""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                return True
        except Exception as e:
            print(f"Database availability check failed: {e}")
            return False

# Create a global db_manager instance
db_manager = DatabaseManager()
