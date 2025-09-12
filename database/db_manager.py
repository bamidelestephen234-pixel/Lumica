import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from .models import Base, User, VerificationCode
import streamlit as st
import hashlib
import secrets

class DatabaseManager:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._setup_database()
    
    def _get_database_url(self):
        """Get database URL from environment or secrets, with SQLite fallback"""
        # Try environment variable first
        database_url = os.getenv("DATABASE_URL")
        
        # Try Streamlit secrets if no env var
        if not database_url:
            try:
                database_url = st.secrets.get("DATABASE_URL")
            except:
                database_url = None
        
        # Fallback to SQLite
        if not database_url:
            database_url = "sqlite:///akins_sunrise_school.db"
        
        return database_url
    
    def _setup_database(self):
        """Setup database engine and session"""
        database_url = self._get_database_url()
        
        # Configure engine based on database type
        if database_url.startswith("sqlite"):
            self.engine = create_engine(
                database_url,
                connect_args={"check_same_thread": False}
            )
        else:
            self.engine = create_engine(database_url)
        
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def get_session(self):
        """Get SQLAlchemy session"""
        return self.SessionLocal()
    
    def init_database(self):
        """Initialize database with tables"""
        # Create all tables
        Base.metadata.create_all(bind=self.engine)
        
        # Insert default users if they don't exist
        session = self.get_session()
        try:
            existing_user = session.query(User).filter(User.id == "teacher_bamstep").first()
            if not existing_user:
                default_users = [
                    User(
                        id="teacher_bamstep",
                        full_name="Principal Bamstep",
                        email="principal@akinssunrise.edu.ng",
                        password_hash=self.hash_password("admin789"),
                        role="principal"
                    ),
                    User(
                        id="teacher_bola",
                        full_name="Teacher Bola",
                        email="bola@akinssunrise.edu.ng",
                        password_hash=self.hash_password("secret123"),
                        role="class_teacher"
                    ),
                    User(
                        id="school_ict",
                        full_name="Akins Sunrise",
                        email="akinssunrise@gmail.com",
                        password_hash=self.hash_password("akins1111"),
                        role="principal"
                    )
                ]
                
                for user in default_users:
                    session.add(user)
                session.commit()
        finally:
            session.close()
    
    def hash_password(self, password: str) -> str:
        """PBKDF2 password hashing with salt for security"""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return salt + pwd_hash.hex()
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against PBKDF2 hash"""
        try:
            salt = hashed_password[:32]
            stored_hash = hashed_password[32:]
            pwd_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode(), salt.encode(), 100000)
            return pwd_hash.hex() == stored_hash
        except:
            return False
    
    def store_verification_code(self, code_type: str, code_value: str, user_id: str = None, 
                              entity_id: str = None, expires_at: datetime = None, extra_data: str = None):
        """Store a verification code in the database"""
        session = self.get_session()
        try:
            verification_code = VerificationCode(
                user_id=user_id,
                code_type=code_type,
                code_value=code_value,
                entity_id=entity_id,
                expires_at=expires_at,
                extra_data=extra_data
            )
            session.add(verification_code)
            session.commit()
            return verification_code.id
        finally:
            session.close()
    
    def verify_code(self, code_type: str, code_value: str, user_id: str = None, entity_id: str = None):
        """Verify a code and mark it as used"""
        session = self.get_session()
        try:
            query = session.query(VerificationCode).filter(
                VerificationCode.code_type == code_type,
                VerificationCode.code_value == code_value,
                VerificationCode.is_used == False
            )
            
            if user_id:
                query = query.filter(VerificationCode.user_id == user_id)
            if entity_id:
                query = query.filter(VerificationCode.entity_id == entity_id)
            
            verification_code = query.first()
            
            if verification_code:
                # Check if expired
                if verification_code.expires_at and verification_code.expires_at < datetime.utcnow():
                    return False
                
                # Mark as used
                verification_code.is_used = True
                session.commit()
                return True
            
            return False
        finally:
            session.close()
    
    def get_verification_codes(self, code_type: str = None, user_id: str = None, 
                             entity_id: str = None, active_only: bool = True):
        """Get verification codes based on filters"""
        session = self.get_session()
        try:
            query = session.query(VerificationCode)
            
            if code_type:
                query = query.filter(VerificationCode.code_type == code_type)
            if user_id:
                query = query.filter(VerificationCode.user_id == user_id)
            if entity_id:
                query = query.filter(VerificationCode.entity_id == entity_id)
            if active_only:
                query = query.filter(VerificationCode.is_used == False)
            
            return query.all()
        finally:
            session.close()
    
    def cleanup_expired_codes(self):
        """Remove expired verification codes"""
        session = self.get_session()
        try:
            expired_codes = session.query(VerificationCode).filter(
                VerificationCode.expires_at < datetime.utcnow()
            )
            count = expired_codes.count()
            expired_codes.delete()
            session.commit()
            return count
        finally:
            session.close()

# Global database manager
db_manager = DatabaseManager()
