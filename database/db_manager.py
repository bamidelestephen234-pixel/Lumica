# db_manager.py
import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from database.models import Base


class DatabaseManager:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize database connection with proper error handling"""
        # Get database URL from environment variables only
        DATABASE_URL = os.getenv("DATABASE_URL")
        
        if not DATABASE_URL:
            print("❌ DATABASE_URL not found in environment variables.")
            print("Please set DATABASE_URL in your Replit Secrets.")
            self.engine = None
            self.SessionLocal = None
            return
        
        # Sanitize the URL by removing quotes and whitespace
        url = DATABASE_URL.strip()
        if (url.startswith('"') and url.endswith('"')) or (url.startswith("'") and url.endswith("'")):
            url = url[1:-1]
        
        try:
            self.engine = create_engine(url, pool_pre_ping=True)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            
            # Validate connection with a quick test
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            print("✅ Database connection established and validated successfully.")
        except Exception as e:
            print(f"❌ Failed to create database engine: {e}")
            print(f"   URL format issue detected (credentials not logged for security)")
            self.engine = None
            self.SessionLocal = None
    
    def get_session(self):
        """Get a new database session"""
        if not self.SessionLocal:
            return None
        return self.SessionLocal()
    
    def is_available(self):
        """Check if database connection is available"""
        return self.engine is not None
    
    def init_database(self):
        """Initialize database tables with comprehensive error handling"""
        if not self.is_available():
            print("❌ Database not available, skipping table initialization")
            return False
        
        try:
            Base.metadata.create_all(bind=self.engine)
            print("✅ Database tables initialized successfully.")
            return True
        except OperationalError as e:
            print(f"❌ Database initialization failed: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error during DB init: {e}")
            return False


# Create global instance
db_manager = DatabaseManager()


def init_db():
    """Initialize database tables - standalone function"""
    if not db_manager.is_available():
        print("❌ Database not available, skipping table initialization")
        return False
    
    try:
        Base.metadata.create_all(bind=db_manager.engine)
        print("✅ Database tables initialized successfully.")
        return True
    except OperationalError as e:
        print(f"❌ Database initialization failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error during DB init: {e}")
        return False


if __name__ == "__main__":
    init_db()
