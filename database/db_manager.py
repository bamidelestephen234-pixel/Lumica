# db_manager.py
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from models import Base

# 1. Get database URL from environment/secrets
DATABASE_URL = os.getenv("DATABASE_URL="postgresql://postgres:Stephen%4022.33%2F@db.hiijvgzblottszoulseh.supabase.co:5432/postgres"
")
if not DATABASE_URL:
    sys.exit("❌ DATABASE_URL not set. Please add it to your secrets.")

# 2. Create SQLAlchemy engine
# For Supabase/PostgreSQL
try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
except Exception as e:
    sys.exit(f"❌ Failed to create engine: {e}")

# 3. Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 4. Initialize tables
def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Database initialized successfully.")
    except OperationalError as e:
        sys.exit(f"❌ Database initialization failed: {e}")
    except Exception as e:
        sys.exit(f"❌ Unexpected error during DB init: {e}")

# Optional: quick test when running this file directly
if __name__ == "__main__":
    init_db()
