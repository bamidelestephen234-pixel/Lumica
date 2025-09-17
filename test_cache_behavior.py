import streamlit as st
from sqlalchemy import create_engine, text
import sys

@st.cache_resource(show_spinner=True)
def get_test_engine():
    """Create a test engine with the same settings as the main app"""
    print("Creating new engine instance...")  # This will only print when a new engine is created
    db_url = st.secrets["DATABASE_URL"]
    return create_engine(db_url.strip(), pool_pre_ping=True, pool_recycle=1800)

def test_cached_connection():
    try:
        # First call should create a new engine
        print("First get_test_engine() call:")
        engine1 = get_test_engine()
        
        # Test the first connection
        with engine1.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            print("✅ First connection successful")
        
        # Second call should reuse the cached engine
        print("\nSecond get_test_engine() call:")
        engine2 = get_test_engine()
        
        # Test the second connection
        with engine2.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            print("✅ Second connection successful")
        
        # Verify if we got the same engine instance
        print(f"\nEngine instances are the same: {engine1 is engine2}")
            
    except Exception as e:
        print("❌ Error during test:")
        print(str(e))
        sys.exit(1)

if __name__ == "__main__":
    print("Starting cache behavior test...")
    test_cached_connection()