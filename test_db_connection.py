import streamlit as st
from sqlalchemy import create_engine, text
import sys

def test_connection():
    try:
        # Get the database URL
        db_url = st.secrets["DATABASE_URL"]
        print("✅ Successfully accessed DATABASE_URL from Streamlit secrets")
        
        # Test creating the engine
        print("\nTrying to create SQLAlchemy engine...")
        engine = create_engine(db_url.strip(), pool_pre_ping=True, pool_recycle=1800)
        print("✅ Successfully created SQLAlchemy engine")
        
        # Test making a connection
        print("\nTrying to connect to database...")
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            print("✅ Successfully connected to database")
            print(f"Test query result: {result}")
            
    except KeyError as e:
        print("❌ Error: Could not find DATABASE_URL in Streamlit secrets")
        print(f"Available secret keys: {st.secrets.keys()}")
        sys.exit(1)
    except Exception as e:
        print("❌ Error connecting to database:")
        print(str(e))
        sys.exit(1)

if __name__ == "__main__":
    test_connection()