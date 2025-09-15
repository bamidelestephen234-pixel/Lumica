import sys
import traceback
import streamlit as st
from sqlalchemy import create_engine, text
from database.db_manager import ensure_schema

# Get DB URL from st.secrets
try:
    db_url = st.secrets["DATABASE_URL"]
except Exception as e:
    print(f"FAIL: Could not read DATABASE_URL from st.secrets: {e}")
    sys.exit(1)

engine = create_engine(db_url.strip(), pool_pre_ping=True, pool_recycle=1800)

print("Attempting database initialization...")
try:
    ensure_schema()
    print("PASS: Database initialization succeeded.")
except Exception as e:
    print("FAIL: Database initialization failed.")
    print(f"Error: {e}")
    traceback.print_exc()
    sys.exit(1)

# Check required tables
required_tables = ["users", "students", "reports", "subject_scores", "verification_codes", "activation_keys"]
try:
    with engine.connect() as conn:
        for table in required_tables:
            try:
                result = conn.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))
                print(f"PASS: Table '{table}' exists and is accessible.")
            except Exception as table_err:
                print(f"FAIL: Table '{table}' missing or inaccessible: {table_err}")
except Exception as e:
    print(f"FAIL: Error checking tables: {e}")
    traceback.print_exc()

print("test_db_init.py completed.")
