import os
import sys
import uuid
from datetime import datetime
import streamlit as st
from sqlalchemy import create_engine, text
import hashlib
import secrets

# Use the same password hashing as the app
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + pwd_hash.hex()

# Get DB URL from st.secrets
try:
    db_url = st.secrets["DATABASE_URL"]
except Exception as e:
    print(f"FAIL: Could not read DATABASE_URL from st.secrets: {e}")
    sys.exit(1)

from database.db_manager import get_engine
engine = get_engine()

# Generate unique test user
teacher_id = f"test_teacher_{uuid.uuid4().hex[:8]}"
test_email = f"test_{uuid.uuid4().hex[:8]}@lumica.test"
test_password = "TestPassword123!"
password_hash = hash_password(test_password)

# Step 1: Insert test user
try:
    with engine.begin() as conn:
        insert_sql = text("""
            INSERT INTO users (
                id, password_hash, role, full_name, email, phone, created_date, last_login, is_active,
                two_factor_enabled, two_factor_secret, session_timeout, failed_attempts, locked_until,
                assigned_classes, departments, custom_features, approval_status, approved_by, approval_date, registration_notes, subjects
            ) VALUES (
                :id, :password_hash, :role, :full_name, :email, :phone, :created_date, :last_login, :is_active,
                :two_factor_enabled, :two_factor_secret, :session_timeout, :failed_attempts, :locked_until,
                :assigned_classes, :departments, :custom_features, :approval_status, :approved_by, :approval_date, :registration_notes, :subjects
            )
        """)
        params = {
            "id": teacher_id,
            "password_hash": password_hash,
            "role": "teacher",
            "full_name": "Test Teacher",
            "email": test_email,
            "phone": "1234567890",
            "created_date": datetime.now(),
            "last_login": None,
            "is_active": True,
            "two_factor_enabled": False,
            "two_factor_secret": None,
            "session_timeout": 30,
            "failed_attempts": 0,
            "locked_until": None,
            "assigned_classes": "",
            "departments": "",
            "custom_features": "",
            "approval_status": "approved",
            "approved_by": None,
            "approval_date": None,
            "registration_notes": "Test registration",
            "subjects": ""
        }
        conn.execute(insert_sql, params)
    print(f"PASS: Inserted test user {teacher_id} with email {test_email}")
except Exception as e:
    print(f"FAIL: Could not insert test user: {e}")
    sys.exit(1)

# Step 2: Duplicate check by teacher_id
try:
    with engine.begin() as conn:
        duplicate_sql = text("SELECT 1 FROM users WHERE id = :id")
        result = conn.execute(duplicate_sql, {"id": teacher_id}).fetchone()
        if result:
            print(f"PASS: Duplicate teacher_id {teacher_id} correctly detected")
        else:
            print(f"FAIL: Duplicate teacher_id {teacher_id} NOT detected")
except Exception as e:
    print(f"FAIL: Error checking duplicate teacher_id: {e}")

# Step 3: Duplicate check by email
try:
    with engine.begin() as conn:
        duplicate_sql = text("SELECT 1 FROM users WHERE LOWER(email) = :email")
        result = conn.execute(duplicate_sql, {"email": test_email.lower()}).fetchone()
        if result:
            print(f"PASS: Duplicate email {test_email} correctly detected")
        else:
            print(f"FAIL: Duplicate email {test_email} NOT detected")
except Exception as e:
    print(f"FAIL: Error checking duplicate email: {e}")

# Step 4: Try to insert duplicate user (should fail)
duplicate_inserted = False
try:
    with engine.begin() as conn:
        conn.execute(insert_sql, params)
        duplicate_inserted = True
except Exception as e:
    print(f"PASS: Second insert blocked as expected: {e}")
if duplicate_inserted:
    print("FAIL: Duplicate user was inserted (should have been blocked)")

# Step 5: Cleanup - delete test user
try:
    with engine.begin() as conn:
        delete_sql = text("DELETE FROM users WHERE id = :id")
        conn.execute(delete_sql, {"id": teacher_id})
    print(f"PASS: Deleted test user {teacher_id}")
except Exception as e:
    print(f"FAIL: Could not delete test user: {e}")

print("Test script completed.")
