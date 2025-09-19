import streamlit as st
import uuid
from datetime import datetime, timedelta
from database.verification_keys import init_db, save_key, get_key, key_exists

print("Starting Report Card Verification Test...")

# Initialize database
init_db()

# Generate test data
test_teacher_id = f"test_teacher_{uuid.uuid4().hex[:8]}"
test_report_id = f"test_report_{uuid.uuid4().hex[:8]}"
test_key = str(uuid.uuid4())

print(f"\n1. Saving test verification key...")
try:
    save_key(test_key, test_teacher_id, test_report_id)
    print("✅ Successfully saved verification key")
except Exception as e:
    print(f"❌ Failed to save key: {e}")
    raise

print("\n2. Verifying key exists...")
try:
    exists = key_exists(test_key)
    if exists:
        print("✅ Key found in database")
    else:
        print("❌ Key not found in database")
        raise Exception("Key not found")
except Exception as e:
    print(f"❌ Error checking key: {e}")
    raise

print("\n3. Retrieving key details...")
try:
    key_data = get_key(test_key)
    if key_data:
        print("✅ Successfully retrieved key data:")
        print(f"  - Key: {key_data[1]}")
        print(f"  - Teacher ID: {key_data[2]}")
        print(f"  - Report ID: {key_data[3]}")
        print(f"  - Created: {key_data[4]}")
    else:
        print("❌ No data returned for key")
        raise Exception("No key data found")
except Exception as e:
    print(f"❌ Error retrieving key data: {e}")
    raise

print("\n4. Verifying non-existent key...")
fake_key = str(uuid.uuid4())
try:
    exists = key_exists(fake_key)
    if not exists:
        print("✅ Non-existent key correctly returns false")
    else:
        print("❌ Non-existent key incorrectly returns true")
        raise Exception("False positive on non-existent key")
except Exception as e:
    print(f"❌ Error checking fake key: {e}")
    raise

print("\nAll tests completed successfully!")