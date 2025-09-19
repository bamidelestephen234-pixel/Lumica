# Smoke test: simulate DB failure, show backoff/counters, and verify verification key persistence
import time
import uuid

import importlib
import sys
import os
# Ensure workspace root is on sys.path so 'app' can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import app
from database import verification_keys

print("Starting smoke test: DB backoff simulation + verification key persistence")

# Reset counters
for name in ("DB_QUERY_RETRY_COUNT", "DB_EXECUTE_RETRY_COUNT", "DB_COOLDOWN_COUNT"):
    try:
        setattr(app, name, 0)
    except Exception:
        pass

# Create a fake connection object whose .query() raises a pool exhaustion error
class FakeBrokenConn:
    def query(self, *args, **kwargs):
        raise Exception("FATAL: MaxClientsInSessionMode: max clients reached - in Session mode max clients are limited to pool_size")
    def __repr__(self):
        return "<FakeBrokenConn>"

# Patch init_sql_connection to return the fake broken connection
original_init = getattr(app, 'init_sql_connection', None)
app.init_sql_connection = lambda: FakeBrokenConn()

print("Patched init_sql_connection to return a broken connection. Now calling query_with_retry...")

# Exercise query_with_retry to trigger retry/backoff logic
try:
    try:
        app.query_with_retry("SELECT 1", retries=3, ttl=0)
    except Exception as e:
        print(f"query_with_retry final exception (expected): {e}")
finally:
    # Print counters after query attempts
    print("After query attempts:")
    print("  DB_QUERY_RETRY_COUNT:", getattr(app, 'DB_QUERY_RETRY_COUNT', 'N/A'))
    print("  DB_EXECUTE_RETRY_COUNT:", getattr(app, 'DB_EXECUTE_RETRY_COUNT', 'N/A'))
    print("  DB_COOLDOWN_COUNT:", getattr(app, 'DB_COOLDOWN_COUNT', 'N/A'))
    print("  DB_COOLDOWN_UNTIL:", getattr(app, 'DB_COOLDOWN_UNTIL', 'N/A'))

# Exercise execute_sql_with_retry to trigger execute retry logic
print("\nCalling execute_sql_with_retry to simulate execute retries...")
try:
    ok = app.execute_sql_with_retry("UPDATE users SET is_active = false WHERE id = 'nonexistent'", retries=2)
    print("execute_sql_with_retry returned:", ok)
except Exception as e:
    print("execute_sql_with_retry raised:", e)
finally:
    print("After execute attempts:")
    print("  DB_QUERY_RETRY_COUNT:", getattr(app, 'DB_QUERY_RETRY_COUNT', 'N/A'))
    print("  DB_EXECUTE_RETRY_COUNT:", getattr(app, 'DB_EXECUTE_RETRY_COUNT', 'N/A'))
    print("  DB_COOLDOWN_COUNT:", getattr(app, 'DB_COOLDOWN_COUNT', 'N/A'))
    print("  DB_COOLDOWN_UNTIL:", getattr(app, 'DB_COOLDOWN_UNTIL', 'N/A'))

# Restore original init_sql_connection
if original_init is not None:
    app.init_sql_connection = original_init

print("\nTesting verification key persistence in PostgreSQL...")
import streamlit as st

# Initialize database connection
verification_keys.init_db()

# Generate a test key and metadata
test_key = str(uuid.uuid4())
user_id = 'smoke_test_user'
result_id = 'smoke_test_result'

# Test saving
try:
    verification_keys.save_key(test_key, user_id, result_id)
    print("✅ Successfully saved verification key")
except Exception as e:
    print(f"❌ Failed to save verification key: {e}")
    raise

# Test retrieval
try:
    fetched = verification_keys.get_key(test_key)
    print(f"✅ Successfully retrieved key: {fetched}")
except Exception as e:
    print(f"❌ Failed to retrieve key: {e}")
    raise

# Test existence check
try:
    exists = verification_keys.key_exists(test_key)
    print(f"✅ Key existence check successful: {exists}")
except Exception as e:
    print(f"❌ Failed to check key existence: {e}")
    raise

# Additional verification
if fetched:
    print("\nVerification key details:")
    print(f"Key: {test_key}")
    print(f"User ID: {user_id}")
    print(f"Result ID: {result_id}")
    print(f"Created at: {fetched[4] if len(fetched) > 4 else 'N/A'}")
else:
    print("❌ No data returned for verification key")

print("\nSmoke test complete.")
