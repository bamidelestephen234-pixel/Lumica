import os
import sys
import uuid
from datetime import datetime
import streamlit as st
from sqlalchemy import create_engine, text
import traceback

# Get DB URL from st.secrets
db_url = "postgresql://postgres:[password]@db.hiijvgzblottszoulseh.supabase.co:5432/postgres"

engine = create_engine(db_url.strip(), pool_pre_ping=True, pool_recycle=1800)

# Generate a unique test user ID
test_user_id = f"test_user_{uuid.uuid4().hex[:8]}"

def test_user_activation():
    try:
        # Step 1: Create an inactive user
        print(f"\nStep 1: Creating test user {test_user_id}")
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO users (
                    id, full_name, email, password_hash, role, is_active, approval_status, created_date
                ) VALUES (
                    :id, :full_name, :email, :password_hash, 'teacher', FALSE, 'pending', :now
                )
            """), {
                "id": test_user_id,
                "full_name": "Test User",
                "email": f"test_{test_user_id}@lumica.test",
                "password_hash": "test_hash",
                "now": datetime.now()
            })
        print("✅ Test user created")

        # Step 2: Verify initial state
        print("\nStep 2: Verifying initial state")
        with engine.begin() as conn:
            result = conn.execute(text(
                "SELECT is_active, approval_status FROM users WHERE id = :id"
            ), {"id": test_user_id}).fetchone()
            if result and result[0] is False and result[1] == 'pending':
                print("✅ Initial state correct (inactive & pending)")
            else:
                print("❌ Initial state incorrect:", result)
                raise Exception("Initial state verification failed")

        # Step 3: Enable the user
        print("\nStep 3: Enabling user")
        with engine.begin() as conn:
            conn.execute(text("""
                UPDATE users 
                SET is_active = TRUE,
                    approval_status = 'approved',
                    approved_by = 'test_approver',
                    approval_date = :now
                WHERE id = :id
            """), {"id": test_user_id, "now": datetime.now()})
        print("✅ User enabled")

        # Step 4: Verify final state
        print("\nStep 4: Verifying final state")
        with engine.begin() as conn:
            result = conn.execute(text(
                "SELECT is_active, approval_status, approved_by FROM users WHERE id = :id"
            ), {"id": test_user_id}).fetchone()
            if result and result[0] is True and result[1] == 'approved' and result[2] == 'test_approver':
                print("✅ Final state correct (active & approved)")
            else:
                print("❌ Final state incorrect:", result)
                raise Exception("Final state verification failed")

        print("\n✅ All tests passed!")

    except Exception as e:
        print("\n❌ Test failed:")
        print(str(e))
        traceback.print_exc()
    finally:
        # Cleanup: Delete test user
        try:
            with engine.begin() as conn:
                conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": test_user_id})
            print("\n✅ Test user deleted")
        except Exception as e:
            print(f"\n❌ Error deleting test user: {e}")

if __name__ == "__main__":
    test_user_activation()