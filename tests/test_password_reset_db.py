import os
import importlib.util
import sys

# Ensure project root is on path
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

# Ensure tests use in-memory DB
os.environ['TESTING'] = '1'

spec = importlib.util.spec_from_file_location("app", os.path.join(os.getcwd(), "app.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def test_password_reset_db_backed(monkeypatch):
    # Initialize DB in TESTING mode
    assert app.init_database_tables() is True

    # Save a student with DB
    ok = app.save_student_data('DB Reset', 'SS1A', 'Parent', 'dbparent@example.com', '+1111111', student_photo=None, gender='Male', admission_no='ASS/33/999')
    assert ok is True

    # Request reset (should create token and send email attempt but we don't have SMTP configured)
    token = app.request_password_reset('ASS/33/999')
    assert token is not None

    # Reset password using token
    ok2 = app.reset_password_with_token(token, 'ASS/33/999', 'newdbpass')
    assert ok2 is True

    # Authenticate using new password
    auth = app.authenticate_student_with_password('ASS/33/999', 'newdbpass')
    assert auth is not None
