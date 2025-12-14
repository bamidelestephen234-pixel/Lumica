import os
import importlib.util
import sys
from sqlalchemy import create_engine

# Ensure project root is on path
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

# Import app module
import os
os.environ['TESTING'] = '1'
spec = importlib.util.spec_from_file_location("app", os.path.join(os.getcwd(), "app.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def test_db_backed_student_password_login(tmp_path, monkeypatch):
    # Create an in-memory sqlite engine and patch init_sql_connection
    engine = create_engine('sqlite:///:memory:', future=True)

    def _sql_conn_override():
        return engine

    monkeypatch.setattr(app, 'init_sql_connection', _sql_conn_override)
    # Clear streamlit cached resources to ensure override takes effect
    try:
        app.st.cache_resource.clear()
    except Exception:
        pass

    # Initialize DB tables (should create students table with password_hash)
    assert app.init_database_tables() is True

    # Save a student with a password (DB-backed path)
    ok = app.save_student_data('DB Student', 'SS1A', 'Parent', 'p@example.com', '+1111111', student_photo=None, gender='Male', admission_no='ASS/99/555', password='secret123')
    assert ok is True

    # Authenticate using password
    student = app.authenticate_student_with_password('ASS/99/555', 'secret123')
    assert student is not None
    assert student.get('admission_no') == 'ASS/99/555'

    # Negative case
    bad = app.authenticate_student_with_password('ASS/99/555', 'wrongpass')
    assert bad is None
