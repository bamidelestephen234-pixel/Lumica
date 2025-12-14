import os
import json
import importlib.util
import sys

# Ensure project root is on path
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

import os
os.environ['TESTING'] = '1'
spec = importlib.util.spec_from_file_location("app", os.path.join(os.getcwd(), "app.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def test_password_reset_json_fallback(tmp_path, monkeypatch):
    sd = tmp_path / "student_database"
    sd.mkdir()

    student = {
        "student_name": "Reset Student",
        "student_class": "SS1A",
        "admission_no": "ASS/88/001",
        "parent_name": "Parent",
        "data_encrypted": False
    }

    file_path = sd / "Reset_Student_SS1A.json"
    with open(file_path, 'w') as f:
        json.dump(student, f)

    monkeypatch.chdir(tmp_path)

    token = app.request_password_reset("ASS/88/001")
    assert token is not None

    # Try to reset with token
    ok = app.reset_password_with_token(token, "ASS/88/001", "newpass123")
    assert ok is True

    # Authenticate using new password via JSON fallback
    auth = app.authenticate_student_with_password("ASS/88/001", "newpass123")
    assert auth is not None

    # Cleanup
    os.remove(file_path)
