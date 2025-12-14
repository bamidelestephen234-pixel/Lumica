import os
import shutil
import json
import pytest
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


def test_update_student_json_fallback(tmp_path, monkeypatch):
    # Prepare a temporary student_database dir
    sd = tmp_path / "student_database"
    sd.mkdir()

    student = {
        "student_name": "Alice Johnson",
        "student_class": "SS1A",
        "admission_no": "ASS/99/010",
        "parent_name": "Mrs Johnson",
        "parent_email": app.encrypt_data("parent@example.com", app.generate_encryption_key("akins_sunrise_school_encryption")),
        "parent_phone": app.encrypt_data("+12345678", app.generate_encryption_key("akins_sunrise_school_encryption")),
        "data_encrypted": True
    }

    file_path = sd / "Alice_Johnson_SS1A.json"
    with open(file_path, 'w') as f:
        json.dump(student, f)

    # Monkeypatch os.getcwd to tmp_path for this test so functions use tmp dir
    monkeypatch.chdir(tmp_path)

    # Update the student
    ok = app.update_student_data("ASS/99/010", {"student_name": "Alice J.", "parent_email": "newparent@example.com"})
    assert ok is True

    # Verify file updated
    with open(file_path, 'r') as f:
        s2 = json.load(f)
    assert s2['student_name'] == "Alice J."
    # Decrypted parent email should be stored encrypted; try decrypting
    decrypted = app.decrypt_data(s2['parent_email'], app.generate_encryption_key("akins_sunrise_school_encryption"))
    assert decrypted == "newparent@example.com"

    # Cleanup
    shutil.rmtree(str(sd))
