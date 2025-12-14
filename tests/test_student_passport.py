import os
import json
import io
import shutil
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


def test_save_student_passport_json_fallback(tmp_path, monkeypatch):
    sd = tmp_path / "student_database"
    sd.mkdir()

    student = {
        "student_name": "Passport Student",
        "student_class": "SS1A",
        "admission_no": "ASS/77/001",
        "parent_name": "Parent",
        "data_encrypted": False
    }

    file_path = sd / "Passport_Student_SS1A.json"
    with open(file_path, 'w') as f:
        json.dump(student, f)

    monkeypatch.chdir(tmp_path)

    # Create a fake uploaded file with bytes and name
    fake_file = io.BytesIO(b"fake-image-bytes")
    fake_file.name = "passport.jpg"

    saved = app.save_student_passport("ASS/77/001", fake_file)
    assert saved is not None

    passports_dir = tmp_path / "student_passports"
    assert passports_dir.exists()

    saved_path = passports_dir / saved
    assert saved_path.exists()

    # Verify student JSON updated with photo filename
    with open(file_path, 'r') as f:
        s2 = json.load(f)
    assert s2.get('photo_filename') == saved

    # Cleanup
    shutil.rmtree(str(passports_dir))
    shutil.rmtree(str(sd))
