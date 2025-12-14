import os
import shutil
import importlib.util

# Import app.py as a module by path
import sys
# Ensure workspace root is on sys.path so app imports succeed
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())

spec = importlib.util.spec_from_file_location("app", os.path.join(os.getcwd(), "app.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

save_report_for_student = app.save_report_for_student
list_reports_for_student = app.list_reports_for_student
_ensure_student_reports_dir = app._ensure_student_reports_dir


def test_save_and_list_report(tmp_path):
    # Use a temporary directory by pointing student_reports to tmp_path via environment
    reports_dir = tmp_path / "student_reports"
    reports_dir.mkdir()

    # Monkeypatch internal helper to return the tmp index path
    # We can't easily monkeypatch private functions here without pytest fixtures, so test via direct call
    admission = "ASS/99/001"
    report_id = "TEST-001"
    pdf_bytes = b"%PDF-1.4 testpdf"
    metadata = {"student_name": "Test Student", "student_class": "TS1", "term": "1st Term"}

    # Save report
    ok = save_report_for_student(admission, report_id, pdf_bytes, metadata)
    assert ok is True

    # List reports
    reports = list_reports_for_student(admission)
    assert isinstance(reports, list)
    assert any(r['report_id'] == report_id for r in reports)

    # Cleanup: remove student_reports directory if created
    reports_dir_path = os.path.join(os.getcwd(), "student_reports")
    if os.path.exists(reports_dir_path):
        shutil.rmtree(reports_dir_path)
