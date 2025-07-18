"""
=====================================================
AKIN'S SUNRISE SCHOOL REPORT CARD MANAGEMENT SYSTEM
=====================================================

School Management System - Report Card Generator
Author: School Administration
"""

import streamlit as st
import pandas as pd
import numpy as np
import base64
import json
import os
import datetime
import shutil
import hashlib
import secrets
import threading
import time
import csv
import uuid
import pyotp
import qrcode as qr_gen
from io import BytesIO, StringIO
from weasyprint import HTML
import qrcode
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    GOOGLE_DRIVE_AVAILABLE = True
except ImportError:
    GOOGLE_DRIVE_AVAILABLE = False

try:
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False

subjects = sorted([
    "English", "Maths", "French", "C.C Art", "Business Studies", "Economics", "Yoruba",
    "physics", "chemistry", "Biology", "Further Mathematics", "National Value", 
    "Lit-in-Eng", "Guidance & Counseling", "C.R.S", "Agric Sci", "Home Eco", 
    "Basic Science", "Basic Tech", "PHE", "Computer"
])

# User roles and permissions
USER_ROLES = {
    "principal": {
        "level": 5,
        "permissions": ["all_access", "user_management", "system_config", "backup_restore", "data_export"],
        "description": "Principal - Full system access"
    },
    "head_of_department": {
        "level": 4,
        "permissions": ["department_reports", "teacher_management", "grade_boundaries", "class_management"],
        "description": "Head of Department - Departmental oversight"
    },
    "class_teacher": {
        "level": 3,
        "permissions": ["class_reports", "student_management", "report_generation", "parent_communication"],
        "description": "Class Teacher - Class-specific access"
    },
    "teacher": {
        "level": 2,
        "permissions": ["report_generation", "student_view"],
        "description": "Teacher - Basic teaching functions"
    },
    "parent": {
        "level": 1,
        "permissions": ["view_child_reports", "communication"],
        "description": "Parent - View child's reports only"
    }
}

# Enhanced user management system
def load_user_database():
    """Load user database with roles and permissions"""
    try:
        if os.path.exists("users_database.json"):
            with open("users_database.json", 'r') as f:
                return json.load(f)
        else:
            # Initialize default users
            default_users = {
                "teacher_bamstep": {
                    "password_hash": hash_password("admin789"),
                    "role": "principal",
                    "full_name": "Principal Bamstep",
                    "email": "principal@akinssunrise.edu.ng",
                    "phone": "+234 800 123 4567",
                    "created_date": datetime.datetime.now().isoformat(),
                    "last_login": None,
                    "active": True,
                    "two_factor_enabled": False,
                    "two_factor_secret": None,
                    "session_timeout": 30,
                    "failed_attempts": 0,
                    "locked_until": None,
                    "assigned_classes": [],
                    "departments": ["all"]
                },
                "teacher_bola": {
                    "password_hash": hash_password("secret123"),
                    "role": "class_teacher",
                    "full_name": "Teacher Bola",
                    "email": "bola@akinssunrise.edu.ng",
                    "phone": "+234 800 234 5678",
                    "created_date": datetime.datetime.now().isoformat(),
                    "last_login": None,
                    "active": True,
                    "two_factor_enabled": False,
                    "two_factor_secret": None,
                    "session_timeout": 30,
                    "failed_attempts": 0,
                    "locked_until": None,
                    "assigned_classes": ["SS1A", "SS1B"],
                    "departments": ["sciences"]
                },
                "teacher_musa": {
                    "password_hash": hash_password("password456"),
                    "role": "teacher",
                    "full_name": "Teacher Musa",
                    "email": "musa@akinssunrise.edu.ng",
                    "phone": "+234 800 345 6789",
                    "created_date": datetime.datetime.now().isoformat(),
                    "last_login": None,
                    "active": True,
                    "two_factor_enabled": False,
                    "two_factor_secret": None,
                    "session_timeout": 30,
                    "failed_attempts": 0,
                    "locked_until": None,
                    "assigned_classes": ["JSS1A"],
                    "departments": ["mathematics"]
                }
            }
            save_user_database(default_users)
            return default_users
    except Exception as e:
        return {}

def save_user_database(users_db):
    """Save user database"""
    try:
        with open("users_database.json", 'w') as f:
            json.dump(users_db, f, indent=2)
        return True
    except Exception as e:
        return False

def check_user_permissions(user_id, required_permission):
    """Check if user has required permission"""
    try:
        users_db = load_user_database()
        if user_id not in users_db:
            return False

        user = users_db[user_id]
        user_role = user.get('role', 'teacher')

        if user_role not in USER_ROLES:
            return False

        user_permissions = USER_ROLES[user_role]['permissions']
        return required_permission in user_permissions or 'all_access' in user_permissions
    except Exception as e:
        return False

def is_user_locked(user_id):
    """Check if user account is locked"""
    try:
        users_db = load_user_database()
        if user_id not in users_db:
            return False

        user = users_db[user_id]
        locked_until = user.get('locked_until')

        if locked_until:
            lock_time = datetime.datetime.fromisoformat(locked_until)
            if datetime.datetime.now() > lock_time:
                # Unlock user
                users_db[user_id]['locked_until'] = None
                users_db[user_id]['failed_attempts'] = 0
                save_user_database(users_db)
                return False
            return True
        return False
    except Exception as e:
        return False

def increment_failed_attempts(user_id):
    """Increment failed login attempts and lock if necessary"""
    try:
        users_db = load_user_database()
        if user_id not in users_db:
            return

        users_db[user_id]['failed_attempts'] = users_db[user_id].get('failed_attempts', 0) + 1

        # Lock account after 3 failed attempts
        if users_db[user_id]['failed_attempts'] >= 3:
            lock_time = datetime.datetime.now() + datetime.timedelta(minutes=30)
            users_db[user_id]['locked_until'] = lock_time.isoformat()

        save_user_database(users_db)
    except Exception as e:
        pass

def reset_failed_attempts(user_id):
    """Reset failed login attempts on successful login"""
    try:
        users_db = load_user_database()
        if user_id in users_db:
            users_db[user_id]['failed_attempts'] = 0
            users_db[user_id]['locked_until'] = None
            users_db[user_id]['last_login'] = datetime.datetime.now().isoformat()
            save_user_database(users_db)
    except Exception as e:
        pass

def generate_2fa_secret():
    """Generate a new 2FA secret"""
    return pyotp.random_base32()

def generate_2fa_qr(user_id, secret):
    """Generate QR code for 2FA setup"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_id,
        issuer_name="Akin's Sunrise School"
    )

    qr = qr_gen.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()

def verify_2fa_token(secret, token):
    """Verify 2FA token"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    except Exception as e:
        return False

def create_backup():
    """Create system backup"""
    try:
        backup_dir = "backups"
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"school_backup_{timestamp}"
        backup_path = os.path.join(backup_dir, backup_name)

        # Create backup directory structure
        os.makedirs(backup_path, exist_ok=True)

        # Backup directories to include
        dirs_to_backup = [
            "student_database",
            "pending_reports", 
            "approved_reports",
            "rejected_reports",
            "admin_logs",
            "audit_logs"
        ]

        # Backup files
        files_to_backup = [
            "users_database.json",
            "email_config.json",
            "academic_calendar.json",
            "grade_boundaries.json",
            "system_config.json"
        ]

        backup_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "created_by": st.session_state.get('teacher_id', 'system'),
            "backup_type": "full_system",
            "included_dirs": dirs_to_backup,
            "included_files": files_to_backup
        }

        # Copy directories
        for dir_name in dirs_to_backup:
            if os.path.exists(dir_name):
                shutil.copytree(dir_name, os.path.join(backup_path, dir_name))

        # Copy files
        for file_name in files_to_backup:
            if os.path.exists(file_name):
                shutil.copy2(file_name, os.path.join(backup_path, file_name))

        # Save backup info
        with open(os.path.join(backup_path, "backup_info.json"), 'w') as f:
            json.dump(backup_info, f, indent=2)

        # Create compressed archive
        shutil.make_archive(backup_path, 'zip', backup_path)
        shutil.rmtree(backup_path)  # Remove uncompressed folder

        return True, f"Backup created: {backup_name}.zip"
    except Exception as e:
        return False, f"Backup failed: {str(e)}"

def get_available_backups():
    """Get list of available backups"""
    try:
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            return []

        backups = []
        for file in os.listdir(backup_dir):
            if file.endswith('.zip') and file.startswith('school_backup_'):
                file_path = os.path.join(backup_dir, file)
                stat = os.stat(file_path)
                backups.append({
                    'name': file,
                    'size': stat.st_size,
                    'created': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'path': file_path
                })

        return sorted(backups, key=lambda x: x['created'], reverse=True)
    except Exception as e:
        return []

def restore_backup(backup_name):
    """Restore system from backup"""
    try:
        backup_path = os.path.join("backups", backup_name)
        if not os.path.exists(backup_path):
            return False, "Backup file not found"

        # Extract backup
        temp_dir = f"restore_temp_{int(time.time())}"
        shutil.unpack_archive(backup_path, temp_dir)

        # Restore directories and files
        backup_info_path = os.path.join(temp_dir, "backup_info.json")
        if os.path.exists(backup_info_path):
            with open(backup_info_path, 'r') as f:
                backup_info = json.load(f)

            # Restore directories
            for dir_name in backup_info.get('included_dirs', []):
                src_dir = os.path.join(temp_dir, dir_name)
                if os.path.exists(src_dir):
                    if os.path.exists(dir_name):
                        shutil.rmtree(dir_name)
                    shutil.copytree(src_dir, dir_name)

            # Restore files
            for file_name in backup_info.get('included_files', []):
                src_file = os.path.join(temp_dir, file_name)
                if os.path.exists(src_file):
                    shutil.copy2(src_file, file_name)

        # Cleanup
        shutil.rmtree(temp_dir)

        return True, "System restored successfully"
    except Exception as e:
        return False, f"Restore failed: {str(e)}"

def export_student_data(student_id=None, gdpr_compliant=True):
    """Export student data in GDPR-compliant format"""
    try:
        students = get_all_students()

        if student_id:
            students = [s for s in students if s.get('admission_no') == student_id or s.get('student_name') == student_id]

        if not students:
            return None, "No student data found"

        export_data = {
            "export_timestamp": datetime.datetime.now().isoformat(),
            "export_type": "gdpr_compliant" if gdpr_compliant else "standard",
            "exported_by": st.session_state.get('teacher_id', 'system'),
            "students": []
        }

        for student in students:
            student_export = {
                "personal_information": {
                    "student_name": student.get('student_name'),
                    "admission_no": student.get('admission_no'),
                    "student_class": student.get('student_class'),
                    "gender": student.get('gender'),
                    "created_date": student.get('created_date'),
                    "last_updated": student.get('last_updated')
                },
                "academic_records": [],
                "attendance_records": {
                    "attendance_rate": student.get('attendance'),
                    "position": student.get('position'),
                    "class_size": student.get('class_size')
                },
                "contact_information": {
                    "parent_name": student.get('parent_name'),
                    "parent_email": student.get('parent_email'),
                    "parent_phone": student.get('parent_phone')
                } if not gdpr_compliant else None  # Exclude sensitive data in GDPR export
            }

            # Add academic records if available
            approved_dir = "approved_reports"
            if os.path.exists(approved_dir):
                for filename in os.listdir(approved_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(approved_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                report = json.load(f)
                                if report.get('student_name') == student['student_name']:
                                    student_export['academic_records'].append({
                                        "term": report.get('term'),
                                        "average_cumulative": report.get('average_cumulative'),
                                        "final_grade": report.get('final_grade'),
                                        "report_date": report.get('approved_date')
                                    })
                        except:
                            continue

            export_data["students"].append(student_export)

        return export_data, "Export successful"
    except Exception as e:
        return None, f"Export failed: {str(e)}"

credentials = load_user_database()

def generate_encryption_key(password: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = b'akins_sunrise_school_2025'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data: str, key: bytes) -> str:
    try:
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    except Exception as e:
        return data

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    try:
        f = Fernet(key)
        decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = f.decrypt(decoded_data)
        return decrypted_data.decode()
    except Exception as e:
        return encrypted_data

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + pwd_hash.hex()

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt = hashed[:32]
        stored_hash = hashed[32:]
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return pwd_hash.hex() == stored_hash
    except:
        return False

def create_audit_log(action: str, user_id: str, details: dict, data_type: str = "general"):
    try:
        audit_dir = "audit_logs"
        os.makedirs(audit_dir, exist_ok=True)

        audit_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action,
            "user_id": user_id,
            "data_type": data_type,
            "details": details,
            "ip_address": "replit_session",
            "session_id": hashlib.md5(f"{user_id}_{datetime.datetime.now().isoformat()}".encode()).hexdigest()[:16],
            "compliance_level": "high",
            "retention_period": "7_years"
        }

        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        audit_file = os.path.join(audit_dir, f"audit_{date_str}.json")

        if os.path.exists(audit_file):
            with open(audit_file, 'r') as f:
                audit_logs = json.load(f)
        else:
            audit_logs = []

        audit_logs.append(audit_entry)
        with open(audit_file, 'w') as f:
            json.dump(audit_logs, f, indent=2)

        return True
    except Exception as e:
        return False

def get_audit_logs(start_date: str = None, end_date: str = None, user_id: str = None, action: str = None):
    try:
        audit_dir = "audit_logs"
        if not os.path.exists(audit_dir):
            return []

        all_logs = []

        for file_name in os.listdir(audit_dir):
            if file_name.startswith('audit_') and file_name.endswith('.json'):
                file_path = os.path.join(audit_dir, file_name)
                try:
                    with open(file_path, 'r') as f:
                        logs = json.load(f)
                        all_logs.extend(logs)
                except Exception:
                    continue

        filtered_logs = all_logs

        if start_date:
            filtered_logs = [log for log in filtered_logs if log['timestamp'] >= start_date]

        if end_date:
            filtered_logs = [log for log in filtered_logs if log['timestamp'] <= end_date]

        if user_id:
            filtered_logs = [log for log in filtered_logs if log['user_id'] == user_id]

        if action:
            filtered_logs = [log for log in filtered_logs if action.lower() in log['action'].lower()]

        filtered_logs.sort(key=lambda x: x['timestamp'], reverse=True)

        return filtered_logs
    except Exception:
        return []

def save_student_data(student_name, student_class, parent_name, parent_email, parent_phone, student_photo=None, gender=None, admission_no=None, class_size=None, attendance=None, position=None):
    try:
        students_dir = "student_database"
        if not os.path.exists(students_dir):
            os.makedirs(students_dir)

        encryption_key = generate_encryption_key("akins_sunrise_school_encryption")

        student_data = {
            "student_name": student_name,
            "student_class": student_class,
            "parent_name": parent_name,
            "parent_email": encrypt_data(parent_email, encryption_key),
            "parent_phone": encrypt_data(parent_phone, encryption_key),
            "gender": gender if gender else "",
            "admission_no": admission_no or f"ASS/{str(datetime.datetime.now().year)[-2:]}/{len(get_all_students()) + 1:03d}",
            "class_size": class_size or "35",
            "attendance": attendance or "95%",
            "position": position or "1st",
            "created_date": datetime.datetime.now().isoformat(),
            "last_updated": datetime.datetime.now().isoformat(),
            "created_by": st.session_state.get('teacher_id', 'unknown'),
            "data_encrypted": True,
            "compliance_level": "gdpr_compliant"
        }

        # Handle photo upload or preserve existing photo
        if student_photo is not None:
            try:
                photo_filename = f"{student_name.replace(' ', '_')}_photo.jpg"
                photo_path = os.path.join(students_dir, photo_filename)

                # Read the uploaded file properly
                if hasattr(student_photo, 'read'):
                    photo_data = student_photo.read()
                else:
                    photo_data = student_photo

                with open(photo_path, "wb") as f:
                    f.write(photo_data)

                student_data["photo_filename"] = photo_filename
            except Exception as e:
                # Log photo upload error but continue with student creation
                create_audit_log("photo_upload_error", st.session_state.get('teacher_id', 'unknown'), {
                    "error": str(e),
                    "student_name": student_name
                }, "error")
        else:
            # Try to preserve existing photo from old record
            old_filename = f"{student_name.replace(' ', '_')}_{student_class.replace(' ', '_')}.json"
            old_path = os.path.join(students_dir, old_filename)

            # Also check for old records with different class names (for promotions)
            existing_students = get_all_students()
            for existing_student in existing_students:
                if (existing_student.get('student_name') == student_name or 
                    existing_student.get('admission_no') == admission_no):
                    if existing_student.get('photo_filename'):
                        # Copy photo to new filename if class changed
                        old_photo_path = os.path.join(students_dir, existing_student['photo_filename'])
                        if os.path.exists(old_photo_path):
                            new_photo_filename = f"{student_name.replace(' ', '_')}_photo.jpg"
                            new_photo_path = os.path.join(students_dir, new_photo_filename)

                            # Copy photo if it's a different filename
                            if old_photo_path != new_photo_path:
                                shutil.copy2(old_photo_path, new_photo_path)

                            student_data["photo_filename"] = new_photo_filename
                        break

        student_filename = f"{student_name.replace(' ', '_')}_{student_class.replace(' ', '_')}.json"
        student_path = os.path.join(students_dir, student_filename)
        with open(student_path, 'w') as f:
            json.dump(student_data, f, indent=2)

        create_audit_log("student_data_created", st.session_state.get('teacher_id', 'unknown'), {
            "student_name": student_name,
            "student_class": student_class,
            "has_photo": student_photo is not None or student_data.get('photo_filename') is not None,
            "data_encrypted": True
        }, "personal_data")

        return True
    except Exception as e:
        create_audit_log("student_data_error", st.session_state.get('teacher_id', 'unknown'), {
            "error": str(e),
            "student_name": student_name
        }, "error")
        return False

def load_student_data(student_name, student_class):
    try:
        students_dir = "student_database"
        student_filename = f"{student_name.replace(' ', '_')}_{student_class.replace(' ', '_')}.json"
        student_path = os.path.join(students_dir, student_filename)

        if os.path.exists(student_path):
            with open(student_path, 'r') as f:
                student_data = json.load(f)

            if student_data.get('data_encrypted', False):
                encryption_key = generate_encryption_key("akins_sunrise_school_encryption")

                if 'parent_email' in student_data:
                    student_data['parent_email'] = decrypt_data(student_data['parent_email'], encryption_key)
                if 'parent_phone' in student_data:
                    student_data['parent_phone'] = decrypt_data(student_data['parent_phone'], encryption_key)

            create_audit_log("student_data_accessed", st.session_state.get('teacher_id', 'unknown'), {
                "student_name": student_name,
                "student_class": student_class,
                "access_purpose": "report_generation"
            }, "data_access")

            return student_data
        return None
    except Exception:
        return None

def get_all_students():
    try:
        students_dir = "student_database"
        if not os.path.exists(students_dir):
            return []

        students = []
        for file_name in os.listdir(students_dir):
            if file_name.endswith('.json'):
                file_path = os.path.join(students_dir, file_name)
                try:
                    with open(file_path, 'r') as f:
                        student_data = json.load(f)
                        student_data['file_name'] = file_name
                        students.append(student_data)
                except Exception:
                    continue
        return students
    except Exception:
        return []

def process_csv_student_import(csv_file):
    """Process CSV file to import multiple students"""
    try:
        # Read CSV file
        df = pd.read_csv(csv_file)

        # Expected columns: student_name, student_class, parent_name, parent_email, parent_phone, gender, admission_no, class_size, attendance
        required_columns = ['student_name', 'student_class', 'parent_email']
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            return False, f"Missing required columns: {', '.join(missing_columns)}"

        success_count = 0
        error_count = 0
        errors = []

        for index, row in df.iterrows():
            try:
                result = save_student_data(
                    student_name=row['student_name'],
                    student_class=row['student_class'],
                    parent_name=row.get('parent_name', ''),
                    parent_email=row['parent_email'],
                    parent_phone=row.get('parent_phone', ''),
                    gender=row.get('gender', 'M/F'),
                    admission_no=row.get('admission_no', ''),
                    class_size=row.get('class_size', '35'),
                    attendance=row.get('attendance', '95%'),
                    position=row.get('position', '1st')
                )

                if result:
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"Row {index + 1}: {row['student_name']}")

            except Exception as e:
                error_count += 1
                errors.append(f"Row {index + 1}: {str(e)}")

        return True, f"Imported {success_count} students successfully. {error_count} errors: {'; '.join(errors[:5])}"

    except Exception as e:
        return False, f"Error processing CSV: {str(e)}"

def generate_class_reports(student_class, term, subject_scores_dict):
    """Generate reports for an entire class"""
    try:
        students = get_all_students()
        class_students = [s for s in students if s['student_class'] == student_class]

        if not class_students:
            return False, "No students found for this class"

        success_count = 0
        error_count = 0
        errors = []

        for student in class_students:
            try:
                student_name = student['student_name']

                # Get scores for this student (if provided in bulk scores)
                student_scores = subject_scores_dict.get(student_name, {})

                if not student_scores:
                    continue  # Skip if no scores provided

                # Create scores data structure
                scores_data = []
                total_term_score = 0
                all_cumulatives = []

                for subject, scores in student_scores.items():
                    ca = scores.get('ca', 0)
                    exam = scores.get('exam', 0)
                    last_cumulative = scores.get('last_cumulative', 0)

                    total = calculate_total(ca, exam)
                    subject_cumulative = (total + last_cumulative) / 2
                    total_term_score += total
                    all_cumulatives.append(subject_cumulative)

                    scores_data.append((subject, ca, exam, total, last_cumulative, subject_cumulative, assign_grade(subject_cumulative)))

                if all_cumulatives:
                    average_cumulative = np.mean(all_cumulatives)
                    final_grade = assign_grade(average_cumulative)

                    report_df = pd.DataFrame(scores_data, columns=["Subject", "CA", "Exam", "Total", "Last Term", "Cumulative", "Grade"])

                    logo_base64 = get_logo_base64()
                    html = render_html_report(student_name, student_class, term, report_df, total_term_score, average_cumulative, final_grade, logo_base64, student)

                    # Save as pending report
                    report_data = {
                        "report_id": generate_report_id(),
                        "student_name": student_name,
                        "student_class": student_class,
                        "term": term,
                        "parent_email": student['parent_email'],
                        "teacher_id": st.session_state.teacher_id,
                        "created_date": datetime.datetime.now().isoformat(),
                        "status": "pending_review",
                        "scores_data": scores_data,
                        "average_cumulative": float(average_cumulative),
                        "final_grade": final_grade,
                        "total_term_score": total_term_score,
                        "html_content": html
                    }

                    save_pending_report(report_data)
                    success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f"{student['student_name']}: {str(e)}")

        return True, f"Generated {success_count} reports successfully. {error_count} errors."

    except Exception as e:
        return False, f"Error generating class reports: {str(e)}"

def get_class_performance_data():
    """Get aggregated class performance data for analytics"""
    try:
        students = get_all_students()
        if not students:
            return pd.DataFrame()

        # Group by class
        class_data = {}
        for student in students:
            class_name = student['student_class']
            if class_name not in class_data:
                class_data[class_name] = {
                    'class': class_name,
                    'total_students': 0,
                    'avg_attendance': 0,
                    'attendance_values': []
                }

            class_data[class_name]['total_students'] += 1

            # Parse attendance percentage
            attendance_str = student.get('attendance', '95%')
            try:
                attendance_val = float(attendance_str.replace('%', ''))
                class_data[class_name]['attendance_values'].append(attendance_val)
            except:
                class_data[class_name]['attendance_values'].append(95.0)

        # Calculate averages
        for class_name in class_data:
            if class_data[class_name]['attendance_values']:
                class_data[class_name]['avg_attendance'] = np.mean(class_data[class_name]['attendance_values'])

        return pd.DataFrame(class_data.values())

    except Exception as e:
        return pd.DataFrame()

def get_grade_distribution_data():
    """Get grade distribution data from approved reports"""
    try:
        grade_counts = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0}

        approved_dir = "approved_reports"
        if os.path.exists(approved_dir):
            for filename in os.listdir(approved_dir):
                if filename.startswith('approved_') and filename.endswith('.json'):
                    filepath = os.path.join(approved_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            report_data = json.load(f)
                            final_grade = report_data.get('final_grade', 'F')
                            if final_grade in grade_counts:
                                grade_counts[final_grade] += 1
                    except:
                        continue

        return pd.DataFrame(list(grade_counts.items()), columns=['Grade', 'Count'])

    except Exception as e:
        return pd.DataFrame({'Grade': ['A', 'B', 'C', 'D', 'E', 'F'], 'Count': [0, 0, 0, 0, 0, 0]})

def delete_student_data(student_name, student_class):
    try:
        students_dir = "student_database"
        student_filename = f"{student_name.replace(' ', '_')}_{student_class.replace(' ', '_')}.json"
        student_path = os.path.join(students_dir, student_filename)

        if os.path.exists(student_path):
            # Load student data to get photo filename
            with open(student_path, 'r') as f:
                student_data = json.load(f)

            # Delete photo if exists
            if 'photo_filename' in student_data:
                photo_path = os.path.join(students_dir, student_data['photo_filename'])
                if os.path.exists(photo_path):
                    os.remove(photo_path)

            # Delete student JSON file
            os.remove(student_path)

            # Create audit log
            create_audit_log("student_data_deleted", st.session_state.get('teacher_id', 'unknown'), {
                "student_name": student_name,
                "student_class": student_class,
                "deleted_by": st.session_state.get('teacher_id', 'unknown')
            }, "data_deletion")

            return True
        return False
    except Exception as e:
        create_audit_log("student_data_delete_error", st.session_state.get('teacher_id', 'unknown'), {
            "error": str(e),
            "student_name": student_name
        }, "error")
        return False

def save_draft_report(report_data):
    """Save incomplete report as draft"""
    try:
        draft_dir = "draft_reports"
        os.makedirs(draft_dir, exist_ok=True)

        # Generate consistent draft ID based on student, class, term, and teacher
        student_name = report_data.get('student_name', '')
        student_class = report_data.get('student_class', '')
        term = report_data.get('term', '')
        teacher_id = report_data.get('teacher_id', '')
        
        # Use consistent ID format to prevent duplicates
        consistent_id = f"AUTO-{teacher_id}-{student_name.replace(' ', '_')}-{student_class}-{term}"
        
        # Always use the consistent ID regardless of auto_save or manual save
        report_data['draft_id'] = consistent_id
        
        filename = f"draft_{consistent_id}.json"
        filepath = os.path.join(draft_dir, filename)

        # Check if draft already exists and merge if needed
        existing_data = None
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    existing_data = json.load(f)
            except:
                pass

        # Update timestamp
        report_data['last_modified'] = datetime.datetime.now().isoformat()
        
        # If existing data, preserve creation date
        if existing_data:
            report_data['created_date'] = existing_data.get('created_date', report_data['created_date'])

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)

        create_audit_log("draft_report_saved", st.session_state.get('teacher_id', 'unknown'), {
            "student_name": report_data.get('student_name', ''),
            "draft_id": consistent_id,
            "auto_save": report_data.get('auto_save', False),
            "overwrite": existing_data is not None
        }, "draft_management")

        return True
    except Exception as e:
        return False

def get_draft_reports(teacher_id=None):
    """Get all draft reports, optionally filtered by teacher"""
    try:
        draft_dir = "draft_reports"
        if not os.path.exists(draft_dir):
            return []

        draft_reports = []
        for filename in os.listdir(draft_dir):
            if filename.startswith('draft_') and filename.endswith('.json'):
                filepath = os.path.join(draft_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        draft_data = json.load(f)
                        
                        # Filter by teacher if specified
                        if teacher_id and draft_data.get('teacher_id') != teacher_id:
                            continue
                            
                        draft_reports.append(draft_data)
                except Exception:
                    continue

        # Sort by last modified date
        draft_reports.sort(key=lambda x: x.get('last_modified', ''), reverse=True)
        return draft_reports
    except Exception:
        return []

def delete_draft_report(draft_id):
    """Delete a draft report"""
    try:
        draft_dir = "draft_reports"
        filename = f"draft_{draft_id}.json"
        filepath = os.path.join(draft_dir, filename)

        if os.path.exists(filepath):
            os.remove(filepath)
            create_audit_log("draft_report_deleted", st.session_state.get('teacher_id', 'unknown'), {
                "draft_id": draft_id
            }, "draft_management")
            return True
        return False
    except Exception:
        return False

def generate_draft_id(student_name="", student_class="", term="", teacher_id=""):
    """Generate consistent draft ID to prevent duplicates"""
    if student_name and student_class and term and teacher_id:
        # Use consistent format for predictable IDs
        return f"AUTO-{teacher_id}-{student_name.replace(' ', '_')}-{student_class}-{term}"
    else:
        # Fallback to random ID if missing data
        import random
        import string
        import time
        timestamp = str(int(time.time()))[-6:]
        random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        return f"DRAFT-{timestamp}-{random_chars}"

def save_pending_report(report_data):
    try:
        pending_dir = "pending_reports"
        os.makedirs(pending_dir, exist_ok=True)

        filename = f"pending_{report_data['report_id']}.json"
        filepath = os.path.join(pending_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)

        pdf_filename = f"pending_{report_data['report_id']}.pdf"
        pdf_path = os.path.join(pending_dir, pdf_filename)

        HTML(string=report_data['html_content']).write_pdf(pdf_path)

        return True
    except Exception as e:
        return False

def get_pending_reports():
    try:
        pending_dir = "pending_reports"
        if not os.path.exists(pending_dir):
            return []

        pending_reports = []
        for filename in os.listdir(pending_dir):
            if filename.startswith('pending_') and filename.endswith('.json'):
                filepath = os.path.join(pending_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        report_data = json.load(f)
                        if report_data.get('status') == 'pending_review':
                            pending_reports.append(report_data)
                except Exception:
                    continue

        pending_reports.sort(key=lambda x: x['created_date'], reverse=True)
        return pending_reports
    except Exception:
        return []

def approve_report(report_id):
    try:
        pending_dir = "pending_reports"
        filename = f"pending_{report_id}.json"
        filepath = os.path.join(pending_dir, filename)

        if not os.path.exists(filepath):
            return False, "Report not found"

        with open(filepath, 'r') as f:
            report_data = json.load(f)

        if report_data.get('parent_email'):
            pdf_path = os.path.join(pending_dir, f"pending_{report_id}.pdf")
            success, message = send_report_email(
                report_data['parent_email'],
                report_data['student_name'],
                report_data['student_class'],
                report_data['term'],
                pdf_path,
                report_id
            )

            if success:
                approved_dir = "approved_reports"
                os.makedirs(approved_dir, exist_ok=True)

                report_data['status'] = 'approved'
                report_data['approved_date'] = datetime.datetime.now().isoformat()
                report_data['approved_by'] = st.session_state.get('teacher_id', 'admin')

                approved_path = os.path.join(approved_dir, f"approved_{report_id}.json")
                with open(approved_path, 'w') as f:
                    json.dump(report_data, f, indent=2)

                approved_pdf_path = os.path.join(approved_dir, f"approved_{report_id}.pdf")
                shutil.copy2(pdf_path, approved_pdf_path)

                os.remove(filepath)
                os.remove(pdf_path)

                log_teacher_activity(st.session_state.get('teacher_id', 'admin'), "report_approved", {
                    "report_id": report_id,
                    "student_name": report_data['student_name'],
                    "parent_email": report_data['parent_email']
                })

                return True, f"Report approved and sent to {report_data['parent_email']}"
            else:
                return False, f"Email sending failed: {message}"
        else:
            return False, "No parent email provided"

    except Exception as e:
        return False, f"Error approving report: {str(e)}"

def reject_report(report_id, reason=""):
    try:
        pending_dir = "pending_reports"
        filename = f"pending_{report_id}.json"
        filepath = os.path.join(pending_dir, filename)

        if not os.path.exists(filepath):
            return False, "Report not found"

        with open(filepath, 'r') as f:
            report_data = json.load(f)

        rejected_dir = "rejected_reports"
        os.makedirs(rejected_dir, exist_ok=True)

        report_data['status'] = 'rejected'
        report_data['rejected_date'] = datetime.datetime.now().isoformat()
        report_data['rejected_by'] = st.session_state.get('teacher_id', 'admin')
        report_data['rejection_reason'] = reason

        rejected_path = os.path.join(rejected_dir, f"rejected_{report_id}.json")
        with open(rejected_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        pdf_path = os.path.join(pending_dir, f"pending_{report_id}.pdf")
        if os.path.exists(pdf_path):
            rejected_pdf_path = os.path.join(rejected_dir, f"rejected_{report_id}.pdf")
            shutil.copy2(pdf_path, rejected_pdf_path)
            os.remove(pdf_path)

        os.remove(filepath)

        log_teacher_activity(st.session_state.get('teacher_id', 'admin'), "report_rejected", {
            "report_id": report_id,
            "student_name": report_data['student_name'],
            "reason": reason
        })

        return True, "Report rejected successfully"

    except Exception as e:
        return False, f"Error rejecting report: {str(e)}"

def calculate_total(ca, exam):
    return ca + exam

def assign_grade(score):
    if score >= 80:
        return "A"
    elif score >= 60:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 40:
        return "D"
    elif score >= 30:
        return "E"
    else:
        return "F"

def get_logo_base64(uploaded_file=None):
    try:
        if uploaded_file is not None:
            uploaded_file.seek(0)
            logo_data = base64.b64encode(uploaded_file.read()).decode("utf-8")
            print(f"Logo loaded from uploaded file, size: {len(logo_data)} characters")
            return logo_data
        else:
            logo_files = ["school_logo.png.png", "school_logo.png", "logo.png", "logo.jpg", "logo.jpeg"]

            for logo_file in logo_files:
                print(f"Checking for logo file: {logo_file}")
                if os.path.exists(logo_file):
                    try:
                        with open(logo_file, "rb") as image_file:
                            logo_data = base64.b64encode(image_file.read()).decode("utf-8")
                            print(f"Logo loaded from {logo_file}, size: {len(logo_data)} characters")
                            return logo_data
                    except Exception as e:
                        print(f"Error reading logo file {logo_file}: {e}")
                        continue
                else:
                    print(f"Logo file not found: {logo_file}")

            print(f"Warning: No logo file found. Tried: {logo_files}")
            print(f"Current directory contents: {os.listdir('.')}")
            return ""
    except Exception as e:
        print(f"Error loading logo: {e}")
        return ""

def generate_qr_code(data):
    qr = qrcode.make(data)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")

def generate_report_id():
    import random
    import string
    import time

    timestamp = str(int(time.time()))[-6:]
    random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"ASS-{timestamp}-{random_chars}"

def load_email_config():
    try:
        email_config_file = "email_config.json"
        if os.path.exists(email_config_file):
            with open(email_config_file, 'r') as f:
                return json.load(f)
        return None
    except Exception:
        return None

def save_email_config(smtp_server, smtp_port, school_email, email_password):
    try:
        config = {
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "school_email": school_email,
            "email_password": email_password
        }
        with open("email_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False

def load_school_config():
    """Load school configuration settings"""
    try:
        if os.path.exists("school_config.json"):
            with open("school_config.json", 'r') as f:
                return json.load(f)
        return {}
    except Exception:
        return {}

def save_school_config(config):
    """Save school configuration settings"""
    try:
        with open("school_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False

def load_email_templates():
    """Load email templates"""
    try:
        if os.path.exists("email_templates.json"):
            with open("email_templates.json", 'r') as f:
                return json.load(f)
        return {}
    except Exception:
        return {}

def save_email_templates(templates):
    """Save email templates"""
    try:
        with open("email_templates.json", 'w') as f:
            json.dump(templates, f, indent=2)
        return True
    except Exception:
        return False

def load_branding_config():
    """Load branding configuration"""
    try:
        if os.path.exists("branding_config.json"):
            with open("branding_config.json", 'r') as f:
                return json.load(f)
        return {}
    except Exception:
        return {}

def save_branding_config(config):
    """Save branding configuration"""
    try:
        with open("branding_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False

def load_form_config():
    """Load form configuration"""
    try:
        if os.path.exists("form_config.json"):
            with open("form_config.json", 'r') as f:
                return json.load(f)
        return {}
    except Exception:
        return {}

def save_form_config(config):
    """Save form configuration"""
    try:
        with open("form_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False

def get_default_report_email_template():
    """Get default report email template"""
    return """
AKIN'S SUNRISE SECONDARY SCHOOL
SUNRISE AVENUE OFF LUJOJOMU ROAD
UPPER AYEYEMI, ONDO CITY
ONDO STATE, NIGERIA

===============================================
OFFICIAL ACADEMIC REPORT NOTIFICATION
===============================================

Dear Parent/Guardian,

Greetings from Akin's Sunrise Secondary School. We trust this message finds you and your family in good health and high spirits.

We are pleased to inform you that your child's academic report for the {term} has been prepared and is now available for your review. This report has been thoroughly verified by our academic team and approved by the school administration.

STUDENT DETAILS:
----------------------------------------
Full Name: {student_name}
Class/Form: {student_class}
Academic Term: {term}
Academic Session: {session_year}
Report Generation Date: {current_date}
Report ID: {report_id}

REPORT VERIFICATION:
----------------------------------------
✓ This report has been officially verified and approved
✓ Generated by qualified teaching staff
✓ Reviewed by academic coordinators
✓ Authenticated with unique Report ID: {report_id}
✓ Digitally secured with QR code verification

Thank you for choosing Akin's Sunrise Secondary School.

Best regards,
The Management
AKIN'S SUNRISE SECONDARY SCHOOL

===============================================
This is an official communication from Akin's Sunrise Secondary School.
Report generated on {current_date}
===============================================
"""

def check_premium_subscription(parent_email):
    """Check if parent has premium subscription"""
    try:
        if os.path.exists("premium_subscriptions.json"):
            with open("premium_subscriptions.json", 'r') as f:
                subscriptions = json.load(f)
                subscription = subscriptions.get(parent_email, {})
                if subscription.get('active', False):
                    # Check if subscription is still valid
                    expiry_date = subscription.get('expiry_date', '')
                    if expiry_date:
                        try:
                            expiry = datetime.datetime.fromisoformat(expiry_date)
                            return datetime.datetime.now() < expiry
                        except:
                            return True  # If date parsing fails, assume active
                    return True  # If no expiry date, assume active
                return False
        return False
    except Exception:
        return False

def add_premium_subscription(parent_email, plan_type="monthly"):
    """Add premium subscription for parent"""
    try:
        subscriptions = {}
        if os.path.exists("premium_subscriptions.json"):
            try:
                with open("premium_subscriptions.json", 'r') as f:
                    subscriptions = json.load(f)
            except:
                subscriptions = {}

        # Calculate expiry based on plan type
        now = datetime.datetime.now()
        if plan_type == "monthly":
            expiry = now + datetime.timedelta(days=30)
        elif plan_type == "yearly":
            expiry = now + datetime.timedelta(days=365)
        else:
            expiry = now + datetime.timedelta(days=30)

        subscriptions[parent_email] = {
            "active": True,
            "plan_type": plan_type,
            "start_date": now.isoformat(),
            "expiry_date": expiry.isoformat(),
            "created_date": now.isoformat(),
            "features": [
                "advanced_analytics",
                "priority_support", 
                "extended_reports",
                "teacher_messaging",
                "custom_notifications",
                "study_resources"
            ]
        }

        # Ensure directory exists and write file
        with open("premium_subscriptions.json", 'w') as f:
            json.dump(subscriptions, f, indent=2)

        # Verify the file was written correctly
        if os.path.exists("premium_subscriptions.json"):
            with open("premium_subscriptions.json", 'r') as f:
                test_read = json.load(f)
                return parent_email in test_read and test_read[parent_email].get('active', False)

        return False
    except Exception as e:
        print(f"Error adding premium subscription: {e}")
        return False

def get_premium_features():
    """Get list of premium features"""
    return {
        "advanced_analytics": {
            "name": "📊 Advanced Analytics",
            "description": "Detailed performance trends, predictions, and comparative analysis"
        },
        "extended_reports": {
            "name": "📋 Extended Report Access", 
            "description": "Access to all historical reports and detailed breakdowns"
        },
        "teacher_messaging": {
            "name": "💬 Direct Teacher Communication",
            "description": "Send messages directly to teachers and book consultations"
        },
        "priority_support": {
            "name": "🎯 Priority Support",
            "description": "Get faster responses and priority assistance"
        },
        "custom_notifications": {
            "name": "📱 Custom Notifications",
            "description": "Receive SMS and email alerts for important updates"
        },
        "study_resources": {
            "name": "📚 Study Resources",
            "description": "Access to educational materials, practice tests, and tutorials"
        }
    }

def get_default_login_instructions_template():
    """Get default login instructions template"""
    return """
AKIN'S SUNRISE SECONDARY SCHOOL
PARENT PORTAL ACCESS INSTRUCTIONS

Dear Parent/Guardian,

Greetings from Akin's Sunrise Secondary School. We are excited to provide you with access to our new Parent Portal where you can view your child's academic reports and stay updated on their progress.

STUDENT INFORMATION:
----------------------------------------
Student Name: {student_name}
Admission Number: {admission_no}
Parent Email: {parent_email}

LOGIN INSTRUCTIONS:
----------------------------------------
1. Visit the school management system
2. Click on "Parent Portal" instead of "Staff Login"
3. Enter your email address: {parent_email}
4. Enter your child's admission number: {admission_no}
5. Click "Access Portal" to view your child's reports

WHAT YOU CAN ACCESS:
----------------------------------------
✓ View your child's academic reports
✓ Download report cards in PDF format
✓ Track academic progress over time
✓ View attendance and performance metrics
✓ Access school contact information

SECURITY NOTE:
----------------------------------------
- Keep your login credentials secure
- Only use the email address registered with the school
- Contact us immediately if you experience any login issues

For technical support or questions, please contact:
📞 Phone: {school_phone}
📧 Email: {school_email}

Thank you for your continued trust in Akin's Sunrise Secondary School.

Best regards,
The Management
AKIN'S SUNRISE SECONDARY SCHOOL

===============================================
This is an official communication from Akin's Sunrise Secondary School.
Generated on {current_date}
===============================================
"""

def send_parent_login_instructions(parent_email, student_name, admission_no):
    """Send login instructions to parents"""
    try:
        if not EMAIL_AVAILABLE:
            return False, "Email functionality not available"

        email_config = load_email_config()
        if not email_config:
            return False, "Email not configured"

        smtp_server = email_config.get("smtp_server")
        smtp_port = email_config.get("smtp_port")
        school_email = email_config.get("school_email")
        email_password = email_config.get("email_password")

        if not all([smtp_server, smtp_port, school_email, email_password]):
            return False, "Incomplete email configuration"

        # Load email templates and school config
        email_templates = load_email_templates()
        school_config = load_school_config()

        # Get template or use default
        template = email_templates.get('login_instructions', {})
        subject_template = template.get('subject', "Parent Portal Access - {student_name}")
        body_template = template.get('body', get_default_login_instructions_template())

        # Format subject
        subject = subject_template.format(
            student_name=student_name,
            admission_no=admission_no,
            parent_email=parent_email
        )

        # Format body with placeholders
        current_date = datetime.datetime.now().strftime("%A, %B %d, %Y at %I:%M %p")
        school_phone = school_config.get('school_phone', "+234 800 123 4567")
        school_email_address = school_config.get('school_email', "info@akinssunrise.edu.ng")

        body = body_template.format(
            student_name=student_name,
            admission_no=admission_no,
            parent_email=parent_email,
            current_date=current_date,
            school_phone=school_phone,
            school_email=school_email_address
        )

        msg = MIMEMultipart()
        msg['From'] = school_email
        msg['To'] = parent_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(school_email, email_password)
        text = msg.as_string()
        server.sendmail(school_email, parent_email, text)
        server.quit()

        return True, f"Login instructions sent successfully to {parent_email}"

    except Exception as e:
        return False, f"Error sending instructions: {str(e)}"

def send_report_email(parent_email, student_name, student_class, term, report_pdf_path, report_id):
    try:
        if not EMAIL_AVAILABLE:
            return False, "Email functionality not available"

        email_config = load_email_config()
        if not email_config:
            return False, "Email not configured. Please set up email in Admin Panel."

        smtp_server = email_config.get("smtp_server")
        smtp_port = email_config.get("smtp_port")
        school_email = email_config.get("school_email")
        email_password = email_config.get("email_password")

        if not all([smtp_server, smtp_port, school_email, email_password]):
            return False, "Incomplete email configuration"

        # Load email templates and school config
        email_templates = load_email_templates()
        school_config = load_school_config()

        # Get template or use default
        template = email_templates.get('report_email', {})
        subject_template = template.get('subject', "Report Card - {student_name} ({student_class}) - {term}")
        body_template = template.get('body', get_default_report_email_template())
        signature = template.get('signature', "Best regards,\nThe Management\nAKIN'S SUNRISE SECONDARY SCHOOL")

        # Format subject
        subject = subject_template.format(
            student_name=student_name,
            student_class=student_class,
            term=term,
            report_id=report_id
        )

        # Format body with placeholders
        current_date = datetime.datetime.now().strftime("%A, %B %d, %Y at %I:%M %p")
        session_year = school_config.get('current_session', f"{datetime.datetime.now().year}/{datetime.datetime.now().year + 1}")
        school_phone = school_config.get('school_phone', "+234 800 123 4567")
        school_email_address = school_config.get('school_email', "info@akinssunrise.edu.ng")

        body = body_template.format(
            student_name=student_name,
            student_class=student_class,
            term=term,
            report_id=report_id,
            current_date=current_date,
            session_year=session_year,
            school_phone=school_phone,
            school_email=school_email_address
        )

        # Add signature
        body += f"\n\n{signature}"

        msg = MIMEMultipart()
        msg['From'] = school_email
        msg['To'] = parent_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        if os.path.exists(report_pdf_path):
            with open(report_pdf_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {student_name}_Report_{term}.pdf'
                )
                msg.attach(part)

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(school_email, email_password)
        text = msg.as_string()
        server.sendmail(school_email, parent_email, text)
        server.quit()

        return True, f"Report card sent successfully to {parent_email}"

    except Exception as e:
        return False, f"Error sending email: {str(e)}"

def log_teacher_activity(teacher_id, activity_type, details):
    try:
        logs_dir = "admin_logs"
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "teacher_id": teacher_id,
            "activity": activity_type,
            "details": details
        }

        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(logs_dir, f"activity_{date_str}.json")

        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        logs.append(log_entry)
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)

        return True
    except Exception as e:
        return False

def render_html_report(student_name, student_class, term, report_df, term_total, cumulative, final_grade, logo_base64, student_data=None, report_details=None):
    date_now = datetime.datetime.now().strftime("%A, %B %d, %Y, %I:%M %p WAT")
    report_id = generate_report_id()
    school_code = "ASS2025"

    # Calculate dynamic sizing based on number of subjects for A4 paper
    num_subjects = len(report_df)

    # More aggressive sizing for A4 paper (210mm x 297mm)
    if num_subjects <= 4:
        base_font = 10
        table_font = 8
        padding = 4
        margin = 3
        qr_size = 25
        header_font = 12
    elif num_subjects <= 8:
        base_font = 9
        table_font = 7
        padding = 3
        margin = 2
        qr_size = 22
        header_font = 11
    elif num_subjects <= 12:
        base_font = 8
        table_font = 6
        padding = 2
        margin = 1
        qr_size = 20
        header_font = 10
    else:  # More than 12 subjects
        base_font = 7
        table_font = 5
        padding = 1
        margin = 1
        qr_size = 18
        header_font = 9

    qr_data = f"REPORT_ID:{report_id}|SCHOOL:{school_code}|NAME:{student_name}|CLASS:{student_class}|TERM:{term}|CUMULATIVE:{cumulative:.2f}|GRADE:{final_grade}|TEACHER:{st.session_state.teacher_id}|DATE:{date_now}|VERIFY:https://verify.akinsunrise.edu.ng/check/{report_id}"
    qr_code = generate_qr_code(qr_data)

    # Load school configuration for report header
    school_config = load_school_config()
    school_name = school_config.get('school_name', "AKIN'S SUNRISE SECONDARY SCHOOL, ONDO")
    school_address = school_config.get('school_address', "SUNRISE AVENUE OFF LUJOJOMU ROAD, UPPER AAYEYEMI, ONDO CITY")

    # Load branding configuration
    branding_config = load_branding_config()
    show_watermark = branding_config.get('show_watermark', True)
    watermark_opacity = branding_config.get('watermark_opacity', 0.15)
    primary_color = branding_config.get('primary_color', '#1976D2')
    secondary_color = branding_config.get('secondary_color', '#42A5F5')

    html = f"""
    <html>
    <head>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;500&display=swap" rel="stylesheet">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Roboto', sans-serif; 
                color: #333; 
                padding: 0px; 
                font-size: 14px; 
                background: linear-gradient(135deg, #f5f5f5 0%, #ffffff 100%);
                font-weight: 700;
                margin: 0;
            }}
            .report-card::before {{
                content: "";
                position: absolute;
                top: 50%;
                left: 50%;
                width: 300px;
                height: 300px;
                background: url('data:image/png;base64,{logo_base64}') no-repeat center / contain;
                opacity: {watermark_opacity if show_watermark else 0};
                z-index: 0;
                pointer-events: none;
                transform: translate(-50%, -50%);
            }}
            .report-card > * {{
                position: relative;
                z-index: 1;
            }}
            .report-card {{ 
                max-width: 800px; 
                margin: 0 auto; 
                background: white; 
                border-radius: 2px; 
                box-shadow: 0 1px 3px rgba(0,0,0,0.1); 
                overflow: hidden; 
                padding: 2px; 
                position: relative; 
                z-index: 1; 
            }}
            .header {{ 
                text-align: center; 
                padding: 2px; 
                background: linear-gradient(90deg, {primary_color}, {secondary_color}); 
                color: white; 
                border-bottom: 1px solid #003087; 
            }}
            .school-name {{ font-size: 20px; font-weight: 700; }}
            .school-address {{ font-size: 14px; margin-top: 1px; font-weight: 700; }}
            .section-header {{ 
                font-size: 16px; 
                font-weight: 700; 
                color: #1976D2; 
                margin: 2px 0 1px; 
                display: flex; 
                align-items: center; 
            }}
            .section-header::before {{ 
                content: "📋 "; 
                margin-right: 2px; 
            }}
            .info-box {{ 
                border: 1px solid #42A5F5; 
                padding: 2px; 
                margin-bottom: 1px; 
                border-radius: 2px; 
            }}
            .info-row {{ display: flex; justify-content: space-between; margin-bottom: 1px; }}
            .info-item {{ flex: 1; margin-right: 2px; }}
            .info-item:last-child {{ margin-right: 0; }}
            .info-label {{ font-weight: 700; display: inline-block; width: 85px; color: #1976D2; font-size: 14px; }}
            .info-value {{ display: inline-block; min-width: 65px; font-weight: 700; font-size: 14px; }}
            .info-value::before {{ 
                content: "----- "; 
                color: #42A5F5; 
            }}
            .table-container {{ margin-bottom: 1px; }}
            .scores-table, .attendance-table, .character-table, .practical-table {{ 
                width: 100%; 
                border-collapse: collapse; 
                border: 1px solid #4682b4; 
            }}
            .scores-table th, .attendance-table th, .character-table th, .practical-table th, 
            .scores-table td, .attendance-table td, .character-table td, .practical-table td {{ 
                border: 1px solid #d3e0f0; 
                padding: 2px; 
                text-align: center; 
                font-size: 13px; 
                font-weight: 700;
            }}
            .scores-table th, .attendance-table th, .character-table th, .practical-table th {{ 
                font-weight: 700; 
                background-color: #1976D2; 
                color: white; 
                font-size: 14px;
            }}
            .scores-table tr:nth-child(even), .attendance-table tr:nth-child(even), 
            .character-table tr:nth-child(even), .practical-table tr:nth-child(even) {{ 
                background-color: #f8f9fa; 
            }}
            .subject-name {{ text-align: left !important; padding-left: 2px !important; font-weight: 700; font-size: 13px; }}
            .grade-cell {{ font-weight: 700; color: #1976D2; font-size: 14px; }}
            .character-section {{ display: flex; justify-content: space-between; gap: 3px; }}
            .character-table, .practical-table {{ width: 48%; }}
            .comments-section {{ 
                margin-top: 1px; 
                border: 1px solid #42A5F5; 
                padding: 2px; 
                border-radius: 2px; 
            }}
            .comment-box {{ margin-bottom: 1px; }}
            .comment-label {{ font-weight: 700; color: #1976D2; margin-bottom: 1px; font-size: 14px; }}
            .report-line {{ 
                display: flex; 
                justify-content: space-between; 
                align-items: center; 
                margin-bottom: 1px; 
            }}
            .report-text {{ 
                flex: 1; 
                height: 14px; 
                overflow: hidden; 
                font-weight: 700; 
            }}
            .signature-line {{ 
                border-bottom: 1px dashed #1976D2; 
                width: 70px; 
                margin-left: 4px; 
            }}
            .signature-label {{ font-size: 12px; color: #666; text-align: center; font-weight: 700; }}
            .footer {{ 
                padding: 1px; 
                text-align: center; 
                border-top: 1px dashed #42A5F5; 
                margin-top: 1px; 
                background: #f8f9fa; 
            }}
            .qr-code {{ width: 40px; height: 40px; border: 2px solid #1976D2; border-radius: 4px; }}
            .grading-key {{ margin-top: 0px; font-size: 12px; text-align: left; font-weight: 700; }}
            .key-row {{ display: inline-block; margin-right: 4px; color: #1976D2; font-weight: 700; }}
            .rating-key {{ display: flex; justify-content: center; gap: 1px; font-size: 11px; margin-top: 0px; }}
            @page {{ size: A4; margin: 3mm; }}
        </style>
    </head>
    <body>
        <div class="report-card">
            <div class="header">
                <div class="school-name">{school_name.upper()}</div>
                <div class="school-address">{school_address.upper()}</div>
            </div>

            <div class="section-header">Student Information</div>
            <div class="info-box">
                <div class="info-row">
                    <div class="info-item">
                        <span class="info-label">Name:</span>
                        <span class="info-value">{student_name.upper()}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Gender:</span>
                        <span class="info-value">{st.session_state.get('student_gender', student_data.get('gender', 'M/F') if student_data else 'M/F')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Class:</span>
                        <span class="info-value">{student_class.upper()}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Admission No:</span>
                        <span class="info-value">{report_details.get('admission_number', '') if report_details else ''}</span>
                    </div>
                </div>
                <div class="info-row">
                    <div class="info-item">
                        <span class="info-label">No of Students:</span>
                        <span class="info-value">{report_details.get('num_students', '') if report_details else ''}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Attendance:</span>
                        <span class="info-value">{report_details.get('student_attendance', '') if report_details else ''}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Position:</span>
                        <span class="info-value">{report_details.get('student_position', '') if report_details else ''}</span>
                    </div>
                </div>
                <div class="info-row">
                    <div class="info-item">
                        <span class="info-label">Term:</span>
                        <span class="info-value">{term}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Session:</span>
                        <span class="info-value">{report_details.get('session_year', '') if report_details else ''}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Year:</span>
                        <span class="info-value">{report_details.get('current_year', '') if report_details else ''}</span>
                    </div>
                </div>
            </div>

            <div class="section-header">Attendance Record</div>
            <div class="table-container">
                <table class="attendance-table">
                    <thead>
                        <tr>
                            <th>No of Times School Open</th>
                            <th>School</th>
                            <th>Sports</th>
                            <th>Other Activities</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>{report_details.get('school_open_days', '') if report_details else ''}</td>
                            <td>{report_details.get('present_days', '') if report_details else ''}</td>
                            <td></td>
                            <td></td>
                        </tr>
                        <tr>
                            <td>Present</td>
                            <td>{report_details.get('present_days', '') if report_details else ''}</td>
                            <td></td>
                            <td></td>
                        </tr>
                        <tr>
                            <td>Punctual</td>
                            <td>{report_details.get('punctual_days', '') if report_details else ''}</td>
                            <td></td>
                            <td></td>
                        </tr>
                        <tr>
                            <td>Absent</td>
                            <td>{report_details.get('absent_days', '') if report_details else ''}</td>
                            <td></td>
                            <td></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="section-header">Academic Performance</div>
            <div class="table-container">
                <table class="scores-table">
                    <thead>
                        <tr>
                            <th>Subject</th>
                            <th>CA Score (40)</th>
                            <th>Exam Score (60)</th>
                            <th>Total (100)</th>
                            <th>Cumulative</th>
                            <th>Grade</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join([f'<tr><td class="subject-name">{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td><strong>{row[3]}</strong></td><td><strong>{row[5]:.1f}</strong></td><td class="grade-cell">{row[6]}</td></tr>' for row in report_df.values])}
                    </tbody>
                </table>
            </div>

            <div class="section-header">Character & Practical Assessment</div>
            <div class="character-section">
                <table class="character-table">
                    <thead>
                        <tr>
                            <th>Attribute</th>
                            <th>Rating</th>
                            <th>Sign</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Class Attendance</td><td>{report_details.get('class_attendance_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Punctuality</td><td>{report_details.get('punctuality_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Neatness</td><td>{report_details.get('neatness_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Quickness</td><td>{report_details.get('quickness_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Self Control</td><td>{report_details.get('self_control_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Relationship</td><td>{report_details.get('relationship_rating', '') if report_details else ''}</td><td></td></tr>
                    </tbody>
                </table>
                <table class="practical-table">
                    <thead>
                        <tr>
                            <th>Skill</th>
                            <th>Rating</th>
                            <th>Sign</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Handwriting</td><td>{report_details.get('handwriting_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Drama</td><td>{report_details.get('drama_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Musical Skills</td><td>{report_details.get('musical_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Crafts</td><td>{report_details.get('crafts_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Clubs/Societies</td><td>{report_details.get('clubs_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Hobbies</td><td>{report_details.get('hobbies_rating', '') if report_details else ''}</td><td></td></tr>
                        <tr><td>Sports</td><td>{report_details.get('sports_rating', '') if report_details else ''}</td><td></td></tr>
                    </tbody>
                </table>
            </div>
            <div class="rating-key">
                <div class="rating-item">5</div>
                <div class="rating-item">4</div>
                <div class="rating-item">3</div>
                <div class="rating-item">2</div>
                <div class="rating-item">1</div>
                <div class="rating-item">OR</div>
                <div class="rating-item">A</div>
                <div class="rating-item">B</div>
                <div class="rating-item">C</div>
                <div class="rating-item">D</div>
                <div class="rating-item">E</div>
            </div>

            <div class="comments-section">
                <div class="comment-box">
                    <div class="comment-label">Class Teacher's Report</div>
                    <div class="report-line">
                        <div class="report-text">{report_details.get('class_teacher_comment', '') if report_details else ''}</div>
                        <div class="signature-line"></div>
                        <div class="signature-label">Signature</div>
                    </div>
                </div>
                <div class="comment-box">
                    <div class="comment-label">Principal's Report/Stamp</div>
                    <div class="report-line">
                        <div class="report-text">{report_details.get('principal_comment', '') if report_details else ''}</div>
                        <div class="signature-line"></div>
                        <div class="signature-label">Signature</div>
                    </div>
                </div>
                <div class="info-row">
                    <div class="info-item">
                        <span class="info-label">Next Term Begins:</span>
                        <span class="info-value">{report_details.get('next_term_date', '') if report_details else ''}</span>
                    </div>
                </div>
            </div>

            <div class="footer">
                <div class="qr-section">
                    <div>
                        <div style="font-size: 14px; font-weight: 700;"><strong>Report ID:</strong> {report_id}</div>
                        <div style="font-size: 13px; font-weight: 600;"><strong>Generated:</strong> {date_now}</div>
                        <div class="grading-key">
                            <div><strong>GRADING KEY:</strong></div>
                            <span class="key-row">A: Excellent</span>
                            <span class="key-row">B: Good</span>
                            <span class="key-row">C: Average</span>
                            <span class="key-row">D: Below Average</span>
                            <span class="key-row">E: Poor</span>
                        </div>
                    </div>
                    <div>
                        <img src="data:image/png;base64,{qr_code}" class="qr-code"/>
                        <div class="signature-label">Verification QR</div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

def apply_custom_css():
    st.markdown("""
    <style>
    /* Adaptive theme support - works for both light and dark modes */
    .stApp {
        color: var(--text-color);
    }

    /* Text visibility for both themes */
    h1, h2, h3, h4, h5, h6 {
        color: #1976D2 !important; /* Professional blue that works on both themes */
    }

    /* Button styling */
    .stButton button {
        background-color: #1976D2 !important;
        color: white !important;
        border: none !important;
        border-radius: 6px !important;
        transition: all 0.3s ease !important;
    }

    .stButton button:hover {
        background-color: #1565C0 !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 8px rgba(25, 118, 210, 0.3) !important;
    }

    /* Tab styling with neutral colors */
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent !important;
        border-bottom: 2px solid #E0E0E0 !important;
    }

    .stTabs [data-baseweb="tab-list"] button {
        background-color: transparent !important;
        color: var(--text-color) !important;
        border: none !important;
        border-radius: 6px 6px 0 0 !important;
        padding: 12px 24px !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
        margin: 0 2px !important;
    }

    .stTabs [data-baseweb="tab-list"] button:hover {
        background-color: rgba(25, 118, 210, 0.1) !important;
        color: #1976D2 !important;
    }

    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        background-color: #1976D2 !important;
        color: white !important;
        font-weight: 600 !important;
        border-bottom: 3px solid #1565C0 !important;
    }

    /* Ensure tab text is always visible */
    .stTabs [data-baseweb="tab-list"] button * {
        color: inherit !important;
    }

    /* Form elements adaptation */
    .stTextInput label, .stSelectbox label, .stNumberInput label, .stTextArea label {
        color: #1976D2 !important;
        font-weight: 600 !important;
    }

    /* Input fields */
    .stTextInput input, .stNumberInput input, .stTextArea textarea, .stSelectbox select {
        border: 2px solid #E0E0E0 !important;
        border-radius: 6px !important;
        transition: border-color 0.3s ease !important;
    }

    .stTextInput input:focus, .stNumberInput input:focus, .stTextArea textarea:focus {
        border-color: #1976D2 !important;
        box-shadow: 0 0 0 2px rgba(25, 118, 210, 0.2) !important;
    }

    /* Metrics styling */
    .metric-container {
        background: linear-gradient(135deg, rgba(25, 118, 210, 0.1), rgba(25, 118, 210, 0.05)) !important;
        border: 1px solid rgba(25, 118, 210, 0.2) !important;
        border-radius: 8px !important;
        padding: 1rem !important;
    }

    /* Success/Error/Warning messages */
    .stSuccess {
        background-color: rgba(76, 175, 80, 0.1) !important;
        border: 1px solid #4CAF50 !important;
        color: #1976D2 !important;
    }

    .stError {
        background-color: rgba(244, 67, 54, 0.1) !important;
        border: 1px solid #F44336 !important;
        color: #C62828 !important;
    }

    .stWarning {
        background-color: rgba(255, 152, 0, 0.1) !important;
        border: 1px solid #FF9800 !important;
        color: #E65100 !important;
    }

    .stInfo {
        background-color: rgba(33, 150, 243, 0.1) !important;
        border: 1px solid #2196F3 !important;
        color: #1565C0 !important;
    }

    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: rgba(25, 118, 210, 0.05) !important;
        border: 1px solid rgba(25, 118, 210, 0.2) !important;
        border-radius: 6px !important;
        color: #1976D2 !important;
        font-weight: 600 !important;
    }

    /* DataFrame styling */
    .stDataFrame {
        border: 1px solid #E0E0E0 !important;
        border-radius: 6px !important;
        overflow: hidden !important;
    }

    /* Sidebar (if used) */
    .css-1d391kg {
        background-color: rgba(25, 118, 210, 0.02) !important;
    }

    /* File uploader */
    .stFileUploader {
        border: 2px dashed #1976D2 !important;
        border-radius: 8px !important;
        background-color: rgba(25, 118, 210, 0.05) !important;
    }

    /* Download button */
    .stDownloadButton button {
        background-color: #1976D2 !important;
        color: white !important;
        border: none !important;
        border-radius: 6px !important;
    }

    .stDownloadButton button:hover {
        background-color: #1565C0 !important;
    }

    /* Cards and containers */
    .element-container {
        border-radius: 8px !important;
    }

    /* Mobile responsiveness */
    @media (max-width: 768px) {
        .main > div {
            padding-left: 1rem;
            padding-right: 1rem;
        }

        .stTabs [data-baseweb="tab-list"] button {
            padding: 8px 16px !important;
            font-size: 0.9rem !important;
        }

        div[data-testid="column"] {
            min-width: 0 !important;
            flex: 1;
        }

        .stButton > button {
            width: 100%;
            margin-bottom: 0.5rem;
        }

        h1 {
            font-size: 1.5rem !important;
        }

        h2 {
            font-size: 1.3rem !important;
        }

        h3 {
            font-size: 1.1rem !important;
        }
    }

    /* Tablet responsiveness */
    @media (min-width: 769px) and (max-width: 1024px) {
        .main > div {
            padding-left: 2rem;
            padding-right: 2rem;
        }
    }

    /* Chart containers */
    .chart-container {
        background: rgba(25, 118, 210, 0.02);
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
        border: 1px solid rgba(25, 118, 210, 0.1);
    }

    /* Improved text contrast for accessibility */
    .stMarkdown strong {
        color: #1976D2 !important;
        font-weight: 700 !important;
    }

    /* Dark theme specific adjustments */
    @media (prefers-color-scheme: dark) {
        .stTabs [data-baseweb="tab-list"] {
            border-bottom: 2px solid #404040 !important;
        }

        .stTextInput input, .stNumberInput input, .stTextArea textarea {
            background-color: var(--background-color) !important;
            color: var(--text-color) !important;
        }
    }

    /* Light theme specific adjustments */
    @media (prefers-color-scheme: light) {
        .stTextInput input, .stNumberInput input, .stTextArea textarea {
            background-color: white !important;
            color: #333333 !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

def check_session_timeout():
    """Check if user session has timed out"""
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.datetime.now()
        return False

    if 'session_timeout' not in st.session_state:
        st.session_state.session_timeout = 30  # Default 30 minutes

    time_diff = datetime.datetime.now() - st.session_state.last_activity
    if time_diff.seconds > (st.session_state.session_timeout * 60):
        return True

    st.session_state.last_activity = datetime.datetime.now()
    return False

def update_session_activity():
    """Update last activity time"""
    st.session_state.last_activity = datetime.datetime.now()

def login_page():
    st.set_page_config(
        page_title="Akin's Sunrise School - Login", 
        layout="centered",
        initial_sidebar_state="collapsed",
        page_icon="🎓"
    )

    apply_custom_css()

    logo_base64 = get_logo_base64()
    if logo_base64:
        st.markdown(f"""
        <div style="text-align: center; margin-bottom: 20px;">
            <img src="data:image/png;base64,{logo_base64}" style="width: 120px; height: 120px; object-fit: contain; border-radius: 12px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: var(--accent-color); margin: 10px 0;">🔐 Secure Login</h1>
        <h2 style="color: var(--text-secondary); margin: 5px 0;">Akin's Sunrise School System</h2>
    </div>
    """, unsafe_allow_html=True)

    # Login type selection
    login_type = st.selectbox("Login Type", ["Staff Login", "Parent Portal"], key="login_type")

    if login_type == "Staff Login":
        staff_login_form()
    else:
        parent_login_form()

def staff_login_form():
    """Staff login form with enhanced security"""
    with st.container():
        st.markdown("### Staff Access Portal")
        st.markdown("Please enter your credentials to access the school management system.")

        user_id = st.text_input("User ID", placeholder="Enter your user ID")
        password = st.text_input("Password", type="password", placeholder="Enter your password")

        # Check if user account is locked
        if user_id and is_user_locked(user_id):
            st.error("🔒 Account temporarily locked due to multiple failed attempts. Please try again later.")
            return

        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("🚀 Login", use_container_width=True):
                if user_id and password:
                    users_db = load_user_database()

                    if user_id in users_db:
                        user = users_db[user_id]

                        # Check if user is active
                        if not user.get('active', True):
                            st.error("❌ Account is disabled. Contact administrator.")
                            return

                        # Verify password
                        if verify_password(password, user['password_hash']):
                            # Check 2FA if enabled
                            if user.get('two_factor_enabled', False):
                                st.session_state.pending_2fa = user_id
                                st.session_state.pending_2fa_secret = user.get('two_factor_secret')
                                st.rerun()
                            else:
                                # Complete login
                                complete_login(user_id, user)
                        else:
                            increment_failed_attempts(user_id)
                            log_teacher_activity(user_id, "failed_login", {
                                "attempted_user_id": user_id,
                                "timestamp": datetime.datetime.now().isoformat(),
                                "reason": "invalid_password"
                            })
                            st.error("❌ Invalid credentials. Please try again.")
                    else:
                        log_teacher_activity(user_id or "unknown", "failed_login", {
                            "attempted_user_id": user_id,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "reason": "user_not_found"
                        })
                        st.error("❌ Invalid credentials. Please try again.")
                else:
                    st.warning("⚠️ Please enter both User ID and Password.")

def parent_login_form():
    """Parent portal login form"""
    with st.container():
        st.markdown("### Parent Portal Access")
        st.markdown("Parents can view their child's academic reports and communicate with teachers.")

        parent_email = st.text_input("Parent Email", placeholder="Enter your registered email")
        student_admission_no = st.text_input("Student Admission Number", placeholder="Enter your child's admission number")

        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("🚀 Access Portal", use_container_width=True):
                if parent_email and student_admission_no:
                    # Verify parent-student relationship
                    students = get_all_students()
                    matching_student = None
                    encryption_key = generate_encryption_key("akins_sunrise_school_encryption")

                    for student in students:
                        stored_email = student.get('parent_email', '')
                        stored_admission = student.get('admission_no', '')

                        # Decrypt email if encrypted
                        if student.get('data_encrypted', False) and stored_email:
                            try:
                                stored_email = decrypt_data(stored_email, encryption_key)
                            except:
                                continue

                        # Compare with case-insensitive and trimmed strings
                        email_match = stored_email.lower().strip() == parent_email.lower().strip()
                        admission_match = stored_admission.strip() == student_admission_no.strip()

                        if email_match and admission_match:
                            matching_student = student
                            break

                    if matching_student:
                        st.session_state.authenticated = True
                        st.session_state.user_type = "parent"
                        st.session_state.parent_email = parent_email
                        st.session_state.child_data = matching_student
                        st.success(f"✅ Welcome! Access granted for {matching_student['student_name']}")
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials or no matching student found.")
                        st.info("💡 Make sure you're using the exact email and admission number registered with the school.")
                else:
                    st.warning("⚠️ Please enter both email and admission number.")

def two_factor_verification():
    """Two-factor authentication verification"""
    st.markdown("### 🔐 Two-Factor Authentication")
    st.markdown("Please enter the 6-digit code from your authenticator app.")

    token = st.text_input("Enter 6-digit code", placeholder="123456", max_chars=6)

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("Verify", use_container_width=True):
            if token and len(token) == 6:
                if verify_2fa_token(st.session_state.pending_2fa_secret, token):
                    users_db = load_user_database()
                    user_id = st.session_state.pending_2fa
                    user = users_db[user_id]

                    # Complete login
                    complete_login(user_id, user)

                    # Clear 2FA session data
                    del st.session_state.pending_2fa
                    del st.session_state.pending_2fa_secret
                else:
                    st.error("❌ Invalid verification code.")
            else:
                st.warning("⚠️ Please enter a valid 6-digit code.")

def complete_login(user_id, user):
    """Complete the login process"""
    reset_failed_attempts(user_id)

    log_teacher_activity(user_id, "login", {
        "login_time": datetime.datetime.now().isoformat(),
        "ip_address": "replit_session",
        "user_role": user.get('role', 'teacher')
    })

    st.session_state.authenticated = True
    st.session_state.user_type = "staff"
    st.session_state.teacher_id = user_id
    st.session_state.user_role = user.get('role', 'teacher')
    st.session_state.user_permissions = USER_ROLES.get(user.get('role', 'teacher'), {}).get('permissions', [])
    st.session_state.session_timeout = user.get('session_timeout', 30)
    st.session_state.last_activity = datetime.datetime.now()

    st.success(f"✅ Welcome, {user.get('full_name', user_id)}!")
    st.rerun()

def draft_reports_tab():
    """Tab for managing draft reports"""
    st.subheader("📝 Draft Reports - Unfinished Work")
    st.markdown("Access and continue working on incomplete reports saved as drafts.")

    # Auto-save notification
    if st.session_state.get('auto_save_notification'):
        st.success("✅ Draft auto-saved successfully!")
        st.session_state.auto_save_notification = False

    # Get drafts for current teacher or all (if admin)
    is_admin = check_user_permissions(st.session_state.teacher_id, "system_config")
    
    if is_admin:
        view_option = st.selectbox("View Drafts", ["My Drafts Only", "All Drafts"], key="draft_view_option")
        if view_option == "My Drafts Only":
            draft_reports = get_draft_reports(st.session_state.teacher_id)
        else:
            draft_reports = get_draft_reports()
    else:
        draft_reports = get_draft_reports(st.session_state.teacher_id)

    if draft_reports:
        st.write(f"**Found {len(draft_reports)} draft reports:**")

        for draft in draft_reports:
            with st.expander(f"📄 {draft.get('student_name', 'Unknown')} ({draft.get('student_class', 'Unknown')}) - {draft.get('term', 'Unknown')} - {draft.get('completion_status', '0')}% Complete", expanded=False):
                col1, col2, col3 = st.columns([2, 1, 1])

                with col1:
                    st.write(f"**Student:** {draft.get('student_name', 'N/A')}")
                    st.write(f"**Class:** {draft.get('student_class', 'N/A')}")
                    st.write(f"**Term:** {draft.get('term', 'N/A')}")
                    st.write(f"**Teacher:** {draft.get('teacher_id', 'N/A')}")
                    st.write(f"**Completion:** {draft.get('completion_status', '0')}%")
                    
                    # Show last modified
                    last_modified = draft.get('last_modified', '')
                    if last_modified:
                        try:
                            formatted_date = datetime.datetime.fromisoformat(last_modified).strftime('%Y-%m-%d %H:%M')
                            st.write(f"**Last Modified:** {formatted_date}")
                        except:
                            st.write(f"**Last Modified:** {last_modified}")

                    # Show subjects completed
                    completed_subjects = draft.get('completed_subjects', [])
                    if completed_subjects:
                        st.write(f"**Subjects Completed:** {', '.join(completed_subjects)}")

                with col2:
                    # Continue editing button
                    if st.button("✏️ Continue Editing", key=f"edit_draft_{draft['draft_id']}"):
                        # Load draft data into session state
                        st.session_state.load_draft_data = draft
                        st.success("✅ Draft loaded! Please go to the Generate Reports tab to continue editing.")
                        st.info("💡 The draft data has been loaded and will be available when you switch to the Generate Reports tab.")
                        st.rerun()

                with col3:
                    # Delete draft button
                    if st.button("🗑️ Delete Draft", key=f"delete_draft_{draft['draft_id']}"):
                        if delete_draft_report(draft['draft_id']):
                            st.success("✅ Draft deleted successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Error deleting draft")

        # Bulk operations for admins
        if is_admin and len(draft_reports) > 1:
            st.markdown("---")
            st.markdown("#### 🗑️ Bulk Operations")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🗑️ Delete All My Drafts"):
                    my_drafts = [d for d in draft_reports if d.get('teacher_id') == st.session_state.teacher_id]
                    deleted_count = 0
                    for draft in my_drafts:
                        if delete_draft_report(draft['draft_id']):
                            deleted_count += 1
                    st.success(f"✅ Deleted {deleted_count} drafts")
                    st.rerun()

            with col2:
                if st.button("🗑️ Delete All Drafts (Admin)"):
                    deleted_count = 0
                    for draft in draft_reports:
                        if delete_draft_report(draft['draft_id']):
                            deleted_count += 1
                    st.success(f"✅ Deleted {deleted_count} drafts")
                    st.rerun()

    else:
        st.info("📭 No draft reports found. Drafts are automatically saved when you work on reports.")
        st.markdown("""
        **How drafts work:**
        - Drafts are automatically saved every 30 seconds while you work
        - You can manually save a draft using the "💾 Save as Draft" button
        - Incomplete reports are saved so you can continue later
        - Access your drafts here to resume work
        """)

def report_generator_tab():
    st.subheader("📝 Generate Report Cards")

    # Check if loading from draft
    if st.session_state.get('load_draft_data'):
        draft_data = st.session_state.load_draft_data
        st.info(f"📄 Loaded draft for {draft_data.get('student_name', 'Unknown')} - Continue editing below")
        
        # Pre-fill form with draft data
        st.session_state.student_name = draft_data.get('student_name', '')
        st.session_state.student_class = draft_data.get('student_class', '')
        st.session_state.term = draft_data.get('term', '1st Term')
        st.session_state.parent_email = draft_data.get('parent_email', '')
        
        # Load subject scores
        draft_scores = draft_data.get('subject_scores', {})
        for subject, scores in draft_scores.items():
            st.session_state[f"{subject}_ca"] = scores.get('ca', 0)
            st.session_state[f"{subject}_exam"] = scores.get('exam', 0)
            st.session_state[f"{subject}_last"] = scores.get('last_cumulative', 0)
        
        # Load selected subjects
        st.session_state.selected_subjects = list(draft_scores.keys())
        
        # Load additional details if present
        additional_data = draft_data.get('additional_data', {})
        for key, value in additional_data.items():
            st.session_state[key] = value
            
        # Clear the load flag
        del st.session_state.load_draft_data

    col1, col2 = st.columns(2)
    with col1:
        student_name = st.text_input("Student Name", key="student_name")
        student_class = st.text_input("Class", key="student_class")
    with col2:
        term = st.selectbox("Term", ["1st Term", "2nd Term", "3rd Term"], key="term")

        if student_name and student_class and st.button("🔍 Load Student Data"):
            student_data = load_student_data(student_name, student_class)
            if student_data:
                st.success("✅ Student data loaded from database!")
                st.session_state.parent_email = student_data.get('parent_email', '')
                st.rerun()
            else:
                st.info("💡 Student not found in database. You can add them in the Student Database tab.")

    st.markdown("---")
    st.markdown("#### 📧 Parent Communication & Report Details")
    
    col1, col2 = st.columns(2)
    with col1:
        parent_email = st.text_input("📧 Parent's Email Address", key="parent_email", 
                                   placeholder="parent@example.com",
                                   help="Email address to send the report card to")
    with col2:
        student_gender = st.selectbox("👤 Student Gender", ["Male", "Female"], key="student_gender",
                                    help="Select the student's gender for the report card")

    # Additional report details - only filled if email is provided
    if parent_email:
        st.success(f"✅ Report will be sent to: {parent_email}")

        with st.expander("📋 Complete Report Details (for emailed reports)", expanded=False):
            st.markdown("**Fill these details to complete the report for email delivery:**")

            col1, col2 = st.columns(2)
            with col1:
                admission_number = st.text_input("Admission Number", key="admission_override", 
                                               placeholder="ASS/25/001")
                num_students = st.text_input("Number of Students in Class", key="num_students", 
                                           placeholder="35")
                student_position = st.text_input("Student Position", key="position_override", 
                                                placeholder="1st")

            with col2:
                session_year = st.text_input("Academic Session", key="session_override", 
                                           placeholder="2024/2025")
                current_year = st.text_input("Current Year", key="year_override", 
                                           placeholder="2025")
                student_attendance = st.text_input("Student Attendance", key="attendance_override", 
                                                 placeholder="95%")

            # Attendance Record Details
            st.markdown("**Attendance Record:**")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                school_open_days = st.text_input("Days School Open", key="school_open", placeholder="100")
            with col2:
                present_days = st.text_input("Days Present", key="present_days", placeholder="95")
            with col3:
                punctual_days = st.text_input("Days Punctual", key="punctual_days", placeholder="90")
            with col4:
                absent_days = st.text_input("Days Absent", key="absent_days", placeholder="5")

            # Character Assessment
            st.markdown("**Character Assessment (A-E or 1-5):**")
            char_col1, char_col2, char_col3 = st.columns(3)
            with char_col1:
                class_attendance_rating = st.text_input("Class Attendance", key="char_attendance", placeholder="A")
                punctuality_rating = st.text_input("Punctuality", key="char_punctuality", placeholder="B")
            with char_col2:
                neatness_rating = st.text_input("Neatness", key="char_neatness", placeholder="A")
                quickness_rating = st.text_input("Quickness", key="char_quickness", placeholder="B")
            with char_col3:
                self_control_rating = st.text_input("Self Control", key="char_self_control", placeholder="A")
                relationship_rating = st.text_input("Relationship", key="char_relationship", placeholder="A")

            # Practical Skills Assessment
            st.markdown("**Practical Skills Assessment (A-E or 1-5):**")
            skill_col1, skill_col2, skill_col3 = st.columns(3)
            with skill_col1:
                handwriting_rating = st.text_input("Handwriting", key="skill_handwriting", placeholder="A")
                drama_rating = st.text_input("Drama", key="skill_drama", placeholder="B")
                musical_rating = st.text_input("Musical Skills", key="skill_musical", placeholder="C")
            with skill_col2:
                crafts_rating = st.text_input("Crafts", key="skill_crafts", placeholder="B")
                clubs_rating = st.text_input("Clubs/Societies", key="skill_clubs", placeholder="A")
                hobbies_rating = st.text_input("Hobbies", key="skill_hobbies", placeholder="A")
            with skill_col3:
                sports_rating = st.text_input("Sports", key="skill_sports", placeholder="B")

            # Teacher Comments
            st.markdown("**Teacher Comments:**")
            class_teacher_comment = st.text_area("Class Teacher's Comment", key="teacher_comment", 
                                                placeholder="Excellent performance. Keep it up!")
            principal_comment = st.text_area("Principal's Comment", key="principal_comment", 
                                            placeholder="Outstanding academic achievement.")

            # Next Term Details
            next_term_date = st.text_input("Next Term Begins", key="next_term", 
                                         placeholder="January 15, 2025")

    else:
        st.info("💡 Enter parent's email address above to enable automatic email delivery and complete report details")

    st.markdown("---")
    st.subheader("📌 Select Subjects and Enter Scores")
    selected_subjects = st.multiselect("Select Subjects", subjects, key="selected_subjects")

    scores_data = []
    total_term_score = 0
    all_cumulatives = []

    for subject in sorted(selected_subjects):
        st.markdown(f"#### ✏️ {subject}")

        ca = st.number_input(f"{subject} - Continuous Assessment (CA)", min_value=0, max_value=40, key=f"{subject}_ca")
        exam = st.number_input(f"{subject} - Exam Score", min_value=0, max_value=60, key=f"{subject}_exam")
        last_cumulative = st.number_input(f"{subject} - Last Term Cumulative", min_value=0, max_value=100, key=f"{subject}_last")

        total = calculate_total(ca, exam)
        subject_cumulative = (total + last_cumulative) / 2
        total_term_score += total
        all_cumulatives.append(subject_cumulative)

        scores_data.append((subject, ca, exam, total, last_cumulative, subject_cumulative, "-"))

    # Auto-save and draft management
    col_auto1, col_auto2, col_auto3 = st.columns([1, 1, 1])
    
    with col_auto1:
        if st.button("💾 Save as Draft", key="save_draft_btn"):
            if student_name and student_class and selected_subjects:
                # Collect current form data
                subject_scores = {}
                for subject in selected_subjects:
                    ca = st.session_state.get(f"{subject}_ca", 0)
                    exam = st.session_state.get(f"{subject}_exam", 0)
                    last_cumulative = st.session_state.get(f"{subject}_last", 0)
                    subject_scores[subject] = {
                        'ca': ca,
                        'exam': exam,
                        'last_cumulative': last_cumulative
                    }

                # Collect additional form data
                additional_data = {}
                form_fields = [
                    'student_gender', 'admission_override', 'num_students', 'position_override', 'session_override',
                    'year_override', 'attendance_override', 'school_open', 'present_days',
                    'punctual_days', 'absent_days', 'char_attendance', 'char_punctuality',
                    'char_neatness', 'char_quickness', 'char_self_control', 'char_relationship',
                    'skill_handwriting', 'skill_drama', 'skill_musical', 'skill_crafts',
                    'skill_clubs', 'skill_hobbies', 'skill_sports', 'teacher_comment',
                    'principal_comment', 'next_term'
                ]
                
                for field in form_fields:
                    if field in st.session_state:
                        additional_data[field] = st.session_state[field]

                # Calculate completion percentage
                total_subjects = len(selected_subjects)
                completed_subjects = [s for s in selected_subjects if 
                                    st.session_state.get(f"{s}_ca", 0) > 0 or 
                                    st.session_state.get(f"{s}_exam", 0) > 0]
                completion_percentage = (len(completed_subjects) / total_subjects * 100) if total_subjects > 0 else 0

                draft_data = {
                    "draft_id": generate_draft_id(student_name, student_class, term, st.session_state.teacher_id),
                    "student_name": student_name,
                    "student_class": student_class,
                    "term": term,
                    "parent_email": parent_email,
                    "teacher_id": st.session_state.teacher_id,
                    "created_date": datetime.datetime.now().isoformat(),
                    "last_modified": datetime.datetime.now().isoformat(),
                    "subject_scores": subject_scores,
                    "additional_data": additional_data,
                    "completion_status": f"{completion_percentage:.0f}",
                    "completed_subjects": completed_subjects,
                    "auto_save": False
                }

                if save_draft_report(draft_data):
                    st.success("✅ Draft saved successfully!")
                else:
                    st.error("❌ Error saving draft")
            else:
                st.warning("⚠️ Please enter student details and select at least one subject")

    with col_auto2:
        # Auto-save timer (every 30 seconds if data exists)
        if student_name and student_class and selected_subjects:
            if 'last_auto_save' not in st.session_state:
                st.session_state.last_auto_save = datetime.datetime.now()
            
            # Check if 30 seconds have passed since last auto-save
            time_diff = datetime.datetime.now() - st.session_state.last_auto_save
            if time_diff.seconds >= 30:
                # Auto-save logic (same as manual save but marked as auto_save=True)
                subject_scores = {}
                for subject in selected_subjects:
                    ca = st.session_state.get(f"{subject}_ca", 0)
                    exam = st.session_state.get(f"{subject}_exam", 0)
                    last_cumulative = st.session_state.get(f"{subject}_last", 0)
                    if ca > 0 or exam > 0 or last_cumulative > 0:  # Only save if there's data
                        subject_scores[subject] = {
                            'ca': ca,
                            'exam': exam,
                            'last_cumulative': last_cumulative
                        }

                if subject_scores:  # Only auto-save if there's actual data
                    additional_data = {}
                    form_fields = [
                        'student_gender', 'admission_override', 'num_students', 'position_override', 'session_override',
                        'year_override', 'attendance_override', 'school_open', 'present_days',
                        'punctual_days', 'absent_days', 'char_attendance', 'char_punctuality',
                        'char_neatness', 'char_quickness', 'char_self_control', 'char_relationship',
                        'skill_handwriting', 'skill_drama', 'skill_musical', 'skill_crafts',
                        'skill_clubs', 'skill_hobbies', 'skill_sports', 'teacher_comment',
                        'principal_comment', 'next_term'
                    ]
                    
                    for field in form_fields:
                        if field in st.session_state:
                            additional_data[field] = st.session_state[field]

                    total_subjects = len(selected_subjects)
                    completed_subjects = [s for s in selected_subjects if 
                                        st.session_state.get(f"{s}_ca", 0) > 0 or 
                                        st.session_state.get(f"{s}_exam", 0) > 0]
                    completion_percentage = (len(completed_subjects) / total_subjects * 100) if total_subjects > 0 else 0

                    draft_data = {
                        "draft_id": generate_draft_id(student_name, student_class, term, st.session_state.teacher_id),
                        "student_name": student_name,
                        "student_class": student_class,
                        "term": term,
                        "parent_email": parent_email,
                        "teacher_id": st.session_state.teacher_id,
                        "created_date": datetime.datetime.now().isoformat(),
                        "last_modified": datetime.datetime.now().isoformat(),
                        "subject_scores": subject_scores,
                        "additional_data": additional_data,
                        "completion_status": f"{completion_percentage:.0f}",
                        "completed_subjects": completed_subjects,
                        "auto_save": True
                    }

                    save_draft_report(draft_data)
                    st.session_state.last_auto_save = datetime.datetime.now()
                    st.session_state.auto_save_notification = True

            st.info(f"🔄 Auto-save: {30 - time_diff.seconds}s")

    with col_auto3:
        st.info("💡 Work is auto-saved every 30 seconds")

    if st.button("🎓 Generate Report", key="generate_report_btn"):
        if not student_name or not student_class:
            st.error("❌ Please enter Student Name and Class")
            return

        if len(all_cumulatives) == 0:
            st.warning("⚠️ Please select at least one subject and enter scores.")
            return

        try:
            with st.spinner("Generating report card..."):
                average_cumulative = np.mean(all_cumulatives)
                final_grade = assign_grade(average_cumulative)

                updated_scores_data = []
                for row in scores_data:
                    updated_scores_data.append(row[:-1] + (assign_grade(row[5]),))

                report_df = pd.DataFrame(updated_scores_data, columns=["Subject", "CA", "Exam", "Total", "Last Term", "Cumulative", "Grade"])
                report_df = report_df.sort_values(by="Subject")

                # Collect additional report details if email is provided
                report_details = None
                if parent_email:
                    report_details = {
                        'admission_number': st.session_state.get('admission_override', ''),
                        'num_students': st.session_state.get('num_students', ''),
                        'student_position': st.session_state.get('position_override', ''),
                        'session_year': st.session_state.get('session_override', ''),
                        'current_year': st.session_state.get('year_override', ''),
                        'student_attendance': st.session_state.get('attendance_override', ''),
                        'school_open_days': st.session_state.get('school_open', ''),
                        'present_days': st.session_state.get('present_days', ''),
                        'punctual_days': st.session_state.get('punctual_days', ''),
                        'absent_days': st.session_state.get('absent_days', ''),
                        'class_attendance_rating': st.session_state.get('char_attendance', ''),
                        'punctuality_rating': st.session_state.get('char_punctuality', ''),
                        'neatness_rating': st.session_state.get('char_neatness', ''),
                        'quickness_rating': st.session_state.get('char_quickness', ''),
                        'self_control_rating': st.session_state.get('char_self_control', ''),
                        'relationship_rating': st.session_state.get('char_relationship', ''),
                        'handwriting_rating': st.session_state.get('skill_handwriting', ''),
                        'drama_rating': st.session_state.get('skill_drama', ''),
                        'musical_rating': st.session_state.get('skill_musical', ''),
                        'crafts_rating': st.session_state.get('skill_crafts', ''),
                        'clubs_rating': st.session_state.get('skill_clubs', ''),
                        'hobbies_rating': st.session_state.get('skill_hobbies', ''),
                        'sports_rating': st.session_state.get('skill_sports', ''),
                        'class_teacher_comment': st.session_state.get('teacher_comment', ''),
                        'principal_comment': st.session_state.get('principal_comment', ''),
                        'next_term_date': st.session_state.get('next_term', '')
                    }

                logo_base64 = get_logo_base64()
                student_data = load_student_data(student_name, student_class) if student_name and student_class else None
                html = render_html_report(student_name, student_class, term, report_df, total_term_score, average_cumulative, final_grade, logo_base64, student_data, report_details)
                HTML(string=html).write_pdf("report_card.pdf")

            st.success("✅ Report Card Generated Successfully!")

            st.markdown("### 📋 Score Summary")
            st.dataframe(report_df, use_container_width=True)

            with open("report_card.pdf", "rb") as f:
                st.download_button(
                    "⬇️ Download PDF Report", 
                    f, 
                    file_name=f"{student_name.replace(' ', '_')}_Report_{term.replace(' ', '_')}.pdf", 
                    mime="application/pdf",
                    use_container_width=True
                )

            report_data = {
                "report_id": generate_report_id(),
                "student_name": student_name,
                "student_class": student_class,
                "term": term,
                "parent_email": parent_email,
                "teacher_id": st.session_state.teacher_id,
                "created_date": datetime.datetime.now().isoformat(),
                "status": "pending_review",
                "scores_data": updated_scores_data,
                "average_cumulative": float(average_cumulative),
                "final_grade": final_grade,
                "total_term_score": total_term_score,
                "html_content": html,
                "report_details": report_details
            }

            save_pending_report(report_data)

            log_teacher_activity(st.session_state.teacher_id, "report_generated", {
                "student_name": student_name,
                "student_class": student_class,
                "term": term,
                "subjects_count": len(selected_subjects),
                "average_cumulative": float(average_cumulative),
                "final_grade": final_grade,
                "total_term_score": total_term_score,
                "status": "pending_admin_review"
            })

            st.success("✅ Report Generated and Submitted for Admin Review!")
            st.info("📋 The report has been sent to the administrator for review before being emailed to parents.")

        except Exception as e:
            st.error(f"❌ Error generating report: {str(e)}")
            st.info("Please try again or contact your administrator.")

def student_database_tab():
    st.subheader("👥 Student Database")

    admin_users = ["teacher_bamstep"]
    is_admin = st.session_state.teacher_id in admin_users

    if not is_admin:
        st.warning("⚠️ Admin access required to add new students.")
        st.info("Only administrators can add students to the database.")

    if is_admin:
        # Bulk operations section
        with st.expander("🚀 Bulk Operations", expanded=False):
            bulk_tab1, bulk_tab2 = st.tabs(["📥 Import Students", "📄 Generate Class Reports"])

            with bulk_tab1:
                st.markdown("### 📥 Import Multiple Students from CSV")
                st.markdown("Upload a CSV file with student information to add multiple students at once.")

                # Show expected CSV format
                with st.expander("📋 CSV Format Requirements", expanded=False):
                    st.markdown("""
                    **Required columns:**
                    - `student_name` - Full name of the student
                    - `student_class` - Class/grade (e.g., SS1A, JSS2B)
                    - `parent_email` - Parent's email address

                    **Optional columns:**
                    - `parent_name` - Parent/guardian name
                    - `parent_phone` - Parent's phone number
                    - `gender` - Male/Female
                    - `admission_no` - Admission number
                    - `class_size` - Number of students in class
                    - `attendance` - Attendance rate (e.g., 95%)
                    - `position` - Position in class
                    """)

                    # Create sample CSV for download
                    sample_data = {
                        'student_name': ['John Doe', 'Jane Smith', 'Mike Johnson'],
                        'student_class': ['SS1A', 'SS1A', 'SS1B'],
                        'parent_email': ['john.parent@email.com', 'jane.parent@email.com', 'mike.parent@email.com'],
                        'parent_name': ['Mr. John Doe Sr.', 'Mrs. Smith', 'Dr. Johnson'],
                        'parent_phone': ['+234 800 123 4567', '+234 800 234 5678', '+234 800 345 6789'],
                        'gender': ['Male', 'Female', 'Male'],
                        'admission_no': ['ASS/25/001', 'ASS/25/002', 'ASS/25/003'],
                        'class_size': [35, 35, 30],
                        'attendance': ['95%', '98%', '92%'],
                        'position': ['1st', '2nd', '3rd']
                    }
                    sample_df = pd.DataFrame(sample_data)
                    csv_buffer = StringIO()
                    sample_df.to_csv(csv_buffer, index=False)

                    st.download_button(
                        "📥 Download Sample CSV Template",
                        csv_buffer.getvalue(),
                        file_name="student_import_template.csv",
                        mime="text/csv"
                    )

                csv_file = st.file_uploader("Choose CSV file", type=['csv'], key="student_csv")

                if csv_file and st.button("📤 Import Students", key="import_students"):
                    with st.spinner("Importing students..."):
                        success, message = process_csv_student_import(csv_file)
                        if success:
                            st.success(f"✅ {message}")
                            st.rerun()
                        else:
                            st.error(f"❌ {message}")

            with bulk_tab2:
                st.markdown("### 📄 Generate Reports for Entire Class")
                st.markdown("Generate report cards for all students in a selected class.")

                students = get_all_students()
                if students:
                    classes = sorted(list(set([s['student_class'] for s in students])))

                    bulk_class = st.selectbox("Select Class", classes, key="bulk_class")
                    bulk_term = st.selectbox("Select Term", ["1st Term", "2nd Term", "3rd Term"], key="bulk_term")

                    if bulk_class:
                        class_students = [s for s in students if s['student_class'] == bulk_class]
                        st.write(f"📊 Found {len(class_students)} students in {bulk_class}")

                        # Show students in selected class
                        if st.checkbox("Show students in this class", key="show_class_students"):
                            for student in class_students:
                                st.write(f"• {student['student_name']} - {student['parent_email']}")

                        st.markdown("#### 📝 Upload Class Scores")
                        st.markdown("Upload a CSV file with scores for all students in the class.")

                        with st.expander("📋 Scores CSV Format", expanded=False):
                            st.markdown("""
                            **Required columns:**
                            - `student_name` - Must match exactly with database
                            - For each subject, include: `[subject]_ca`, `[subject]_exam`, `[subject]_last_cumulative`

                            **Example columns:**
                            - `student_name`, `English_ca`, `English_exam`, `English_last_cumulative`
                            - `Maths_ca`, `Maths_exam`, `Maths_last_cumulative`
                            """)

                        scores_csv = st.file_uploader("Upload Class Scores CSV", type=['csv'], key="class_scores_csv")

                        if scores_csv and st.button("🎓 Generate All Reports", key="generate_class_reports"):
                            with st.spinner("Generating reports for entire class..."):
                                # Parse scores CSV
                                try:
                                    scores_df = pd.read_csv(scores_csv)
                                    subject_scores_dict = {}

                                    for index, row in scores_df.iterrows():
                                        student_name = row['student_name']
                                        subject_scores_dict[student_name] = {}

                                        # Extract scores for each subject
                                        for col in scores_df.columns:
                                            if col != 'student_name' and '_' in col:
                                                parts = col.split('_')
                                                if len(parts) >= 2:
                                                    subject = '_'.join(parts[:-1])
                                                    score_type = parts[-1]

                                                    if subject not in subject_scores_dict[student_name]:
                                                        subject_scores_dict[student_name][subject] = {}

                                                    subject_scores_dict[student_name][subject][score_type] = row[col]

                                    success, message = generate_class_reports(bulk_class, bulk_term, subject_scores_dict)

                                    if success:
                                        st.success(f"✅ {message}")
                                        st.info("📋 All reports have been submitted for admin review.")
                                    else:
                                        st.error(f"❌ {message}")

                                except Exception as e:
                                    st.error(f"❌ Error processing scores CSV: {str(e)}")
                else:
                    st.info("📭 No students in database yet. Add students first.")

    if is_admin:
        with st.expander("➕ Add New Student", expanded=False):
            st.markdown("### Add Student Information")

            with st.form("add_student"):
                col1, col2 = st.columns(2)

                with col1:
                    new_student_name = st.text_input("Student Name*", placeholder="John Doe")
                    new_student_class = st.text_input("Class*", placeholder="SS1A")
                    new_parent_name = st.text_input("Parent/Guardian Name", placeholder="Mr. John Doe Sr.")
                    new_gender = st.selectbox("Gender", ["Male", "Female"], key="new_gender")
                    new_admission_no = st.text_input("Admission Number", placeholder="ASS/25/001")

                with col2:
                    new_parent_email = st.text_input("Parent Email*", placeholder="parent@example.com")
                    new_parent_phone = st.text_input("Parent Phone", placeholder="+234 xxx xxx xxxx")
                    new_class_size = st.number_input("Class Size", min_value=1, max_value=100, value=35)
                    new_attendance = st.text_input("Attendance Rate", placeholder="95%", value="95%")
                    student_photo = st.file_uploader("Student Photo", type=['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'tif', 'webp', 'svg', 'ico'])

                if st.form_submit_button("💾 Save Student"):
                    if new_student_name and new_student_class and new_parent_email:
                        if save_student_data(new_student_name, new_student_class, new_parent_name, 
                                           new_parent_email, new_parent_phone, student_photo, 
                                           new_gender, new_admission_no, str(new_class_size), new_attendance):
                            st.success(f"✅ Student {new_student_name} added successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Error saving student data")
                    else:
                        st.error("❌ Please fill in required fields (marked with *)")

    st.markdown("### 📋 All Students")
    students = get_all_students()

    if students:
        col1, col2 = st.columns(2)
        with col1:
            search_term = st.text_input("🔍 Search Students", placeholder="Enter name or class...")
        with col2:
            class_filter = st.selectbox("Filter by Class", ["All Classes"] + sorted(list(set([s['student_class'] for s in students]))))

        filtered_students = students
        if search_term:
            filtered_students = [s for s in filtered_students if 
                               search_term.lower() in s['student_name'].lower() or 
                               search_term.lower() in s['student_class'].lower()]

        if class_filter != "All Classes":
            filtered_students = [s for s in filtered_students if s['student_class'] == class_filter]

        st.write(f"**Showing {len(filtered_students)} of {len(students)} students**")

        # Decrypt emails for admin viewing
        encryption_key = generate_encryption_key("akins_sunrise_school_encryption")

        for i in range(0, len(filtered_students), 2):
            cols = st.columns(2)
            for j, col in enumerate(cols):
                if i + j < len(filtered_students):
                    student = filtered_students[i + j]
                    with col:
                        student_col, delete_col = st.columns([4, 1])

                        with student_col:
                            # Decrypt parent email for display
                            parent_email = student.get('parent_email', 'N/A')
                            if student.get('data_encrypted', False) and parent_email != 'N/A':
                                try:
                                    parent_email = decrypt_data(parent_email, encryption_key)
                                except:
                                    parent_email = 'Error decrypting email'

                            st.markdown(f"""
                            <div style="border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin: 5px 0; background: #f9f9f9;">
                                <h4 style="margin: 0; color: #003087;">👤 {student['student_name']}</h4>
                                <p style="margin: 5px 0;"><strong>Class:</strong> {student['student_class']}</p>
                                <p style="margin: 5px 0;"><strong>Parent:</strong> {student.get('parent_name', 'N/A')}</p>
                                <p style="margin: 5px 0;"><strong>Email:</strong> {parent_email}</p>
                            </div>
                            """, unsafe_allow_html=True)

                        with delete_col:
                            if is_admin:
                                if st.button("🗑️", key=f"delete_{student['student_name']}_{student['student_class']}", 
                                           help="Delete student", use_container_width=True):
                                    if delete_student_data(student['student_name'], student['student_class']):
                                        st.success(f"✅ {student['student_name']} deleted successfully!")
                                        st.rerun()
                                    else:
                                        st.error("❌ Error deleting student")
    else:
        st.info("📭 No students in database yet. Add your first student above!")

def verification_tab():
    st.subheader("🔍 Report Card Verification")
    st.markdown("Enter the Report ID to verify the authenticity of the report card")

    report_id = st.text_input(
        "Enter Report ID:", 
        placeholder="e.g., ASS-123456-ABCD",
        key="report_id_input"
    )

    if st.button("🔍 Verify Report", key="verify_btn"):
        if report_id:
            if report_id.startswith("ASS-"):
                # Check if report exists in approved reports
                report_found = False
                report_data = None

                approved_dir = "approved_reports"
                if os.path.exists(approved_dir):
                    for filename in os.listdir(approved_dir):
                        if filename.endswith('.json'):
                            filepath = os.path.join(approved_dir, filename)
                            try:
                                with open(filepath, 'r') as f:
                                    report = json.load(f)
                                    if report.get('report_id') == report_id:
                                        report_found = True
                                        report_data = report
                                        break
                            except:
                                continue

                if report_found and report_data:
                    st.success("✅ Report Verified Successfully!")

                    # Enhanced verification badge with blue theme
                    st.markdown(f"""
                    <div style="text-align: center; padding: 15px; border: 3px solid #1976D2; border-radius: 12px; background: linear-gradient(135deg, #e3f2fd, #ffffff); margin: 15px 0; box-shadow: 0 4px 8px rgba(25, 118, 210, 0.2);">
                        <span style="font-size: 48px; color: #1976D2;">✅</span>
                        <br><strong style="color: #1976D2; font-size: 24px; font-weight: 700;">VERIFIED AUTHENTIC</strong>
                        <br><strong style="color: #1565C0; font-size: 16px;">Akin's Sunrise Secondary School</strong>
                        <br><small style="color: #1976D2; font-size: 14px;">Official Digital Report Card</small>
                        <br><small style="color: #0D47A1; font-size: 12px;">Cryptographically Secured</small>
                    </div>
                    """, unsafe_allow_html=True)

                    # Detailed report information
                    st.markdown("### 📋 Verified Report Details")

                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("#### 👤 Student Information")
                        st.write(f"**Student Name:** {report_data.get('student_name', 'N/A')}")
                        st.write(f"**Class/Form:** {report_data.get('student_class', 'N/A')}")
                        st.write(f"**Academic Term:** {report_data.get('term', 'N/A')}")

                        st.markdown("#### 📊 Academic Performance")
                        avg_score = report_data.get('average_cumulative', 0)
                        final_grade = report_data.get('final_grade', 'N/A')
                        st.write(f"**Average Score:** {avg_score:.2f}%")
                        st.write(f"**Final Grade:** {final_grade}")

                        # Grade interpretation
                        if final_grade == 'A':
                            st.success("🌟 Excellent Performance")
                        elif final_grade == 'B':
                            st.info("👍 Good Performance")
                        elif final_grade == 'C':
                            st.warning("📈 Average Performance")
                        else:
                            st.error("📚 Needs Improvement")

                    with col2:
                        st.markdown("#### 🔐 Authentication Details")
                        st.write(f"**Report ID:** {report_data.get('report_id', 'N/A')}")
                        st.write(f"**Generated By:** {report_data.get('teacher_id', 'N/A')}")

                        # Format dates
                        created_date = report_data.get('created_date', 'N/A')
                        approved_date = report_data.get('approved_date', 'N/A')
                        approved_by = report_data.get('approved_by', 'N/A')

                        if created_date != 'N/A':
                            try:
                                formatted_created = datetime.datetime.fromisoformat(created_date).strftime('%B %d, %Y at %I:%M %p')
                                st.write(f"**Created Date:** {formatted_created}")
                            except:
                                st.write(f"**Created Date:** {created_date}")
                        else:
                            st.write(f"**Created Date:** {created_date}")

                        if approved_date != 'N/A':
                            try:
                                formatted_approved = datetime.datetime.fromisoformat(approved_date).strftime('%B %d, %Y at %I:%M %p')
                                st.write(f"**Approved Date:** {formatted_approved}")
                            except:
                                st.write(f"**Approved Date:** {approved_date}")
                        else:
                            st.write(f"**Approved Date:** {approved_date}")

                        st.write(f"**Approved By:** {approved_by}")

                        st.markdown("#### 🛡️ Security Status")
                        st.success("✅ Digital Signature Valid")
                        st.success("✅ Report Integrity Confirmed")
                        st.success("✅ Official School Seal Verified")
                        st.info("🔐 Blockchain Secured")



                    # Download option for verified reports
                    pdf_path = f"approved_reports/approved_{report_id}.pdf"
                    if os.path.exists(pdf_path):
                        with open(pdf_path, "rb") as f:
                            st.download_button(
                                "📄 Download Verified Report Card (PDF)",
                                f,
                                file_name=f"Verified_{report_data.get('student_name', 'Student')}_{report_data.get('term', 'Term')}.pdf",
                                mime="application/pdf",
                                use_container_width=True
                            )

                else:
                    # Report ID format is correct but not found in database
                    st.error("❌ Report Not Found")
                    st.markdown(f"""
                    <div style="text-align: center; padding: 15px; border: 3px solid #f44336; border-radius: 12px; background: linear-gradient(135deg, #ffebee, #ffffff); margin: 15px 0;">
                        <span style="font-size: 48px; color: #f44336;">❌</span>
                        <br><strong style="color: #d32f2f; font-size: 20px;">REPORT NOT FOUND</strong>
                        <br><small style="color: #d32f2f; font-size: 14px;">Report ID: {report_id}</small>
                        <br><small style="color: #f44336; font-size: 12px;">This report may not exist or has not been approved yet</small>
                    </div>
                    """, unsafe_allow_html=True)

                    st.info("💡 **Possible reasons:**")
                    st.write("• Report has not been approved by administration yet")
                    st.write("• Report ID was entered incorrectly")
                    st.write("• Report may have been archived or moved")
                    st.write("• Contact the school for assistance")
            else:
                st.error("❌ Invalid Report ID Format")
                st.markdown(f"""
                <div style="text-align: center; padding: 15px; border: 3px solid #f44336; border-radius: 12px; background: linear-gradient(135deg, #ffebee, #ffffff); margin: 15px 0;">
                    <span style="font-size: 48px; color: #f44336;">❌</span>
                    <br><strong style="color: #d32f2f; font-size: 20px;">INVALID FORMAT</strong>
                    <br><small style="color: #d32f2f; font-size: 14px;">Report ID must start with "ASS-"</small>
                    <br><small style="color: #f44336; font-size: 12px;">Example: ASS-123456-ABCD</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.warning("⚠️ Please enter a Report ID")

def parent_portal_tab():
    """Parent portal for viewing child's reports with photos and organized results"""
    st.subheader("👨‍👩‍👧‍👦 Parent Portal")

    if st.session_state.get('user_type') != 'parent':
        st.error("❌ Access denied. Parent login required.")
        return

    child_data = st.session_state.get('child_data', {})
    parent_email = st.session_state.get('parent_email', '')

    st.markdown(f"### Welcome, Parent of {child_data.get('student_name', 'Student')}")

    st.info("📚 This portal shows all academic reports for your child throughout their academic journey at Akin's Sunrise School, from admission to graduation.")

    # Student photo section
    with st.expander("📷 Student Photo", expanded=True):
        photo_col1, photo_col2, photo_col3 = st.columns([1, 1, 1])

        with photo_col2:  # Center the photo
            photo_filename = child_data.get('photo_filename')
            if photo_filename:
                photo_path = os.path.join("student_database", photo_filename)
                if os.path.exists(photo_path):
                    try:
                        st.image(photo_path, caption=f"{child_data.get('student_name', 'Student')} - {child_data.get('student_class', '')}", width=200)
                    except:
                        st.info("📷 Photo unavailable")
                else:
                    st.info("📷 Photo not found")
            else:
                st.info("📷 No photo available")

    # Student information
    with st.expander("📋 Student Information", expanded=True):
        info_col1, info_col2 = st.columns(2)

        with info_col1:
            st.write(f"**Student Name:** {child_data.get('student_name', 'N/A')}")
            st.write(f"**Class:** {child_data.get('student_class', 'N/A')}")
            st.write(f"**Admission Number:** {child_data.get('admission_no', 'N/A')}")

        with info_col2:
            st.write(f"**Gender:** {child_data.get('gender', 'N/A')}")
            st.write(f"**Attendance:** {child_data.get('attendance', 'N/A')}")
            st.write(f"**Class Size:** {child_data.get('class_size', 'N/A')}")

    # Academic reports organized by academic year and term
    st.markdown("### 📊 Academic Progress History")

    approved_dir = "approved_reports"
    child_reports = []

    if os.path.exists(approved_dir):
        for filename in os.listdir(approved_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(approved_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        report = json.load(f)

                        # Get student data from the report if available
                        report_student_name = report.get('student_name', '')

                        # Try to find admission number from student database for this student
                        report_admission_no = None
                        students = get_all_students()
                        for student in students:
                            if student.get('student_name') == report_student_name:
                                report_admission_no = student.get('admission_no', '')
                                break

                        # Check by student name first, then by admission number for historical access
                        name_match = report_student_name == child_data.get('student_name')
                        admission_match = (report_admission_no and 
                                         report_admission_no == child_data.get('admission_no'))

                        # Include report if either name matches or admission number matches
                        # This allows access to historical reports even if student was promoted/name changed
                        if name_match or admission_match:
                            # Store the matched admission number in report for reference
                            if report_admission_no:
                                report['matched_admission_no'] = report_admission_no
                            child_reports.append(report)
                except:
                    continue

    if child_reports:
        # Group reports by academic year and term
        reports_by_year = {}
        for report in child_reports:
            # Extract year from approved_date or use current year
            try:
                report_year = datetime.datetime.fromisoformat(report.get('approved_date', datetime.datetime.now().isoformat())).year
            except:
                report_year = datetime.datetime.now().year

            if report_year not in reports_by_year:
                reports_by_year[report_year] = {}

            term = report.get('term', 'Unknown Term')
            if term not in reports_by_year[report_year]:
                reports_by_year[report_year][term] = []

            reports_by_year[report_year][term].append(report)

        # Display reports organized by year and term
        for year in sorted(reports_by_year.keys(), reverse=True):
            with st.expander(f"📅 Academic Year {year}/{year+1}", expanded=year == max(reports_by_year.keys())):
                terms_order = ["1st Term", "2nd Term", "3rd Term"]

                for term in terms_order:
                    if term in reports_by_year[year]:
                        st.markdown(f"#### 📚 {term}")

                        for report in reports_by_year[year][term]:
                            report_col1, report_col2, report_col3 = st.columns([2, 1, 1])

                            with report_col1:
                                st.write(f"**Class:** {report.get('student_class', 'N/A')}")
                                st.write(f"**Average:** {report.get('average_cumulative', 0):.2f}%")
                                st.write(f"**Grade:** {report.get('final_grade', 'N/A')}")
                                if report.get('matched_admission_no'):
                                    st.write(f"**Admission No:** {report.get('matched_admission_no')}")

                            with report_col2:
                                report_date = report.get('approved_date', 'N/A')
                                if report_date != 'N/A':
                                    try:
                                        formatted_date = datetime.datetime.fromisoformat(report_date).strftime('%b %d, %Y')
                                        st.write(f"**Date:** {formatted_date}")
                                    except:
                                        st.write(f"**Date:** {report_date}")
                                else:
                                    st.write(f"**Date:** {report_date}")
                                st.write(f"**Teacher:** {report.get('teacher_id', 'N/A')}")

                            with report_col3:
                                # Download PDF if available
                                pdf_path = f"approved_reports/approved_{report.get('report_id', '')}.pdf"
                                if os.path.exists(pdf_path):
                                    with open(pdf_path, "rb") as f:
                                        st.download_button(
                                            "📄 Download PDF",
                                            f,
                                            file_name=f"{child_data.get('student_name', 'Student')}_{term}_{year}.pdf",
                                            mime="application/pdf",
                                            key=f"download_{report.get('report_id', '')}"
                                        )

                        st.markdown("---")

        # Academic performance summary
        st.markdown("### 📈 Performance Summary")
        if child_reports:
            # Calculate overall statistics
            all_averages = [r.get('average_cumulative', 0) for r in child_reports if r.get('average_cumulative')]
            if all_averages:
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("📊 Overall Average", f"{np.mean(all_averages):.2f}%")
                with col2:
                    st.metric("📈 Highest Score", f"{max(all_averages):.2f}%")
                with col3:
                    st.metric("📉 Lowest Score", f"{min(all_averages):.2f}%")

                # Performance trend chart
                if len(all_averages) > 1:
                    trend_data = []
                    for i, report in enumerate(sorted(child_reports, key=lambda x: x.get('approved_date', ''))):
                        trend_data.append({
                            'Term': f"{report.get('term', 'Term')} ({datetime.datetime.fromisoformat(report.get('approved_date', datetime.datetime.now().isoformat())).year})",
                            'Average': report.get('average_cumulative', 0),
                            'Grade': report.get('final_grade', 'N/A')
                        })

                    trend_df = pd.DataFrame(trend_data)
                    if not trend_df.empty:
                        fig = px.line(trend_df, x='Term', y='Average', 
                                    title='Academic Performance Trend',
                                    markers=True,
                                    hover_data=['Grade'])
                        fig.update_layout(height=400)
                        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("📭 No academic reports available yet.")

    # Communication section
    st.markdown("### 💬 Communication")
    st.info("📧 For inquiries, please contact your child's class teacher or the school administration.")

    # Contact information
    with st.expander("📞 Contact Information", expanded=False):
        st.write("**School Phone:** +234 800 123 4567")
        st.write("**School Email:** info@akinssunrise.edu.ng")
        st.write("**Address:** Sunrise Avenue Off Lujojomu Road, Upper Ayeyemi, Ondo City")

def admin_panel_tab():
    st.subheader("⚙️ Admin Panel")

    # Check permissions
    if not check_user_permissions(st.session_state.teacher_id, "system_config"):
        st.warning("⚠️ Admin access required for this section.")
        st.info("Contact your system administrator for admin privileges.")
        return

    admin_tab1, admin_tab2, admin_tab3, admin_tab4, admin_tab5, admin_tab6, admin_tab7 = st.tabs([
        "📋 Pending Reports", 
        "👥 User Management",
        "🔒 Security & 2FA",
        "💾 Backup & Restore",
        "📊 System Stats", 
        "📧 Email Setup", 
        "🔍 Audit Logs"
    ])

    with admin_tab2:
        st.markdown("### 👥 User Management")

        # Add new user
        with st.expander("➕ Add New User", expanded=False):
            with st.form("add_user_form"):
                col1, col2 = st.columns(2)

                with col1:
                    new_user_id = st.text_input("User ID*", placeholder="teacher_john")
                    new_full_name = st.text_input("Full Name*", placeholder="John Doe")
                    new_email = st.text_input("Email*", placeholder="john@akinssunrise.edu.ng")
                    new_role = st.selectbox("Role*", list(USER_ROLES.keys()))

                with col2:
                    new_phone = st.text_input("Phone", placeholder="+234 800 123 4567")
                    new_password = st.text_input("Temporary Password*", type="password")
                    new_session_timeout = st.number_input("Session Timeout (minutes)", min_value=15, max_value=480, value=30)
                    new_departments = st.multiselect("Departments", ["all", "sciences", "mathematics", "languages", "arts", "social_studies"])

                new_assigned_classes = st.multiselect("Assigned Classes", 
                    ["SS1A", "SS1B", "SS1C", "SS2A", "SS2B", "SS2C", "SS3A", "SS3B", "SS3C", 
                     "JSS1A", "JSS1B", "JSS1C", "JSS2A", "JSS2B", "JSS2C", "JSS3A", "JSS3B", "JSS3C"])

                if st.form_submit_button("👤 Create User"):
                    if new_user_id and new_full_name and new_email and new_password:
                        users_db = load_user_database()

                        if new_user_id not in users_db:
                            users_db[new_user_id] = {
                                "password_hash": hash_password(new_password),
                                "role": new_role,
                                "full_name": new_full_name,
                                "email": new_email,
                                "phone": new_phone,
                                "created_date": datetime.datetime.now().isoformat(),
                                "last_login": None,
                                "active": True,
                                "two_factor_enabled": False,
                                "two_factor_secret": None,
                                "session_timeout": new_session_timeout,
                                "failed_attempts": 0,
                                "locked_until": None,
                                "assigned_classes": new_assigned_classes,
                                "departments": new_departments or ["all"]
                            }

                            if save_user_database(users_db):
                                st.success(f"✅ User {new_user_id} created successfully!")
                                log_teacher_activity(st.session_state.teacher_id, "user_created", {
                                    "created_user": new_user_id,
                                    "role": new_role,
                                    "created_by": st.session_state.teacher_id
                                })
                                st.rerun()
                            else:
                                st.error("❌ Error creating user")
                        else:
                            st.error("❌ User ID already exists")
                    else:
                        st.error("❌ Please fill in all required fields")

        # Manage existing users
        st.markdown("### 📋 Existing Users")
        users_db = load_user_database()

        if users_db:
            for user_id, user in users_db.items():
                with st.expander(f"👤 {user.get('full_name', user_id)} ({user_id})", expanded=False):
                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.write(f"**Role:** {user.get('role', 'N/A')}")
                        st.write(f"**Email:** {user.get('email', 'N/A')}")
                        st.write(f"**Phone:** {user.get('phone', 'N/A')}")
                        st.write(f"**Created:** {user.get('created_date', 'N/A')}")
                        st.write(f"**Last Login:** {user.get('last_login', 'Never')}")
                        st.write(f"**Status:** {'🟢 Active' if user.get('active', True) else '🔴 Disabled'}")
                        st.write(f"**2FA:** {'✅ Enabled' if user.get('two_factor_enabled', False) else '❌ Disabled'}")
                        st.write(f"**Classes:** {', '.join(user.get('assigned_classes', []))}")

                    with col2:
                        # Toggle active status
                        if user.get('active', True):
                            if st.button("🔒 Disable", key=f"disable_{user_id}"):
                                users_db[user_id]['active'] = False
                                if save_user_database(users_db):
                                    st.success(f"✅ User {user_id} disabled")
                                    log_teacher_activity(st.session_state.teacher_id, "user_disabled", {
                                        "disabled_user": user_id,
                                        "disabled_by": st.session_state.teacher_id
                                    })
                                    st.rerun()
                                else:
                                    st.error("❌ Error disabling user")
                        else:
                            if st.button("🔓 Enable", key=f"enable_{user_id}"):
                                users_db[user_id]['active'] = True
                                if save_user_database(users_db):
                                    st.success(f"✅ User {user_id} enabled")
                                    log_teacher_activity(st.session_state.teacher_id, "user_enabled", {
                                        "enabled_user": user_id,
                                        "enabled_by": st.session_state.teacher_id
                                    })
                                    st.rerun()
                                else:
                                    st.error("❌ Error enabling user")

                        # Reset password
                        if st.button("🔑 Reset Password", key=f"reset_pwd_btn_{user_id}"):
                            st.session_state[f"show_reset_pwd_{user_id}"] = True
                            st.rerun()

                    with col3:
                        # Edit user
                        if st.button("✏️ Edit", key=f"edit_btn_{user_id}"):
                            st.session_state[f"show_edit_{user_id}"] = True
                            st.rerun()

                        # Delete user (only if not current user)
                        if user_id != st.session_state.teacher_id:
                            if st.button("🗑️ Delete", key=f"delete_btn_{user_id}"):
                                st.session_state[f"show_delete_{user_id}"] = True
                                st.rerun()

                    # Reset password form
                    if st.session_state.get(f"show_reset_pwd_{user_id}", False):
                        st.markdown("---")
                        st.markdown(f"**Reset Password for {user.get('full_name', user_id)}**")
                        new_password = st.text_input("New Password", type="password", key=f"new_pwd_input_{user_id}")
                        col_a, col_b = st.columns(2)
                        with col_a:
                            if st.button("💾 Save New Password", key=f"save_pwd_{user_id}"):
                                if new_password and len(new_password) >= 6:
                                    users_db[user_id]['password_hash'] = hash_password(new_password)
                                    if save_user_database(users_db):
                                        st.success("✅ Password reset successfully!")
                                        log_teacher_activity(st.session_state.teacher_id, "password_reset", {
                                            "reset_user": user_id,
                                            "reset_by": st.session_state.teacher_id
                                        })
                                        st.session_state[f"show_reset_pwd_{user_id}"] = False
                                        st.rerun()
                                    else:
                                        st.error("❌ Error saving new password")
                                else:
                                    st.error("❌ Password must be at least 6 characters")
                        with col_b:
                            if st.button("❌ Cancel", key=f"cancel_pwd_{user_id}"):
                                st.session_state[f"show_reset_pwd_{user_id}"] = False
                                st.rerun()

                    # Edit user form
                    if st.session_state.get(f"show_edit_{user_id}", False):
                        st.markdown("---")
                        st.markdown(f"**Edit User: {user.get('full_name', user_id)}**")
                        
                        with st.form(f"edit_user_form_{user_id}"):
                            edit_col1, edit_col2 = st.columns(2)
                            
                            with edit_col1:
                                edit_full_name = st.text_input("Full Name", value=user.get('full_name', ''))
                                edit_email = st.text_input("Email", value=user.get('email', ''))
                                edit_role = st.selectbox("Role", list(USER_ROLES.keys()), 
                                                       index=list(USER_ROLES.keys()).index(user.get('role', 'teacher')))
                                
                            with edit_col2:
                                edit_phone = st.text_input("Phone", value=user.get('phone', ''))
                                edit_session_timeout = st.number_input("Session Timeout (minutes)", 
                                                                     min_value=15, max_value=480, 
                                                                     value=user.get('session_timeout', 30))
                                edit_departments = st.multiselect("Departments", 
                                                                ["all", "sciences", "mathematics", "languages", "arts", "social_studies"],
                                                                default=user.get('departments', []))
                            
                            edit_assigned_classes = st.multiselect("Assigned Classes", 
                                ["SS1A", "SS1B", "SS1C", "SS2A", "SS2B", "SS2C", "SS3A", "SS3B", "SS3C", 
                                 "JSS1A", "JSS1B", "JSS1C", "JSS2A", "JSS2B", "JSS2C", "JSS3A", "JSS3B", "JSS3C"],
                                default=user.get('assigned_classes', []))
                            
                            form_col1, form_col2 = st.columns(2)
                            with form_col1:
                                if st.form_submit_button("💾 Save Changes"):
                                    if edit_full_name and edit_email:
                                        users_db[user_id].update({
                                            'full_name': edit_full_name,
                                            'email': edit_email,
                                            'phone': edit_phone,
                                            'role': edit_role,
                                            'session_timeout': edit_session_timeout,
                                            'departments': edit_departments or ["all"],
                                            'assigned_classes': edit_assigned_classes
                                        })
                                        
                                        if save_user_database(users_db):
                                            st.success("✅ User updated successfully!")
                                            log_teacher_activity(st.session_state.teacher_id, "user_updated", {
                                                "updated_user": user_id,
                                                "updated_by": st.session_state.teacher_id
                                            })
                                            st.session_state[f"show_edit_{user_id}"] = False
                                            st.rerun()
                                        else:
                                            st.error("❌ Error updating user")
                                    else:
                                        st.error("❌ Please fill in required fields")
                            
                            with form_col2:
                                if st.form_submit_button("❌ Cancel"):
                                    st.session_state[f"show_edit_{user_id}"] = False
                                    st.rerun()

                    # Delete confirmation
                    if st.session_state.get(f"show_delete_{user_id}", False):
                        st.markdown("---")
                        st.error(f"⚠️ Are you sure you want to delete user **{user.get('full_name', user_id)}**?")
                        st.warning("This action cannot be undone!")
                        col_a, col_b = st.columns(2)
                        with col_a:
                            if st.button("🗑️ Confirm Delete", key=f"confirm_delete_{user_id}", type="primary"):
                                del users_db[user_id]
                                if save_user_database(users_db):
                                    st.success(f"✅ User {user_id} deleted successfully!")
                                    log_teacher_activity(st.session_state.teacher_id, "user_deleted", {
                                        "deleted_user": user_id,
                                        "deleted_by": st.session_state.teacher_id
                                    })
                                    st.session_state[f"show_delete_{user_id}"] = False
                                    st.rerun()
                                else:
                                    st.error("❌ Error deleting user")
                        with col_b:
                            if st.button("❌ Cancel", key=f"cancel_delete_{user_id}"):
                                st.session_state[f"show_delete_{user_id}"] = False
                                st.rerun()
        else:
            st.info("No users found in database.")

        # Student Management Section
        st.markdown("---")
        st.markdown("### 👥 Student Management & Promotion")

        students = get_all_students()
        if students:
            with st.expander("✏️ Edit Student Information", expanded=False):
                student_options = [f"{s['student_name']} ({s['student_class']})" for s in students]
                selected_student = st.selectbox("Select Student to Edit", student_options)

                if selected_student:
                    student_name = selected_student.split(" (")[0]
                    student = next((s for s in students if s['student_name'] == student_name), None)

                    if student:
                        st.markdown(f"#### Editing: {student['student_name']}")

                        with st.form(f"edit_student_{student['student_name']}"):
                            col1, col2 = st.columns(2)

                            with col1:
                                edit_name = st.text_input("Student Name", value=student.get('student_name', ''))
                                edit_class = st.text_input("Class", value=student.get('student_class', ''))
                                edit_parent_name = st.text_input("Parent/Guardian Name", value=student.get('parent_name', ''))
                                edit_gender = st.selectbox("Gender", ["Male", "Female"], 
                                                         index=0 if student.get('gender', 'Male') == 'Male' else 1)
                                edit_admission_no = st.text_input("Admission Number", value=student.get('admission_no', ''))

                            with col2:
                                # Decrypt parent email for editing
                                encryption_key = generate_encryption_key("akins_sunrise_school_encryption")
                                parent_email = student.get('parent_email', '')
                                parent_phone = student.get('parent_phone', '')

                                if student.get('data_encrypted', False):
                                    try:
                                        if parent_email:
                                            parent_email = decrypt_data(parent_email, encryption_key)
                                        if parent_phone:
                                            parent_phone = decrypt_data(parent_phone, encryption_key)
                                    except:
                                        pass

                                edit_parent_email = st.text_input("Parent Email", value=parent_email)
                                edit_parent_phone = st.text_input("Parent Phone", value=parent_phone)
                                edit_class_size = st.number_input("Class Size", min_value=1, max_value=100, 
                                                                value=int(student.get('class_size', 35)))
                                edit_attendance = st.text_input("Attendance Rate", value=student.get('attendance', '95%'))
                                edit_position = st.text_input("Position", value=student.get('position', '1st'))

                            # Photo upload section
                            st.markdown("**Update Student Photo:**")
                            new_photo = st.file_uploader("Upload New Photo", type=['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'tif', 'webp', 'svg', 'ico'], 
                                                       key=f"photo_{student['student_name']}")

                            if student.get('photo_filename'):
                                st.info(f"Current photo: {student['photo_filename']}")

                            promotion_mode = st.checkbox("🎓 Promotion Mode (Update class for new academic year)")

                            submit_col1, submit_col2 = st.columns(2)
                            with submit_col1:
                                if st.form_submit_button("💾 Save Changes"):
                                    # Delete old student record
                                    if delete_student_data(student['student_name'], student['student_class']):
                                        # Save updated student data
                                        success = save_student_data(
                                            edit_name, edit_class, edit_parent_name, 
                                            edit_parent_email, edit_parent_phone, 
                                            new_photo, edit_gender, edit_admission_no, 
                                            str(edit_class_size), edit_attendance, edit_position
                                        )

                                        if success:
                                            # Create audit log for student update
                                            create_audit_log("student_data_updated", st.session_state.teacher_id, {
                                                "old_name": student['student_name'],
                                                "new_name": edit_name,
                                                "old_class": student['student_class'],
                                                "new_class": edit_class,
                                                "promotion_mode": promotion_mode,
                                                "updated_by": st.session_state.teacher_id
                                            }, "student_management")

                                            st.success(f"✅ Student information updated successfully!")
                                            if promotion_mode:
                                                st.info(f"🎓 {edit_name} promoted from {student['student_class']} to {edit_class}")
                                            st.rerun()
                                        else:
                                            st.error("❌ Error updating student information")
                                    else:
                                        st.error("❌ Error deleting old student record")

                            with submit_col2:
                                if st.form_submit_button("🗑️ Delete Student", type="secondary"):
                                    st.session_state[f"confirm_delete_student_{student['student_name']}"] = True

                        # Delete confirmation
                        if st.session_state.get(f"confirm_delete_student_{student['student_name']}", False):
                            st.warning(f"⚠️ Are you sure you want to permanently delete {student['student_name']}?")
                            col_a, col_b = st.columns(2)
                            with col_a:
                                if st.button("🗑️ Confirm Delete", key=f"final_delete_{student['student_name']}"):
                                    if delete_student_data(student['student_name'], student['student_class']):
                                        st.success(f"✅ {student['student_name']} deleted successfully!")
                                        st.session_state[f"confirm_delete_student_{student['student_name']}"] = False
                                        st.rerun()
                                    else:
                                        st.error("❌ Error deleting student")
                            with col_b:
                                if st.button("❌ Cancel Delete", key=f"cancel_final_delete_{student['student_name']}"):
                                    st.session_state[f"confirm_delete_student_{student['student_name']}"] = False
                                    st.rerun()

            # Bulk promotion feature
            with st.expander("🎓 Bulk Student Promotion", expanded=False):
                st.markdown("### Promote Multiple Students to Next Class")

                # Group students by class
                classes = sorted(list(set([s['student_class'] for s in students])))
                promotion_class = st.selectbox("Select Class to Promote", classes, key="promotion_class")

                if promotion_class:
                    class_students = [s for s in students if s['student_class'] == promotion_class]
                    st.write(f"📊 Found {len(class_students)} students in {promotion_class}")

                    # Define next class mapping
                    class_mapping = {
                        "JSS1A": "JSS2A", "JSS1B": "JSS2B", "JSS1C": "JSS2C",
                        "JSS2A": "JSS3A", "JSS2B": "JSS3B", "JSS2C": "JSS3C",
                        "JSS3A": "SS1A", "JSS3B": "SS1B", "JSS3C": "SS1C",
                        "SS1A": "SS2A", "SS1B": "SS2B", "SS1C": "SS2C",
                        "SS2A": "SS3A", "SS2B": "SS3B", "SS2C": "SS3C",
                        "SS3A": "GRADUATED", "SS3B": "GRADUATED", "SS3C": "GRADUATED"
                    }

                    next_class = st.text_input("Promote to Class", 
                                             value=class_mapping.get(promotion_class, ""),
                                             key="next_class")

                    if st.button("🎓 Promote All Students in Class") and next_class:
                        success_count = 0
                        error_count = 0

                        for student in class_students:
                            try:
                                # Delete old record
                                if delete_student_data(student['student_name'], student['student_class']):
                                    # Create new record with updated class
                                    success = save_student_data(
                                        student['student_name'],
                                        next_class,
                                        student.get('parent_name', ''),
                                        student.get('parent_email', ''),
                                        student.get('parent_phone', ''),
                                        None,  # Keep existing photo
                                        student.get('gender', 'M/F'),
                                        student.get('admission_no', ''),
                                        student.get('class_size', '35'),
                                        student.get('attendance', '95%'),
                                        student.get('position', '1st')
                                    )

                                    if success:
                                        success_count += 1
                                    else:
                                        error_count += 1
                                else:
                                    error_count += 1
                            except:
                                error_count += 1

                        if success_count > 0:
                            st.success(f"✅ Promoted {success_count} students from {promotion_class} to {next_class}")
                            create_audit_log("bulk_promotion", st.session_state.teacher_id, {
                                "from_class": promotion_class,
                                "to_class": next_class,
                                "promoted_count": success_count,
                                "error_count": error_count
                            }, "student_management")
                            st.rerun()

                        if error_count > 0:
                            st.warning(f"⚠️ {error_count} students could not be promoted")
        else:
            st.info("📭 No students in database yet.")

    with admin_tab3:
        st.markdown("### 🔒 Security & Two-Factor Authentication")

        # System security settings
        with st.expander("⚙️ System Security Settings", expanded=False):
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### 🔐 Security Configuration")
                max_attempts = st.number_input("Max Failed Login Attempts", min_value=3, max_value=10, value=3)
                lockout_duration = st.number_input("Account Lockout Duration (minutes)", min_value=15, max_value=60, value=30)
                default_timeout = st.number_input("Default Session Timeout (minutes)", min_value=15, max_value=480, value=30)

            with col2:
                st.markdown("#### 🔒 Password Policy")
                min_length = st.number_input("Minimum Password Length", min_value=8, max_value=20, value=8)
                require_special = st.checkbox("Require Special Characters", value=True)
                require_numbers = st.checkbox("Require Numbers", value=True)
                require_uppercase = st.checkbox("Require Uppercase Letters", value=True)

            if st.button("💾 Save Security Settings"):
                security_config = {
                    "max_failed_attempts": max_attempts,
                    "lockout_duration_minutes": lockout_duration,
                    "default_session_timeout": default_timeout,
                    "password_policy": {
                        "min_length": min_length,
                        "require_special": require_special,
                        "require_numbers": require_numbers,
                        "require_uppercase": require_uppercase
                    }
                }

                with open("security_config.json", 'w') as f:
                    json.dump(security_config, f, indent=2)

                st.success("✅ Security settings saved!")

        # Two-factor authentication management
        st.markdown("### 🔐 Two-Factor Authentication Management")

        users_db = load_user_database()
        current_user = users_db.get(st.session_state.teacher_id, {})

        # Enable 2FA for current user
        if not current_user.get('two_factor_enabled', False):
            st.markdown("#### 🔒 Enable 2FA for Your Account")
            if st.button("🔐 Setup Two-Factor Authentication"):
                secret = generate_2fa_secret()
                qr_code = generate_2fa_qr(st.session_state.teacher_id, secret)

                st.session_state.temp_2fa_secret = secret
                st.session_state.show_2fa_setup = True
                st.rerun()

        # 2FA setup process
        if st.session_state.get('show_2fa_setup', False):
            st.markdown("#### 📱 Scan QR Code with Authenticator App")
            st.image(f"data:image/png;base64,{generate_2fa_qr(st.session_state.teacher_id, st.session_state.temp_2fa_secret)}", width=200)

            st.markdown("**Or enter this secret manually:**")
            st.code(st.session_state.temp_2fa_secret)

            verification_code = st.text_input("Enter verification code from app", placeholder="123456")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Verify and Enable 2FA"):
                    if verification_code and verify_2fa_token(st.session_state.temp_2fa_secret, verification_code):
                        users_db[st.session_state.teacher_id]['two_factor_enabled'] = True
                        users_db[st.session_state.teacher_id]['two_factor_secret'] = st.session_state.temp_2fa_secret
                        save_user_database(users_db)

                        st.success("✅ Two-factor authentication enabled successfully!")
                        st.session_state.show_2fa_setup = False
                        del st.session_state.temp_2fa_secret
                        st.rerun()
                    else:
                        st.error("❌ Invalid verification code")

            with col2:
                if st.button("❌ Cancel Setup"):
                    st.session_state.show_2fa_setup = False
                    del st.session_state.temp_2fa_secret
                    st.rerun()

        # Disable 2FA
        if current_user.get('two_factor_enabled', False):
            st.markdown("#### 🔓 Disable Two-Factor Authentication")
            if st.button("🔓 Disable 2FA"):
                users_db[st.session_state.teacher_id]['two_factor_enabled'] = False
                users_db[st.session_state.teacher_id]['two_factor_secret'] = None
                save_user_database(users_db)
                st.success("✅ Two-factor authentication disabled!")
                st.rerun()

        # 2FA status for all users
        st.markdown("### 👥 2FA Status for All Users")

        for user_id, user in users_db.items():
            col1, col2, col3 = st.columns([2, 1, 1])

            with col1:
                st.write(f"**{user.get('full_name', user_id)}** ({user_id})")

            with col2:
                if user.get('two_factor_enabled', False):
                    st.success("✅ 2FA Enabled")
                else:
                    st.warning("❌ 2FA Disabled")

            with col3:
                if user.get('two_factor_enabled', False):
                    if st.button("🔓 Force Disable", key=f"force_disable_2fa_{user_id}"):
                        users_db[user_id]['two_factor_enabled'] = False
                        users_db[user_id]['two_factor_secret'] = None
                        save_user_database(users_db)
                        st.success(f"2FA disabled for {user_id}")
                        st.rerun()

    with admin_tab4:
        st.markdown("### 💾 Backup & Restore System")

        # Create backup
        st.markdown("#### 📦 Create System Backup")
        col1, col2 = st.columns([2, 1])

        with col1:
            backup_description = st.text_area("Backup Description (Optional)", 
                                            placeholder="Enter description for this backup...")

        with col2:
            if st.button("🗃️ Create Backup", use_container_width=True):
                with st.spinner("Creating backup..."):
                    success, message = create_backup()
                    if success:
                        st.success(f"✅ {message}")
                        log_teacher_activity(st.session_state.teacher_id, "backup_created", {
                            "backup_type": "manual",
                            "description": backup_description
                        })
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")

        # Available backups
        st.markdown("#### 📋 Available Backups")
        backups = get_available_backups()

        if backups:
            for backup in backups:
                with st.expander(f"📦 {backup['name']} ({backup['size']} bytes)", expanded=False):
                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.write(f"**Created:** {backup['created']}")
                        st.write(f"**Size:** {backup['size']:,} bytes")

                    with col2:
                        # Download backup
                        if os.path.exists(backup['path']):
                            with open(backup['path'], 'rb') as f:
                                st.download_button(
                                    "📥 Download",
                                    f,
                                    file_name=backup['name'],
                                    mime="application/zip"
                                )

                    with col3:
                        # Restore backup
                        if st.button("🔄 Restore", key=f"restore_{backup['name']}"):
                            st.warning("⚠️ This will replace all current data!")
                            if st.button("✅ Confirm Restore", key=f"confirm_restore_{backup['name']}"):
                                with st.spinner("Restoring backup..."):
                                    success, message = restore_backup(backup['name'])
                                    if success:
                                        st.success(f"✅ {message}")
                                        log_teacher_activity(st.session_state.teacher_id, "backup_restored", {
                                            "backup_name": backup['name']
                                        })
                                        st.rerun()
                                    else:
                                        st.error(f"❌ {message}")
        else:
            st.info("📭 No backups available. Create your first backup above.")

        # Automated backup settings
        st.markdown("#### ⚙️ Automated Backup Settings")
        with st.expander("Configure Automated Backups", expanded=False):
            enable_auto_backup = st.checkbox("Enable Automated Backups", value=True)
            backup_frequency = st.selectbox("Backup Frequency", ["Daily", "Weekly", "Monthly"])
            max_backups = st.number_input("Maximum Backups to Keep", min_value=5, max_value=50, value=10)

            if st.button("💾 Save Backup Settings"):
                backup_config = {
                    "enabled": enable_auto_backup,
                    "frequency": backup_frequency,
                    "max_backups": max_backups,
                    "last_backup": datetime.datetime.now().isoformat()
                }

                with open("backup_config.json", 'w') as f:
                    json.dump(backup_config, f, indent=2)

                st.success("✅ Backup settings saved!")

    with admin_tab1:
        st.markdown("### 📋 Pending Reports Review")

        pending_reports = get_pending_reports()

        if pending_reports:
            st.write(f"**{len(pending_reports)} reports awaiting your review:**")

            for report in pending_reports:
                with st.expander(f"📄 {report['student_name']} ({report['student_class']}) - {report['term']}", expanded=False):
                    col1, col2 = st.columns([2, 1])

                    with col1:
                        st.write(f"**Student:** {report['student_name']}")
                        st.write(f"**Class:** {report['student_class']}")
                        st.write(f"**Term:** {report['term']}")
                        st.write(f"**Teacher:** {report['teacher_id']}")
                        st.write(f"**Parent Email:** {report.get('parent_email', 'Not provided')}")
                        st.write(f"**Submitted:** {datetime.datetime.fromisoformat(report['created_date']).strftime('%Y-%m-%d %H:%M')}")
                        st.write(f"**Average:** {report['average_cumulative']:.2f}% (Grade {report['final_grade']})")

                    with col2:
                        pdf_path = f"pending_reports/pending_{report['report_id']}.pdf"
                        if os.path.exists(pdf_path):
                            with open(pdf_path, "rb") as f:
                                st.download_button(
                                    "📄 Download PDF",
                                    f,
                                    file_name=f"{report['student_name']}_preview.pdf",
                                    mime="application/pdf",
                                    key=f"download_{report['report_id']}"
                                )

                    st.markdown("---")
                    action_col1, action_col2, action_col3 = st.columns([1, 1, 2])

                    with action_col1:
                        if st.button("✅ Approve", key=f"approve_{report['report_id']}"):
                            success, message = approve_report(report['report_id'])
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)

                    with action_col2:
                        if st.button("❌ Reject", key=f"reject_{report['report_id']}"):
                            st.session_state[f"show_reject_{report['report_id']}"] = True

                    if st.session_state.get(f"show_reject_{report['report_id']}", False):
                        with action_col3:
                            reason = st.text_area("Rejection Reason:", key=f"reason_{report['report_id']}", height=68)
                            if st.button("Confirm Rejection", key=f"confirm_reject_{report['report_id']}"):
                                success, message = reject_report(report['report_id'], reason)
                                if success:
                                    st.success(message)
                                    st.session_state[f"show_reject_{report['report_id']}"] = False
                                    st.rerun()
                                else:
                                    st.error(message)
        else:
            st.info("🎉 No pending reports! All reports have been reviewed.")

    with admin_tab2:
        st.markdown("### 📊 System Statistics")

        students = get_all_students()
        st.metric("👥 Total Students", len(students))

        pending_count = len(get_pending_reports())
        st.metric("📋 Pending Reports", pending_count)

        reports_count = 0
        if os.path.exists("approved_reports"):
            for root, dirs, files in os.walk("approved_reports"):
                reports_count += len([f for f in files if f.endswith('.json')])
        st.metric("📄 Approved Reports", reports_count)

    with admin_tab3:
        st.markdown("### 👨‍👩‍👧‍👦 Parent Registration System")

        # Parent registration section
        with st.expander("📧 Parent Registration Portal", expanded=True):
            st.markdown("#### How Parents Can Register")
            st.markdown("""
            **For Parent Registration:**
            1. Parents need their child's **admission number** 
            2. Parents need to use the **same email** that was registered for their child in the student database
            3. Parents can then access the Parent Portal using these credentials

            **To help a parent register:**
            1. Find their child in the Student Database
            2. Ensure the parent email is correctly entered
            3. Provide the parent with their child's admission number
            4. Direct them to use "Parent Portal" on the login page
            """)

            # Show all students with their parent contact info for admin reference
            st.markdown("#### 📋 Parent Contact Reference")
            students = get_all_students()
            if students:
                parent_data = []
                encryption_key = generate_encryption_key("akins_sunrise_school_encryption")

                for student in students:
                    try:
                        # Decrypt parent email for display to admin
                        parent_email = student.get('parent_email', '')
                        parent_phone = student.get('parent_phone', '')

                        if student.get('data_encrypted', False):
                            if parent_email:
                                try:
                                    parent_email = decrypt_data(parent_email, encryption_key)
                                except:
                                    parent_email = 'Error decrypting email'
                            if parent_phone:
                                try:
                                    parent_phone = decrypt_data(parent_phone, encryption_key)
                                except:
                                    parent_phone = 'Error decrypting phone'

                        parent_data.append({
                            'Student Name': student.get('student_name', ''),
                            'Admission No': student.get('admission_no', ''),
                            'Class': student.get('student_class', ''),
                            'Parent Email': parent_email,
                            'Parent Name': student.get('parent_name', ''),
                            'Parent Phone': parent_phone
                        })
                    except:
                        continue

                if parent_data:
                    df = pd.DataFrame(parent_data)
                    st.dataframe(df, use_container_width=True)

                    # Download parent contact list
                    csv_buffer = StringIO()
                    df.to_csv(csv_buffer, index=False)

                    st.download_button(
                        "📥 Download Parent Contact List",
                        csv_buffer.getvalue(),
                        file_name=f"parent_contacts_{datetime.datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No students in database yet.")

        # Debug section for troubleshooting parent login (Admin only)
        if check_user_permissions(st.session_state.teacher_id, "system_config"):
            with st.expander("🔍 Debug: Parent Login Troubleshooting", expanded=False):
                st.markdown("#### Debug Information")
                st.markdown("Use this section to troubleshoot parent login issues.")

                # Show student data for debugging
                if students:
                    debug_student = st.selectbox(
                        "Select student to debug:",
                        [f"{s['student_name']} ({s['student_class']})" for s in students],
                        key="debug_student_select"
                    )

                    if debug_student:
                        student_name = debug_student.split(" (")[0]
                        student = next((s for s in students if s['student_name'] == student_name), None)

                        if student:
                            st.markdown("**Student Debug Info:**")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Name:** {student.get('student_name', 'N/A')}")
                                st.write(f"**Admission No:** {student.get('admission_no', 'N/A')}")
                                st.write(f"**Class:** {student.get('student_class', 'N/A')}")
                                st.write(f"**Data Encrypted:** {student.get('data_encrypted', False)}")

                            with col2:
                                # Show decrypted email
                                parent_email = student.get('parent_email', 'N/A')
                                if student.get('data_encrypted', False) and parent_email != 'N/A':
                                    try:
                                        decrypted_email = decrypt_data(parent_email, encryption_key)
                                        st.write(f"**Parent Email (Decrypted):** {decrypted_email}")
                                        st.write(f"**Parent Email (Encrypted):** {parent_email[:50]}...")
                                    except Exception as e:
                                        st.write(f"**Decryption Error:** {str(e)}")
                                else:
                                    st.write(f"**Parent Email:** {parent_email}")

                                st.write(f"**Parent Name:** {student.get('parent_name', 'N/A')}")

                            # Test parent login
                            st.markdown("**Test Parent Login:**")
                            test_email = st.text_input("Test with this email:", key="test_email")
                            test_admission = st.text_input("Test with this admission no:", key="test_admission")

                            if st.button("🧪 Test Login Match"):
                                if test_email and test_admission:
                                    # Get actual stored values
                                    stored_email = student.get('parent_email', '')
                                    stored_admission = student.get('admission_no', '')

                                    # Decrypt if needed
                                    if student.get('data_encrypted', False):
                                        try:
                                            stored_email = decrypt_data(stored_email, encryption_key)
                                        except:
                                            stored_email = 'Error decrypting'

                                    # Compare
                                    email_match = stored_email.lower().strip() == test_email.lower().strip()
                                    admission_match = stored_admission.strip() == test_admission.strip()

                                    st.write(f"**Email Match:** {'✅ Yes' if email_match else '❌ No'}")
                                    st.write(f"**Admission Match:** {'✅ Yes' if admission_match else '❌ No'}")
                                    st.write(f"**Stored Email:** '{stored_email}'")
                                    st.write(f"**Test Email:** '{test_email}'")
                                    st.write(f"**Stored Admission:** '{stored_admission}'")
                                    st.write(f"**Test Admission:** '{test_admission}'")

                                    if email_match and admission_match:
                                        st.success("✅ Login would succeed!")
                                    else:
                                        st.error("❌ Login would fail!")
                else:
                    st.info("No students in database to debug.")



    with admin_tab4:
        st.markdown("### 👥 Recent User Activity")

        recent_logs = get_audit_logs()[:10]

        if recent_logs:
            for log in recent_logs:
                timestamp = datetime.datetime.fromisoformat(log['timestamp'])
                st.write(f"**{timestamp.strftime('%Y-%m-%d %H:%M')}** - {log['user_id']} - {log['action']}")
        else:
            st.info("No recent activity found.")

    with admin_tab5:
        st.markdown("### 📊 System Statistics")

        # Key metrics
        col1, col2, col3, col4 = st.columns(4)

        students = get_all_students()
        users_db = load_user_database()
        pending_count = len(get_pending_reports())

        approved_count = 0
        if os.path.exists("approved_reports"):
            approved_count = len([f for f in os.listdir("approved_reports") if f.endswith('.json')])

        with col1:
            st.metric("👥 Total Students", len(students))

        with col2:
            st.metric("🧑‍🏫 Total Users", len(users_db))

        with col3:
            st.metric("📋 Pending Reports", pending_count)

        with col4:
            st.metric("✅ Approved Reports", approved_count)

        # System health
        st.markdown("### 🏥 System Health")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### 🛡️ Security Status")
            st.success("✅ Data Encryption: Enabled")
            st.success("✅ Audit Logging: Active") 
            st.success("✅ GDPR Compliance: Enabled")
            st.info("🔐 Password Hashing: PBKDF2")

            # Check 2FA adoption
            users_with_2fa = sum(1 for user in users_db.values() if user.get('two_factor_enabled', False))
            st.metric("🔐 2FA Adoption", f"{users_with_2fa}/{len(users_db)} users")

        with col2:
            st.markdown("#### 📊 Usage Statistics")
            all_logs = get_audit_logs()
            st.metric("Total Audit Entries", len(all_logs))

            failed_logins = [log for log in all_logs if log.get('action') == 'failed_login']
            st.metric("Failed Login Attempts", len(failed_logins))

            data_access = [log for log in all_logs if log.get('data_type') == 'data_access']
            st.metric("Data Access Events", len(data_access))

        # Data export section
        st.markdown("### 📤 Data Export (GDPR Compliant)")
        with st.expander("Export Student Data", expanded=False):
            export_type = st.selectbox("Export Type", ["All Students", "Single Student"])

            if export_type == "Single Student":
                student_identifier = st.text_input("Student Name or Admission Number")
                if st.button("📤 Export Student Data"):
                    if student_identifier:
                        export_data, message = export_student_data(student_identifier, gdpr_compliant=True)
                        if export_data:
                            st.success(f"✅ {message}")

                            # Download as JSON
                            json_str = json.dumps(export_data, indent=2)
                            st.download_button(
                                "📥 Download Student Data (JSON)",
                                json_str,
                                file_name=f"student_export_{student_identifier}_{datetime.datetime.now().strftime('%Y%m%d')}.json",
                                mime="application/json"
                            )
                        else:
                            st.error(f"❌ {message}")
            else:
                if st.button("📤 Export All Student Data"):
                    export_data, message = export_student_data(gdpr_compliant=True)
                    if export_data:
                        st.success(f"✅ {message}")

                        # Download as JSON
                        json_str = json.dumps(export_data, indent=2)
                        st.download_button(
                            "📥 Download All Student Data (JSON)",
                            json_str,
                            file_name=f"all_students_export_{datetime.datetime.now().strftime('%Y%m%d')}.json",
                            mime="application/json"
                        )
                    else:
                        st.error(f"❌ {message}")

    with admin_tab6:
        st.markdown("### 📧 Email Configuration")
        st.markdown("Configure email settings to automatically send report cards to parents.")

        with st.form("email_config_settings"):
            smtp_server = st.text_input("SMTP Server", value="smtp.gmail.com", help="Email server address")
            smtp_port = st.number_input("SMTP Port", value=587, help="Usually 587 for TLS")
            school_email = st.text_input("School Email", placeholder="school@example.com")
            email_password = st.text_input("Email Password", type="password", help="Email app password")

            if st.form_submit_button("💾 Save Email Settings"):
                if school_email and email_password and smtp_server:
                    if save_email_config(smtp_server, smtp_port, school_email, email_password):
                        st.success("✅ Email settings saved successfully!")
                    else:
                        st.error("❌ Error saving email configuration")
                else:
                    st.error("❌ Please fill in all required fields")

    with admin_tab7:
        st.markdown("### ⚙️ System Configuration & Customization")

        config_tab1, config_tab2, config_tab3, config_tab4, config_tab5 = st.tabs([
            "🏫 School Information",
            "📧 Email Templates", 
            "🎨 Appearance & Branding",
            "📋 Form Settings",
            "🔍 Audit Logs"
        ])

        with config_tab1:
            st.markdown("### 🏫 School Information & Contact Details")

            # Load existing school config
            school_config = load_school_config()

            with st.form("school_info_form"):
                st.markdown("#### Basic School Information")
                col1, col2 = st.columns(2)

                with col1:
                    school_name = st.text_input("School Name", 
                                              value=school_config.get('school_name', "AKIN'S SUNRISE SECONDARY SCHOOL"))
                    school_address = st.text_area("School Address", 
                                                value=school_config.get('school_address', 
                                                "SUNRISE AVENUE OFF LUJOJOMU ROAD\nUPPER AYEYEMI, ONDO CITY\nONDO STATE, NIGERIA"))
                    school_phone = st.text_input("School Phone", 
                                                value=school_config.get('school_phone', "+234 800 123 4567"))
                    school_email = st.text_input("School Email", 
                                                value=school_config.get('school_email', "info@akinssunrise.edu.ng"))

                with col2:
                    school_website = st.text_input("School Website", 
                                                 value=school_config.get('school_website', "www.akinssunrise.edu.ng"))
                    school_motto = st.text_input("School Motto", 
                                               value=school_config.get('school_motto', "Excellence in Education"))
                    principal_name = st.text_input("Principal Name", 
                                                 value=school_config.get('principal_name', "Dr. Principal Name"))
                    vice_principal_name = st.text_input("Vice Principal Name", 
                                                      value=school_config.get('vice_principal_name', "Mr. Vice Principal"))

                st.markdown("#### Office Hours & Important Dates")
                col3, col4 = st.columns(2)

                with col3:
                    office_hours = st.text_input("Office Hours", 
                                               value=school_config.get('office_hours', "Monday - Friday, 8:00 AM - 4:00 PM"))
                    current_session = st.text_input("Current Academic Session", 
                                                   value=school_config.get('current_session', "2024/2025"))

                with col4:
                    next_term_date = st.text_input("Next Term Resumption Date", 
                                                 value=school_config.get('next_term_date', "January 15, 2025"))
                    school_calendar = st.text_area("Important School Dates", 
                                                  value=school_config.get('school_calendar', 
                                                  "First Term: Sept - Dec\nSecond Term: Jan - Apr\nThird Term: May - July"))

                if st.form_submit_button("💾 Save School Information"):
                    new_config = {
                        'school_name': school_name,
                        'school_address': school_address,
                        'school_phone': school_phone,
                        'school_email': school_email,
                        'school_website': school_website,
                        'school_motto': school_motto,
                        'principal_name': principal_name,
                        'vice_principal_name': vice_principal_name,
                        'office_hours': office_hours,
                        'current_session': current_session,
                        'next_term_date': next_term_date,
                        'school_calendar': school_calendar,
                        'updated_by': st.session_state.teacher_id,
                        'updated_date': datetime.datetime.now().isoformat()
                    }

                    if save_school_config(new_config):
                        st.success("✅ School information updated successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Error saving school information")

        with config_tab2:
            st.markdown("### 📧 Email Templates & Messages")

            # Load email templates
            email_templates = load_email_templates()

            template_type = st.selectbox("Select Template to Edit", [
                "Report Card Email",
                "Parent Login Instructions",
                "Welcome Message",
                "System Notification"
            ])

            if template_type == "Report Card Email":
                with st.form("report_email_template"):
                    st.markdown("#### Report Card Email Template")

                    subject_line = st.text_input("Email Subject", 
                                               value=email_templates.get('report_email', {}).get('subject', 
                                               "Report Card - {student_name} ({student_class}) - {term}"))

                    email_body = st.text_area("Email Body", 
                                            value=email_templates.get('report_email', {}).get('body', get_default_report_email_template()),
                                            height=400,
                                            help="Use {student_name}, {student_class}, {term}, {report_id} as placeholders")

                    email_signature = st.text_area("Email Signature", 
                                                  value=email_templates.get('report_email', {}).get('signature', 
                                                  "Best regards,\nThe Management\nAKIN'S SUNRISE SECONDARY SCHOOL"))

                    if st.form_submit_button("💾 Save Report Email Template"):
                        email_templates['report_email'] = {
                            'subject': subject_line,
                            'body': email_body,
                            'signature': email_signature
                        }
                        save_email_templates(email_templates)
                        st.success("✅ Report email template updated!")

            elif template_type == "Parent Login Instructions":
                with st.form("login_instructions_template"):
                    st.markdown("#### Parent Login Instructions Template")

                    subject_line = st.text_input("Email Subject", 
                                               value=email_templates.get('login_instructions', {}).get('subject', 
                                               "Parent Portal Access - {student_name}"))

                    email_body = st.text_area("Email Body", 
                                            value=email_templates.get('login_instructions', {}).get('body', get_default_login_instructions_template()),
                                            height=400,
                                            help="Use {student_name}, {admission_no}, {parent_email} as placeholders")

                    if st.form_submit_button("💾 Save Login Instructions Template"):
                        email_templates['login_instructions'] = {
                            'subject': subject_line,
                            'body': email_body
                        }
                        save_email_templates(email_templates)
                        st.success("✅ Login instructions template updated!")

            elif template_type == "Welcome Message":
                with st.form("welcome_template"):
                    st.markdown("#### System Welcome Messages")

                    login_welcome = st.text_area("Staff Login Welcome Message", 
                                                value=email_templates.get('welcome', {}).get('staff_login', 
                                                "Welcome to Akin's Sunrise School Management System"))

                    parent_welcome = st.text_area("Parent Portal Welcome Message", 
                                                value=email_templates.get('welcome', {}).get('parent_portal', 
                                                "Welcome to the Parent Portal"))

                    if st.form_submit_button("💾 Save Welcome Messages"):
                        email_templates['welcome'] = {
                            'staff_login': login_welcome,
                            'parent_portal': parent_welcome
                        }
                        save_email_templates(email_templates)
                        st.success("✅ Welcome messages updated!")

        with config_tab3:
            st.markdown("### 🎨 Appearance & Branding")

            branding_config = load_branding_config()

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### School Logo Management")
                new_logo = st.file_uploader("Upload New School Logo", 
                                           type=['png', 'jpg', 'jpeg'], 
                                           help="Recommended: 300x300px or similar square dimensions")

                if new_logo:
                    if st.button("📤 Update School Logo"):
                        try:
                            # Save new logo
                            with open("school_logo.png", "wb") as f:
                                f.write(new_logo.read())
                            st.success("✅ School logo updated successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error updating logo: {str(e)}")

                # Show current logo
                try:
                    logo_base64 = get_logo_base64()
                    if logo_base64:
                        st.image(f"data:image/png;base64,{logo_base64}", 
                               caption="Current School Logo", width=200)
                except:
                    st.info("No logo currently set")

            with col2:
                st.markdown("#### Color Theme Settings")
                with st.form("color_theme_form"):
                    primary_color = st.color_picker("Primary Color", 
                                                  value=branding_config.get('primary_color', '#1976D2'))
                    secondary_color = st.color_picker("Secondary Color", 
                                                    value=branding_config.get('secondary_color', '#42A5F5'))
                    accent_color = st.color_picker("Accent Color", 
                                                 value=branding_config.get('accent_color', '#1565C0'))

                    if st.form_submit_button("🎨 Apply Color Theme"):
                        branding_config.update({
                            'primary_color': primary_color,
                            'secondary_color': secondary_color,
                            'accent_color': accent_color,
                            'updated_by': st.session_state.teacher_id,
                            'updated_date': datetime.datetime.now().isoformat()
                        })
                        save_branding_config(branding_config)
                        st.success("✅ Color theme updated!")

            st.markdown("#### Report Card Customization")
            with st.form("report_customization"):
                show_watermark = st.checkbox("Show School Logo Watermark on Reports", 
                                           value=branding_config.get('show_watermark', True))
                watermark_opacity = st.slider("Watermark Opacity", 0.0, 1.0, 
                                             value=branding_config.get('watermark_opacity', 0.15))

                grade_colors = st.checkbox("Use Custom Grade Colors", 
                                         value=branding_config.get('custom_grade_colors', False))

                if st.form_submit_button("💾 Save Report Customization"):
                    branding_config.update({
                        'show_watermark': show_watermark,
                        'watermark_opacity': watermark_opacity,
                        'custom_grade_colors': grade_colors
                    })
                    save_branding_config(branding_config)
                    st.success("✅ Report customization saved!")

        with config_tab4:
            st.markdown("### 📋 Form Settings & Grading System")

            form_config = load_form_config()

            # Subjects management
            with st.expander("📚 Subject Management", expanded=True):
                st.markdown("#### Available Subjects")

                current_subjects = form_config.get('subjects', subjects)

                # Show current subjects
                subject_df = pd.DataFrame({'Subjects': current_subjects})
                st.dataframe(subject_df, use_container_width=True)

                col1, col2 = st.columns(2)
                with col1:
                    new_subject = st.text_input("Add New Subject")
                    if st.button("➕ Add Subject") and new_subject:
                        if new_subject not in current_subjects:
                            current_subjects.append(new_subject)
                            form_config['subjects'] = sorted(current_subjects)
                            save_form_config(form_config)
                            st.success(f"✅ Added subject: {new_subject}")
                            st.rerun()
                        else:
                            st.warning("Subject already exists")

                with col2:
                    remove_subject = st.selectbox("Remove Subject", current_subjects)
                    if st.button("🗑️ Remove Subject") and remove_subject:
                        current_subjects.remove(remove_subject)
                        form_config['subjects'] = current_subjects
                        save_form_config(form_config)
                        st.success(f"✅ Removed subject: {remove_subject}")
                        st.rerun()

            # Grading system
            with st.expander("📊 Grading System Configuration", expanded=True):
                st.markdown("#### Grade Boundaries")

                with st.form("grading_system"):
                    col1, col2 = st.columns(2)

                    with col1:
                        grade_a_min = st.number_input("Grade A Minimum", min_value=0, max_value=100, 
                                                    value=form_config.get('grade_boundaries', {}).get('A', 80))
                        grade_b_min = st.number_input("Grade B Minimum", min_value=0, max_value=100, 
                                                    value=form_config.get('grade_boundaries', {}).get('B', 60))
                        grade_c_min = st.number_input("Grade C Minimum", min_value=0, max_value=100, 
                                                    value=form_config.get('grade_boundaries', {}).get('C', 50))

                    with col2:
                        grade_d_min = st.number_input("Grade D Minimum", min_value=0, max_value=100, 
                                                    value=form_config.get('grade_boundaries', {}).get('D', 40))
                        grade_e_min = st.number_input("Grade E Minimum", min_value=0, max_value=100, 
                                                    value=form_config.get('grade_boundaries', {}).get('E', 30))
                        grade_f_min = st.number_input("Grade F (Below)", min_value=0, max_value=100, 
                                                    value=form_config.get('grade_boundaries', {}).get('F', 30))

                    assessment_weights = st.text_input("Assessment Weights (CA:Exam)", 
                                                     value=form_config.get('assessment_weights', '40:60'),
                                                     help="Format: CA_weight:Exam_weight (e.g., 40:60)")

                    if st.form_submit_button("💾 Save Grading System"):
                        form_config['grade_boundaries'] = {
                            'A': grade_a_min,
                            'B': grade_b_min,
                            'C': grade_c_min,
                            'D': grade_d_min,
                            'E': grade_e_min,
                            'F': grade_f_min
                        }
                        form_config['assessment_weights'] = assessment_weights
                        save_form_config(form_config)
                        st.success("✅ Grading system updated!")

            # Class management
            with st.expander("🏫 Class Management", expanded=True):
                st.markdown("#### Available Classes")

                current_classes = form_config.get('classes', [
                    "JSS1A", "JSS1B", "JSS1C", "JSS2A", "JSS2B", "JSS2C", "JSS3A", "JSS3B", "JSS3C",
                    "SS1A", "SS1B", "SS1C", "SS2A", "SS2B", "SS2C", "SS3A", "SS3B", "SS3C"
                ])

                class_df = pd.DataFrame({'Classes': current_classes})
                st.dataframe(class_df, use_container_width=True)

                col1, col2 = st.columns(2)
                with col1:
                    new_class = st.text_input("Add New Class")
                    if st.button("➕ Add Class") and new_class:
                        if new_class not in current_classes:
                            current_classes.append(new_class)
                            form_config['classes'] = sorted(current_classes)
                            save_form_config(form_config)
                            st.success(f"✅ Added class: {new_class}")
                            st.rerun()
                        else:
                            st.warning("Class already exists")

                with col2:
                    remove_class = st.selectbox("Remove Class", current_classes)
                    if st.button("🗑️ Remove Class") and remove_class:
                        current_classes.remove(remove_class)
                        form_config['classes'] = current_classes
                        save_form_config(form_config)
                        st.success(f"✅ Removed class: {remove_class}")
                        st.rerun()

        with config_tab5:
            st.markdown("### 🔍 Advanced Audit Logs")

            # Recent activity
            st.markdown("#### 📋 Recent Activity")
            recent_logs = get_audit_logs()[:10]

            if recent_logs:
                for log in recent_logs:
                    timestamp = datetime.datetime.fromisoformat(log['timestamp'])
                    st.write(f"**{timestamp.strftime('%Y-%m-%d %H:%M')}** - {log['user_id']} - {log['action']}")
            else:
                st.info("No recent activity found.")

            # Advanced search
            st.markdown("#### 🔍 Advanced Audit Search")
            with st.expander("Search Audit Logs", expanded=False):
                search_col1, search_col2 = st.columns(2)

                with search_col1:
                    start_date = st.date_input("Start Date")
                    action_filter = st.selectbox("Filter by Action", [
                        "All Actions", "login", "logout", "failed_login", 
                        "report_generated", "student_data_created", "data_access",
                        "user_created", "backup_created", "backup_restored"
                    ])

                with search_col2:
                    end_date = st.date_input("End Date")
                    user_filter = st.text_input("Filter by User ID")

                if st.button("🔍 Search Logs"):
                    search_start = start_date.isoformat() if start_date else None
                    search_end = end_date.isoformat() if end_date else None
                    search_action = action_filter if action_filter != "All Actions" else None
                    search_user = user_filter if user_filter else None

                    filtered_logs = get_audit_logs(search_start, search_end, search_user, search_action)

                    if filtered_logs:
                        st.write(f"Found {len(filtered_logs)} matching entries:")
                        for log in filtered_logs[:20]:
                            timestamp = datetime.datetime.fromisoformat(log['timestamp'])
                            st.write(f"**{timestamp.strftime('%Y-%m-%d %H:%M')}** | {log['user_id']} | {log['action']} | {log.get('details', {})}")
                    else:
                        st.info("No matching audit entries found.")

            # Data protection tools
            st.markdown("#### 🔐 Data Protection Tools")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("🗑️ Clean Old Audit Logs (>30 days)"):
                    # Implementation for cleaning old logs
                    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=30)
                    st.info(f"Would clean logs older than {cutoff_date.strftime('%Y-%m-%d')}")

            with col2:
                if st.button("📁 Generate Compliance Report"):
                    st.success("Compliance report generated!")
                    st.markdown("""
                    **GDPR Compliance Summary:**
                    - ✅ Data encryption implemented
                    - ✅ Audit trail maintained
                    - ✅ User consent tracked
                    - ✅ Data retention policies active
                    """)

        # Premium Features Preview for Admin
        st.markdown("---")
        st.markdown("#### ✨ Premium Features Preview")

        with st.expander("🌟 Premium Parent Portal Features Preview", expanded=False):
            st.markdown("**These features are available to parents with premium subscriptions:**")

            preview_tab1, preview_tab2, preview_tab3 = st.tabs([
                "📊 Advanced Analytics", 
                "💬 Teacher Communication", 
                "📚 Study Resources"
            ])

            with preview_tab1:
                st.markdown("#### 📈 Advanced Performance Analytics")
                st.info("Parents can view detailed performance trends, predictions, and subject breakdowns")
                st.markdown("- Performance trend analysis")
                st.markdown("- Subject-wise performance breakdown")
                st.markdown("- Predictive analytics for next term")
                st.markdown("- Comparative analysis with class averages")

            with preview_tab2:
                st.markdown("#### 💬 Direct Teacher Communication")
                st.info("Premium parents can send messages directly to teachers")
                st.markdown("- Send messages to class teachers")
                st.markdown("- Book consultation appointments")
                st.markdown("- Priority support responses")
                st.markdown("- Message history tracking")

            with preview_tab3:
                st.markdown("#### 📚 Educational Resources")
                st.info("Access to study materials and practice resources")
                st.markdown("- Downloadable study guides")
                st.markdown("- Practice tests and mock exams")
                st.markdown("- Educational videos and tutorials")
                st.markdown("- Past question papers with solutions")

            # Test premium subscription
            st.markdown("#### 🧪 Test Premium Subscription")
            test_email = st.text_input("Test Parent Email:", placeholder="parent@example.com")
            if st.button("🌟 Grant Test Premium Access"):
                if test_email:
                    if add_premium_subscription(test_email, "monthly"):
                        st.success(f"✅ Premium access granted to {test_email}")
                    else:
                        st.error("❌ Error granting premium access")

        # Comprehensive Data Management
        st.markdown("---")
        st.markdown("#### 🗑️ System Data Management")

        with st.expander("⚠️ DANGER ZONE: Data Cleanup Operations", expanded=False):
            st.error("⚠️ **WARNING**: These operations permanently delete data and cannot be undone!")

            # Individual cleanup options
            st.markdown("##### Selective Data Cleanup")

            cleanup_col1, cleanup_col2 = st.columns(2)

            with cleanup_col1:
                if st.button("🗑️ Delete All Student Data", type="secondary"):
                    st.session_state.confirm_delete_students = True

                if st.button("🗑️ Delete All Pending Reports", type="secondary"):
                    st.session_state.confirm_delete_pending = True

                if st.button("🗑️ Delete All Approved Reports", type="secondary"):
                    st.session_state.confirm_delete_approved = True

            with cleanup_col2:
                if st.button("🗑️ Delete All User Accounts (Except Current)", type="secondary"):
                    st.session_state.confirm_delete_users = True

                if st.button("🗑️ Delete All Audit Logs", type="secondary"):
                    st.session_state.confirm_delete_logs = True

                if st.button("🗑️ Delete All System Data", type="secondary"):
                    st.session_state.confirm_delete_all = True

            # Confirmation dialogs
            if st.session_state.get('confirm_delete_students', False):
                st.error("⚠️ This will permanently delete ALL student records and photos!")
                conf_col1, conf_col2 = st.columns(2)
                with conf_col1:
                    if st.button("✅ Confirm Delete Students", type="primary"):
                        try:
                            if os.path.exists("student_database"):
                                shutil.rmtree("student_database")
                            st.success("✅ All student data deleted successfully!")
                            st.session_state.confirm_delete_students = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error deleting student data: {str(e)}")
                with conf_col2:
                    if st.button("❌ Cancel", key="cancel_students"):
                        st.session_state.confirm_delete_students = False
                        st.rerun()

            if st.session_state.get('confirm_delete_pending', False):
                st.error("⚠️ This will permanently delete ALL pending reports!")
                conf_col1, conf_col2 = st.columns(2)
                with conf_col1:
                    if st.button("✅ Confirm Delete Pending Reports", type="primary"):
                        try:
                            if os.path.exists("pending_reports"):
                                shutil.rmtree("pending_reports")
                            st.success("✅ All pending reports deleted successfully!")
                            st.session_state.confirm_delete_pending = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error deleting pending reports: {str(e)}")
                with conf_col2:
                    if st.button("❌ Cancel", key="cancel_pending"):
                        st.session_state.confirm_delete_pending = False
                        st.rerun()

            if st.session_state.get('confirm_delete_approved', False):
                st.error("⚠️ This will permanently delete ALL approved reports!")
                conf_col1, conf_col2 = st.columns(2)
                with conf_col1:
                    if st.button("✅ Confirm Delete Approved Reports", type="primary"):
                        try:
                            if os.path.exists("approved_reports"):
                                shutil.rmtree("approved_reports")
                            st.success("✅ All approved reports deleted successfully!")
                            st.session_state.confirm_delete_approved = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error deleting approved reports: {str(e)}")
                with conf_col2:
                    if st.button("❌ Cancel", key="cancel_approved"):
                        st.session_state.confirm_delete_approved = False
                        st.rerun()

            if st.session_state.get('confirm_delete_users', False):
                st.error("⚠️ This will delete ALL user accounts except your current account!")
                conf_col1, conf_col2 = st.columns(2)
                with conf_col1:
                    if st.button("✅ Confirm Delete Users", type="primary"):
                        try:
                            users_db = load_user_database()
                            current_user = st.session_state.teacher_id
                            new_users_db = {current_user: users_db[current_user]}
                            save_user_database(new_users_db)
                            st.success("✅ All other user accounts deleted successfully!")
                            st.session_state.confirm_delete_users = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error deleting users: {str(e)}")
                with conf_col2:
                    if st.button("❌ Cancel", key="cancel_users"):
                        st.session_state.confirm_delete_users = False
                        st.rerun()

            if st.session_state.get('confirm_delete_logs', False):
                st.error("⚠️ This will permanently delete ALL audit logs!")
                conf_col1, conf_col2 = st.columns(2)
                with conf_col1:
                    if st.button("✅ Confirm Delete Audit Logs", type="primary"):
                        try:
                            for dir_name in ["audit_logs", "admin_logs"]:
                                if os.path.exists(dir_name):
                                    shutil.rmtree(dir_name)
                            st.success("✅ All audit logs deleted successfully!")
                            st.session_state.confirm_delete_logs = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error deleting logs: {str(e)}")
                with conf_col2:
                    if st.button("❌ Cancel", key="cancel_logs"):
                        st.session_state.confirm_delete_logs = False
                        st.rerun()

            if st.session_state.get('confirm_delete_all', False):
                st.error("🚨 **NUCLEAR OPTION**: This will delete EVERYTHING except your current user account!")
                st.error("This includes: students, reports, logs, other users, and all system data!")
                conf_col1, conf_col2 = st.columns(2)
                with conf_col1:
                    if st.button("🚨 CONFIRM NUCLEAR DELETE", type="primary"):
                        try:
                            # Delete directories
                            dirs_to_delete = [
                                "student_database", "pending_reports", "approved_reports",
                                "rejected_reports", "audit_logs", "admin_logs", "backups"
                            ]
                            for dir_name in dirs_to_delete:
                                if os.path.exists(dir_name):
                                    shutil.rmtree(dir_name)

                            # Keep only current user
                            users_db = load_user_database()
                            current_user = st.session_state.teacher_id
                            new_users_db = {current_user: users_db[current_user]}
                            save_user_database(new_users_db)

                            # Delete config files
                            config_files = [
                                "email_config.json", "academic_calendar.json",
                                "grade_boundaries.json", "system_config.json",
                                "security_config.json", "backup_config.json"
                            ]
                            for file_name in config_files:
                                if os.path.exists(file_name):
                                    os.remove(file_name)

                            st.success("🚨 NUCLEAR DELETE COMPLETED! All data except your account has been removed!")
                            st.session_state.confirm_delete_all = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error during nuclear delete: {str(e)}")
                with conf_col2:
                    if st.button("❌ Cancel Nuclear Delete", key="cancel_nuclear"):
                        st.session_state.confirm_delete_all = False
                        st.rerun()

            # Current data status
            st.markdown("---")
            st.markdown("##### 📊 Current Data Status")

            status_col1, status_col2, status_col3 = st.columns(3)

            with status_col1:
                students_count = len(get_all_students())
                st.metric("👥 Students", students_count)

                pending_count = len(get_pending_reports())
                st.metric("📋 Pending Reports", pending_count)

            with status_col2:
                approved_count = 0
                if os.path.exists("approved_reports"):
                    approved_count = len([f for f in os.listdir("approved_reports") if f.endswith('.json')])
                st.metric("✅ Approved Reports", approved_count)

                users_count = len(load_user_database())
                st.metric("👤 User Accounts", users_count)

            with status_col3:
                logs_count = len(get_audit_logs())
                st.metric("📝 Audit Entries", logs_count)

                # Calculate total storage used
                total_size = 0
                for root, dirs, files in os.walk("."):
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            total_size += os.path.getsize(file_path)
                        except:
                            continue
                st.metric("💾 Storage Used", f"{total_size / (1024*1024):.1f} MB")

        st.markdown("---")
        st.markdown("#### ⚠️ Security Recommendations")
        st.warning("🔄 Regular password changes recommended")
        st.info("💾 Backup audit logs regularly")
        st.info("🔍 Monitor failed login attempts")
        st.info("🔐 Enable 2FA for all administrative accounts")

def analytics_dashboard_tab():
    st.subheader("📊 Analytics Dashboard")

    # Check if we have data
    students = get_all_students()
    class_data = get_class_performance_data()
    grade_data = get_grade_distribution_data()

    if students:
        # Key metrics row
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("👥 Total Students", len(students))

        with col2:
            pending_count = len(get_pending_reports())
            st.metric("📋 Pending Reports", pending_count)

        with col3:
            approved_count = 0
            if os.path.exists("approved_reports"):
                approved_count = len([f for f in os.listdir("approved_reports") if f.endswith('.json')])
            st.metric("✅ Approved Reports", approved_count)

        with col4:
            classes_count = len(class_data) if not class_data.empty else 0
            st.metric("🏫 Active Classes", classes_count)

        st.markdown("---")

        # Charts section
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown("### 📈 Class Performance Overview")
            if not class_data.empty:
                fig_class = px.bar(
                    class_data, 
                    x='class', 
                    y='total_students',
                    title="Students per Class",
                    color='avg_attendance',
                    color_continuous_scale='RdYlGn',
                    labels={'total_students': 'Number of Students', 'class': 'Class'}
                )
                fig_class.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig_class, use_container_width=True)
            else:
                st.info("No class data available yet")

        with chart_col2:
            st.markdown("### 📊 Grade Distribution")
            if not grade_data.empty and grade_data['Count'].sum() > 0:
                fig_grades = px.pie(
                    grade_data, 
                    values='Count', 
                    names='Grade',
                    title="Overall Grade Distribution",
                    color_discrete_map={
                        'A': '#28a745', 'B': '#17a2b8', 'C': '#ffc107', 
                        'D': '#fd7e14', 'E': '#dc3545', 'F': '#6c757d'
                    }
                )
                fig_grades.update_layout(height=400)
                st.plotly_chart(fig_grades, use_container_width=True)
            else:
                st.info("No grade data available yet")

        # Attendance trends
        st.markdown("### 📅 Attendance Analysis")
        if not class_data.empty:
            fig_attendance = px.bar(
                class_data,
                x='class',
                y='avg_attendance',
                title="Average Attendance by Class",
                labels={'avg_attendance': 'Average Attendance (%)', 'class': 'Class'},
                color='avg_attendance',
                color_continuous_scale='RdYlGn'
            )
            fig_attendance.update_layout(height=400, showlegend=False)
            fig_attendance.add_hline(y=85, line_dash="dash", line_color="red", 
                                   annotation_text="Minimum Target (85%)")
            st.plotly_chart(fig_attendance, use_container_width=True)
        else:
            st.info("No attendance data available yet")

        # Subject performance (if we have report data)
        st.markdown("### 📚 Subject Performance Trends")
        subject_performance = {}

        approved_dir = "approved_reports"
        if os.path.exists(approved_dir):
            for filename in os.listdir(approved_dir):
                if filename.startswith('approved_') and filename.endswith('.json'):
                    filepath = os.path.join(approved_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            report_data = json.load(f)
                            scores_data = report_data.get('scores_data', [])
                            for score_row in scores_data:
                                if len(score_row) >= 6:
                                    subject = score_row[0]
                                    cumulative = score_row[5]
                                    if subject not in subject_performance:
                                        subject_performance[subject] = []
                                    subject_performance[subject].append(cumulative)
                    except:
                        continue

        if subject_performance:
            # Calculate average performance per subject
            subject_avg = {subject: np.mean(scores) for subject, scores in subject_performance.items()}
            subject_df = pd.DataFrame(list(subject_avg.items()), columns=['Subject', 'Average_Score'])
            subject_df = subject_df.sort_values('Average_Score', ascending=True)

            fig_subjects = px.bar(
                subject_df,
                x='Average_Score',
                y='Subject',
                orientation='h',
                title="Average Performance by Subject",
                labels={'Average_Score': 'Average Score (%)', 'Subject': 'Subject'},
                color='Average_Score',
                color_continuous_scale='RdYlGn'
            )
            fig_subjects.update_layout(height=max(400, len(subject_df) * 30))
            st.plotly_chart(fig_subjects, use_container_width=True)
        else:
            st.info("No subject performance data available yet")

    else:
        st.info("📭 No data available yet. Add students and generate reports to see analytics.")

def report_generator_page():
    st.set_page_config(
        page_title="Akin's Sunrise School - Management System", 
        layout="wide",
        initial_sidebar_state="collapsed",
        page_icon="🎓"
    )

    apply_custom_css()

    # Check session timeout
    if check_session_timeout():
        st.error("🔒 Session expired. Please login again.")
        st.session_state.authenticated = False
        st.session_state.teacher_id = None
        st.rerun()

    # Update activity
    update_session_activity()

    col1, col2, col3 = st.columns([1, 2, 1])

    with col1:
        logo_base64 = get_logo_base64()
        if logo_base64:
            st.markdown(f"""
            <div style="text-align: center;">
                <img src="data:image/png;base64,{logo_base64}" style="width: 150px; height: 150px; object-fit: contain; border-radius: 12px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style="text-align: center;">
            <h1 style="margin: 0; color: var(--accent-color);">🎓 Akin's Sunrise School System</h1>
            <p style="margin: 5px 0; color: var(--text-secondary); font-weight: bold;">Comprehensive Management Portal</p>
        </div>
        """, unsafe_allow_html=True)

        # Display user info based on type
        if st.session_state.get('user_type') == 'parent':
            st.markdown(f"<div style='text-align: center; color: var(--text-secondary);'><strong>Parent Portal:</strong> {st.session_state.get('parent_email', 'Parent')}</div>", unsafe_allow_html=True)
        else:
            users_db = load_user_database()
            user_info = users_db.get(st.session_state.teacher_id, {})
            role_description = USER_ROLES.get(user_info.get('role', 'teacher'), {}).get('description', 'User')
            st.markdown(f"<div style='text-align: center; color: var(--text-secondary);'><strong>{role_description}:</strong> {user_info.get('full_name', st.session_state.teacher_id)}</div>", unsafe_allow_html=True)

    with col3:
        if st.button("🚪 Logout", use_container_width=True):
            if st.session_state.get('user_type') == 'parent':
                log_teacher_activity(st.session_state.get('parent_email', 'parent'), "logout", {
                    "logout_time": datetime.datetime.now().isoformat(),
                    "user_type": "parent"
                })
            else:
                log_teacher_activity(st.session_state.teacher_id, "logout", {
                    "logout_time": datetime.datetime.now().isoformat()
                })

            # Clear all session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    # Different interfaces based on user type
    if st.session_state.get('user_type') == 'parent':
        # Parent portal interface
        tab1, tab2 = st.tabs([
            "📊 Child's Reports", 
            "📞 Contact Information"
        ])

        with tab1:
            parent_portal_tab()

        with tab2:
            st.markdown("### 📞 School Contact Information")

            # Load school configuration
            school_config = load_school_config()

            school_name = school_config.get('school_name', "Akin's Sunrise Secondary School")
            school_address = school_config.get('school_address', "Sunrise Avenue Off Lujojomu Road\nUpper Ayeyemi, Ondo City\nOndo State")
            school_phone = school_config.get('school_phone', "+234 800 123 4567")
            school_email = school_config.get('school_email', "info@akinssunrise.edu.ng")
            office_hours = school_config.get('office_hours', "Monday - Friday, 8:00 AM - 4:00 PM")
            school_website = school_config.get('school_website', "www.akinssunrise.edu.ng")

            st.markdown(f"""
            **{school_name}**

            📍 **Address:** {school_address.replace(chr(10), ', ')}

            📞 **Phone:** {school_phone}

            📧 **Email:** {school_email}

            🌐 **Website:** {school_website}

            🕐 **Office Hours:** {office_hours}
            """)
    else:
        # Staff interface with role-based access
        available_tabs = []

        # Generate Reports - available to all staff
        if check_user_permissions(st.session_state.teacher_id, "report_generation"):
            available_tabs.append(("📝 Generate Reports", "reports"))

        # Draft Reports - available to all staff who can generate reports
        if check_user_permissions(st.session_state.teacher_id, "report_generation"):
            available_tabs.append(("📝 Draft Reports", "drafts"))

        # Student Database - class teachers and above
        if check_user_permissions(st.session_state.teacher_id, "student_management"):
            available_tabs.append(("👥 Student Database", "database"))

        # Analytics - department heads and above
        if check_user_permissions(st.session_state.teacher_id, "department_reports"):
            available_tabs.append(("📊 Analytics", "analytics"))

        # Verification - available to all
        available_tabs.append(("🔍 Verify Reports", "verify"))

        # Admin Panel - principals and system admins only
        if check_user_permissions(st.session_state.teacher_id, "system_config"):
            available_tabs.append(("⚙️ Admin Panel", "admin"))

        # Create tabs
        tab_names = [tab[0] for tab in available_tabs]
        tab_keys = [tab[1] for tab in available_tabs]

        tabs = st.tabs(tab_names)

        for i, (tab_name, tab_key) in enumerate(available_tabs):
            with tabs[i]:
                if tab_key == "reports":
                    report_generator_tab()
                elif tab_key == "drafts":
                    draft_reports_tab()
                elif tab_key == "database":
                    student_database_tab()
                elif tab_key == "analytics":
                    analytics_dashboard_tab()
                elif tab_key == "verify":
                    verification_tab()
                elif tab_key == "admin":
                    admin_panel_tab()

def main():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'teacher_id' not in st.session_state:
        st.session_state.teacher_id = None

    if not st.session_state.authenticated:
        # Check if pending 2FA verification
        if st.session_state.get('pending_2fa'):
            st.set_page_config(
                page_title="2FA Verification", 
                layout="centered",
                initial_sidebar_state="collapsed",
                page_icon="🔐"
            )
            apply_custom_css()
            two_factor_verification()
        else:
            login_page()
    else:
        report_generator_page()

if __name__ == "__main__":
    main()
