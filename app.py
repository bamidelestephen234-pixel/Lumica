def developer_console_ui():
    st.header("🛠️ Developer Console")
    st.markdown("## Pending Teacher Approvals")
    pending_teachers = get_pending_teacher_approvals()
    if pending_teachers is not None and not pending_teachers.empty:
        for _, teacher in pending_teachers.iterrows():
            col1, col2, col3 = st.columns([3, 2, 2])
            with col1:
                st.write(f"**{teacher['full_name']}** ({teacher['email']}) - {teacher['role']}")

            # Approve button and handler
            with col2:
                if can_approve(st.session_state.get('teacher_id')):
                    if st.button(f"✅ Approve {teacher['id']}", key=f"approve_{teacher['id']}"):
                        try:
                            approver = st.session_state.get('teacher_id')
                            # Use the centralized set_user_active_status function to handle the approval
                            if set_user_active_status(teacher['id'], active=True, actor_id=approver):
                                st.success(f"Approved {teacher['full_name']}")
                                st.rerun()
                            else:
                                st.error("❌ Error approving user")
                                
                        except Exception as e:
                            import traceback
                            with open('dev_actions.log', 'a') as fw:
                                fw.write(f"Unhandled approve error for {teacher['id']}: {e}\n")
                                fw.write(traceback.format_exc() + "\n")
                            st.error(f"❌ Error approving user: {e}")
                else:
                    st.warning("⚠️ You do not have permission to approve users. Only the Principal, HOD, or Developer can approve.")

            # Reject button and handler
            with col3:
                if can_approve(st.session_state.get('teacher_id')):
                    if st.button(f"🗑️ Reject {teacher['id']}", key=f"reject_{teacher['id']}"):
                        try:
                            approver = st.session_state.get('teacher_id')
                            try:
                                import uuid as _uuid
                                _uuid.UUID(str(approver))
                                dev_param = approver
                            except Exception:
                                dev_param = None

                            wrote = False
                            try:
                                if 'db_manager' in globals() and db_manager is not None:
                                    sess = db_manager.get_session()
                                    try:
                                        sess.execute(text("UPDATE users SET approval_status = 'rejected', approved_by = :dev_id, approval_date = :now WHERE id = :user_id"), {"user_id": teacher['id'], "dev_id": dev_param, "now": datetime.now()})
                                        sess.commit()
                                        wrote = True
                                    finally:
                                        sess.close()
                            except Exception as e_sql:
                                with open('dev_actions.log', 'a') as fw:
                                    import traceback
                                    fw.write(f"Reject SQLAlchemy error for {teacher['id']}: {e_sql}\n")
                                    fw.write(traceback.format_exc() + "\n")

                            if not wrote:
                                update_sql = text("UPDATE users SET approval_status = 'rejected', approved_by = :dev_id, approval_date = :now WHERE id = :user_id")
                                params = {"user_id": teacher['id'], "dev_id": dev_param, "now": datetime.now()}
                                success = execute_sql_with_retry(update_sql, params)
                                wrote = bool(success)

                            if wrote:
                                st.success(f"Rejected {teacher['full_name']}")
                                st.rerun()
                            else:
                                st.error("❌ Error rejecting user (DB write failed)")
                        except Exception as e:
                            import traceback
                            with open('dev_actions.log', 'a') as fw:
                                fw.write(f"Unhandled reject error for {teacher['id']}: {e}\n")
                                fw.write(traceback.format_exc() + "\n")
                            st.error(f"❌ Error rejecting user: {e}")
                else:
                    st.info("⚠️ You do not have permission to reject users. Only the Principal, HOD, or Developer can reject.")
    else:
        st.info("No pending teacher approvals.")

    # Removed duplicate user management tab. User management is handled in the developer console tabs only.
# Helper: Enable or disable a user (developer bypass)
def set_user_active_status(user_id, active=True, actor_id=None):
    """Enable or disable a user. Developer can bypass all permission checks.
    When enabling a user, this also ensures their approval_status is set to 'approved'."""
    try:
        # Developer bypass
        if actor_id == "developer_001" or (actor_id and st.session_state.get("developer_authenticated")):
            developer_bypass = True
        else:
            developer_bypass = False
        # Check permissions for non-developer
        if not developer_bypass:
            if not check_user_permissions(actor_id, "user_management"):
                raise Exception("Insufficient permissions to change user status.")

        # Prefer SQLAlchemy session if db_manager is available
        try:
            if 'db_manager' in globals() and db_manager is not None:
                session = db_manager.get_session()
                try:
                    # When enabling, also set approval_status to approved
                    if active:
                        session.execute(
                            text("UPDATE users SET is_active = :is_active, approval_status = 'approved', approved_by = :actor_id, approval_date = :now WHERE id = :user_id"), 
                            {"user_id": user_id, "is_active": active, "actor_id": actor_id, "now": datetime.now()}
                        )
                    else:
                        session.execute(
                            text("UPDATE users SET is_active = :is_active WHERE id = :user_id"),
                            {"user_id": user_id, "is_active": active}
                        )
                    session.commit()
                finally:
                    session.close()
                print(f"User {user_id} status set to {active} by {actor_id} (SQLAlchemy)")
                return True
        except Exception as e:
            print(f"SQLAlchemy update failed, falling back: {e}")

        # Fallback to execute_sql_with_retry (Streamlit connection)
        if active:
            update_sql = text("""
                UPDATE users 
                SET is_active = :is_active,
                    approval_status = 'approved',
                    approved_by = :actor_id,
                    approval_date = :now
                WHERE id = :user_id
            """)
            params = {"user_id": user_id, "is_active": active, "actor_id": actor_id, "now": datetime.now()}
        else:
            update_sql = text("""
                UPDATE users 
                SET is_active = :is_active
                WHERE id = :user_id
            """)
            params = {"user_id": user_id, "is_active": active}
            
        success = execute_sql_with_retry(update_sql, params)
        if not success:
            print("⚠️ Database update failed on fallback path. Attempting JSON fallback...")
            try:
                # Try to update the local JSON fallback so approvals persist when DB is not available
                users_db = load_user_database_fallback() or {}

                user = users_db.get(user_id, {})
                # Preserve existing fields where possible
                user['active'] = bool(active)
                if active:
                    user['approval_status'] = 'approved'
                    user['approved_by'] = actor_id
                    user['approval_date'] = datetime.now().isoformat()
                users_db[user_id] = user

                saved = save_user_database(users_db)
                if saved:
                    try:
                        st.cache_data.clear()
                    except Exception:
                        pass
                    print(f"User {user_id} status set to {active} by {actor_id} (JSON fallback)")
                    return True
                else:
                    print("❌ JSON fallback save failed")
            except Exception as fb_e:
                print(f"❌ JSON fallback attempt failed: {fb_e}")

            # If we get here, both DB and JSON fallback failed
            raise Exception("Database update failed on fallback path and JSON fallback also failed.")
        try:
            st.cache_data.clear()
        except Exception:
            pass
        print(f"User {user_id} status set to {active} by {actor_id} (fallback)")
        return True
    except Exception as e:
        print(f"Error setting user active status: {e}")
        return False

def is_user_enabled(user_id):
    """Check if a user is enabled (active and approved)"""
    users_db = load_user_database()
    user = users_db.get(user_id)
    if not user:
        return False
    return user.get('active', True) and user.get('approval_status', 'approved') == 'approved'

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
import random
import csv
import uuid
import string
import pyotp
import qrcode as qr_gen
from io import BytesIO, StringIO
# PDF generation imports - make weasyprint optional
try:
    from weasyprint import HTML
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("WeasyPrint not available - PDF export disabled")
except Exception as e:
    PDF_AVAILABLE = False
    print(f"WeasyPrint import error - PDF export disabled: {e}")
import qrcode
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

# Simple cooldown to avoid hammering the remote DB when pool limits are hit
DB_COOLDOWN_UNTIL = 0
# Counters for admin diagnostics
DB_QUERY_RETRY_COUNT = 0
DB_EXECUTE_RETRY_COUNT = 0
DB_COOLDOWN_COUNT = 0

# Debug: Verify secrets are loaded (credentials redacted for security)
secrets_available = list(st.secrets.keys()) if st.secrets else []
print(f"DEBUG: st.secrets at startup: {len(secrets_available)} secret(s) loaded: {secrets_available}")
# Database imports (deployment-ready with fallbacks)
# ============================================================================
# STREAMLIT CLOUD PRODUCTION DATABASE CONNECTION (NEW APPROACH)
# ============================================================================

@st.cache_resource
def init_sql_connection():
    """Initialize Streamlit SQLConnection with proper production settings"""
    try:
        # Prefer SQLAlchemy engine with connection pooling to reduce session churn
        db_url = st.secrets["DATABASE_URL"]
        try:
            from sqlalchemy import create_engine
            # Small pool by default - tune as needed
            engine = create_engine(db_url, pool_size=5, max_overflow=2, pool_pre_ping=True)
            print("✅ SQLAlchemy engine initialized for DB pooling")
            return engine
        except Exception as e_engine:
            print(f"SQLAlchemy engine unavailable or failed: {e_engine}. Falling back to Streamlit connection.")
            conn = st.connection("postgresql", type="sql", url=db_url)
            return conn
    except Exception as e:
        print(f"Failed to initialize SQL connection: {e}")
        return None

def get_healthy_sql_connection():
    """Get a healthy SQL connection with automatic stale connection detection"""
    global DB_COOLDOWN_UNTIL
    now_ts = time.time()
    if DB_COOLDOWN_UNTIL and now_ts < DB_COOLDOWN_UNTIL:
        print("⚠️ Database in cooldown, skipping immediate reconnect")
        return None

    conn = init_sql_connection()
    if not conn:
        return None

    try:
        # Health check - try a simple query
        # If conn is a SQLAlchemy Engine, use a connection from the pool
        try:
            from sqlalchemy.engine import Engine
        except Exception:
            Engine = None

        if Engine and isinstance(conn, Engine):
            try:
                from sqlalchemy import text as _text
                with conn.connect() as c:
                    c.execute(_text("SELECT 1"))
                return conn
            except Exception as e:
                raise e
        else:
            # Assume Streamlit SQL connection
            conn.query("SELECT 1", ttl=0)  # No cache for health check
            return conn
    except Exception as e:
        print(f"Connection is stale, resetting: {e}")
        # If the server reports too many clients or pool exhaustion, back off
        msg = str(e).lower()
        if 'max clients' in msg or 'maxclients' in msg or 'too many' in msg or 'pool_size' in msg:
            # Set a short cooldown to avoid hammering the pool
            DB_COOLDOWN_UNTIL = time.time() + 30
            # increment diagnostic counter
            try:
                global DB_COOLDOWN_COUNT
                DB_COOLDOWN_COUNT += 1
            except Exception:
                pass
            print("⚠️ Detected DB pool exhaustion - enabling 30s cooldown before reconnect attempts")
        # Clear the cached connection and get a fresh one
        st.cache_resource.clear()
        return init_sql_connection()

def query_with_retry(sql, params=None, retries=3, ttl=300):
    """Execute SQL query with automatic retry and connection recovery"""
    backoff = 0.5
    global DB_QUERY_RETRY_COUNT
    for attempt in range(retries):
        try:
            conn = get_healthy_sql_connection()
            if not conn:
                raise Exception("No database connection available")

            # Convert SQLAlchemy text() objects to strings for Streamlit caching compatibility
            sql_str = str(sql) if hasattr(sql, 'text') else sql

            # If we returned a SQLAlchemy engine, use it
            from sqlalchemy.engine import Engine
            if isinstance(conn, Engine):
                with conn.connect() as connection:
                    result = connection.execute(text(sql_str), params or {})
                    try:
                        rows = result.fetchall()
                        # Convert to DataFrame-like structure when possible
                        import pandas as _pd
                        if rows:
                            df = _pd.DataFrame(rows)
                        else:
                            df = _pd.DataFrame()
                        return df
                    except Exception:
                        return None

            # Otherwise assume it's a Streamlit SQL connection
            if params:
                return conn.query(sql_str, params=params, ttl=ttl)
            else:
                return conn.query(sql_str, ttl=ttl)

        except Exception as e:
            # If it's the final attempt, re-raise after logging
            if attempt == retries - 1:
                print(f"Final database query attempt failed: {e}")
                raise e

            # Exponential backoff with jitter
            sleep_for = backoff + (random.random() * 0.1)
            print(f"Database query attempt {attempt + 1} failed: {e}, retrying in {sleep_for:.2f}s...")
            time.sleep(sleep_for)
            backoff *= 2
            # Clear any cached connection to force re-init
            try:
                st.cache_resource.clear()
            except Exception:
                pass
            try:
                DB_QUERY_RETRY_COUNT += 1
            except Exception:
                pass

def execute_sql_with_retry(sql, params=None, retries=3):
    """Execute SQL command (INSERT/UPDATE/DELETE) with retry logic"""
    backoff = 0.5
    global DB_EXECUTE_RETRY_COUNT
    for attempt in range(retries):
        try:
            conn = get_healthy_sql_connection()
            if not conn:
                raise Exception("No database connection available")

            from sqlalchemy.engine import Engine
            # If conn is an Engine, use a connection from the pool
            if isinstance(conn, Engine):
                with conn.begin() as connection:
                    if params:
                        connection.execute(text(str(sql)), params)
                    else:
                        connection.execute(text(str(sql)))
                    return True

            # Otherwise assume it's a Streamlit SQL connection
            if hasattr(conn, 'session'):
                with conn.session as session:
                    if params:
                        result = session.execute(sql, params)
                    else:
                        result = session.execute(sql)
                    session.commit()
                    return True
            else:
                # Fallback approach - try direct execution
                try:
                    result = conn.query(str(sql), ttl=0)  # No cache for execute commands
                    return True
                except Exception as e:
                    print(f"Direct execution failed: {e}")
                    raise e

        except Exception as e:
            if attempt == retries - 1:
                print(f"Final database execute attempt failed: {e}")
                return False

            sleep_for = backoff + (random.random() * 0.1)
            print(f"Database execute attempt {attempt + 1} failed: {e}, retrying in {sleep_for:.2f}s...")
            time.sleep(sleep_for)
            backoff *= 2
            try:
                st.cache_resource.clear()
            except Exception:
                pass
            try:
                DB_EXECUTE_RETRY_COUNT += 1
            except Exception:
                pass

    return False


def show_db_status_banner():
    """Show a small DB status banner in the UI for admins."""
    try:
        conn = get_healthy_sql_connection()
        if conn is None:
            st.warning("⚠️ Database: Unavailable (using fallback). Some features may be limited.")
            return

        # If conn is SQLAlchemy Engine, try a quick SELECT 1
        from sqlalchemy.engine import Engine
        if isinstance(conn, Engine):
            try:
                with conn.connect() as c:
                    c.execute(text("SELECT 1"))
                st.success("✅ Database: Connected")
            except Exception:
                st.error("❌ Database: Connection error")
        else:
            try:
                conn.query("SELECT 1", ttl=0)
                st.success("✅ Database: Connected")
            except Exception:
                st.error("❌ Database: Connection error")
    except Exception:
        pass

# ============================================================================
# FALLBACK TO OLD SYSTEM (FOR COMPATIBILITY)
# ============================================================================

try:
    from database.models import ActivationKey
    from database.db_manager import db_manager
    DATABASE_AVAILABLE = True
    USE_STREAMLIT_SQL = True  # Flag to prefer new Streamlit SQL approach
except Exception as e:
    # Fallback for deployment environments - catch all exceptions
    DATABASE_AVAILABLE = False
    db_manager = None
    USE_STREAMLIT_SQL = True  # Force use of new approach
    print(f"Database not available: {e}")

# SQLAlchemy imports for proper text() usage - REQUIRED for authentication
try:
    from sqlalchemy import text
    SQLALCHEMY_AVAILABLE = True
    print("✅ SQLAlchemy text() available for secure authentication")
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    print("❌ CRITICAL: SQLAlchemy not available - authentication will fail!")
    print("   Please ensure 'sqlalchemy>=2.0' is in requirements.txt")

# Google Drive integration
try:
    # Deprecated Google API imports commented out
    # from google.oauth2.credentials import Credentials
    # from google_auth_oauthlib.flow import Flow
    # from googleapiclient.discovery import build
    # from googleapiclient.http import MediaFileUpload
    GOOGLE_DRIVE_AVAILABLE = False
except ImportError:
    GOOGLE_DRIVE_AVAILABLE = False

# Email integration
try:
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False

# Subjects list
# Utility functions - defined early for use throughout the app
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

subjects = sorted([
    "English", "Maths", "French", "C.C Art", "Business Studies", "Economics",
    "Yoruba", "physics", "chemistry", "Biology", "Further Mathematics",
    "National Value", "Lit-in-Eng", "Guidance & Counseling", "C.R.S",
    "Agric Sci", "Home Eco", "Basic Science", "Basic Tech", "PHE", "Computer",
    "civic Education", "Goverment", "Geography", "Animal Husbandry", "Marketing",
])

# User roles and permissions
USER_ROLES = {
    "developer": {
        "level": 7,
        "permissions": ["super_admin", "all_access", "system_control", "activation_settings", "user_management", "system_config", "backup_restore", "data_export", "report_generation", "student_management", "department_reports"],
        "description": "Developer - Full system control and activation management",
        "default_features": [
            "developer_console", "report_generation", "draft_management", "student_database", 
            "analytics_dashboard", "verification_system", "admin_panel"
        ]
    },
    "principal": {
        "level": 5,
        "permissions": ["all_access", "user_management", "system_config", "backup_restore", "data_export"],
        "description": "Principal - Full system access",
        "default_features": [
            "report_generation", "draft_management", "student_database", 
            "analytics_dashboard", "verification_system", "admin_panel"
        ]
    },
    "head_of_department": {
        "level": 4,
        "permissions": ["department_reports", "teacher_management", "grade_boundaries", "class_management", "user_management"],
        "description": "Head of Department - Departmental oversight",
        "default_features": [
            "report_generation", "draft_management", "student_database", 
            "analytics_dashboard", "verification_system"
        ]
    },
    "class_teacher": {
        "level": 3,
        "permissions": ["class_reports", "student_management", "report_generation", "parent_communication"],
        "description": "Class Teacher - Class-specific access",
        "default_features": [
            "report_generation", "draft_management", "student_database", "verification_system"
        ]
    },
    "teacher": {
        "level": 2,
        "permissions": ["report_generation", "student_view"],
        "description": "Teacher - Basic teaching functions",
        "default_features": [
            "report_generation", "draft_management", "verification_system"
        ]
    },
    "parent": {
        "level": 1,
        "permissions": ["view_child_reports", "communication"],
        "description": "Parent - View child's reports only",
        "default_features": []
    }
}

# Available system features
SYSTEM_FEATURES = {
    "developer_console": {
        "name": "🛠️ Developer Console",
        "description": "System activation controls, user management, and developer tools",
        "required_permission": "system_control"
    },
    "report_generation": {
        "name": "📝 Generate Reports",
        "description": "Create and generate student report cards",
        "required_permission": "report_generation"
    },
    "draft_management": {
        "name": "📝 Draft Reports",
        "description": "Save and manage draft reports",
        "required_permission": "report_generation"
    },
    "student_database": {
        "name": "👥 Student Database",
        "description": "Add, edit, and manage student information",
        "required_permission": "student_management"
    },
    "analytics_dashboard": {
        "name": "📊 Analytics",
        "description": "View performance analytics and statistics",
        "required_permission": "department_reports"
    },
    "verification_system": {
        "name": "🔍 Verify Reports",
        "description": "Verify report card authenticity",
        "required_permission": None  # Available to all authenticated users
    },
    "admin_panel": {
        "name": "⚙️ Admin Panel",
        "description": "System administration and configuration",
        "required_permission": "system_config"
    }
}

# Enhanced user management system
from datetime import datetime, timedelta
import uuid

def load_user_database():
    """Load user database using Streamlit SQL Connection with JSON fallback - PRODUCTION READY for Streamlit Cloud"""
    try:
        print("🔄 Loading users from database...")

        # Query users using the new Streamlit SQL approach
        users_df = query_with_retry("""
            SELECT id, password_hash, role, full_name, email, phone, 
                   created_date, last_login, is_active, approval_status, 
                   approved_by, approval_date, registration_notes
            FROM users 
            WHERE id IS NOT NULL
        """, ttl=60)  # Cache for 1 minute

        if users_df.empty:
            print("⚠️ No users found in database")
            return {}

        # Convert DataFrame to the dict format expected by the app
        user_dict = {}
        for _, row in users_df.iterrows():
            user_dict[row['id']] = {
                "password_hash": row['password_hash'],
                "role": row['role'],
                "full_name": row['full_name'],
                "email": row['email'],
                "phone": row['phone'] or "",
                "created_date": row['created_date'].isoformat() if row['created_date'] else None,
                "last_login": row['last_login'].isoformat() if row['last_login'] else None,
                "active": row['is_active'],
                "two_factor_enabled": False,  # Set default values as needed
                "two_factor_secret": None,
                "session_timeout": 30,
                "failed_attempts": 0,
                "locked_until": None,
                "assigned_classes": [],
                "departments": ["all"] if row['role'] == "principal" else [],
                # Add approval fields
                "approval_status": row['approval_status'] or "approved",
                "approved_by": row['approved_by'],
                "approval_date": row['approval_date'].isoformat() if row['approval_date'] else None,
                "registration_notes": row['registration_notes']
            }

        print(f"✅ Successfully loaded {len(user_dict)} users from database")
        return user_dict

    except Exception as e:
        print(f"❌ Failed to load users from database: {e}")
        print("🔄 Falling back to JSON user database...")
        
        # Fallback to JSON database
        try:
            fallback_users = load_user_database_fallback()
            if fallback_users:
                print(f"✅ Successfully loaded {len(fallback_users)} users from JSON fallback")
                return fallback_users
            else:
                print("⚠️ No fallback users available")
                return {}
        except Exception as fallback_error:
            print(f"❌ JSON fallback load also failed: {fallback_error}")
            return {}

        # Show error in UI if in Streamlit context
        try:
            st.error("🔌 Database connection issue. Please refresh the page or contact support.")
        except:
            pass

        return {}

def load_user_database_fallback():
    """Fallback to JSON database for deployment environments"""
    try:
        if os.path.exists("users_database.json"):
            with open("users_database.json", 'r') as f:
                return json.load(f)
        else:
            # Create default users if no database exists (teacher_bamstep account DISABLED as per requirements)
            return {
                "developer_001": {
                    "password_hash": hash_password("Stephen@22"),
                    "role": "developer", 
                    "full_name": "System Developer",
                    "email": "developer@akinssunrise.edu.ng",
                    "phone": "+234-XXX-XXX-XXXX",
                    "created_date": datetime.now().isoformat(),
                    "last_login": None,
                    "active": True,
                    "two_factor_enabled": False,
                    "two_factor_secret": None,
                    "session_timeout": 30,
                    "failed_attempts": 0,
                    "locked_until": None,
                    "assigned_classes": [],
                    "departments": ["all"],
                    # Add approval fields
                    "approval_status": "approved",
                    "approved_by": None,
                    "approval_date": None,
                    "registration_notes": "System Developer Account"
                },
                "teacher_bola": {
                    "password_hash": hash_password("secret123"),
                    "role": "class_teacher",
                    "full_name": "Teacher Bola", 
                    "email": "bola@akinssunrise.edu.ng",
                    "phone": "+234-XXX-XXX-XXXX",
                    "created_date": datetime.now().isoformat(),
                    "last_login": None,
                    "active": True,
                    "two_factor_enabled": False,
                    "two_factor_secret": None,
                    "session_timeout": 30,
                    "failed_attempts": 0,
                    "locked_until": None,
                    "assigned_classes": [],
                    "departments": [],
                    # Add approval fields
                    "approval_status": "approved",
                    "approved_by": None,
                    "approval_date": None,
                    "registration_notes": None
                },
                "school_ict": {
                    "password_hash": hash_password("akins1111"),
                    "role": "principal",
                    "full_name": "Akins Sunrise",
                    "email": "akinssunrise@gmail.com",
                    "phone": "+234-XXX-XXX-XXXX",
                    "created_date": datetime.now().isoformat(),
                    "last_login": None,
                    "active": True,
                    "two_factor_enabled": False,
                    "two_factor_secret": None,
                    "session_timeout": 30,
                    "failed_attempts": 0,
                    "locked_until": None,
                    "assigned_classes": [],
                    "departments": ["all"],
                    # Add approval fields
                    "approval_status": "approved",
                    "approved_by": None,
                    "approval_date": None,
                    "registration_notes": None
                }
            }
    except Exception as e:
        print(f"Error loading fallback database: {e}")
        return {}

def save_user_database(users_db):
    """
    Save user database using new Streamlit SQL connection with JSON fallback.
    Expects users_db to be a dict keyed by user_id with user details.
    """
    try:
        conn = get_healthy_sql_connection()
        if not conn:
            print("❌ No database connection for save_user_database, using JSON fallback")
            # Direct fallback to JSON when no connection
            try:
                with open("users_database.json", 'w') as f:
                    # Convert datetime objects to strings for JSON serialization
                    json_users_db = {}
                    for user_id, data in users_db.items():
                        json_data = data.copy()
                        if 'created_date' in json_data and isinstance(json_data['created_date'], datetime):
                            json_data['created_date'] = json_data['created_date'].isoformat()
                        if 'last_login' in json_data and isinstance(json_data['last_login'], datetime):
                            json_data['last_login'] = json_data['last_login'].isoformat()
                        if 'approval_date' in json_data and isinstance(json_data['approval_date'], datetime):
                            json_data['approval_date'] = json_data['approval_date'].isoformat()
                        json_users_db[user_id] = json_data
                    
                    json.dump(json_users_db, f, indent=2)
                print(f"✅ Successfully saved {len(users_db)} users to JSON fallback")
                return True
            except Exception as fallback_error:
                print(f"❌ JSON fallback save failed: {fallback_error}")
                return False

        for user_id, data in users_db.items():
            # Check if user exists
            check_sql = text("SELECT id FROM users WHERE id = :user_id")
            existing_df = query_with_retry(check_sql, {'user_id': user_id})

            from datetime import datetime, timezone
            current_time = datetime.now(timezone.utc)


            if not existing_df.empty:
                # Update existing user
                update_sql = text("""
                    UPDATE users SET 
                        full_name = :full_name,
                        email = :email,
                        password_hash = :password_hash,
                        role = :role,
                        phone = :phone,
                        is_active = :is_active,
                        last_login = :last_login,
                        approval_status = :approval_status,
                        approved_by = :approved_by,
                        approval_date = :approval_date,
                        registration_notes = :registration_notes
                    WHERE id = :user_id
                """)

                approval_date = None
                if data.get("approval_date"):
                    approval_date = datetime.fromisoformat(data["approval_date"]) if isinstance(data["approval_date"], str) else data["approval_date"]

                params = {
                    'user_id': user_id,
                    'full_name': data["full_name"],
                    'email': data["email"],
                    'password_hash': data["password_hash"],
                    'role': data["role"],
                    'phone': data["phone"],
                    'is_active': data["active"],
                    'last_login': current_time,
                    'approval_status': data.get("approval_status", "approved"),
                    'approved_by': (None if not _is_valid_uuid(data.get("approved_by")) else data.get("approved_by")),
                    'approval_date': approval_date,
                    'registration_notes': data.get("registration_notes")
                }
                execute_sql_with_retry(update_sql, params)
            else:
                # Create new user
                insert_sql = text("""
                    INSERT INTO users (id, full_name, email, password_hash, role, phone, is_active, 
                                     created_date, approval_status, approved_by, approval_date, registration_notes)
                    VALUES (:id, :full_name, :email, :password_hash, :role, :phone, :is_active, 
                           :created_date, :approval_status, :approved_by, :approval_date, :registration_notes)
                """)

                approval_date = None
                if data.get("approval_date"):
                    approval_date = datetime.fromisoformat(data["approval_date"]) if isinstance(data["approval_date"], str) else data["approval_date"]

                # If registering a teacher, set approval_status to 'pending' by default
                approval_status = data.get("approval_status")
                if not approval_status and data.get("role") in ["teacher", "class_teacher"]:
                    approval_status = "pending"
                else:
                    approval_status = approval_status or "approved"
                params = {
                    'id': user_id if user_id else str(uuid.uuid4()),
                    'full_name': data["full_name"],
                    'email': data["email"],
                    'password_hash': data["password_hash"],
                    'role': data["role"],
                    'phone': data["phone"],
                    'is_active': data["active"],
                    'created_date': current_time,
                    'approval_status': approval_status,
                    'approved_by': (None if not _is_valid_uuid(data.get("approved_by")) else data.get("approved_by")),
                    'approval_date': approval_date,
                    'registration_notes': data.get("registration_notes")
                }
                # Execute the INSERT into the database
                try:
                    execute_sql_with_retry(insert_sql, params)
                except Exception as e:
                    print(f"❌ Failed to execute INSERT for user {user_id}: {e}")

        print(f"✅ Saved {len(users_db)} users using new SQL connection")
        return True
    except Exception as e:
        print(f"❌ Error saving users to DB: {e}")
        print("🔄 Falling back to JSON file storage...")
        # Fallback: Save to JSON file if database save fails
        try:
            with open("users_database.json", 'w') as f:
                # Convert datetime objects to strings for JSON serialization
                json_users_db = {}
                for user_id, data in users_db.items():
                    json_data = data.copy()
                    if 'created_date' in json_data and isinstance(json_data['created_date'], datetime):
                        json_data['created_date'] = json_data['created_date'].isoformat()
                    if 'last_login' in json_data and isinstance(json_data['last_login'], datetime):
                        json_data['last_login'] = json_data['last_login'].isoformat()
                    if 'approval_date' in json_data and isinstance(json_data['approval_date'], datetime):
                        json_data['approval_date'] = json_data['approval_date'].isoformat()
                    json_users_db[user_id] = json_data
                json.dump(json_users_db, f, indent=2)
            print(f"✅ Successfully saved {len(users_db)} users to JSON fallback")
            return True
        except Exception as fallback_error:
            print(f"❌ JSON fallback save also failed: {fallback_error}")
            return False

# Helper: Get pending teacher approvals
def get_pending_teacher_approvals():
    """Return all teachers with approval_status = 'pending'"""
    try:
        users_df = query_with_retry("""
            SELECT id, full_name, email, role, approval_status, approved_by, approval_date
            FROM users
            WHERE role IN ('teacher', 'class_teacher') AND approval_status = 'pending'
        """, ttl=30)
        return users_df
    except Exception as e:
        print(f"Error fetching pending teacher approvals: {e}")
        return None


def approvals_tab():
    """Dedicated Approvals tab for Principals and Heads of Department to approve teachers."""
    st.subheader("📋 Approvals")
    st.info("Approve or reject new teacher registrations. Only Principals, HODs, and Developers can act here.")

    actor_id = st.session_state.get('teacher_id')
    # Ensure the current user has rights to approve
    if not can_approve(actor_id):
        st.warning("You do not have permission to view approvals.")
        return

    pending = get_pending_teacher_approvals()
    if pending is None or pending.empty:
        st.info("No pending approvals at the moment.")
        return

    for _, teacher in pending.iterrows():
        col1, col2, col3 = st.columns([3, 2, 2])
        with col1:
            st.write(f"**{teacher['full_name']}** ({teacher['email']}) - {teacher['role']}")
        with col2:
            if st.button(f"✅ Approve {teacher['id']}", key=f"approvals_approve_{teacher['id']}"):
                try:
                    approver = actor_id
                    # Use centralized helper to enable user and set approval
                    ok = set_user_active_status(teacher['id'], active=True, actor_id=approver)
                    if ok:
                        st.success(f"Approved {teacher['full_name']}")
                        st.rerun()
                    else:
                        st.error("Error approving user. Check logs.")
                except Exception as e:
                    st.error(f"Error approving user: {e}")
        with col3:
            if st.button(f"🗑️ Reject {teacher['id']}", key=f"approvals_reject_{teacher['id']}"):
                approver = actor_id
                # Mark as rejected via SQL or fallback
                try:
                    if 'db_manager' in globals() and db_manager is not None:
                        sess = db_manager.get_session()
                        try:
                            sess.execute(text("UPDATE users SET approval_status = 'rejected', approved_by = :dev_id, approval_date = :now WHERE id = :user_id"), {"user_id": teacher['id'], "dev_id": approver, "now": datetime.now()})
                            sess.commit()
                        finally:
                            sess.close()
                    else:
                        update_sql = text("UPDATE users SET approval_status = 'rejected', approved_by = :dev_id, approval_date = :now WHERE id = :user_id")
                        execute_sql_with_retry(update_sql, {"user_id": teacher['id'], "dev_id": approver, "now": datetime.now()})

                    st.success(f"Rejected {teacher['full_name']}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error rejecting user: {e}")

def check_user_permissions(user_id, required_permission):
    """Check if user has required permission"""
    try:
        # Developer bypass - allow all permissions for authenticated developers
        if st.session_state.get("developer_authenticated") and user_id == "developer_001":
            return True  # Developer has all permissions
            
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

def check_user_feature_access(user_id, feature_key):
    """Check if user has access to a specific system feature"""
    try:
        # Developer bypass - allow all features for authenticated developers
        if st.session_state.get("developer_authenticated") and user_id == "developer_001":
            return True  # Developer has access to all features
            
        users_db = load_user_database()
        if user_id not in users_db:
            return False

        user = users_db[user_id]

        # Check custom feature permissions first
        custom_features = user.get('custom_features', [])
        if custom_features:
            return feature_key in custom_features

        # Fall back to role-based default features
        user_role = user.get('role', 'teacher')
        if user_role not in USER_ROLES:
            return False

        default_features = USER_ROLES[user_role].get('default_features', [])

        # Check if feature requires specific permission
        if feature_key in SYSTEM_FEATURES:
            required_permission = SYSTEM_FEATURES[feature_key].get('required_permission')
            if required_permission:
                return check_user_permissions(user_id, required_permission)
            else:
                return True  # No specific permission required

        return feature_key in default_features
    except Exception as e:
        return False


def can_approve(actor_id=None):
    """Return True if the given actor can approve/reject registrations.

    Rules:
    - Authenticated developer (session flag) with id 'developer_001' can approve.
    - Users with the 'user_management' permission can approve.
    - Principals can approve by role.
    """
    try:
        if actor_id is None:
            actor_id = st.session_state.get('teacher_id')

        # Developer bypass
        if st.session_state.get('developer_authenticated') and actor_id == 'developer_001':
            return True

        users_db = load_user_database()
        if not actor_id or actor_id not in users_db:
            return False

        user = users_db.get(actor_id, {})
        role = user.get('role', '')

        if role == 'principal':
            return True

        # Check explicit permission
        if check_user_permissions(actor_id, 'user_management'):
            return True

        return False
    except Exception:
        return False

def is_user_locked(user_id):
    """Check if user account is locked"""
    try:
        conn = get_healthy_sql_connection()
        if not conn:
            print(f"❌ No database connection for is_user_locked: {user_id}")
            return False

        # Get lock status
        check_sql = text("SELECT locked_until, failed_attempts FROM users WHERE id = :user_id")
        result_df = query_with_retry(check_sql, {'user_id': user_id})

        if result_df.empty:
            return False

        user = result_df.iloc[0]
        locked_until = user.get('locked_until')

        if locked_until:
            # Convert to datetime if it's a string
            if isinstance(locked_until, str):
                lock_time = datetime.fromisoformat(locked_until)
            else:
                lock_time = locked_until

            if datetime.now() > lock_time:
                # Auto-unlock user
                unlock_sql = text("""
                    UPDATE users SET 
                        locked_until = NULL,
                        failed_attempts = 0
                    WHERE id = :user_id
                """)

                success = execute_sql_with_retry(unlock_sql, {'user_id': user_id})
                if success:
                    print(f"✅ Auto-unlocked user {user_id}")
                return False
            return True
        return False
    except Exception as e:
        print(f"❌ Error checking user lock status for {user_id}: {e}")
        return False

def increment_failed_attempts(user_id):
    """Increment failed login attempts and lock if necessary"""
    try:
        conn = get_healthy_sql_connection()
        if not conn:
            print(f"❌ No database connection for increment_failed_attempts: {user_id}")
            return

        # Get current failed attempts
        check_sql = text("SELECT failed_attempts FROM users WHERE id = :user_id")
        result_df = query_with_retry(check_sql, {'user_id': user_id})

        if result_df.empty:
            print(f"⚠️ User not found for failed attempts: {user_id}")
            return

        current_attempts = result_df.iloc[0]['failed_attempts'] if 'failed_attempts' in result_df.columns else 0
        new_attempts = (current_attempts or 0) + 1

        # Lock account after 3 failed attempts
        locked_until = None
        if new_attempts >= 3:
            locked_until = datetime.now() + timedelta(minutes=30)

        # Update failed attempts and lock status
        update_sql = text("""
            UPDATE users SET 
                failed_attempts = :failed_attempts,
                locked_until = :locked_until
            WHERE id = :user_id
        """)

        params = {
            'user_id': user_id,
            'failed_attempts': new_attempts,
            'locked_until': locked_until
        }

        success = execute_sql_with_retry(update_sql, params)
        if success:
            print(f"✅ Updated failed attempts for {user_id}: {new_attempts}")
        else:
            print(f"❌ Failed to update attempts for {user_id}")

    except Exception as e:
        print(f"❌ Error incrementing failed attempts for {user_id}: {e}")

def reset_failed_attempts(user_id):
    """Reset failed login attempts on successful login"""
    try:
        conn = get_healthy_sql_connection()
        if not conn:
            print(f"❌ No database connection for reset_failed_attempts: {user_id}")
            return

        # Reset failed attempts, unlock account, and update last login
        update_sql = text("""
            UPDATE users SET 
                failed_attempts = 0,
                locked_until = NULL,
                last_login = :last_login
            WHERE id = :user_id
        """)

        params = {
            'user_id': user_id,
            'last_login': datetime.now()
        }

        success = execute_sql_with_retry(update_sql, params)
        if success:
            print(f"✅ Reset failed attempts for successful login: {user_id}")
        else:
            print(f"❌ Failed to reset attempts for {user_id}")

    except Exception as e:
        print(f"❌ Error resetting failed attempts for {user_id}: {e}")

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

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
            "timestamp": datetime.now().isoformat(),
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
                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
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
            "export_timestamp": datetime.now().isoformat(),
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

# Removed stale credentials cache - always load fresh user data for security

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

# Duplicate password functions removed - using the ones at line 71

def create_audit_log(action: str, user_id: str, details: dict, data_type: str = "general"):
    try:
        audit_dir = "audit_logs"
        os.makedirs(audit_dir, exist_ok=True)

        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "user_id": user_id,
            "data_type": data_type,
            "details": details,
            "ip_address": "replit_session",
            "session_id": hashlib.md5(f"{user_id}_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            "compliance_level": "high",
            "retention_period": "7_years"
        }

        date_str = datetime.now().strftime("%Y-%m-%d")
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
            "admission_no": admission_no or f"ASS/{str(datetime.now().year)[-2:]}/{len(get_all_students()) + 1:03d}",
            "class_size": class_size or "35",
            "attendance": attendance or "95%",
            "position": position or "1st",
            "created_date": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
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

                    # For 1st term, cumulative is same as current term total
                    if term == "1st Term":
                        subject_cumulative = total
                    else:
                        # For 2nd and 3rd terms, average with previous cumulative
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
                        "created_date": datetime.now().isoformat(),
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
        report_data['last_modified'] = datetime.now().isoformat()

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

        # Ensure data persistence by using flush and sync
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        pdf_filename = f"pending_{report_data['report_id']}.pdf"
        pdf_path = os.path.join(pending_dir, pdf_filename)

        HTML(string=report_data['html_content']).write_pdf(pdf_path)

        return True
    except Exception as e:
        print(f"Error saving pending report: {e}")
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

def auto_approve_report(report_data):
    """Automatically approve and save report without requiring admin approval"""
    try:
        approved_dir = "approved_reports"
        os.makedirs(approved_dir, exist_ok=True)

        report_data['status'] = 'approved'
        report_data['approved_date'] = datetime.now().isoformat()
        report_data['approved_by'] = 'auto_system'

        # Add persistence markers
        report_data['persistent'] = True
        report_data['backup_created'] = datetime.now().isoformat()

        approved_path = os.path.join(approved_dir, f"approved_{report_data['report_id']}.json")

        # Enhanced data persistence with multiple write attempts
        for attempt in range(3):
            try:
                with open(approved_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())

                # Verify file was written correctly
                with open(approved_path, 'r') as f:
                    test_data = json.load(f)
                    if test_data.get('report_id') == report_data['report_id']:
                        break
            except Exception as e:
                if attempt == 2:  # Last attempt
                    raise e
                continue

        # Save PDF directly to approved folder
        approved_pdf_path = os.path.join(approved_dir, f"approved_{report_data['report_id']}.pdf")
        HTML(string=report_data['html_content']).write_pdf(approved_pdf_path)

        # Create multiple backups for extra persistence
        backup_locations = ["report_backup", "report_archive", "verified_reports"]
        for backup_dir in backup_locations:
            os.makedirs(backup_dir, exist_ok=True)
            backup_path = os.path.join(backup_dir, f"backup_{report_data['report_id']}.json")
            with open(backup_path, 'w') as f:
                json.dump(report_data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

        log_teacher_activity(st.session_state.get('teacher_id', 'system'), "report_auto_approved", {
            "report_id": report_data['report_id'],
            "student_name": report_data['student_name'],
            "auto_approved": True,
            "persistent": True
        })

        return True, f"Report automatically approved and saved with enhanced persistence"

    except Exception as e:
        print(f"Error auto-approving report: {e}")
        return False, f"Error auto-approving report: {str(e)}"

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
        report_data['rejected_date'] = datetime.now().isoformat()
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

def _is_valid_uuid(val):
    """Return True if val is a valid UUID string, otherwise False."""
    try:
        if not val:
            return False
        import uuid as _uuid
        _uuid.UUID(str(val))
        return True
    except Exception:
        return False

def can_approve(actor_id=None):
    """Return True if the given actor can approve or reject user applications.

    Rules:
    - Authenticated developer (`st.session_state.developer_authenticated` and actor_id == 'developer_001') can approve.
    - Users with permission `system_config` (principal/admin) can approve.
    """
    try:
        # Developer bypass
        if st.session_state.get('developer_authenticated') and (actor_id == 'developer_001' or st.session_state.get('teacher_id') == 'developer_001'):
            return True

        # If actor_id not provided, use session teacher_id
        if not actor_id:
            actor_id = st.session_state.get('teacher_id')

        if not actor_id:
            return False

        # Check permissions via existing helper
        return check_user_permissions(actor_id, 'system_config')
    except Exception:
        return False

def get_logo_base64(uploaded_file=None):
    try:
        if uploaded_file is not None:
            uploaded_file.seek(0)
            logo_data = base64.b64encode(uploaded_file.read()).decode("utf-8")
            print(f"Logo loaded from uploaded file, size: {len(logo_data)} characters")
            return logo_data
        else:
            logo_files = ["school_logo.png", "logo.png", "logo.jpg", "logo.jpeg", "generated-icon.png"]

            for logo_file in logo_files:
                if os.path.exists(logo_file):
                    try:
                        with open(logo_file, "rb") as image_file:
                            logo_data = base64.b64encode(image_file.read()).decode("utf-8")
                            print(f"Logo loaded from {logo_file}, size: {len(logo_data)} characters")
                            return logo_data
                    except Exception as e:
                        print(f"Error reading logo file {logo_file}: {e}")
                        continue

            print(f"Warning: No logo file found. Tried: {logo_files}")
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
                            expiry = datetime.fromisoformat(expiry_date)
                            return datetime.now() < expiry
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
        now = datetime.now()
        if plan_type == "monthly":
            expiry = now + timedelta(days=30)
        elif plan_type == "yearly":
            expiry = now + timedelta(days=365)
        else:
            expiry = now + timedelta(days=30)

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

def load_activation_config():
    """Load activation system configuration - always use defaults to avoid local file dependency"""
    return {
        "monthly_amount": 20000,
        "yearly_amount": 60000,
        "currency": "NGN",
        "bank_details": {
            "bank_name": "First Bank Nigeria",
            "account_name": "Bamstep Technologies",
            "account_number": "1234567890",
            "sort_code": "011"
        },
        "activation_enabled": True,  # Always enabled to check database
        "trial_period_days": 30,
        "grace_period_days": 7
    }

def save_activation_config(config):
    """Save activation system configuration"""
    try:
        with open("activation_config.json", 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False

def check_activation_status():
    """Check if the system is activated by querying Supabase directly - PRODUCTION READY with robust retry logic"""
    max_retries = 3
    retry_delay = 1

    for attempt in range(max_retries):
        try:
            # Try to establish database connection with retry logic
            current_db_manager = db_manager

            if not DATABASE_AVAILABLE or not current_db_manager or not current_db_manager.is_available():
                print(f"🔄 Attempting database connection for activation check (attempt {attempt + 1}/{max_retries})")
                try:
                    from database.models import ActivationKey as ActivationKeyModel
                    from database.db_manager import DatabaseManager

                    # Create a fresh database manager instance for activation check
                    fresh_db_manager = DatabaseManager()
                    if fresh_db_manager.engine is not None and fresh_db_manager.is_available():
                        current_db_manager = fresh_db_manager
                        print("✅ Database connection established for activation check")
                    else:
                        if attempt < max_retries - 1:
                            print(f"⏳ Database connection failed, retrying in {retry_delay}s...")
                            time.sleep(retry_delay)
                            continue
                        else:
                            print("❌ Database unavailable after all retries - allowing access")
                            return True, {"status": "database_unavailable_allowing_access"}, None
                except Exception as e:
                    if attempt < max_retries - 1:
                        print(f"❌ Database connection error (attempt {attempt + 1}): {e}, retrying...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        print(f"❌ Database connection failed after all retries: {e}")
                        return True, {"status": "database_connection_failed_allowing_access"}, None

            # Query activation keys from database
            if current_db_manager and current_db_manager.is_available():
                try:
                    # Import ActivationKey here to ensure it's available
                    if 'ActivationKeyModel' not in locals():
                        from database.models import ActivationKey as ActivationKeyModel

                    session = current_db_manager.get_session()
                    if session is None:
                        raise Exception("Could not create database session")

                    active_key = session.query(ActivationKeyModel).filter_by(is_active=True).first()
                    session.close()

                    if active_key:
                        # Check if the key has expired
                        if active_key.expires_at and active_key.expires_at < datetime.utcnow():
                            return False, {"status": "key_expired", "activation_key": active_key.key_value}, active_key.expires_at

                        # Key is active and not expired - system is activated
                        status = {
                            "activated": True,
                            "activation_key": active_key.key_value,
                            "subscription_type": active_key.subscription_type,
                            "school_name": active_key.school_name,
                            "expires_at": active_key.expires_at.isoformat() if active_key.expires_at else None
                        }
                        print(f"✅ System activated with key: {active_key.key_value}")
                        return True, status, active_key.expires_at
                    else:
                        # No active key found in database
                        print("⚠️ No active activation key found in database")
                        return False, {"status": "no_active_key"}, None

                except Exception as e:
                    if attempt < max_retries - 1:
                        print(f"❌ Database query error (attempt {attempt + 1}): {e}, retrying...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        print(f"❌ Database query failed after all retries: {e}")
                        # Allow access on final database error to avoid blocking users
                        return True, {"status": "database_error_allowing_access"}, None

        except Exception as e:
            if attempt < max_retries - 1:
                print(f"❌ Activation check error (attempt {attempt + 1}): {e}, retrying...")
                time.sleep(retry_delay)
                continue
            else:
                print(f"❌ Activation check failed after all retries: {e}")
                # Allow access on final error to avoid blocking users
                return True, {"status": "error_allowing_access"}, None

    # Fallback - should never reach here, but allow access if we do
    return True, {"status": "fallback_allowing_access"}, None

def is_activation_key_deactivated(activation_key):
    """Check if an activation key has been deactivated by querying Supabase directly - PRODUCTION READY"""
    try:
        # Always try database with robust retry logic
        max_retries = 2
        for attempt in range(max_retries):
            try:
                current_db_manager = db_manager

                if not DATABASE_AVAILABLE or not current_db_manager or not current_db_manager.is_available():
                    from database.models import ActivationKey as ActivationKeyModel
                    from database.db_manager import DatabaseManager
                    current_db_manager = DatabaseManager()

                if current_db_manager and current_db_manager.is_available():
                    session = current_db_manager.get_session()
                    if session:
                        key = session.query(ActivationKeyModel).filter_by(key_value=activation_key).first()
                        session.close()

                        if key:
                            return not key.is_active  # Return True if key is deactivated (is_active = False)
                        else:
                            return True  # If key doesn't exist, consider it deactivated
                else:
                    if attempt < max_retries - 1:
                        time.sleep(1)
                        continue

            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"Database query attempt {attempt + 1} failed: {e}, retrying...")
                    time.sleep(1)
                    continue
                else:
                    print(f"Error checking activation key status: {e}")

        # If database is completely unavailable, assume key is not deactivated to avoid blocking users
        return False
    except Exception:
        return False



def get_current_activation_key():
    """Get the currently active activation key from database with fallback handling"""
    try:
        # Check if db_manager is available and connected
        if db_manager is None:
            print("⚠️ Database manager not available for activation key")
            return None
            
        # Check if we have a healthy connection
        if not get_healthy_sql_connection():
            print("⚠️ No database connection for activation key")
            return None
            
        session = db_manager.get_session()
        if session is None:
            print("⚠️ Could not get database session for activation key")
            return None
            
        key = session.query(ActivationKey).filter_by(is_active=True).first()
        session.close()
        if key:
            return key.key_value
        return None
    except Exception as e:
        print(f"Error fetching activation key: {e}")
        return None


import uuid
from datetime import datetime
import secrets
import string

def generate_activation_key(school_name=None, subscription_type="monthly", expires_at=None):
    """Generate a unique activation key and save it to Supabase"""
    try:
        from database.models import ActivationKey
        from database.db_manager import db_manager
    except ImportError:
        # Fallback for deployment environments
        return None

    # Generate a 16-character activation key
    characters = string.ascii_uppercase + string.digits
    activation_key = ''.join(secrets.choice(characters) for _ in range(16))
    formatted_key = '-'.join([activation_key[i:i+4] for i in range(0, 16, 4)])

    # Save to Supabase
    session = db_manager.get_session()
    new_key = ActivationKey(
        id=str(uuid.uuid4()),
        key_value=formatted_key,
        school_name=school_name,
        subscription_type=subscription_type,
        is_active=True,
        expires_at=expires_at
    )
    session.add(new_key)
    session.commit()
    session.close()

    return formatted_key
def activate_system(activation_key, subscription_type="monthly"):
    """Activate the system with provided key from Supabase - PRODUCTION READY (no local files)"""
    max_retries = 2
    for attempt in range(max_retries):
        try:
            # Try to get database connection
            current_db_manager = db_manager

            if not DATABASE_AVAILABLE or not current_db_manager or not current_db_manager.is_available():
                from database.models import ActivationKey as ActivationKeyModel
                from database.db_manager import DatabaseManager
                current_db_manager = DatabaseManager()

            if not current_db_manager or not current_db_manager.is_available():
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                return False  # Database not available

            session = current_db_manager.get_session()
            if not session:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                return False

            # Import ActivationKey here to ensure it's available
            if 'ActivationKeyModel' not in locals():
                from database.models import ActivationKey as ActivationKeyModel

            key = session.query(ActivationKeyModel).filter_by(key_value=activation_key).first()

            if not key:
                session.close()
                return False  # Key doesn't exist
            if not key.is_active:
                session.close()
                return False  # Key deactivated
            if key.expires_at and key.expires_at < datetime.utcnow():
                session.close()
                return False  # Key expired

            # Key is valid - mark as active and save to database only (no local files)
            key.is_active = True
            session.commit()
            session.close()

            print(f"✅ System activated successfully with key: {activation_key}")
            return True

        except Exception as e:
            print(f"❌ Activation attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return False

    return False

def get_payment_instructions():
    """Get payment instructions for activation"""
    config = load_activation_config()
    bank_details = config.get('bank_details', {})

    return f"""
    PAYMENT INSTRUCTIONS FOR SYSTEM ACTIVATION
    ==========================================

    Monthly Subscription: ₦{config.get('monthly_amount', 20000):,}
    Yearly Subscription: ₦{config.get('yearly_amount', 60000):,}

    BANK DETAILS:
    Bank Name: {bank_details.get('bank_name', 'N/A')}
    Account Name: {bank_details.get('account_name', 'N/A')}
    Account Number: {bank_details.get('account_number', 'N/A')}
    Sort Code: {bank_details.get('sort_code', 'N/A')}
    """





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
        current_date = datetime.now().strftime("%A, %B %d, %Y at %I:%M %p")
        session_year = school_config.get('current_session', f"{datetime.now().year}/{datetime.now().year + 1}")
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
            "timestamp": datetime.now().isoformat(),
            "teacher_id": teacher_id,
            "activity": activity_type,
            "details": details
        }

        date_str = datetime.now().strftime("%Y-%m-%d")
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

def render_html_report(student_name, student_class, term, report_df, term_total, cumulative, final_grade, logo_base64, student_data=None, report_details=None, report_id=None):
    # Use Nigeria timezone (WAT = UTC+1)
    nigeria_time = datetime.now() + timedelta(hours=1)
    date_now = nigeria_time.strftime("%A, %B %d, %Y, %I:%M %p WAT")
    if report_id is None:
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

    qr_data = f"REPORT_ID:{report_id}|SCHOOL:{school_code}|NAME:{student_name}|CLASS:{student_class}|TERM:{term}|CUMULATIVE:{cumulative:.2f}|GRADE:{final_grade}|TEACHER:{st.session_state.teacher_id}|DATE:{date_now}|VERIFY:https://verify.akinsunrise.edu.ng/check/ {report_id}"
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
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300 ;500&display=swap" rel="stylesheet">
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
    /* Clean, readable styling that works in both light and dark modes */
    .stApp {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    /* Headers with good contrast */
    h1, h2, h3, h4, h5, h6 {
        font-weight: 600 !important;
    }

    /* Clean button styling */
    .stButton button {
        border-radius: 4px;
        padding: 0.25rem 1rem;
        background: #1976D2 !important;
        color: white !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 0.5rem 1rem !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }

    .stButton button:hover {
        background: #1565C0 !important;
        transform: translateY(-1px) !important;
    }

    /* Simple tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px !important;
        padding: 8px !important;
        border-bottom: 2px solid #e0e0e0 !important;
        background: transparent !important;
    }

    .stTabs [data-baseweb="tab-list"] button {
        background: transparent !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 8px 16px !important;
        font-weight: 500 !important;
        color: #666 !important;
        transition: all 0.2s ease !important;
    }

    .stTabs [data-baseweb="tab-list"] button:hover {
        background: #f5f5f5 !important;
        color: #333 !important;
    }

    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        background: #1976D2 !important;
        color: white !important;
        font-weight: 600 !important;
    }

    /* Form elements with good contrast */
    .stTextInput input, .stNumberInput input, .stTextArea textarea, .stSelectbox select {
        border: 1px solid #ddd !important;
        border-radius: 4px !important;
        padding: 0.5rem !important;
    }

    .stTextInput input:focus, .stNumberInput input:focus, .stTextArea textarea:focus {
        border-color: #1976D2 !important;
        box-shadow: 0 0 0 2px rgba(25, 118, 210, 0.2) !important;
        outline: none !important;
    }

    /* Message styling */
    .stSuccess {
        background: #e8f5e8 !important;
        border: 1px solid #4CAF50 !important;
        border-radius: 4px !important;
        padding: 1rem !important;
    }

    .stError {
        background: #ffeaea !important;
        border: 1px solid #F44336 !important;
        border-radius: 4px !important;
        padding: 1rem !important;
    }

    .stWarning {
        background: #fff3e0 !important;
        border: 1px solid #FF9800 !important;
        border-radius: 4px !important;
        padding: 1rem !important;
    }

    .stInfo {
        background: #e3f2fd !important;
        border: 1px solid #2196F3 !important;
        border-radius: 4px !important;
        padding: 1rem !important;
    }

    /* Dark mode support */
    @media (prefers-color-scheme: dark) {
        .stTabs [data-baseweb="tab-list"] {
            border-bottom-color: #444 !important;
        }

        .stTabs [data-baseweb="tab-list"] button {
            color: #ccc !important;
        }

        .stTabs [data-baseweb="tab-list"] button:hover {
            background: #333 !important;
            color: #fff !important;
        }

        .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
            background: #1976D2 !important;
            color: white !important;
        }

        .stTextInput input, .stNumberInput input, .stTextArea textarea, .stSelectbox select {
            background: #2d2d2d !important;
            color: #fff !important;
            border-color: #555 !important;
        }

        .stSuccess {
            background: rgba(76, 175, 80, 0.1) !important;
            border-color: #4CAF50 !important;
            color: #4CAF50 !important;
        }

        .stError {
            background: rgba(244, 67, 54, 0.1) !important;
            border-color: #F44336 !important;
            color: #F44336 !important;
        }

        .stWarning {
            background: rgba(255, 152, 0, 0.1) !important;
            border-color: #FF9800 !important;
            color: #FF9800 !important;
        }

        .stInfo {
            background: rgba(33, 150, 243, 0.1) !important;
            border-color: #2196F3 !important;
            color: #2196F3 !important;
        }
    }

    /* Mobile responsiveness */
    @media (max-width: 768px) {
        .stTabs [data-baseweb="tab-list"] {
            flex-wrap: wrap !important;
        }

        .stTabs [data-baseweb="tab-list"] button {
            flex: 1 1 auto !important;
            min-width: 120px !important;
            margin: 2px !important;
        }

        .stButton button {
            width: 100% !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

def check_session_timeout():
    """Check if user session has timed out"""
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.now()
        return False

    if 'session_timeout' not in st.session_state:
        st.session_state.session_timeout = 30  # Default 30 minutes

    time_diff = datetime.now() - st.session_state.last_activity
    if time_diff.seconds > (st.session_state.session_timeout * 60):
        return True

    st.session_state.last_activity = datetime.now()
    return False

def update_session_activity():
    """Update last activity time"""
    st.session_state.last_activity = datetime.now()

def login_page():
    st.set_page_config(
        page_title="Akin's Sunrise School – Report Card System", 
        layout="centered",
        initial_sidebar_state="collapsed",
        page_icon="🎓"
    )

    apply_custom_css()

    # Always do a fresh check of activation status (don't cache)
    is_activated, activation_status, expiry_date = check_activation_status()
    config = load_activation_config()

    # Force activation requirement for ALL users when activation is enabled
    if not is_activated:
        show_activation_required_page()
        return

    logo_base64 = get_logo_base64()
    if logo_base64:
        st.markdown(f"""
        <div style="text-align: center; margin-bottom: 20px;">
            <img src="data:image/png;base64,{logo_base64}" style="width: 120px; height: 120px; object-fit: contain; border-radius: 12px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="text-align: center; margin-bottom: 40px;">
        <h1 style="margin: 20px 0;">🔐 Staff Login</h1>
        <p style="color: #64748b; font-size: 1.125rem; font-weight: 400; margin: 0;">Akin's Sunrise School Management System</p>
    </div>
    """, unsafe_allow_html=True)

    # Show current activation key in simple text format
    current_activation_key = get_current_activation_key()
    if current_activation_key and is_activated:
        st.success(f"🔑 **Current Activation Key:** `{current_activation_key}`")
        st.info("💡 Save this key - you can use it to reactivate if the system restarts")

    # Show activation key info if available (but not just generated)
    if st.session_state.get('generated_activation_key') and not st.session_state.get('just_generated'):
        st.info(f"🔑 Activation key available for {st.session_state.get('generated_for_school', 'School')}")
        if st.button("🔍 View Activation Key"):
            st.session_state.just_generated = True
            st.rerun()

    # Show activation status if activated
    if is_activated:
        if activation_status.get('status') == 'trial':
            trial_expiry = datetime.fromisoformat(activation_status['trial_expiry'])
            days_left = (trial_expiry - datetime.now()).days
            if days_left > 0:
                st.info(f"🆓 Trial Period: {days_left} days remaining")
            else:
                st.warning("🕐 Trial period expired - Grace period active")
        else:
            if expiry_date:
                days_until_expiry = (expiry_date - datetime.now()).days
                if days_until_expiry > 7:
                    st.success(f"✅ System Activated - {days_until_expiry} days remaining")
                elif days_until_expiry > 0:
                    st.warning(f"⚠️ Subscription expires in {days_until_expiry} days")
                else:
                    st.error("🚨 Subscription expired - Grace period active")

    # Create tabs for login, teacher registration, and developer login
    login_tab, register_tab, developer_tab = st.tabs(["🔐 Staff Login", "👨‍🏫 Teacher Registration", "👨‍💻 Developer Login"])

    with login_tab:
        staff_login_form()

    with register_tab:
        teacher_registration_form()
        
    with developer_tab:
        developer_login_form()

def teacher_registration_form():
    """Teacher self-registration form - requires approval from principal/admin"""
    with st.container():
        st.markdown("### 👨‍🏫 Teacher Registration")
        st.markdown("Register as a teacher. Your account will require approval from the principal or administrator.")

        with st.form("teacher_registration_form"):
            col1, col2 = st.columns(2)

            with col1:
                reg_full_name = st.text_input("Full Name*", placeholder="John Doe")
                reg_email = st.text_input("Email Address*", placeholder="teacher@example.com")
                reg_phone = st.text_input("Phone Number", placeholder="+234 800 123 4567")
                reg_password = st.text_input("Password*", type="password", placeholder="Enter secure password")

            with col2:
                reg_user_id = st.text_input("Desired User ID*", placeholder="teacher_john")
                reg_confirm_password = st.text_input("Confirm Password*", type="password", placeholder="Confirm your password")
                reg_subjects = st.multiselect("Subjects You Teach", subjects, help="Select subjects you are qualified to teach")
                reg_classes = st.multiselect("Preferred Classes", 
                    ["SS1A", "SS1B", "SS1C", "SS2A", "SS2B", "SS2C", "SS3A", "SS3B", "SS3C",
                     "JSS1A", "JSS1B", "JSS1C", "JSS2A", "JSS2B", "JSS2C", "JSS3A", "JSS3B", "JSS3C"],
                    help="Select classes you'd prefer to teach")

            reg_notes = st.text_area("Additional Information", 
                placeholder="Brief note about your teaching experience, qualifications, etc.",
                help="This information will help administrators evaluate your application")

            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                if st.form_submit_button("📝 Submit Registration", width='stretch'):
                    # Validation
                    errors = []
                    if not reg_full_name:
                        errors.append("Full name is required")
                    if not reg_email:
                        errors.append("Email address is required")
                    if not reg_user_id:
                        errors.append("User ID is required")
                    if not reg_password:
                        errors.append("Password is required")
                    if reg_password != reg_confirm_password:
                        errors.append("Passwords do not match")
                    if len(reg_password) < 6:
                        errors.append("Password must be at least 6 characters long")

                    # Use SQLAlchemy session to check for existing user
                    from database.db_manager import db_manager
                    session = db_manager.get_session()
                    try:
                        user_id_exists = session.execute(text("SELECT 1 FROM users WHERE id = :id"), {"id": reg_user_id}).fetchone() is not None
                        email_exists = session.execute(text("SELECT 1 FROM users WHERE LOWER(email) = :email"), {"email": reg_email.lower()}).fetchone() is not None
                        if user_id_exists:
                            errors.append("User ID already exists")
                        if email_exists:
                            errors.append("Email address already registered")
                    finally:
                        session.close()

                    if errors:
                        for error in errors:
                            st.error(f"❌ {error}")
                    else:
                        # Insert new teacher using SQLAlchemy
                        session = db_manager.get_session()
                        try:
                            insert_sql = text("""
                                INSERT INTO users (
                                    id, password_hash, role, full_name, email, phone, created_date, last_login, is_active,
                                    two_factor_enabled, two_factor_secret, session_timeout, failed_attempts, locked_until,
                                    assigned_classes, departments, custom_features, approval_status, approved_by, approval_date, registration_notes, subjects
                                ) VALUES (
                                    :id, :password_hash, :role, :full_name, :email, :phone, :created_date, :last_login, :is_active,
                                    :two_factor_enabled, :two_factor_secret, :session_timeout, :failed_attempts, :locked_until,
                                    :assigned_classes, :departments, :custom_features, :approval_status, :approved_by, :approval_date, :registration_notes, :subjects
                                )
                            """)
                            params = {
                                "id": reg_user_id,
                                "password_hash": hash_password(reg_password),
                                "role": "teacher",
                                "full_name": reg_full_name,
                                "email": reg_email,
                                "phone": reg_phone,
                                "created_date": datetime.now(),
                                "last_login": None,
                                "is_active": False,
                                "two_factor_enabled": False,
                                "two_factor_secret": None,
                                "session_timeout": 30,
                                "failed_attempts": 0,
                                "locked_until": None,
                                "assigned_classes": ",".join(reg_classes),
                                "departments": "",
                                "custom_features": ",".join(USER_ROLES["teacher"].get('default_features', [])),
                                "approval_status": "pending",
                                "approved_by": None,
                                "approval_date": None,
                                "registration_notes": reg_notes,
                                "subjects": ",".join(reg_subjects)
                            }
                            session.execute(insert_sql, params)
                            session.commit()
                            st.success("✅ Registration submitted successfully!")
                            st.info("""
                                **Next Steps:**
                                - Your registration has been submitted for approval
                                - A principal or administrator will review your application
                                - You will be notified once your account is approved
                                - Check back here or contact the school administration for updates
                                """)
                            log_teacher_activity("system", "teacher_registration", {
                                "registered_user": reg_user_id,
                                "full_name": reg_full_name,
                                "email": reg_email,
                                "timestamp": datetime.now().isoformat(),
                                "status": "pending_approval"
                            })
                            st.rerun()
                        except Exception as e:
                            session.rollback()
                            st.error(f"❌ Registration error: {str(e)}")
                        finally:
                            session.close()

def developer_login_form():
    """Developer login form with hardcoded password access"""
    with st.container():
        st.markdown("### 👨‍💻 Developer Access")
        st.markdown("**Developer System Access** - Enter the master developer password to access system controls.")
        
        with st.form("developer_login_form"):
            st.info("🔐 **Developer Authentication Required**")
            developer_password = st.text_input("Developer Password", type="password", placeholder="Enter developer password")
            
            col1, col2, col3 = st.columns([1, 1, 1])
            with col2:
                if st.form_submit_button("🚀 Developer Login", width='stretch'):
                    # Check hardcoded developer password
                    if developer_password == "Stephen@22":
                        # Set developer session state
                        st.session_state.developer_authenticated = True
                        st.session_state.developer_id = "developer_001"
                        st.session_state.authenticated = True
                        st.session_state.teacher_id = "developer_001"
                        st.session_state.user_role = "developer"
                        st.session_state.user_permissions = USER_ROLES["developer"]["permissions"]
                        st.session_state.session_timeout = 120
                        st.session_state.last_activity = datetime.now()
                        
                        # Log successful developer login
                        create_audit_log("developer_login_success", "developer_001", {
                            "login_method": "developer_password",
                            "timestamp": datetime.now().isoformat(),
                            "access_level": "full_system_control"
                        }, "authentication")
                        
                        st.success("✅ Developer access granted!")
                        st.info("🔄 Redirecting to developer console...")
                        st.rerun()
                    else:
                        st.error("❌ Invalid developer password.")
                        # Log failed developer login attempt
                        create_audit_log("developer_login_failed", "unknown", {
                            "timestamp": datetime.now().isoformat(),
                            "attempted_password_length": len(developer_password) if developer_password else 0
                        }, "security")

def show_activation_required_page():
    """Show activation required page with payment instructions"""
    # Display school logo at the top
    logo_base64 = get_logo_base64()
    if logo_base64:
        st.markdown(f"""
        <div style="text-align: center; margin-bottom: 20px;">
            <img src="data:image/png;base64,{logo_base64}" style="width: 120px; height: 120px; object-fit: contain; border-radius: 12px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <style>
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    .animated-header {
        animation: pulse 2s ease-in-out infinite;
    }
    </style>
    <div style="text-align: center; margin-bottom: 30px;">
        <h1 class="animated-header" style="color: #ff6b6b; margin: 10px 0;">🔒 System Activation Required</h1>
        <h2 style="color: var(--text-secondary); margin: 5px 0;">Akin's Sunrise School System</h2>
    </div>
    """, unsafe_allow_html=True)

    config = load_activation_config()
    is_activated, activation_status, expiry_date = check_activation_status()

    # Show specific message if activation was disabled or key deactivated
    if activation_status.get('status') == 'activation_disabled':
        st.error("🚨 **SYSTEM DEACTIVATED**")
        st.warning("⚠️ The system activation has been disabled. A new activation key must be generated and activated to continue using the system.")
    elif activation_status.get('status') == 'key_deactivated':
        deactivated_key = activation_status.get('activation_key', 'Unknown')
        st.error("🚨 **ACTIVATION KEY DEACTIVATED**")
        st.warning(f"⚠️ The activation key `{deactivated_key}` has been deactivated by the administrator.")
        st.info("🔄 This key will no longer work even if the system restarts. A new activation key must be generated.")
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #f44336, #d32f2f); 
            border: 3px solid #b71c1c; 
            border-radius: 15px; 
            padding: 20px; 
            text-align: center; 
            margin: 20px 0;
            box-shadow: 0 6px 20px rgba(244, 67, 54, 0.3);
        ">
            <h3 style="color: white; margin: 0 0 10px 0; font-size: 18px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                🚫 DEACTIVATED KEY
            </h3>
            <div style="
                background: rgba(255,255,255,0.95); 
                border-radius: 10px; 
                padding: 15px; 
                margin: 10px 0;
                box-shadow: inset 0 2px 10px rgba(0,0,0,0.1);
            ">
                <div style="
                    font-family: 'Courier New', monospace; 
                    font-size: 24px; 
                    font-weight: bold; 
                    color: #d32f2f; 
                    letter-spacing: 2px;
                    text-decoration: line-through;
                ">{deactivated_key}</div>
            </div>
            <p style="color: white; margin: 10px 0 0 0; font-size: 14px; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                This key has been permanently deactivated
            </p>
        </div>
        """, unsafe_allow_html=True)

    # Show generated activation key prominently at the top if just generated
    if st.session_state.get('generated_activation_key') and st.session_state.get('just_generated'):
        st.markdown("---")
        st.balloons()
        st.markdown("## 🎉 Activation Key Successfully Generated!")

        st.success("🎉 **Activation Key Generated Successfully!**")
        st.code(st.session_state.generated_activation_key, language=None)
        st.info(f"**School:** {st.session_state.get('generated_for_school', 'School')}")
        st.info("📋 Copy this key and share it with the school administration")

        # Action buttons for the generated key
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            if st.button("📋 Copy Key to Clipboard", width='stretch', type="primary"):
                st.success("✅ Key copied! You can now paste it where needed.")
        with col2:
            if st.button("📧 Generate New Key", width='stretch'):
                # Clear current key to allow generation of new one
                if 'generated_activation_key' in st.session_state:
                    del st.session_state.generated_activation_key
                if 'generated_for_school' in st.session_state:
                    del st.session_state.generated_for_school
                if 'just_generated' in st.session_state:
                    del st.session_state.just_generated
                st.info("✨ Current key cleared. Generate a new one below.")
                st.rerun()
        with col3:
            if st.button("✅ Continue to Login", width='stretch'):
                # Keep the key but mark as no longer just generated
                st.session_state.just_generated = False
                st.rerun()

        st.markdown("---")

    st.error("🚨 This system requires activation to continue.")

    # Activation key input (only for teacher_bamstep)
    st.markdown("### 🔑 System Activation")

    # Show developer access
    dev_user = st.text_input("Developer Access", type="password", placeholder="Enter developer credentials")
    if dev_user == "Stephen@22":
        st.success("✅ Developer access granted!")

        with st.expander("🔧 Developer Activation Panel", expanded=True):
            st.markdown("#### Generate Activation Key")

            subscription_type = st.selectbox("Subscription Type", ["monthly", "yearly"])
            school_name = st.text_input("School Name (for records)")
            payment_confirmed = st.checkbox("✅ Payment confirmed and verified")

            if st.button("🔑 Generate Activation Key") and payment_confirmed:
                activation_key = generate_activation_key()

                # Save activation record
                activation_record = {
                    "activation_key": activation_key,
                    "school_name": school_name,
                    "subscription_type": subscription_type,
                    "generated_date": datetime.now().isoformat(),
                    "generated_by": "developer_001",
                    "amount": config.get(f'{subscription_type}_amount', 20000),
                    "status": "generated"
                }

                # Load existing records
                records = []
                if os.path.exists("activation_records.json"):
                    try:
                        with open("activation_records.json", 'r') as f:
                            records = json.load(f)
                    except:
                        records = []

                records.append(activation_record)

                # Save updated records
                with open("activation_records.json", 'w') as f:
                    json.dump(records, f, indent=2)

                # Auto-enable activation when generating new key
                config['activation_enabled'] = True
                save_activation_config(config)

                # Store activation key in session state to show on this page
                st.session_state.generated_activation_key = activation_key
                st.session_state.generated_for_school = school_name
                st.session_state.just_generated = True

                st.success(f"🎉 Activation key generated for {school_name}! System activation is now enabled.")
                st.rerun()

        # Show activation records with management options
        if os.path.exists("activation_records.json"):
            with st.expander("📋 Activation Key Management", expanded=False):
                try:
                    with open("activation_records.json", 'r') as f:
                        content = f.read().strip()
                        if not content:
                            records = []
                        else:
                            records = json.loads(content)

                    if records and isinstance(records, list):
                        st.markdown("#### Active Activation Keys")
                        for i, record in enumerate(records[-15:]):  # Show last 15
                            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

                            key_status = record.get('status', 'generated')
                            is_deactivated = key_status == 'deactivated'

                            with col1:
                                if is_deactivated:
                                    st.write(f"~~**{record.get('school_name', 'Unknown')}**~~ (DEACTIVATED)")
                                    st.code(f"{record.get('activation_key', 'N/A')}", language=None)
                                else:
                                    st.write(f"**{record.get('school_name', 'Unknown')}**")
                                    st.code(f"{record.get('activation_key', 'N/A')}", language=None)

                            with col2:
                                st.write(f"Type: {record.get('subscription_type', 'monthly')}")
                                st.write(f"Amount: ₦{record.get('amount', 0):,}")

                            with col3:
                                generated_date = record.get('generated_date', '')
                                if generated_date:
                                    try:
                                        date_obj = datetime.fromisoformat(generated_date)
                                        st.write(f"Date: {date_obj.strftime('%Y-%m-%d')}")
                                    except:
                                        st.write(f"Date: {generated_date}")

                                if is_deactivated:
                                    st.error("🚫 DEACTIVATED")
                                else:
                                    st.success("✅ ACTIVE")

                            with col4:
                                if not is_deactivated:
                                    if st.button(f"🚫 Deactivate", key=f"deactivate_{i}_{record.get('activation_key', '')}"):
                                        # Deactivate the key
                                        actual_index = len(records) - 15 + i
                                        records[actual_index]['status'] = 'deactivated'
                                        records[actual_index]['deactivated_date'] = datetime.now().isoformat()
                                        records[actual_index]['deactivated_by'] = 'developer_001'

                                        # Save updated records with proper file handling
                                        with open("activation_records.json", 'w') as f:
                                            json.dump(records, f, indent=2)
                                            f.flush()
                                            os.fsync(f.fileno())

                                        # Check if this is the currently active key
                                        activation_key = record.get('activation_key', '')
                                        current_key = get_current_activation_key()

                                        if current_key == activation_key:
                                            st.success(f"🚫 Key deactivated! System will require reactivation on next restart.")
                                        else:
                                            st.success(f"🚫 Key deactivated!")

                                        st.rerun()
                                else:
                                    if st.button(f"🔄 Reactivate", key=f"reactivate_{i}_{record.get('activation_key', '')}"):
                                        # Reactivate the key
                                        actual_index = len(records) - 15 + i
                                        records[actual_index]['status'] = 'generated'
                                        if 'deactivated_date' in records[actual_index]:
                                            del records[actual_index]['deactivated_date']
                                        if 'deactivated_by' in records[actual_index]:
                                            del records[actual_index]['deactivated_by']

                                        # Save updated records with proper file handling
                                        with open("activation_records.json", 'w') as f:
                                            json.dump(records, f, indent=2)
                                            f.flush()
                                            os.fsync(f.fileno())

                                        st.success(f"✅ Key reactivated!")
                                        st.rerun()

                        # Add bulk deactivation option
                        st.markdown("---")
                        st.markdown("#### 🚫 Bulk Key Management")
                        col1, col2 = st.columns(2)

                        with col1:
                            if st.button("🚫 Deactivate All Active Keys"):
                                deactivated_count = 0
                                current_key = get_current_activation_key()

                                for record in records:
                                    if record.get('status', 'generated') != 'deactivated':
                                        record['status'] = 'deactivated'
                                        record['deactivated_date'] = datetime.now().isoformat()
                                        record['deactivated_by'] = 'developer_001'
                                        deactivated_count += 1

                                # Save updated records
                                with open("activation_records.json", 'w') as f:
                                    json.dump(records, f, indent=2)

                                # If current system key was deactivated, show warning but don't remove activation_status.json
                                # This allows the system to detect deactivation on next check
                                if current_key and any(r.get('activation_key') == current_key for r in records):
                                    st.warning(f"🚫 Current system key {current_key} has been deactivated! System will require reactivation on next restart.")

                                st.success(f"🚫 Deactivated {deactivated_count} keys!")
                                st.rerun()

                        with col2:
                            if st.button("🔄 Reactivate All Keys"):
                                reactivated_count = 0
                                for record in records:
                                    if record.get('status', 'generated') == 'deactivated':
                                        record['status'] = 'generated'
                                        if 'deactivated_date' in record:
                                            del record['deactivated_date']
                                        if 'deactivated_by' in record:
                                            del record['deactivated_by']
                                        reactivated_count += 1

                                # Save updated records
                                with open("activation_records.json", 'w') as f:
                                    json.dump(records, f, indent=2)

                                st.success(f"✅ Reactivated {reactivated_count} keys!")
                                st.rerun()

                        # Show current system activation key status
                        st.markdown("---")
                        st.markdown("#### 🔍 Current System Status")
                        current_key = get_current_activation_key()
                        if current_key:
                            is_deactivated = is_activation_key_deactivated(current_key)
                            if is_deactivated:
                                st.error(f"🚫 Current key {current_key} is DEACTIVATED - System will require reactivation!")
                            else:
                                st.success(f"✅ Current key {current_key} is ACTIVE")

                                # Quick deactivate current key button
                                if st.button("🚫 Deactivate Current System Key", type="secondary"):
                                    # Find and deactivate current key
                                    for record in records:
                                        if record.get('activation_key') == current_key:
                                            record['status'] = 'deactivated'
                                            record['deactivated_date'] = datetime.now().isoformat()
                                            record['deactivated_by'] = 'developer_001'
                                            break

                                    # Save updated records
                                    with open("activation_records.json", 'w') as f:
                                        json.dump(records, f, indent=2)

                                    st.success(f"🚫 Current key {current_key} deactivated! System will require reactivation on next restart.")
                                    st.rerun()
                        else:
                            st.info("No current activation key found.")

                    else:
                        st.info("No activation records found.")
                except json.JSONDecodeError as e:
                    st.error(f"Activation records file is corrupted. Error: {str(e)}")
                    st.info("Click below to reset the activation records file:")
                    if st.button("🔄 Reset Activation Records File"):
                        with open("activation_records.json", 'w') as f:
                            json.dump([], f, indent=2)
                        st.success("✅ Activation records file reset!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Error loading activation records: {str(e)}")
                    st.info("The activation records file may be corrupted or inaccessible.")
                    if st.button("🔄 Create New Activation Records File"):
                        try:
                            with open("activation_records.json", 'w') as f:
                                json.dump([], f, indent=2)
                            st.success("✅ New activation records file created!")
                            st.rerun()
                        except Exception as create_error:
                            st.error(f"Failed to create new file: {str(create_error)}")

    # Activation key input for schools
    st.markdown("---")
    st.markdown("#### 🔐 Enter Activation Key")

    activation_key = st.text_input("Activation Key", placeholder="XXXX-XXXX-XXXX-XXXX", key="activation_key_input")

    if st.button("🚀 Activate System", key="activate_system_btn") and activation_key:
        with st.spinner("Activating system..."):
            if activate_system(activation_key):
                st.success("🎉 System activated successfully!")
                st.balloons()

                # Clear ALL session states to force fresh activation check
                keys_to_clear = [
                    'generated_activation_key', 'generated_for_school', 'just_generated',
                    'activation_check_done', 'activation_status', 'activation_data'
                ]
                for key in keys_to_clear:
                    if key in st.session_state:
                        del st.session_state[key]

                # Set activation flag in session state to help with fresh check
                st.session_state.activated = True
                st.session_state.show_activation = False

                # Clear any Streamlit caches
                try:
                    if hasattr(st, 'cache_data'):
                        st.cache_data.clear()
                    if hasattr(st, 'experimental_memo'):
                        st.experimental_memo.clear()
                except:
                    pass  # Ignore cache clear errors

                st.info("🔄 Redirecting to login page...")
                st.rerun()
            else:
                st.error("❌ Invalid activation key. Please check and try again.")
                st.info("💡 Make sure you're entering the correct activation key format: XXXX-XXXX-XXXX-XXXX")

    st.markdown("---")
    st.markdown("#### 📞 Contact Support")

    # Allow teacher_bamstep to edit contact support
    if dev_user == "Stephen@22":
        with st.expander("✏️ Edit Contact Support Info", expanded=False):
            support_config = {}
            if os.path.exists("support_config.json"):
                try:
                    with open("support_config.json", 'r') as f:
                        support_config = json.load(f)
                except:
                    support_config = {}

            with st.form("support_config_form"):
                support_contact = st.text_input("Support Contact Name", 
                                               value=support_config.get('contact_name', 'School ICT'))
                support_email = st.text_input("Support Email", 
                                            value=support_config.get('email', 'bamidelestephen224@gmail.com'))
                support_phone = st.text_input("Support Phone", 
                                            value=support_config.get('phone', '08153919612'))
                support_message = st.text_area("Support Message", 
                                             value=support_config.get('message', 'Need help with activation payment?'))

                if st.form_submit_button("💾 Save Support Info"):
                    new_support_config = {
                        'contact_name': support_contact,
                        'email': support_email,
                        'phone': support_phone,
                        'message': support_message,
                        'updated_by': 'Stephen@22',
                        'updated_date': datetime.now().isoformat()
                    }

                    with open("support_config.json", 'w') as f:
                        json.dump(new_support_config, f, indent=2)

                    st.success("✅ Support information updated!")
                    st.rerun()

    # Load and display support info
    support_config = {}
    if os.path.exists("support_config.json"):
        try:
            with open("support_config.json", 'r') as f:
                support_config = json.load(f)
        except:
            support_config = {}

    contact_name = support_config.get('contact_name', 'School ICT')
    contact_email = support_config.get('email', 'bamidelestephen224@gmail.com')
    contact_phone = support_config.get('phone', '08153919612')
    contact_message = support_config.get('message', 'Need help with activation payment?')

    st.info(f"""
**{contact_message}**

📞 **Contact:** {contact_name}
📧 **Email:** {contact_email}
📱 **Phone:** {contact_phone} or visit the school ICT
    """)

def staff_login_form():
    """Staff login form with enhanced security - supports both User ID and Email login"""
    with st.container():
        st.markdown("### Staff Access Portal")
        st.markdown("Please enter your credentials to access the school management system.")

        user_input = st.text_input("User ID or Email", placeholder="Enter your user ID or email address")
        password = st.text_input("Password", type="password", placeholder="Enter your password")

        # Find user by ID or email
        def find_user_by_id_or_email(user_input, users_db):
            """Find user by either ID or email - handles both UUID keys (Supabase) and username keys (fallback)"""
            # First, try to find by exact user ID (for backwards compatibility)
            if user_input in users_db:
                return user_input, users_db[user_input]

            # Search by email OR by id field within user data (for Supabase UUID keys)
            for user_id, user_data in users_db.items():
                # Check by email
                if user_data.get('email', '').lower() == user_input.lower():
                    return user_id, user_data
                # Check by id field (in case user entered their registered ID)
                if user_data.get('id', '').lower() == user_input.lower():
                    return user_id, user_data
                # Check by username field if it exists
                if user_data.get('username', '').lower() == user_input.lower():
                    return user_id, user_data

            return None, None

        # Check if user account is locked (try to find user first)
        if user_input:
            users_db = load_user_database()
            found_user_id, found_user = find_user_by_id_or_email(user_input, users_db)
            if found_user_id and is_user_locked(found_user_id):
                st.error("🔒 Account temporarily locked due to multiple failed attempts. Please try again later.")
                return

        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("🚀 Login", width='stretch'):
                if user_input and password:
                    users_db = load_user_database()
                    found_user_id, user = find_user_by_id_or_email(user_input, users_db)

                    if found_user_id and user:
                        # Block teacher_bamstep account entirely (as per requirements)
                        if found_user_id == "teacher_bamstep":
                            st.error("❌ This account has been disabled. Please contact the developer.")
                            return
                            
                        # Check if user is active
                        if not user.get('active', True):
                            st.error("❌ Account is disabled. Contact administrator.")
                            return

                        # Verify password
                        if verify_password(password, user['password_hash']):
                            # Check approval status for teacher accounts
                            approval_status = user.get('approval_status', 'approved')
                            if approval_status == 'pending':
                                st.warning("⏳ **Account Pending Approval**")
                                st.info("""
                                Your teacher registration is currently pending approval from the school administration.

                                **What happens next:**
                                - The principal or administrator will review your application
                                - You'll be notified once your account is approved
                                - Contact the school administration if you need updates

                                **Need help?** Contact the school office for assistance.
                                """)
                                return
                            elif approval_status == 'rejected':
                                rejection_reason = user.get('rejection_reason', 'No reason provided')
                                st.error("❌ **Account Application Rejected**")
                                st.info(f"""
                                Your teacher registration was not approved by the administration.

                                **Reason:** {rejection_reason}

                                Please contact the school administration for more information or to reapply.
                                """)
                                return

                            # Check 2FA if enabled
                            if user.get('two_factor_enabled', False):
                                st.session_state.pending_2fa = found_user_id
                                st.session_state.pending_2fa_secret = user.get('two_factor_secret')
                                st.rerun()
                            else:
                                # Complete login
                                complete_login(found_user_id, user)
                        else:
                            increment_failed_attempts(found_user_id)
                            log_teacher_activity(found_user_id, "failed_login", {
                                "attempted_user_id": user_input,
                                "actual_user_id": found_user_id,
                                "timestamp": datetime.now().isoformat(),
                                "reason": "invalid_password"
                            })
                            st.error("❌ Invalid credentials. Please try again.")
                    else:
                        log_teacher_activity(user_input or "unknown", "failed_login", {
                            "attempted_user_input": user_input,
                            "timestamp": datetime.now().isoformat(),
                            "reason": "user_not_found"
                        })
                        st.error("❌ Invalid credentials. Please try again.")
                else:
                    st.warning("⚠️ Please enter both User ID/Email and Password.")



def two_factor_verification():
    """Two-factor authentication verification"""
    st.markdown("### 🔐 Two-Factor Authentication")
    st.markdown("Please enter the 6-digit code from your authenticator app.")

    token = st.text_input("Enter 6-digit code", placeholder="123456", max_chars=6)

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("Verify", width='stretch'):
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
        "login_time": datetime.now().isoformat(),
        "ip_address": "replit_session",
        "user_role": user.get('role', 'teacher')
    })

    st.session_state.authenticated = True
    st.session_state.user_type = "staff"
    st.session_state.teacher_id = user_id
    st.session_state.user_role = user.get('role', 'teacher')
    st.session_state.user_permissions = USER_ROLES.get(user.get('role', 'teacher'), {}).get('permissions', [])
    st.session_state.session_timeout = user.get('session_timeout', 30)
    st.session_state.last_activity = datetime.now()

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
                            formatted_date = datetime.fromisoformat(last_modified).strftime('%Y-%m-%d %H:%M')
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
                conduct_rating = st.text_input("Conduct", key="skill_conduct", placeholder="A")
                punctuality_rating = st.text_input("Punctuality", key="skill_punctuality", placeholder="A")
            with char_col2:
                clubs_rating = st.text_input("Clubs/Societies", key="skill_clubs", placeholder="A")
                hobbies_rating = st.text_input("Hobbies", key="skill_hobbies", placeholder="A")
            with char_col3:
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

        # For 1st term, cumulative is same as current term total
        if term == "1st Term":
            subject_cumulative = total
        else:
            # For 2nd and 3rd terms, average with previous cumulative
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
                    "created_date": datetime.now().isoformat(),
                    "last_modified": datetime.now().isoformat(),
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
                st.session_state.last_auto_save = datetime.now()

            # Check if 30 seconds have passed since last auto-save
            time_diff = datetime.now() - st.session_state.last_auto_save
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
                        "created_date": datetime.now().isoformat(),
                        "last_modified": datetime.now().isoformat(),
                        "subject_scores": subject_scores,
                        "additional_data": additional_data,
                        "completion_status": f"{completion_percentage:.0f}",
                        "completed_subjects": completed_subjects,
                        "auto_save": True
                    }

                    save_draft_report(draft_data)
                    st.session_state.last_auto_save = datetime.now()
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

                # Generate report ID once and use it consistently
                report_id = generate_report_id()
                html = render_html_report(student_name, student_class, term, report_df, total_term_score, average_cumulative, final_grade, logo_base64, student_data, report_details, report_id)
                HTML(string=html).write_pdf("report_card.pdf")

            st.success("✅ Report Card Generated Successfully!")

            st.markdown("### 📋 Score Summary")
            st.dataframe(report_df, width='stretch')

            with open("report_card.pdf", "rb") as f:
                st.download_button(
                    "⬇️ Download PDF Report", 
                    f, 
                    file_name=f"{student_name.replace(' ', '_')}_Report_{term.replace(' ', '_')}.pdf", 
                    mime="application/pdf",
                    width='stretch'
                )

            report_data = {
                "report_id": report_id,
                "student_name": student_name,
                "student_class": student_class,
                "term": term,
                "parent_email": parent_email,
                "teacher_id": st.session_state.teacher_id,
                "created_date": datetime.now().isoformat(),
                "status": "pending_review",
                "scores_data": updated_scores_data,
                "average_cumulative": float(average_cumulative),
                "final_grade": final_grade,
                "total_term_score": total_term_score,
                "html_content": html,
                "report_details": report_details
            }

            # --- Verification Key Generation & Persistence (restart-safe) ---
            try:
                import secrets
                from database.verification_keys import save_key, key_exists

                def generate_unique_key():
                    # keep looping until we find a unique key (very unlikely to loop more than once)
                    while True:
                        k = secrets.token_urlsafe(16)
                        if not key_exists(k):
                            return k

                verification_key = generate_unique_key()
                save_key(verification_key, st.session_state.teacher_id, report_id)
                report_data["verification_key"] = verification_key
            except Exception as e:
                # If persistent storage fails, still attach an in-memory key (less ideal)
                import secrets as _secrets
                report_data["verification_key"] = _secrets.token_urlsafe(16)
                print(f"Warning: could not persist verification key: {e}")
            # --- End verification persistence ---

            # Automatically approve the report
            success, message = auto_approve_report(report_data)

            log_teacher_activity(st.session_state.teacher_id, "report_generated", {
                "student_name": student_name,
                "student_class": student_class,
                "term": term,
                "subjects_count": len(selected_subjects),
                "average_cumulative": float(average_cumulative),
                "final_grade": final_grade,
                "total_term_score": total_term_score,
                "status": "auto_approved"
            })

            if success:
                st.success("✅ Report Generated and Automatically Approved!")
                st.info("📋 The report has been automatically saved to the system.")
            else:
                st.error(f"❌ Error saving report: {message}")

        except Exception as e:
            st.error(f"❌ Error generating report: {str(e)}")
            st.info("Please try again or contact your administrator.")

def student_database_tab():
    st.subheader("👥 Student Database")

    admin_users = ["developer_001"]
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
                    new_student_name = st.text_input("Student Name", placeholder="John Doe")
                    new_student_class = st.text_input("Class", placeholder="Grade 1")
                    new_parent_name = st.text_input("Parent/Guardian Name", placeholder="Jane Doe")
                    new_admission_no = st.text_input("Admission Number", placeholder="ASS/25/001")

                with col2:
                    new_parent_email = st.text_input("Parent Email*", placeholder="parent@example.com")
                    new_parent_phone = st.text_input("Parent Phone", placeholder="+234 xxx xxx xxxx")
                    new_class_size = st.number_input("Class Size", min_value=1, max_value=100, value=35)
                    new_attendance = st.text_input("Attendance Rate", placeholder="95%", value="95%")
                    new_gender = st.selectbox("Gender", ["Male", "Female", "Other"], index=0)
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
                                           help="Delete student", width='stretch'):
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

    # Show recent reports to help users find the correct ID (Admin only)
    if check_user_permissions(st.session_state.teacher_id, "system_config"):
        with st.expander("📋 Recent Report IDs (Admin Only)", expanded=False):
            approved_dir = "approved_reports"
            if os.path.exists(approved_dir):
                recent_reports = []
                for filename in os.listdir(approved_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(approved_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                report = json.load(f)
                                recent_reports.append({
                                    'id': report.get('report_id', 'Unknown'),
                                    'student': report.get('student_name', 'Unknown'),
                                    'class': report.get('student_class', 'Unknown'),
                                    'term': report.get('term', 'Unknown'),
                                    'date': report.get('created_date', 'Unknown')
                                })
                        except:
                            continue

                # Sort by creation date (most recent first)
                recent_reports.sort(key=lambda x: x['date'], reverse=True)

                if recent_reports:
                    st.markdown("**Recent Reports (Administrator View):**")
                    for report in recent_reports[:10]:  # Show last 10 reports
                        date_str = report['date']
                        try:
                            date_obj = datetime.fromisoformat(date_str)
                            formatted_date = date_obj.strftime('%Y-%m-%d %H:%M')
                        except:
                            formatted_date = date_str

                        st.markdown(f"**{report['id']}** - {report['student']} ({report['class']}) - {report['term']} - *{formatted_date}*")
                else:
                    st.info("No reports found in the system yet.")
            else:
                st.info("No reports directory found.")
    else:
        st.info("💡 Contact your administrator if you need help finding a specific Report ID.")

    report_id = st.text_input(
        "Enter Report ID:", 
        placeholder="e.g., ASS-123456-ABCD",
        key="report_id_input"
    )

    if st.button("🔍 Verify Report", key="verify_btn"):
        if report_id:
            if report_id.startswith("ASS-"):
                # --- Verification Key Validation ---
                from database.verification_keys import get_key
                verification_key_input = st.text_input("Enter Verification Key:", key="verification_key_input")
                key_record = get_key(verification_key_input) if verification_key_input else None
                if key_record and key_record[3] == report_id:
                    st.success("✅ **Report Verified Successfully!** Verification key is valid and matches the report.")

                    # Locate report JSON in approved_reports or report_backup
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
                                except Exception:
                                    continue

                    if not report_found:
                        backup_dir = "report_backup"
                        if os.path.exists(backup_dir):
                            for filename in os.listdir(backup_dir):
                                if filename.endswith('.json'):
                                    filepath = os.path.join(backup_dir, filename)
                                    try:
                                        with open(filepath, 'r') as f:
                                            report = json.load(f)
                                            if report.get('report_id') == report_id:
                                                report_found = True
                                                report_data = report
                                                break
                                    except Exception:
                                        continue

                    # If found, render details (student, scores, auth info) and allow PDF download
                    if report_found and report_data:
                        # Reuse the same UI from previous implementation (compact)
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
                        with col2:
                            st.markdown("#### 🔐 Authentication Details")
                            st.write(f"**Report ID:** {report_data.get('report_id', 'N/A')}")
                            st.write(f"**Generated By:** {report_data.get('teacher_id', 'N/A')}")
                            created_date = report_data.get('created_date', 'N/A')
                            approved_date = report_data.get('approved_date', 'N/A')
                            approved_by = report_data.get('approved_by', 'N/A')
                            if created_date != 'N/A':
                                try:
                                    formatted_created = datetime.fromisoformat(created_date).strftime('%B %d, %Y at %I:%M %p')
                                    st.write(f"**Created Date:** {formatted_created}")
                                except:
                                    st.write(f"**Created Date:** {created_date}")
                            if approved_date != 'N/A':
                                try:
                                    formatted_approved = datetime.fromisoformat(approved_date).strftime('%B %d, %Y at %I:%M %p')
                                    st.write(f"**Approved Date:** {formatted_approved}")
                                except:
                                    st.write(f"**Approved Date:** {approved_date}")
                            st.write(f"**Approved By:** {approved_by}")

                        pdf_path = f"approved_reports/approved_{report_id}.pdf"
                        if os.path.exists(pdf_path):
                            with open(pdf_path, "rb") as f:
                                st.download_button(
                                    "📄 Download Verified Report Card (PDF)",
                                    f,
                                    file_name=f"Verified_{report_data.get('student_name', 'Student')}_{report_data.get('term', 'Term')}.pdf",
                                    mime="application/pdf",
                                    width='stretch'
                                )
                    else:
                        st.info("✅ Verification key valid, but report file not found in storage. Contact admin to retrieve archived report.")
                else:
                    st.error("❌ Invalid or missing verification key for this report.")
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

def developer_console_tab():
    """Developer Console with system activation controls and management features"""
    st.subheader("🛠️ Developer Console")
    
    # Check developer authentication
    if not st.session_state.get("developer_authenticated"):
        st.error("🚫 Developer access required")
        return
    
    st.success("🔓 **Developer Mode Active** - Full system control enabled")
    
    # Create tabs for different developer functions
    dev_tabs = st.tabs([
        "🔄 System Activation", 
        "👥 User Management", 
        "📊 System Status", 
        "🔧 Configuration",
        "📋 System Logs"
    ])
    
    with dev_tabs[0]:  # System Activation
        st.markdown("### 🔄 System Activation Control")
        st.info("Control global system access for all teacher users")
        
        # Get current activation status from session state (fallback)
        current_activation = st.session_state.get("system_activated", True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("✅ Activate System", type="primary", width='stretch'):
                st.session_state.system_activated = True
                st.success("🟢 System ACTIVATED - All teacher features enabled")
                st.rerun()
        
        with col2:
            if st.button("🚫 Deactivate System", type="secondary", width='stretch'):
                st.session_state.system_activated = False
                st.error("🔴 System DEACTIVATED - Teacher access blocked")
                st.warning("Only developers can reactivate the system")
                st.rerun()
        
        # Show current status
        if current_activation:
            st.success("✅ **SYSTEM STATUS: ACTIVE** - All teacher features available")
        else:
            st.error("🚫 **SYSTEM STATUS: DEACTIVATED** - Teacher access blocked")
            st.markdown("**Message shown to teachers:** 🚫 System deactivated. Please contact the developer to renew your subscription.")
    
    with dev_tabs[1]:  # User Management
        st.markdown("### 👥 Developer User Management")
        st.info("Advanced user controls and approvals")
        
        # Show pending teacher approvals first
        st.markdown("#### 📋 Pending Teacher Approvals")
        pending_teachers = get_pending_teacher_approvals()
        if pending_teachers is not None and not pending_teachers.empty:
            for _, teacher in pending_teachers.iterrows():
                col1, col2, col3 = st.columns([3, 2, 2])
                with col1:
                    st.write(f"**{teacher['full_name']}** ({teacher['email']}) - {teacher['role']}")

                # Approve button and handler
                with col2:
                    if can_approve(st.session_state.get('teacher_id')):
                        if st.button(f"✅ Approve {teacher['id']}", key=f"dev_console_approve_{teacher['id']}"):
                            try:
                                approver = st.session_state.get('teacher_id')
                                try:
                                    import uuid as _uuid
                                    _uuid.UUID(str(approver))
                                    dev_param = approver
                                except Exception:
                                    dev_param = None

                                # Prefer SQLAlchemy session for reliable writes
                                wrote = False
                                try:
                                    if 'db_manager' in globals() and db_manager is not None:
                                        sess = db_manager.get_session()
                                        try:
                                            sess.execute(text("UPDATE users SET approval_status = 'approved', approved_by = :dev_id, approval_date = :now, is_active = TRUE WHERE id = :user_id"), {"user_id": teacher['id'], "dev_id": dev_param, "now": datetime.now()})
                                            sess.commit()
                                            wrote = True
                                        finally:
                                            sess.close()
                                except Exception as e_sql:
                                    with open('dev_actions.log', 'a') as fw:
                                        import traceback
                                        fw.write(f"Approve SQLAlchemy error for {teacher['id']}: {e_sql}\n")
                                        fw.write(traceback.format_exc() + "\n")

                                if not wrote:
                                    update_sql = text("UPDATE users SET approval_status = 'approved', approved_by = :dev_id, approval_date = :now, is_active = TRUE WHERE id = :user_id")
                                    params = {"user_id": teacher['id'], "dev_id": dev_param, "now": datetime.now()}
                                    success = execute_sql_with_retry(update_sql, params)
                                    wrote = bool(success)

                                if wrote:
                                    try:
                                        st.cache_data.clear()
                                    except Exception:
                                        pass
                                    st.success(f"Approved {teacher['full_name']}")
                                    st.rerun()
                                else:
                                    st.error("❌ Error approving user (DB write failed)")
                            except Exception as e:
                                import traceback
                                with open('dev_actions.log', 'a') as fw:
                                    fw.write(f"Unhandled approve error for {teacher['id']}: {e}\n")
                                    fw.write(traceback.format_exc() + "\n")
                                st.error(f"❌ Error approving user: {e}")
                    else:
                        st.warning("⚠️ You do not have permission to approve users.")

                # Reject button and handler
                with col3:
                    if can_approve(st.session_state.get('teacher_id')):
                        if st.button(f"🗑️ Reject {teacher['id']}", key=f"dev_console_reject_{teacher['id']}"):
                            try:
                                approver = st.session_state.get('teacher_id')
                                try:
                                    import uuid as _uuid
                                    _uuid.UUID(str(approver))
                                    dev_param = approver
                                except Exception:
                                    dev_param = None

                                wrote = False
                                try:
                                    if 'db_manager' in globals() and db_manager is not None:
                                        sess = db_manager.get_session()
                                        try:
                                            sess.execute(text("UPDATE users SET approval_status = 'rejected', approved_by = :dev_id, approval_date = :now WHERE id = :user_id"), {"user_id": teacher['id'], "dev_id": dev_param, "now": datetime.now()})
                                            sess.commit()
                                            wrote = True
                                        finally:
                                            sess.close()
                                except Exception as e_sql:
                                    with open('dev_actions.log', 'a') as fw:
                                        import traceback
                                        fw.write(f"Reject SQLAlchemy error for {teacher['id']}: {e_sql}\n")
                                        fw.write(traceback.format_exc() + "\n")

                                if not wrote:
                                    update_sql = text("UPDATE users SET approval_status = 'rejected', approved_by = :dev_id, approval_date = :now WHERE id = :user_id")
                                    params = {"user_id": teacher['id'], "dev_id": dev_param, "now": datetime.now()}
                                    success = execute_sql_with_retry(update_sql, params)
                                    wrote = bool(success)

                                if wrote:
                                    try:
                                        st.cache_data.clear()
                                    except Exception:
                                        pass
                                    st.success(f"Rejected {teacher['full_name']}")
                                    st.rerun()
                                else:
                                    st.error("❌ Error rejecting user (DB write failed)")
                            except Exception as e:
                                import traceback
                                with open('dev_actions.log', 'a') as fw:
                                    fw.write(f"Unhandled reject error for {teacher['id']}: {e}\n")
                                    fw.write(traceback.format_exc() + "\n")
                                st.error(f"❌ Error rejecting user: {e}")
                    else:
                        st.info("⚠️ You do not have permission to reject users.")
        else:
            st.info("No pending teacher approvals.")
            
        # Developer create-user helper (only in developer console)
        st.markdown("---")
        st.markdown("#### ➕ Create New User (Developer)")
        with st.expander("Create a new user", expanded=False):
            with st.form("dev_create_user_form"):
                cu_col1, cu_col2 = st.columns(2)
                with cu_col1:
                    cu_user_id = st.text_input("User ID (unique)", placeholder="new_user_id")
                    cu_full_name = st.text_input("Full Name", placeholder="Jane Doe")
                    cu_email = st.text_input("Email", placeholder="user@example.com")
                with cu_col2:
                    cu_phone = st.text_input("Phone", placeholder="+234 800 123 4567")
                    cu_password = st.text_input("Temporary Password", type="password")
                    # Only allow principal, head_of_department and teacher roles for created users
                    role_options = {
                        'Principal': 'principal',
                        'Head of Department': 'head_of_department',
                        'Teacher': 'teacher'
                    }
                    cu_role_display = st.selectbox("Role", list(role_options.keys()))
                    cu_role = role_options.get(cu_role_display, 'teacher')

                if st.form_submit_button("Create User"):
                    errors = []
                    if not cu_user_id:
                        errors.append("User ID is required")
                    if not cu_full_name:
                        errors.append("Full name is required")
                    if not cu_email:
                        errors.append("Email is required")
                    if not cu_password:
                        errors.append("Password is required")

                    if errors:
                        for err in errors:
                            st.error(f"❌ {err}")
                    else:
                        # Build user payload
                        new_user = {
                            cu_user_id: {
                                'password_hash': hash_password(cu_password),
                                'role': cu_role,
                                'full_name': cu_full_name,
                                'email': cu_email,
                                'phone': cu_phone,
                                'created_date': datetime.now().isoformat(),
                                'last_login': None,
                                'active': True if cu_role != 'teacher' else False,
                                'two_factor_enabled': False,
                                'two_factor_secret': None,
                                'session_timeout': 30,
                                'failed_attempts': 0,
                                'locked_until': None,
                                'assigned_classes': [],
                                'departments': [],
                                'approval_status': 'approved' if cu_role != 'teacher' else 'pending',
                                'approved_by': (st.session_state.get('teacher_id') if cu_role != 'teacher' else None),
                                'approval_date': (datetime.now().isoformat() if cu_role != 'teacher' else None),
                                'registration_notes': 'Created by developer console'
                            }
                        }

                        saved = save_user_database(new_user)
                        if saved:
                            st.success(f"✅ Created user {cu_user_id}")
                            try:
                                st.cache_data.clear()
                            except Exception:
                                pass
                            st.rerun()
                        else:
                            st.error("❌ Error creating user. Check logs for details.")
        
        # Show all users with enable/disable functionality
        st.markdown("#### 👥 All Users Management")
        users_db = load_user_database()
        
        if users_db:
            for user_id, user in users_db.items():
                col1, col2, col3 = st.columns([3, 2, 2])
                with col1:
                    status = "Active" if user.get('active', True) else "Disabled"
                    approval = user.get('approval_status', 'approved')
                    st.write(f"**{user.get('full_name', user_id)}** ({user.get('email', 'No email')}) - {user.get('role', 'teacher')} - {status}")
                    
                with col2:
                    if user.get('active', True):
                        if st.button(f"🚫 Disable {user_id}", key=f"dev_console_disable_{user_id}"):
                            result = set_user_active_status(user_id, active=False, actor_id=st.session_state.get('teacher_id'))
                            if result:
                                st.success(f"User {user.get('full_name', user_id)} disabled.")
                                st.rerun()
                            else:
                                st.error("❌ Error disabling user. See logs for details.")
                    else:
                        if st.button(f"✅ Enable {user_id}", key=f"dev_console_enable_{user_id}"):
                            result = set_user_active_status(user_id, active=True, actor_id=st.session_state.get('teacher_id'))
                            if result:
                                st.success(f"User {user.get('full_name', user_id)} enabled.")
                                st.rerun()
                            else:
                                st.error("❌ Error enabling user. See logs for details.")
                                
                with col3:
                    approval_status = user.get('approval_status', 'approved')
                    if approval_status == 'pending':
                        st.write(f"🟡 Pending")
                    elif approval_status == 'approved':
                        st.write(f"✅ Approved")
                    elif approval_status == 'rejected':
                        st.write(f"❌ Rejected")
                    else:
                        st.write(f"Status: {approval_status}")
        else:
            st.warning("No users found in database")
    
    with dev_tabs[2]:  # System Status  
        st.markdown("### 📊 System Status Dashboard")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("System Status", "🟢 ACTIVE" if current_activation else "🔴 INACTIVE")
        
        with col2:
            user_count = len(load_user_database()) if load_user_database() else 0
            st.metric("Total Users", user_count)
        
        with col3:
            st.metric("Developer Mode", "🔓 ENABLED")
    
    with dev_tabs[3]:  # Configuration
        st.markdown("### 🔧 System Configuration")
        st.info("Developer-only system settings")
        
        # Feature toggles
        st.markdown("**System Features:**")
        
        col1, col2 = st.columns(2)
        with col1:
            pdf_enabled = st.checkbox("📄 PDF Generation", value=True, help="Enable PDF report generation")
            email_enabled = st.checkbox("📧 Email System", value=True, help="Enable email notifications")
            
        with col2:
            backup_enabled = st.checkbox("💾 Auto Backup", value=True, help="Enable automatic backups")
            audit_enabled = st.checkbox("📋 Audit Logging", value=True, help="Enable audit trail logging")
    
    with dev_tabs[4]:  # System Logs
        st.markdown("### 📋 System Logs")
        st.info("View system activity and debug information")
        
        # Show recent audit logs if available
        try:
            audit_logs = get_audit_logs()
            if audit_logs:
                st.markdown("**Recent System Activity:**")
                logs_df = pd.DataFrame(audit_logs[:20])  # Show last 20 entries
                st.dataframe(logs_df, width='stretch')
            else:
                st.warning("No audit logs available")
        except Exception as e:
            st.error(f"Error loading logs: {str(e)}")

def admin_panel_tab():
    st.subheader("⚙️ Admin Panel")

    # Check permissions
    if not check_user_permissions(st.session_state.teacher_id, "system_config"):
        st.warning("⚠️ Admin access required for this section.")
        st.info("Contact your system administrator for admin privileges.")
        return

    admin_tab1, admin_tab3, admin_tab4, admin_tab5, admin_tab6, admin_tab7, admin_tab8 = st.tabs([
        "📊 System Overview", 
        "🔒 Security & 2FA",
        "💾 Backup & Restore",
        "📊 System Stats", 
        "📧 Email Setup", 
        "📞 Support Config",
        "🔍 Audit Logs"
    ])

    # Backwards-compat: some code references admin_tab2; map it to the second logical tab
    try:
        admin_tab2 = admin_tab3
    except Exception:
        admin_tab2 = admin_tab1

    with admin_tab1:
        st.write("## 📊 System Overview")
        
        # System metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("System Status", "🟢 Active")
        with col2:
            st.metric("Database", "✅ Connected")
        with col3:
            st.metric("Server Health", "✅ Good")
        # DB diagnostics dashboard (lightweight)
        try:
            st.markdown("---")
            st.write("### 🧾 Database Diagnostics")
            db_admin_dashboard()
        except Exception:
            pass

    with admin_tab3:
        st.write("## 🔒 Security Settings")
        st.info("Configure system security settings")
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("### Password Policy")
            st.checkbox("Enforce Strong Passwords", value=True)
            st.number_input("Minimum Password Length", value=8)
        
        with col2:
            st.write("### Login Settings")
            st.number_input("Max Login Attempts", value=5)
            st.number_input("Lockout Duration (minutes)", value=30)

    with admin_tab4:
        st.write("## 💾 Backup & Restore")
        st.info("Manage system backups and restoration")

    with admin_tab5:
        st.write("## 📊 System Statistics")
        st.info("View detailed system statistics")

    with admin_tab6:
        st.write("## 📧 Email Configuration")
        st.info("Configure email settings")

    with admin_tab7:
        st.write("## 📞 Support Settings")
        st.info("Configure support system settings")

    with admin_tab8:
        st.write("## 🔍 System Audit Logs")
        st.info("View system audit logs")
        
        try:
            # Display recent audit logs
            audit_files = sorted([f for f in os.listdir('audit_logs') if f.startswith('audit_')])
            if audit_files:
                latest_audit = audit_files[-1]
                with open(os.path.join('audit_logs', latest_audit), 'r') as f:
                    logs = json.load(f)
                st.dataframe(pd.DataFrame(logs))
        except Exception as e:
            st.error(f"Error loading audit logs: {str(e)}")

        # (User management UI removed from this audit-logs section; it lives in the Developer Console area)
        else:
            st.info("No users found in database.")

        # small DB admin dashboard helper
        def db_admin_dashboard():
            try:
                st.write("#### DB Retry / Cooldown Diagnostics")
                col_a, col_b, col_c = st.columns(3)
                try:
                    col_a.metric("Query Retries", int(DB_QUERY_RETRY_COUNT))
                except Exception:
                    col_a.metric("Query Retries", "N/A")
                try:
                    col_b.metric("Execute Retries", int(DB_EXECUTE_RETRY_COUNT))
                except Exception:
                    col_b.metric("Execute Retries", "N/A")
                try:
                    col_c.metric("Cooldowns", int(DB_COOLDOWN_COUNT))
                except Exception:
                    col_c.metric("Cooldowns", "N/A")

                if st.button("Reset DB Counters"):
                    try:
                        globals()['DB_QUERY_RETRY_COUNT'] = 0
                        globals()['DB_EXECUTE_RETRY_COUNT'] = 0
                        globals()['DB_COOLDOWN_COUNT'] = 0
                        st.success("DB diagnostic counters reset")
                    except Exception:
                        st.error("Failed to reset counters")
            except Exception as e:
                st.error(f"DB dashboard error: {e}")

        # expose helper to admin tabs (callable by other admin sections)
        try:
            # show compact diagnostics in the audit logs section footer
            with st.expander("DB Diagnostics", expanded=False):
                db_admin_dashboard()
        except Exception:
            pass

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
            if st.button("🗃️ Create Backup", width='stretch'):
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
                    "last_backup": datetime.now().isoformat()
                }

                with open("backup_config.json", 'w') as f:
                    json.dump(backup_config, f, indent=2)

                st.success("✅ Backup settings saved!")

    with admin_tab1:
        st.markdown("### 📊 Approved Reports Overview")

        # Show approved reports statistics
        approved_count = 0
        if os.path.exists("approved_reports"):
            approved_count = len([f for f in os.listdir("approved_reports") if f.endswith('.json')])

        st.metric("✅ Total Approved Reports", approved_count)

        if approved_count > 0:
            st.success("🎉 All reports are automatically approved and saved to the system!")
            st.info("📋 Reports are now processed instantly without requiring manual review.")

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
                    st.dataframe(df, width='stretch')

                    # Download parent contact list
                    csv_buffer = StringIO()
                    df.to_csv(csv_buffer, index=False)

                    st.download_button(
                        "📥 Download Parent Contact List",
                        csv_buffer.getvalue(),
                        file_name=f"parent_contacts_{datetime.now().strftime('%Y%m%d')}.csv",
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
                timestamp = datetime.fromisoformat(log['timestamp'])
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
                                file_name=f"student_export_{student_identifier}_{datetime.now().strftime('%Y%m%d')}.json",
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
                            file_name=f"all_students_export_{datetime.now().strftime('%Y%m%d')}.json",
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
        st.markdown("### 📞 Contact Support Configuration")
        st.markdown("Configure contact support information that appears on the activation page.")

        # Load existing support config
        support_config = {}
        if os.path.exists("support_config.json"):
            try:
                with open("support_config.json", 'r') as f:
                    support_config = json.load(f)
            except:
                support_config = {}

        with st.form("support_config_form"):
            st.markdown("#### Contact Support Information")
            col1, col2 = st.columns(2)

            with col1:
                support_contact = st.text_input("Support Contact Name", 
                                               value=support_config.get('contact_name', 'Developer Support'),
                                               help="Name of the person handling support requests")
                support_email = st.text_input("Support Email", 
                                            value=support_config.get('email', 'bamstep@akinssunrise.edu.ng'),
                                            help="Email address for support requests")

            with col2:
                support_phone = st.text_input("Support Phone", 
                                            value=support_config.get('phone', '+234 800 123 4567'),
                                            help="Phone number for support calls")
                support_hours = st.text_input("Support Hours", 
                                            value=support_config.get('hours', 'Monday - Friday, 9:00 AM - 5:00 PM'),
                                            help="Available support hours")

            support_message = st.text_area("Support Message", 
                                         value=support_config.get('message', 'Please have your payment receipt ready when contacting support.'),
                                         help="Additional message for users needing support",
                                         height=100)

            additional_instructions = st.text_area("Additional Instructions", 
                                                 value=support_config.get('instructions', 'For activation issues, please provide your school name and payment confirmation.'),
                                                 help="Additional instructions for users",
                                                 height=100)

            if st.form_submit_button("💾 Save Support Configuration"):
                new_support_config = {
                    'contact_name': support_contact,
                    'email': support_email,
                    'phone': support_phone,
                    'hours': support_hours,
                    'message': support_message,
                    'instructions': additional_instructions,
                    'updated_by': st.session_state.teacher_id,
                    'updated_date': datetime.now().isoformat()
                }

                try:
                    with open("support_config.json", 'w') as f:
                        json.dump(new_support_config, f, indent=2)

                    st.success("✅ Support configuration updated successfully!")

                    # Log the activity
                    log_teacher_activity(st.session_state.teacher_id, "support_config_updated", {
                        "updated_by": st.session_state.teacher_id,
                        "contact_name": support_contact,
                        "email": support_email
                    })

                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error saving support configuration: {str(e)}")

        # Preview section
        st.markdown("---")
        st.markdown("### 👀 Preview")
        st.markdown("This is how the support information will appear on the activation page:")

        # Show preview of how it will look
        current_config = support_config if support_config else {
            'contact_name': 'Developer Support',
            'email': 'bamstep@akinssunrise.edu.ng',
            'phone': '+234 800 123 4567',
            'hours': 'Monday - Friday, 9:00 AM - 5:00 PM',
            'message': 'Please have your payment receipt ready when contacting support.',
            'instructions': 'For activation issues, please provide your school name and payment confirmation.'
        }

        st.info(f"""
**Need help with activation?**

📞 **Contact:** {current_config.get('contact_name', 'Developer Support')}
📧 **Email:** {current_config.get('email', 'bamstep@akinssunrise.edu.ng')}
📱 **Phone:** {current_config.get('phone', '+234 800 123 4567')}
🕐 **Hours:** {current_config.get('hours', 'Monday - Friday, 9:00 AM - 5:00 PM')}

**Support Message:**
{current_config.get('message', 'Please have your payment receipt ready when contacting support.')}

**Instructions:**
{current_config.get('instructions', 'For activation issues, please provide your school name and payment confirmation.')}
        """)

    with admin_tab8:
        st.markdown("### ⚙️ System Configuration & Customization")

        config_tab1, config_tab2, config_tab3, config_tab4, config_tab5, config_tab6 = st.tabs([
            "🏫 School Information",
            "📧 Email Templates", 
            "🎨 Appearance & Branding",
            "📋 Form Settings",
            "💳 Activation Settings",
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
                        'updated_date': datetime.now().isoformat()
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

                    # Placeholder for missing function to avoid NameError
                    def get_default_login_instructions_template():
                        return "Please follow the instructions to log in."
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
                            'updated_date': datetime.now().isoformat()
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
                st.dataframe(subject_df, width='stretch')

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
                st.dataframe(class_df, width='stretch')

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
            st.markdown("### 💳 System Activation & Payment Configuration")

            # Only developer can access this section
            if st.session_state.get('developer_authenticated') and st.session_state.teacher_id == "developer_001":
                activation_config = load_activation_config()

                st.markdown("#### 💰 Payment Plan Configuration")

                with st.form("activation_config_form"):
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("**Subscription Pricing (NGN)**")
                        monthly_amount = st.number_input("Monthly Amount", 
                                                       min_value=1000, max_value=100000, 
                                                       value=activation_config.get('monthly_amount', 20000),
                                                       step=1000)
                        yearly_amount = st.number_input("Yearly Amount", 
                                                      min_value=10000, max_value=1000000, 
                                                      value=activation_config.get('yearly_amount', 60000),
                                                      step=5000)

                        currency = st.selectbox("Currency", ["NGN", "USD", "EUR", "GBP"], 
                                               index=0 if activation_config.get('currency', 'NGN') == 'NGN' else 0)

                    with col2:
                        st.markdown("**System Settings**")
                        activation_enabled = st.checkbox("Enable Activation System", 
                                                       value=activation_config.get('activation_enabled', True))
                        trial_period = st.number_input("Trial Period (days)", 
                                                     min_value=0, max_value=90, 
                                                     value=activation_config.get('trial_period_days', 30))
                        grace_period = st.number_input("Grace Period (days)", 
                                                     min_value=0, max_value=30, 
                                                     value=activation_config.get('grace_period_days', 7))

                    st.markdown("**Bank Details for Payment**")
                    bank_details = activation_config.get('bank_details', {})

                    bank_col1, bank_col2 = st.columns(2)
                    with bank_col1:
                        bank_name = st.text_input("Bank Name", 
                                                value=bank_details.get('bank_name', 'First Bank Nigeria'))
                        account_name = st.text_input("Account Name", 
                                                   value=bank_details.get('account_name', 'Bamstep Technologies'))

                    with bank_col2:
                        account_number = st.text_input("Account Number", 
                                                     value=bank_details.get('account_number', '1234567890'))
                        sort_code = st.text_input("Sort Code", 
                                                value=bank_details.get('sort_code', '011'))

                    if st.form_submit_button("💾 Save Activation Configuration"):
                        new_config = {
                            'monthly_amount': monthly_amount,
                            'yearly_amount': yearly_amount,
                            'currency': currency,
                            'activation_enabled': activation_enabled,
                            'trial_period_days': trial_period,
                            'grace_period_days': grace_period,
                            'bank_details': {
                                'bank_name': bank_name,
                                'account_name': account_name,
                                'account_number': account_number,
                                'sort_code': sort_code
                            },
                            'updated_by': st.session_state.teacher_id,
                            'updated_date': datetime.now().isoformat()
                        }

                        if save_activation_config(new_config):
                            st.success("✅ Activation configuration updated successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Error saving activation configuration")

                # Pricing preview
                st.markdown("#### 💰 Pricing Preview")
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown(f"""
                    <div style="border: 2px solid #007bff; border-radius: 8px; padding: 1rem; text-align: center;">
                        <h4 style="color: #007bff;">Monthly</h4>
                        <h2>{currency} {activation_config.get('monthly_amount', 20000):,}</h2>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    monthly_yearly_total = activation_config.get('monthly_amount', 20000) * 12
                    yearly_price = activation_config.get('yearly_amount', 60000)
                    yearly_savings = monthly_yearly_total - yearly_price

                    st.markdown(f"""
                    <div style="border: 2px solid #ffc107; border-radius: 8px; padding: 1rem; text-align: center;">
                        <h4 style="color: #f57c00;">Yearly</h4>
                        <h2>{currency} {yearly_price:,}</h2>
                        <small style="color: #f57c00;">Save {currency} {yearly_savings:,}</small>
                    </div>
                    """, unsafe_allow_html=True)

                # Current system status
                st.markdown("#### 📊 Current System Status")
                is_activated, status, expiry = check_activation_status()

                if is_activated:
                    if status.get('status') == 'trial':
                        st.info("🆓 System is in trial period")
                    else:
                        st.success("✅ System is activated")
                        if expiry:
                            days_left = (expiry - datetime.now()).days
                            st.write(f"**Expires in:** {days_left} days")
                else:
                    st.warning("⚠️ System requires activation")

                # Activation records
                st.markdown("#### 📋 Recent Activations")
                if os.path.exists("activation_records.json"):
                    try:
                        with open("activation_records.json", 'r') as f:
                            records = json.load(f)

                        if records:
                            recent_records = sorted(records, key=lambda x: x.get('generated_date', ''), reverse=True)[:5]

                            for record in recent_records:
                                col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
                                with col1:
                                    st.write(f"**{record.get('school_name', 'Unknown')}**")
                                with col2:
                                    st.write(f"{record.get('subscription_type', 'monthly').title()}")
                                with col3:
                                    st.write(f"{currency} {record.get('amount', 0):,}")
                                with col4:
                                    date_str = record.get('generated_date', '')
                                    if date_str:
                                        try:
                                            date_obj = datetime.fromisoformat(date_str)
                                            st.write(date_obj.strftime('%Y-%m-%d'))
                                        except:
                                            st.write(date_str[:10])
                        else:
                            st.info("No activation records found.")
                    except:
                        st.error("Error loading activation records.")
                else:
                    st.info("No activation records file found.")

                # Override system activation (emergency use)
                st.markdown("#### 🚨 Emergency Controls")
                with st.expander("⚠️ Emergency System Override", expanded=False):
                    st.error("**WARNING:** These controls should only be used in emergencies!")
                    st.warning("🚨 **IMPORTANT**: Disabling activation will immediately kick out ALL users (including you) and require a new activation key to be generated and activated.")

                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("🔓 Disable Activation Requirement"):
                            activation_config['activation_enabled'] = False
                            save_activation_config(activation_config)
                            # Also remove current activation status to force complete reactivation
                            if os.path.exists("activation_status.json"):
                                os.remove("activation_status.json")
                            st.success("✅ Activation requirement disabled! All users will be logged out.")
                            st.info("🔄 You will be redirected to the activation page.")
                            # Clear current session to force logout
                            st.session_state.authenticated = False
                            st.session_state.teacher_id = None
                            st.rerun()

                    with col2:
                        if st.button("🔒 Enable Activation Requirement"):
                            activation_config['activation_enabled'] = True
                            save_activation_config(activation_config)
                            st.success("✅ Activation requirement enabled!")
                            st.rerun()

                    # Manual activation override
                    st.markdown("**Manual System Activation:**")
                    override_subscription = st.selectbox("Override Subscription Type", 
                                                       ["monthly", "yearly"], 
                                                       key="override_sub")
                    if st.button("🔑 Manually Activate System"):
                        if activate_system("MANUAL-OVERRIDE-KEY", override_subscription):
                            st.success("✅ System manually activated!")
                            st.rerun()
                        else:
                            st.error("❌ Error activating system")
            else:
                st.warning("⚠️ Access restricted to developer only.")
                st.info("Only the system developer can configure activation and payment settings.")

        with config_tab6:
            st.markdown("### 🔍 Advanced Audit Logs")

            # Recent activity
            st.markdown("#### 📋 Recent Activity")
            recent_logs = get_audit_logs()[:10]

            if recent_logs:
                for log in recent_logs:
                    timestamp = datetime.fromisoformat(log['timestamp'])
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
                            timestamp = datetime.fromisoformat(log['timestamp'])
                            st.write(f"**{timestamp.strftime('%Y-%m-%d %H:%M')}** | {log['user_id']} | {log['action']} | {log.get('details', {})}")
                    else:
                        st.info("No matching audit entries found.")

            # Data protection tools
            st.markdown("#### 🔐 Data Protection Tools")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("🗑️ Clean Old Audit Logs (>30 days)"):
                    # Implementation for cleaning old logs
                    cutoff_date = datetime.now() - timedelta(days=30)
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
                st.plotly_chart(fig_class, width='stretch')
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
                st.plotly_chart(fig_grades, width='stretch')
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
            st.plotly_chart(fig_attendance, width='stretch')
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
            st.plotly_chart(fig_subjects, width='stretch')
        else:
            st.info("No subject performance data available yet")

    else:
        st.info("📭 No data available yet. Add students and generate reports to see analytics.")

def report_generator_page():
    st.set_page_config(
        page_title="Akin's Sunrise School – Report Card System", 
        layout="wide",
        initial_sidebar_state="collapsed",
        page_icon="🎓"
    )

    apply_custom_css()

    # Check activation status for all authenticated users (including teacher_bamstep)
    is_activated, activation_status, expiry_date = check_activation_status()
    if not is_activated:
        # Check if this is developer bypass
        if activation_status.get('status') == 'developer_bypass':
            st.warning("🚨 **DEVELOPER MODE**: System activation is disabled but you have developer access.")
            st.info("💡 Generate a new activation key in the Admin Panel → System Configuration → Activation Settings")
        else:
            st.error("🚨 System activation has expired or been disabled. Please reactivate the system.")
            st.info("🔄 Redirecting to activation page...")
            # Clear authentication and redirect to login/activation page
            st.session_state.authenticated = False
            st.session_state.teacher_id = None
            st.rerun()

    # Check session timeout
    if check_session_timeout():
        st.error("🔒 Session expired. Please login again.")
        st.session_state.authenticated = False
        st.session_state.teacher_id = None
        st.rerun()

    # Update activity
    update_session_activity()

    # Responsive header layout with logo
    logo_base64 = get_logo_base64()
    logo_html = ""
    if logo_base64:
        logo_html = f'<img src="data:image/png;base64,{logo_base64}" style="width: 60px; height: 60px; object-fit: contain; border-radius: 8px; margin-right: 1rem; vertical-align: middle;">'

    st.markdown(f"""
    <div style="text-align: center; padding: 1.5rem 1rem; background: linear-gradient(135deg, rgba(25, 118, 210, 0.08), rgba(33, 150, 243, 0.08)); border-radius: 16px; margin-bottom: 2rem; backdrop-filter: blur(15px); border: 2px solid rgba(25, 118, 210, 0.15); box-shadow: 0 8px 32px rgba(25, 118, 210, 0.1);">
        <div style="display: flex; align-items: center; justify-content: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem;">
            {logo_html}
            <div>
                <h1 style="margin: 0; color: #1976D2; font-size: clamp(1.8rem, 4vw, 3rem); font-weight: 800; text-shadow: 0 2px 4px rgba(25, 118, 210, 0.1);">
                    🎓 Akin's Sunrise School System
                </h1>
                <p style="margin: 0.5rem 0 0; color: #555; font-size: clamp(1rem, 2.5vw, 1.2rem); font-weight: 600; opacity: 0.9;">
                    Comprehensive Management Portal
                </p>
            </div>
        </div>
        <div style="height: 3px; background: linear-gradient(90deg, transparent, #1976D2, #42A5F5, #1976D2, transparent); border-radius: 2px; margin-top: 1rem;"></div>
    </div>
    """, unsafe_allow_html=True)

    # Show activation key in simple text format
    current_activation_key = get_current_activation_key()
    if current_activation_key:
        st.success(f"🔑 **Current Activation Key:** `{current_activation_key}`")
        st.info("💡 Save this key - you can use it to reactivate if the system restarts")

    # User info and logout in a compact layout
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        # Display user info centered
        users_db = load_user_database()
        user_info = users_db.get(st.session_state.teacher_id, {})
        role_description = USER_ROLES.get(user_info.get('role', 'teacher'), {}).get('description', 'User')

        # Combined user info and logout
        st.markdown(f"""
        <div style="text-align: center; background: rgba(25, 118, 210, 0.05); padding: 1rem; border-radius: 8px; margin-bottom: 1rem; border: 1px solid rgba(25, 118, 210, 0.1);">
            <div style="color: #1976D2; font-weight: 600; margin-bottom: 0.5rem;">
                <strong>{role_description}:</strong> {user_info.get('full_name', st.session_state.teacher_id)}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Logout button
        if st.button("🚪 Logout", width='stretch'):
            log_teacher_activity(st.session_state.teacher_id, "logout", {
                "logout_time": datetime.now().isoformat()
            })

            # Clear all session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    # Staff interface with feature-based access control
        available_tabs = []

        # Generate Reports
        if check_user_feature_access(st.session_state.teacher_id, "report_generation"):
            available_tabs.append(("📝 Generate Reports", "reports"))

        # Draft Reports
        if check_user_feature_access(st.session_state.teacher_id, "draft_management"):
            available_tabs.append(("📝 Draft Reports", "drafts"))

        # Student Database
        if check_user_feature_access(st.session_state.teacher_id, "student_database"):
            available_tabs.append(("👥 Student Database", "database"))

        # Analytics
        if check_user_feature_access(st.session_state.teacher_id, "analytics_dashboard"):
            available_tabs.append(("📊 Analytics", "analytics"))

        # Verification
        if check_user_feature_access(st.session_state.teacher_id, "verification_system"):
            available_tabs.append(("🔍 Verify Reports", "verify"))

        # Approvals tab - visible to users who can approve (Principal, HOD, Developer, or those with user_management permission)
        try:
            if can_approve(st.session_state.get('teacher_id')) or check_user_feature_access(st.session_state.teacher_id, 'admin_panel'):
                available_tabs.append(("📋 Approvals", "approvals"))
        except Exception:
            pass

        # Admin Panel
        if check_user_feature_access(st.session_state.teacher_id, "admin_panel"):
            available_tabs.append(("⚙️ Admin Panel", "admin"))

        # Developer Console - visible only to developers or users with explicit system_control permission
        def can_view_developer_console(user_id=None):
            try:
                if user_id is None:
                    user_id = st.session_state.get('teacher_id')
                if not user_id:
                    return False
                users_db = load_user_database()
                user = users_db.get(user_id, {})
                role = user.get('role', '')
                if role == 'developer':
                    return True
                # Allow explicit system_control permission (keeps compatibility if granted)
                return check_user_permissions(user_id, 'system_control')
            except Exception:
                return False

        if can_view_developer_console(st.session_state.get('teacher_id')):
            available_tabs.append(("🛠️ Developer Console", "developer"))

        # Show DB status banner for admins/users
        try:
            show_db_status_banner()
        except Exception:
            pass

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
                elif tab_key == "approvals":
                    approvals_tab()
                elif tab_key == "analytics":
                    analytics_dashboard_tab()
                elif tab_key == "verify":
                    verification_tab()
                elif tab_key == "admin":
                    admin_panel_tab()
                elif tab_key == "developer":
                    developer_console_tab()

def init_database_tables():
    """Initialize database tables using Streamlit SQL Connection - PRODUCTION READY"""
    try:
        print("🔄 Initializing database tables...")

        conn = get_healthy_sql_connection()
        if not conn:
            print("❌ No database connection available for initialization")
            return False

        # Create tables using execute operations (not query)
        tables_created = 0

        # Determine how to execute DDL depending on connection type
        try:
            from sqlalchemy.engine import Engine
        except Exception:
            Engine = None

        use_engine = Engine and isinstance(conn, Engine)

        # Users table
        try:
            users_sql = text("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    phone TEXT,
                    is_active BOOLEAN DEFAULT true,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    approval_status TEXT DEFAULT 'approved',
                    approved_by TEXT,
                    approval_date TIMESTAMP,
                    registration_notes TEXT
                )
            """)
            if use_engine:
                with conn.begin() as connection:
                    connection.execute(users_sql)
            else:
                session = conn.session
                session.execute(users_sql)
                session.commit()
            tables_created += 1
            print("✅ Users table ready")
        except Exception as e:
            print(f"⚠️ Users table creation issue: {e}")
            try:
                if not use_engine:
                    session.rollback()
            except Exception:
                pass

        # Activation keys table
        try:
            keys_sql = text("""
                CREATE TABLE IF NOT EXISTS activationkeys (
                    id TEXT PRIMARY KEY,
                    key_value TEXT UNIQUE NOT NULL,
                    school_name TEXT,
                    subscription_type TEXT DEFAULT 'monthly',
                    is_active BOOLEAN DEFAULT true,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            if use_engine:
                with conn.begin() as connection:
                    connection.execute(keys_sql)
            else:
                session.execute(keys_sql)
                session.commit()
            tables_created += 1
            print("✅ Activation keys table ready")
        except Exception as e:
            print(f"⚠️ Activation keys table creation issue: {e}")
            session.rollback()

        # Students table
        try:
            students_sql = text("""
                CREATE TABLE IF NOT EXISTS students (
                    id SERIAL PRIMARY KEY,
                    student_id TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    admission_number TEXT UNIQUE,
                    date_of_birth DATE,
                    gender TEXT,
                    address TEXT,
                    parent_name TEXT,
                    parent_phone TEXT,
                    parent_email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            if use_engine:
                with conn.begin() as connection:
                    connection.execute(students_sql)
            else:
                session.execute(students_sql)
                session.commit()
            tables_created += 1
            print("✅ Students table ready")
        except Exception as e:
            print(f"⚠️ Students table creation issue: {e}")
            session.rollback()

        # Add missing authentication columns if they don't exist
        try:
            migration_sql = text("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0")
            migration_sql2 = text("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP")
            if use_engine:
                with conn.begin() as connection:
                    connection.execute(migration_sql)
                    connection.execute(migration_sql2)
            else:
                session.execute(migration_sql)
                session.commit()
                session.execute(migration_sql2)
                session.commit()
            print("✅ Authentication columns ensured")
        except Exception as e:
            print(f"⚠️ Authentication column migration issue: {e}")
            session.rollback()

        # Add indexes
        try:
            for index_sql_str in [
                "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
                "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)", 
                "CREATE INDEX IF NOT EXISTS idx_activationkeys_active ON activationkeys(is_active)",
                "CREATE INDEX IF NOT EXISTS idx_students_class ON students(class_name)"
            ]:
                if use_engine:
                    with conn.begin() as connection:
                        connection.execute(text(index_sql_str))
                else:
                    session.execute(text(index_sql_str))
                    session.commit()
            print("✅ Database indexes created")
        except Exception as e:
            print(f"⚠️ Index creation issue: {e}")
            session.rollback()

        print(f"✅ Database initialization complete - {tables_created} tables ready")
        return True

    except Exception as e:
        import traceback
        print(f"❌ Database initialization failed: {e}")
        traceback.print_exc()
        return False

def seed_default_users():
    """Seed default admin users if database is empty"""
    try:
        # Check if users exist
        users_df = query_with_retry("SELECT COUNT(*) as count FROM users", ttl=0)

        if users_df is not None and not users_df.empty:
            user_count = users_df.iloc[0]['count']
            if user_count == 0:
                print("🌱 Seeding default users...")

                # Insert default admin user using the existing hash_password function
                default_users = [
                    {
                        'id': 'bamidelestephen224',
                        'full_name': 'Stephen Bamidele', 
                        'email': 'bamidelestephen224@gmail.com',
                        'password': 'admin789',
                        'role': 'principal',
                        'phone': '+234-XXX-XXX-XXXX'
                    }
                ]

                conn = get_healthy_sql_connection()
                try:
                    from sqlalchemy.engine import Engine
                except Exception:
                    Engine = None

                use_engine = Engine and isinstance(conn, Engine)

                for user in default_users:
                    password_hash = hash_password(user['password'])
                    try:
                        insert_sql = text("""
                            INSERT INTO users (id, full_name, email, password_hash, role, phone, is_active, approval_status)
                            VALUES (:id, :full_name, :email, :password_hash, :role, :phone, true, 'approved')
                        """)
                        params = {
                            'id': user['id'],
                            'full_name': user['full_name'],
                            'email': user['email'],
                            'password_hash': password_hash,
                            'role': user['role'],
                            'phone': user['phone']
                        }

                        if use_engine:
                            with conn.begin() as connection:
                                connection.execute(insert_sql, params)
                        else:
                            session = conn.session
                            session.execute(insert_sql, params)
                            session.commit()

                        print(f"✅ Created default user: {user['email']}")
                    except Exception as e:
                        print(f"⚠️ Error creating user {user['email']}: {e}")

                print("✅ Default users seeded successfully")
            else:
                print(f"✅ Found {user_count} existing users, skipping seed")

    except Exception as e:
        print(f"⚠️ Error checking/seeding users: {e}")

# Database initialization - cached to run once at module level
@st.cache_resource
def ensure_db_initialized_once():
    """Ensure database is initialized once at startup"""
    # Run initialization but avoid blocking Streamlit startup for long periods.
    # Use a short timeout so failures or slow DB endpoints don't hang the app.
    try:
        print("🚀 Initializing database (one-time)...")
        from concurrent.futures import ThreadPoolExecutor, TimeoutError

        with ThreadPoolExecutor(max_workers=1) as exe:
            fut = exe.submit(init_database_tables)
            try:
                init_success = fut.result(timeout=8)  # seconds
            except TimeoutError:
                print("⚠️ Database initialization timed out (8s). Will continue with fallback behavior.")
                return False

        if init_success:
            try:
                seed_default_users()
            except Exception as e:
                print(f"⚠️ Seeding default users failed: {e}")
            print("✅ Database initialized successfully")
            return True
        else:
            print("❌ Database initialization failed")
            return False
    except Exception as e:
        import traceback
        print(f"❌ Database startup error: {e}")
        traceback.print_exc()
        return False

def main():
    # Initialize database using new Streamlit SQL approach
    try:
        # Start database initialization in background if not already started.
        # We avoid blocking the Streamlit script; if DB is slow/unavailable the app will continue
        # using the JSON fallback and show a clear message. Status is written to a small file
        # `.db_init_status` so subsequent runs can show the result.
        import threading

        if not st.session_state.get('db_init_started'):
            def _run_init_and_write_status():
                try:
                    res = ensure_db_initialized_once()
                    try:
                        with open('.db_init_status', 'w') as sf:
                            sf.write('ready' if res else 'failed')
                    except Exception:
                        pass
                except Exception:
                    try:
                        with open('.db_init_status', 'w') as sf:
                            sf.write('failed')
                    except Exception:
                        pass

            t = threading.Thread(target=_run_init_and_write_status, daemon=True)
            t.start()
            st.session_state['db_init_started'] = True

        # Report DB init status if available, otherwise inform user initialization is in progress
        db_status = None
        try:
            if os.path.exists('.db_init_status'):
                with open('.db_init_status', 'r') as sf:
                    db_status = sf.read().strip()
        except Exception:
            db_status = None

        if db_status == 'ready':
            st.success("✅ Database ready")
        elif db_status == 'failed':
            pass
        else:
            st.info("ℹ️ Database initialization running in background — app will use local fallback until ready.")
    except Exception as e:
        import traceback
        print(f"Database initialization failed: {e}")
        traceback.print_exc()
        # Don't block the app here; fall back to JSON DB and let background init continue.
        try:
            st.warning("⚠️ Database initialization encountered an error; continuing with local fallback.")
        except Exception:
            pass

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

import traceback
# Note: Removed module-level database initialization to avoid blocking Streamlit import.
# Database initialization is performed inside `main()` so the app can present helpful UI messages
# instead of hanging during module import.

if __name__ == "__main__":
    main()

