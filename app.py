"""
=====================================================
AKIN'S SUNRISE SCHOOL REPORT CARD MANAGEMENT SYSTEM
Google-Drive Edition – auto-upload on approval
=====================================================
"""

# 1.  NEW GOOGLE DRIVE IMPORTS
try:
    from googleapiclient.discovery import build
    from google_auth_oauthlib.flow import Flow
    from google.auth.transport.requests import Request
    from googleapiclient.http import MediaFileUpload
    import pickle, os.path
    GDRIVE_AVAIL = True
except ImportError:
    GDRIVE_AVAIL = False
# ---------------------------------------------------

# ---------------  (ORIGINAL IMPORTS)  --------------
import streamlit as st
import pandas as pd
import numpy as np
import base64, json, os, datetime, shutil, hashlib, secrets, csv, uuid
import threading, time, qrcode, pyotp, qrcode as qr_gen
from io import BytesIO, StringIO
from weasyprint import HTML
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# ---------------------------------------------------

# --------------- 2.  GDRIVE HELPERS ----------------
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def gdrive_creds_file(): return "gdrive_token.pickle"

def get_gdrive_service():
    if not GDRIVE_AVAIL: return None
    creds = None
    if os.path.exists(gdrive_creds_file()):
        with open(gdrive_creds_file(), "rb") as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            return None
    return build("drive", "v3", credentials=creds)

def ensure_gdrive_folder(service, root_name="AkinSunriseReports"):
    year = str(datetime.datetime.now().year)
    term = st.session_state.get("current_term_for_sync", "General")
    root_id = _create_folder_if_needed(service, root_name)
    year_id = _create_folder_if_needed(service, year, root_id)
    term_id = _create_folder_if_needed(service, term, year_id)
    return term_id

def _create_folder_if_needed(service, name, parent=None):
    q = f"name='{name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    if parent: q += f" and '{parent}' in parents"
    res = service.files().list(q=q, spaces="drive", fields="files(id)").execute()
    files = res.get("files", [])
    if files: return files[0]["id"]
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder"}
    if parent: meta["parents"] = [parent]
    folder = service.files().create(body=meta, fields="id").execute()
    return folder.get("id")

def upload_to_gdrive(service, local_path, folder_id):
    file_name = os.path.basename(local_path)
    meta = {"name": file_name, "parents": [folder_id]}
    media = MediaFileUpload(local_path, resumable=True)
    file = service.files().create(body=meta, media_body=media, fields="id").execute()
    return file.get("id")

def initiate_gdrive_oauth():
    flow = Flow.from_client_secrets_file(
        "credentials.json", scopes=SCOPES, redirect_uri="urn:ietf:wg:oauth:2.0:oob")
    auth_url, _ = flow.authorization_url(prompt="consent")
    st.session_state["oauth_flow"] = flow
    st.markdown(f"[🔗 Authorize Google Drive]({auth_url})", unsafe_allow_html=True)
    st.text_input("Paste the authorization code:", key="oauth_code")

def complete_gdrive_oauth(code):
    flow = st.session_state["oauth_flow"]
    flow.fetch_token(code=code)
    with open(gdrive_creds_file(), "wb") as token:
        pickle.dump(flow.credentials, token)
    st.success("✅ Google Drive connected!")
    st.session_state.pop("oauth_flow", None)
# ---------------------------------------------------

# ===========  (ORIGINAL ~2 500-LINE CODE) ==========
#  All original functions, classes, constants, etc.
#  Only the auto_upload lines are added inside auto_approve_report()
# ---------------------------------------------------

# --------------  AUTO-UPLOAD HOOK  -----------------
#  Inside auto_approve_report()  (search for the PDF write line)
"""
            HTML(string=report_data['html_content']).write_pdf(approved_pdf_path)

            # Google Drive auto-upload (principal only)
            if st.session_state.get('user_role') == 'principal':
                service = get_gdrive_service()
                if service:
                    folder_id = ensure_gdrive_folder(service)
                    upload_to_gdrive(service, approved_pdf_path, folder_id)
                    upload_to_gdrive(service, approved_path, folder_id)
"""
# ---------------------------------------------------

# -------------  LOGIN / MAIN  ----------------------
#  (your existing login_page() and main() stay unchanged)
# ---------------------------------------------------

# -------------  ADMIN PANEL GDRIVE TAB -------------
#  Added inside the admin-panel tab loop
# ---------------------------------------------------
#  Inside admin_panel_tab()  (search for the tab list)
admin_tabs = [
    "📊 System Overview", "👥 User Management", "🔒 Security & 2FA",
    "💾 Backup & Restore", "📊 System Stats", "📧 Email Setup",
    "📞 Support Config", "🔍 Audit Logs", "📁 Google Drive Sync"
]

tabs = st.tabs(admin_tabs)

for i, tab_name in enumerate(admin_tabs):
    with tabs[i]:
        if tab_name == "📁 Google Drive Sync":
            if st.session_state.user_role != "principal":
                st.warning("⚠️ Restricted to principal.")
            else:
                st.subheader("📁 Google Drive Sync (Principal Only)")
                if not GDRIVE_AVAIL:
                    st.error("pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib")
                else:
                    service = get_gdrive_service()
                    if service is None:
                        st.info("🔗 Connect Google Drive first")
                        if st.button("Connect Google Drive"):
                            initiate_gdrive_oauth()
                        if st.session_state.get("oauth_code"):
                            complete_gdrive_oauth(st.session_state.oauth_code)
                            st.rerun()
                    else:
                        st.success("✅ Drive connected")
                        if st.button("🔄 Manual Sync All Approved Reports"):
                            folder_id = ensure_gdrive_folder(service)
                            count = 0
                            for root, _, files in os.walk("approved_reports"):
                                for f in files:
                                    local = os.path.join(root, f)
                                    upload_to_gdrive(service, local, folder_id)
                                    count += 1
                            st.success(f"📤 Uploaded {count} files")
        #  (existing elif blocks for other admin tabs stay here)
