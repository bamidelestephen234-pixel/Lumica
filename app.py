import streamlit as st
import sqlite3
import json
import os
from datetime import datetime

# Simple database class using built-in sqlite3
class SchoolDatabase:
    def __init__(self):
        self.db_path = "akins_sunrise.db"
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                full_name TEXT,
                email TEXT,
                password_hash TEXT,
                role TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Create students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                class_name TEXT NOT NULL,
                admission_no TEXT UNIQUE,
                parent_email TEXT,
                parent_phone TEXT,
                gender TEXT,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                student_name TEXT,
                student_class TEXT,
                term TEXT,
                average_score REAL,
                final_grade TEXT,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert default users
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = "teacher_bamstep"')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT OR IGNORE INTO users VALUES 
                ('teacher_bamstep', 'Principal Bamstep', 'principal@akinssunrise.edu.ng', 'admin789', 'principal', 1),
                ('teacher_bola', 'Teacher Bola', 'bola@akinssunrise.edu.ng', 'secret123', 'class_teacher', 1),
                ('school_ict', 'Akins Sunrise', 'akinssunrise@gmail.com', 'akins1111', 'principal', 1)
            ''')
        
        conn.commit()
        conn.close()
    
    def authenticate_user(self, username, password):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', 
                      (username, password))
        result = cursor.fetchone()
        conn.close()
        return result
    
    def add_student(self, name, class_name, parent_email, parent_phone="", gender=""):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        admission_no = f"ASS/{datetime.now().year % 100}/{cursor.execute('SELECT COUNT(*) FROM students').fetchone()[0] + 1:03d}"
        cursor.execute('''
            INSERT INTO students (name, class_name, admission_no, parent_email, parent_phone, gender)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, class_name, admission_no, parent_email, parent_phone, gender))
        conn.commit()
        conn.close()
    
    def get_students(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        df = pd.read_sql_query("SELECT * FROM students", conn)
        conn.close()
        return df
    
    def get_users(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        df = pd.read_sql_query("SELECT username, full_name, email, role FROM users WHERE is_active = 1", conn)
        conn.close()
        return df

# Initialize database
school_db = SchoolDatabase()

# Your existing app logic - adapted for database
def main():
    st.set_page_config(
        page_title="Akin's Sunrise School – Report Card System", 
        layout="wide",
        initial_sidebar_state="collapsed",
        page_icon="🎓"
    )
    
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_id = None
    
    # Login page
    if not st.session_state.authenticated:
        login_page()
    else:
        main_dashboard()

def login_page():
    st.title("🔐 Staff Login")
    st.markdown("### Akin's Sunrise School Management System")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        user = school_db.authenticate_user(username, password)
        if user:
            st.session_state.authenticated = True
            st.session_state.user_id = user[0]
            st.session_state.full_name = user[1]
            st.success(f"Welcome, {user[1]}!")
            st.rerun()
        else:
            st.error("Invalid credentials")

def main_dashboard():
    st.title("🎓 Akin's Sunrise School System")
    st.sidebar.success(f"Welcome, {st.session_state.full_name}")
    
    menu = ["�� Generate Reports", "👥 Student Database", "📊 Analytics", "⚙️ Admin"]
    choice = st.sidebar.selectbox("Menu", menu)
    
    if choice == "👥 Student Database":
        student_database()
    elif choice == "📝 Generate Reports":
        report_generator()
    elif choice == "📊 Analytics":
        analytics_dashboard()
    
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.user_id = None
        st.rerun()

def student_database():
    st.header("👥 Student Database")
    
    col1, col2 = st.columns(2)
    
    with col1:
        with st.form("add_student"):
            st.subheader("➕ Add Student")
            name = st.text_input("Student Name")
            class_name = st.text_input("Class")
            email = st.text_input("Parent Email")
            phone = st.text_input("Parent Phone")
            gender = st.selectbox("Gender", ["Male", "Female", "Other"])
            
            if st.form_submit_button("Add Student"):
                school_db.add_student(name, class_name, email, phone, gender)
                st.success("Student added successfully!")
    
    with col2:
        st.subheader("📋 All Students")
        students_df = school_db.get_students()
        if len(students_df) > 0:
            st.dataframe(students_df)
        else:
            st.info("No students added yet")

def report_generator():
    st.header("📝 Generate Report Cards")
    # Your existing report generation logic here
    st.info("Report generation with database support coming soon...")

def analytics_dashboard():
    st.header("📊 Analytics Dashboard")
    # Your existing analytics logic here
    st.info("Analytics with database queries coming soon...")

if __name__ == "__main__":
    main()
