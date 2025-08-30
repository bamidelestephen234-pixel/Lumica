import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime

class SimpleDatabase:
    def __init__(self):
        self.db_path = "akins_sunrise.db"
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                class_name TEXT NOT NULL,
                parent_email TEXT,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                student_name TEXT,
                student_class TEXT,
                term TEXT,
                average_score REAL,
                grade TEXT,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_student(self, name, class_name, parent_email):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO students (name, class_name, parent_email)
            VALUES (?, ?, ?)
        ''', (name, class_name, parent_email))
        conn.commit()
        conn.close()
    
    def get_students(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        df = pd.read_sql_query("SELECT * FROM students", conn)
        conn.close()
        return df

# Initialize
db = SimpleDatabase()

# Streamlit app
st.title("🎓 Akin's Sunrise School - Database Test")
st.sidebar.header("🔍 Database Features")

# Test database
if st.sidebar.button("Test Database"):
    try:
        students = db.get_students()
        st.sidebar.success("✅ Database Connected")
        st.sidebar.metric("Students", len(students))
        
        if len(students) > 0:
            st.write("Current Students:")
            st.dataframe(students)
    except Exception as e:
        st.sidebar.error(f"❌ Error: {e}")

# Add student form
with st.form("add_student"):
    st.header("➕ Add Student")
    name = st.text_input("Student Name")
    class_name = st.text_input("Class")
    email = st.text_input("Parent Email")
    
    if st.form_submit_button("Add"):
        db.add_student(name, class_name, email)
        st.success("Student added!")

# Show all students
st.header("📋 All Students")
students_df = db.get_students()
if len(students_df) > 0:
    st.dataframe(students_df)
else:
    st.info("No students yet. Add one above!")
