import os
import sqlite3
from datetime import datetime
from pathlib import Path

class DatabaseManager:
    def __init__(self):
        self.db_path = "akins_sunrise_school.db"
        self.init_database()
    
    def get_connection(self):
        """Get SQLite connection"""
        return sqlite3.connect(self.db_path, check_same_thread=False)
    
    def init_database(self):
        """Initialize database with tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'teacher',
                phone TEXT,
                is_active INTEGER DEFAULT 1,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        ''')
        
        # Create students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admission_no TEXT UNIQUE NOT NULL,
                student_name TEXT NOT NULL,
                student_class TEXT NOT NULL,
                parent_name TEXT,
                parent_email TEXT NOT NULL,
                parent_phone TEXT,
                gender TEXT,
                class_size INTEGER DEFAULT 35,
                attendance_rate REAL DEFAULT 95.0,
                position TEXT DEFAULT "1st",
                photo_path TEXT,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                student_id INTEGER,
                term TEXT NOT NULL,
                created_date TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'approved',
                total_score REAL,
                average_cumulative REAL,
                final_grade TEXT,
                created_by TEXT,
                FOREIGN KEY (student_id) REFERENCES students (id)
            )
        ''')
        
        # Create subject_scores table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subject_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT,
                subject TEXT NOT NULL,
                ca_score REAL,
                exam_score REAL,
                total_score REAL,
                last_cumulative REAL,
                cumulative REAL,
                grade TEXT,
                FOREIGN KEY (report_id) REFERENCES reports (id)
            )
        ''')
        
        # Insert default users
        cursor.execute('SELECT COUNT(*) FROM users WHERE id = "teacher_bamstep"')
        if cursor.fetchone()[0] == 0:
            # Simple password hash for now (you can upgrade to bcrypt)
            cursor.execute('''
                INSERT OR IGNORE INTO users (id, full_name, email, password_hash, role)
                VALUES 
                ('teacher_bamstep', 'Principal Bamstep', 'principal@akinssunrise.edu.ng', 'admin789', 'principal'),
                ('teacher_bola', 'Teacher Bola', 'bola@akinssunrise.edu.ng', 'secret123', 'class_teacher'),
                ('school_ict', 'Akins Sunrise', 'akinssunrise@gmail.com', 'akins1111', 'principal')
            ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password: str) -> str:
        """Simple password hashing"""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password"""
        return self.hash_password(plain_password) == hashed_password
    
    def get_session(self):
        """Get database connection"""
        return self.get_connection()

# Global database manager
db_manager = DatabaseManager()
