import sqlite3
import json
import os

class SchoolDatabase:
    def __init__(self):
        self.conn = sqlite3.connect('school.db', check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                class_name TEXT NOT NULL,
                admission_no TEXT UNIQUE,
                parent_email TEXT
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
        
        self.conn.commit()
    
    def authenticate_user(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', 
                      (username, password))
        return cursor.fetchone()

# Global instance
school_db = SchoolDatabase()
