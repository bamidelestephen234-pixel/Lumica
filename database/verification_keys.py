import sqlite3
from typing import Optional

DB_PATH = 'database/verification_keys.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS verification_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            user_id TEXT,
            result_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_key(key: str, user_id: Optional[str], result_id: Optional[str]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO verification_keys (key, user_id, result_id) VALUES (?, ?, ?)
    ''', (key, user_id, result_id))
    conn.commit()
    conn.close()

def get_key(key: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM verification_keys WHERE key = ?', (key,))
    result = c.fetchone()
    conn.close()
    return result

def key_exists(key: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT 1 FROM verification_keys WHERE key = ?', (key,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

init_db()
