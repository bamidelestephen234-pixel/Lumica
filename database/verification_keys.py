from typing import Optional
from datetime import datetime
from sqlalchemy import text
from .db_manager import db_manager

def init_db():
    """Initialize the verification keys table"""
    session = db_manager.get_session()
    try:
        session.execute(text('''
            CREATE TABLE IF NOT EXISTS verification_keys (
                id SERIAL PRIMARY KEY,
                key TEXT UNIQUE NOT NULL,
                user_id TEXT,
                result_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        '''))
        session.commit()
    finally:
        db_manager.close_session(session)

def save_key(key: str, user_id: Optional[str], result_id: Optional[str]):
    """Save a verification key to the database"""
    session = db_manager.get_session()
    try:
        session.execute(
            text('INSERT INTO verification_keys (key, user_id, result_id) VALUES (:key, :user_id, :result_id)'),
            {'key': key, 'user_id': user_id, 'result_id': result_id}
        )
        session.commit()
    finally:
        db_manager.close_session(session)

def get_key(key: str):
    """Get a verification key from the database"""
    session = db_manager.get_session()
    try:
        result = session.execute(
            text('SELECT * FROM verification_keys WHERE key = :key'),
            {'key': key}
        ).fetchone()
        return result
    finally:
        db_manager.close_session(session)

def key_exists(key: str) -> bool:
    """Check if a verification key exists in the database"""
    session = db_manager.get_session()
    try:
        result = session.execute(
            text('SELECT 1 FROM verification_keys WHERE key = :key'),
            {'key': key}
        ).fetchone()
        return result is not None
    finally:
        db_manager.close_session(session)

init_db()
