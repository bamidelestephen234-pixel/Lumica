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
    """Save a verification key to the database. Uses ON CONFLICT to handle duplicates."""
    session = db_manager.get_session()
    try:
        session.execute(
            text('''
                INSERT INTO verification_keys (key, user_id, result_id) 
                VALUES (:key, :user_id, :result_id)
                ON CONFLICT (key) DO UPDATE SET 
                    user_id = EXCLUDED.user_id,
                    result_id = EXCLUDED.result_id
            '''),
            {'key': key, 'user_id': user_id, 'result_id': result_id}
        )
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"Error saving verification key: {e}")
        raise
    finally:
        db_manager.close_session(session)


def get_key(key: str) -> Optional[dict]:
    """Look up a verification key.
    
    The function first attempts an exact match on `key`. If not found, it will
    try matching `result_id` against the provided value (useful when callers
    pass a report id).
    
    Returns a dict with fields (id, key, user_id, result_id, created_at) or
    None if no row is found.
    """
    session = db_manager.get_session()
    try:
        # Normalize the input key
        search_val = key.strip().upper() if isinstance(key, str) else key
        
        # Guard against empty search
        if not search_val:
            return None
        
        # Try exact key match (case-insensitive)
        row = session.execute(
            text("SELECT id, key, user_id, result_id, created_at FROM verification_keys WHERE UPPER(key) = :key"),
            {"key": search_val},
        ).fetchone()

        if row:
            return {
                "id": row[0],
                "key": row[1],
                "user_id": row[2],
                "result_id": row[3],
                "created_at": row[4],
            }

        # Try result_id lookup (case-insensitive, handle whitespace and NULLs)
        row = session.execute(
            text("""
                SELECT id, key, user_id, result_id, created_at 
                FROM verification_keys 
                WHERE result_id IS NOT NULL 
                  AND result_id != '' 
                  AND UPPER(TRIM(result_id)) = :rid
            """),
            {"rid": search_val},
        ).fetchone()

        if row:
            return {
                "id": row[0],
                "key": row[1],
                "user_id": row[2],
                "result_id": row[3],
                "created_at": row[4],
            }

        return None
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise RuntimeError(f"Database error while retrieving verification key: {exc}")
    finally:
        db_manager.close_session(session)


def key_exists(key: str) -> bool:
    """Return True if the given verification key exists in the DB."""
    session = db_manager.get_session()
    try:
        row = session.execute(
            text("SELECT 1 FROM verification_keys WHERE key = :key"), {"key": key}
        ).fetchone()
        return row is not None
    finally:
        db_manager.close_session(session)
