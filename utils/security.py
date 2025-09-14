import hashlib
import secrets

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 with a random salt"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + pwd_hash.hex()

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    try:
        salt = hashed[:32]
        stored_hash = hashed[32:]
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return pwd_hash.hex() == stored_hash
    except:
        return False
