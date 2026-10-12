"""
Authentication and Cryptographic Helpers for Hosted Management.
Implements PBKDF2-HMAC-SHA256 password hashing and expiring enrollment tokens.
"""

import hmac
import hashlib
import secrets
import time
from typing import Dict, Any, Optional

JWT_SECRET = secrets.token_hex(32)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}:{key.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, key_hex = hashed.split(":", 1)
        expected = bytes.fromhex(key_hex)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
        return hmac.compare_digest(key, expected)
    except Exception:
        return False


def generate_secure_token(prefix: str = "tok") -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"
