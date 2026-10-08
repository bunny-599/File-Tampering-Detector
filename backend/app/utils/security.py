"""
Security utilities: password hashing (bcrypt) and JWT token management.

Security principles applied:
- Passwords are NEVER stored in plaintext – bcrypt with cost factor 12
- JWT tokens are signed with HS256 and carry minimal claims
- Tokens expire; expiry is validated server-side on every request
- Secret key is loaded from environment, never hard-coded in production
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

# ─── Configuration ───────────────────────────────────────────────────────────

SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-insecure-key-change-in-production-123!")
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# bcrypt with cost factor 12 – good balance of security and performance
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)


# ─── Password Hashing ────────────────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """Return a bcrypt hash of *plain_password*. Never store the plain text."""
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if *plain_password* matches the stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ─── JWT Tokens ──────────────────────────────────────────────────────────────

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token.

    *data* should contain at minimum {"sub": username, "role": role}.
    The 'exp' claim is always added; the caller should not include it.
    """
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload["exp"] = expire
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT token.

    Raises:
        ExpiredSignatureError – if the token has expired
        InvalidTokenError     – if the token is malformed or signature is bad
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def verify_token(token: str) -> Optional[dict]:
    """
    Safe wrapper: returns the decoded payload or None on any failure.
    Use for non-critical checks; for protected endpoints prefer decode_access_token
    so the error propagates to produce a 401.
    """
    try:
        return decode_access_token(token)
    except (InvalidTokenError, ExpiredSignatureError):
        return None
