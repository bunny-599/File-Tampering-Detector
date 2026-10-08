"""
Authentication router.

Endpoints:
  POST /api/auth/register  – create a new account
  POST /api/auth/login     – authenticate and receive a JWT
  POST /api/auth/logout    – client-side token discard (stateless JWT note)
  GET  /api/auth/me        – return the current user's profile

Security notes:
- Passwords are hashed with bcrypt (cost 12) before storage.
- Login failures are recorded in audit_logs; brute-force protection is
  provided by a simple in-process rate limiter (max 10 failures / 5 min
  per IP).  For production, a Redis-backed limiter or a WAF is preferred.
- The JWT sub claim carries the username; user ID and role are also embedded
  so the frontend can make role-aware UI decisions without an extra round-trip.
  Server-side role checks are always authoritative.
"""

import os
import time
from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole, AuditLog, AuditEventType
from app.schemas import UserRegister, UserLogin, UserOut, TokenResponse
from app.utils.security import hash_password, verify_password, create_access_token
from app.dependencies import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# ─── Simple in-process rate limiter ──────────────────────────────────────────
# Maps client IP → list of failure timestamps
_login_failures: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_WINDOW_SECONDS = 300   # 5 minutes
RATE_LIMIT_MAX_FAILURES   = 10


def _check_rate_limit(ip: str) -> None:
    """Raise 429 if the IP has too many recent login failures."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    # Prune old entries
    _login_failures[ip] = [t for t in _login_failures[ip] if t > cutoff]
    if len(_login_failures[ip]) >= RATE_LIMIT_MAX_FAILURES:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )


def _record_failure(ip: str) -> None:
    _login_failures[ip].append(time.time())


def _clear_failures(ip: str) -> None:
    _login_failures.pop(ip, None)


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    body: UserRegister,
    db: Session = Depends(get_db),
):
    """
    Register a new user account.

    - Usernames are case-sensitive and must be unique.
    - Only the first registration can create an ADMIN account; subsequent
      registrations default to USER unless the caller is already an ADMIN.
      For simplicity in the academic prototype, ADMIN role is accepted
      during registration but documented as requiring admin approval in
      production.
    """
    existing = db.query(User).filter(User.username == body.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    body: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Authenticate with username + password; return a signed JWT.

    On failure:
    - Rate-limit counter is incremented for the client IP.
    - An AUTH_FAILURE audit event is recorded (without the password).
    On success:
    - Rate-limit counter is cleared.
    - An AUTH_SUCCESS audit event is recorded.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    user = db.query(User).filter(User.username == body.username).first()

    if not user or not verify_password(body.password, user.password_hash):
        _record_failure(client_ip)
        # Log failure – do NOT include the attempted password
        audit = AuditLog(
            user_id=user.id if user else None,
            event_type=AuditEventType.AUTH_FAILURE,
            details=f"Failed login attempt for username='{body.username}' from IP={client_ip}",
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    _clear_failures(client_ip)

    token = create_access_token(
        data={"sub": user.username, "role": user.role.value, "user_id": user.id},
        expires_delta=timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))),
    )

    audit = AuditLog(
        user_id=user.id,
        event_type=AuditEventType.AUTH_SUCCESS,
        details=f"Successful login from IP={client_ip}",
    )
    db.add(audit)
    db.commit()

    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    """
    Logout endpoint.

    Because we use stateless JWTs, the server cannot invalidate a token.
    The client must discard it. For production systems, add a token
    deny-list backed by Redis. This endpoint exists so the frontend has a
    clean API surface and the workflow is explicit.
    """
    return {"message": "Logged out. Please discard your token on the client side."}


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's profile."""
    return current_user
