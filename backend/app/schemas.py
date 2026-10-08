"""
Pydantic schemas for request validation and response serialization.
Keeps API contract separate from DB models.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, field_validator, model_validator
import re

from app.models import (
    UserRole, FileStatus, AuthorizationStatus,
    AuditEventType, AlertType, AlertSeverity, AlertStatus
)


# ─── Auth ─────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str
    password: str
    role: UserRole = UserRole.USER

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3 or len(v) > 64:
            raise ValueError("Username must be 3–64 characters")
        if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError("Username may only contain letters, digits, _ . -")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    role: UserRole
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ─── Protected Files ──────────────────────────────────────────────────────────

class FileRegisterRequest(BaseModel):
    filepath: str  # absolute path provided by the client

    @field_validator("filepath")
    @classmethod
    def no_traversal(cls, v: str) -> str:
        # Reject obvious path traversal sequences
        if ".." in v:
            raise ValueError("Path traversal sequences are not allowed")
        return v.strip()


class ProtectedFileOut(BaseModel):
    id: int
    filename: str
    filepath: str
    sha256_hash: str
    file_size: Optional[int]
    status: FileStatus
    created_at: datetime
    last_checked: Optional[datetime]
    last_modified: Optional[datetime]

    model_config = {"from_attributes": True}


# ─── Modification Authorization ───────────────────────────────────────────────

class ModificationAuthorizationOut(BaseModel):
    id: int
    user_id: int
    file_id: int
    action: str
    created_at: datetime
    expires_at: datetime
    status: AuthorizationStatus

    model_config = {"from_attributes": True}


class CompleteModificationRequest(BaseModel):
    notes: Optional[str] = None


# ─── Audit Logs ───────────────────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int]
    file_id: Optional[int]
    event_type: AuditEventType
    old_hash: Optional[str]
    new_hash: Optional[str]
    timestamp: datetime
    os_user: Optional[str]
    process_name: Optional[str]
    details: Optional[str]

    model_config = {"from_attributes": True}


# ─── Alerts ───────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    file_id: Optional[int]
    alert_type: AlertType
    severity: AlertSeverity
    message: str
    timestamp: datetime
    status: AlertStatus

    model_config = {"from_attributes": True}


class AlertResolveRequest(BaseModel):
    notes: Optional[str] = None


# ─── Dashboard ────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_protected: int
    safe_files: int
    tampered_files: int
    missing_files: int
    authorized_updates: int
    open_alerts: int
    active_modification_sessions: int
    recent_alerts: List[AlertOut]
    recent_audit: List[AuditLogOut]
