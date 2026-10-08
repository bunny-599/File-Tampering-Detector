"""
SQLAlchemy ORM models for SecureFileGuard.

Tables:
  users                      – application accounts with bcrypt-hashed passwords
  protected_files            – files under integrity monitoring
  modification_authorizations – short-lived write grants
  audit_logs                 – immutable security event journal
  alerts                     – active / resolved security alerts
"""

import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Enum, Text, ForeignKey, BigInteger
)
from sqlalchemy.orm import relationship
from app.database import Base


# ─── Enumerations ────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    USER  = "USER"


class FileStatus(str, enum.Enum):
    PROTECTED         = "PROTECTED"
    AUTHORIZED_UPDATE = "AUTHORIZED_UPDATE"
    TAMPERED          = "TAMPERED"
    MISSING           = "MISSING"
    RECOVERED         = "RECOVERED"


class AuthorizationStatus(str, enum.Enum):
    ACTIVE    = "ACTIVE"
    USED      = "USED"
    EXPIRED   = "EXPIRED"
    REVOKED   = "REVOKED"


class AuditEventType(str, enum.Enum):
    FILE_REGISTERED          = "FILE_REGISTERED"
    FILE_READ                = "FILE_READ"
    MODIFICATION_REQUESTED   = "MODIFICATION_REQUESTED"
    MODIFICATION_AUTHORIZED  = "MODIFICATION_AUTHORIZED"
    AUTHORIZED_UPDATE        = "AUTHORIZED_UPDATE"
    UNAUTHORIZED_MODIFICATION = "UNAUTHORIZED_MODIFICATION"
    FILE_DELETED             = "FILE_DELETED"
    UNAUTHORIZED_FILE_CREATED = "UNAUTHORIZED_FILE_CREATED"
    BASELINE_UPDATED         = "BASELINE_UPDATED"
    PROTECTION_RESTORED      = "PROTECTION_RESTORED"
    FILE_RECOVERED           = "FILE_RECOVERED"
    AUTH_SUCCESS             = "AUTH_SUCCESS"
    AUTH_FAILURE             = "AUTH_FAILURE"
    FILE_UNREGISTERED        = "FILE_UNREGISTERED"


class AlertType(str, enum.Enum):
    UNAUTHORIZED_MODIFICATION = "UNAUTHORIZED_MODIFICATION"
    FILE_DELETED              = "FILE_DELETED"
    UNAUTHORIZED_FILE_CREATED = "UNAUTHORIZED_FILE_CREATED"
    FILE_REPLACED             = "FILE_REPLACED"
    AUTHORIZATION_EXPIRED     = "AUTHORIZATION_EXPIRED"


class AlertSeverity(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN     = "OPEN"
    RESOLVED = "RESOLVED"


# ─── Models ──────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role          = Column(Enum(UserRole), nullable=False, default=UserRole.USER)
    created_at    = Column(DateTime, nullable=False, default=datetime.utcnow)

    authorizations = relationship("ModificationAuthorization", back_populates="user")
    audit_logs     = relationship("AuditLog", back_populates="user")


class ProtectedFile(Base):
    __tablename__ = "protected_files"

    id            = Column(Integer, primary_key=True, index=True)
    filename      = Column(String(256), nullable=False)
    filepath      = Column(String(1024), nullable=False, unique=True)
    sha256_hash   = Column(String(64), nullable=False)   # trusted baseline
    file_size     = Column(BigInteger, nullable=True)
    status        = Column(Enum(FileStatus), nullable=False, default=FileStatus.PROTECTED)
    created_at    = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_checked  = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)

    authorizations = relationship("ModificationAuthorization", back_populates="file")
    audit_logs     = relationship("AuditLog", back_populates="file")
    alerts         = relationship("Alert", back_populates="file")


class ModificationAuthorization(Base):
    __tablename__ = "modification_authorizations"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    file_id    = Column(Integer, ForeignKey("protected_files.id"), nullable=False)
    action     = Column(String(32), nullable=False, default="WRITE")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    status     = Column(Enum(AuthorizationStatus), nullable=False, default=AuthorizationStatus.ACTIVE)

    user = relationship("User", back_populates="authorizations")
    file = relationship("ProtectedFile", back_populates="authorizations")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=True)
    file_id      = Column(Integer, ForeignKey("protected_files.id"), nullable=True)
    event_type   = Column(Enum(AuditEventType), nullable=False)
    old_hash     = Column(String(64), nullable=True)
    new_hash     = Column(String(64), nullable=True)
    timestamp    = Column(DateTime, nullable=False, default=datetime.utcnow)
    os_user      = Column(String(256), nullable=True)
    process_name = Column(String(256), nullable=True)
    details      = Column(Text, nullable=True)

    user = relationship("User", back_populates="audit_logs")
    file = relationship("ProtectedFile", back_populates="audit_logs")


class Alert(Base):
    __tablename__ = "alerts"

    id         = Column(Integer, primary_key=True, index=True)
    file_id    = Column(Integer, ForeignKey("protected_files.id"), nullable=True)
    alert_type = Column(Enum(AlertType), nullable=False)
    severity   = Column(Enum(AlertSeverity), nullable=False, default=AlertSeverity.HIGH)
    message    = Column(Text, nullable=False)
    timestamp  = Column(DateTime, nullable=False, default=datetime.utcnow)
    status     = Column(Enum(AlertStatus), nullable=False, default=AlertStatus.OPEN)

    file = relationship("ProtectedFile", back_populates="alerts")
