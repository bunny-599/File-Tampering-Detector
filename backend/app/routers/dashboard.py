"""
Dashboard statistics router.

Endpoint:
  GET /api/dashboard/stats – aggregated counts and recent events for the
                             security dashboard overview.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    ProtectedFile, FileStatus,
    Alert, AlertStatus,
    AuditLog, AuditEventType,
    ModificationAuthorization, AuthorizationStatus,
    User,
)
from app.schemas import DashboardStats, AlertOut, AuditLogOut
from app.dependencies import get_current_user
from datetime import datetime

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return aggregated statistics for the security dashboard.
    All counts are computed server-side; the client cannot influence them.
    """
    # File counts
    total_protected = db.query(ProtectedFile).count()

    safe_files = (
        db.query(ProtectedFile)
        .filter(ProtectedFile.status == FileStatus.PROTECTED)
        .count()
    )

    tampered_files = (
        db.query(ProtectedFile)
        .filter(ProtectedFile.status == FileStatus.TAMPERED)
        .count()
    )

    missing_files = (
        db.query(ProtectedFile)
        .filter(ProtectedFile.status == FileStatus.MISSING)
        .count()
    )

    # Count files in AUTHORIZED_UPDATE state
    authorized_updates = (
        db.query(ProtectedFile)
        .filter(ProtectedFile.status == FileStatus.AUTHORIZED_UPDATE)
        .count()
    )

    # Open alerts
    open_alerts = (
        db.query(Alert)
        .filter(Alert.status == AlertStatus.OPEN)
        .count()
    )

    # Active modification sessions
    now = datetime.utcnow()
    active_modification_sessions = (
        db.query(ModificationAuthorization)
        .filter(
            ModificationAuthorization.status == AuthorizationStatus.ACTIVE,
            ModificationAuthorization.expires_at > now,
        )
        .count()
    )

    # Recent alerts (last 5)
    recent_alerts = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(5)
        .all()
    )

    # Recent audit events (last 10)
    recent_audit = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
        .all()
    )

    return DashboardStats(
        total_protected=total_protected,
        safe_files=safe_files,
        tampered_files=tampered_files,
        missing_files=missing_files,
        authorized_updates=authorized_updates,
        open_alerts=open_alerts,
        active_modification_sessions=active_modification_sessions,
        recent_alerts=[AlertOut.model_validate(a) for a in recent_alerts],
        recent_audit=[AuditLogOut.model_validate(a) for a in recent_audit],
    )
