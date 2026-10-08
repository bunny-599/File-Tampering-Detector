"""
Audit log router.

Endpoints:
  GET /api/audit              – full audit log (paginated)
  GET /api/audit/{file_id}    – audit events for a specific file

The audit log is read-only through this API. No delete or update
endpoints are exposed – the log is an append-only security record.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, User
from app.schemas import AuditLogOut
from app.dependencies import get_current_user

router = APIRouter(prefix="/api/audit", tags=["Audit Logs"])


@router.get("", response_model=list[AuditLogOut])
def list_audit(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return audit log entries, most recent first.
    Supports pagination via limit/offset.
    """
    return (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/{file_id}", response_model=list[AuditLogOut])
def audit_for_file(
    file_id: int,
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return all audit log entries for a specific protected file."""
    return (
        db.query(AuditLog)
        .filter(AuditLog.file_id == file_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
