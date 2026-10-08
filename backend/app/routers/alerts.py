"""
Alerts router.

Endpoints:
  GET  /api/alerts          – list all alerts (optionally filter by status)
  GET  /api/alerts/{id}     – get a single alert
  POST /api/alerts/{id}/resolve – mark an alert as resolved
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, AlertStatus, User
from app.schemas import AlertOut, AlertResolveRequest
from app.dependencies import get_current_user

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    alert_status: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return alerts, optionally filtered by status (OPEN or RESOLVED).
    Most recent alerts first.
    """
    query = db.query(Alert)
    if alert_status:
        try:
            s = AlertStatus(alert_status.upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status value. Use OPEN or RESOLVED.",
            )
        query = query.filter(Alert.status == s)

    return query.order_by(Alert.timestamp.desc()).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return a single alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/{alert_id}/resolve", response_model=AlertOut)
def resolve_alert(
    alert_id: int,
    body: AlertResolveRequest = AlertResolveRequest(),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Mark an alert as RESOLVED.

    Resolving an alert is an acknowledgement action – it does NOT
    automatically restore the trusted baseline or unlock the file.
    Baseline recovery must go through the authorized modification workflow.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.status == AlertStatus.RESOLVED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Alert is already resolved",
        )

    alert.status = AlertStatus.RESOLVED
    if body.notes:
        alert.message = alert.message + f"\n\nResolution notes: {body.notes}"
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
