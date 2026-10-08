"""
Modification authorization service.

Manages the short-lived write grants that allow legitimate users to
modify protected files through the trusted workflow.

Security principles:
- Authorization tokens are server-side records, not client-provided flags.
- Each grant has a hard expiry (default 60 seconds).
- A grant can only be used once (status transitions ACTIVE -> USED).
- Expired grants are never reactivated.
- The file monitor checks this service before deciding whether a
  detected modification is authorized or suspicious.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.models import (
    ModificationAuthorization, AuthorizationStatus,
    ProtectedFile, FileStatus,
)

logger = logging.getLogger(__name__)

# How long a modification authorization remains valid (seconds)
AUTHORIZATION_TTL_SECONDS: int = 60


def create_authorization(
    db: Session,
    user_id: int,
    file_id: int,
    ttl_seconds: int = AUTHORIZATION_TTL_SECONDS,
) -> ModificationAuthorization:
    """
    Create a new ACTIVE modification authorization for *file_id*.
    Any existing ACTIVE authorization for the same file is expired first
    to prevent overlapping grants.
    """
    _expire_active_authorizations(db, file_id)

    now = datetime.utcnow()
    auth = ModificationAuthorization(
        user_id=user_id,
        file_id=file_id,
        action="WRITE",
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        status=AuthorizationStatus.ACTIVE,
    )
    db.add(auth)

    # Mark the file so the monitor knows a session is open
    pf = db.query(ProtectedFile).filter(ProtectedFile.id == file_id).first()
    if pf:
        pf.status = FileStatus.AUTHORIZED_UPDATE
        db.add(pf)

    db.commit()
    db.refresh(auth)
    logger.info(
        "Authorization created: id=%s file_id=%s user_id=%s expires=%s",
        auth.id, file_id, user_id, auth.expires_at,
    )
    return auth


def get_active_authorization(
    db: Session,
    file_id: int,
) -> Optional[ModificationAuthorization]:
    """
    Return the currently ACTIVE (and unexpired) authorization for *file_id*,
    or None if no such authorization exists.

    This is the critical check the file monitor uses to decide whether
    a detected modification is authorized or suspicious.
    """
    now = datetime.utcnow()
    return (
        db.query(ModificationAuthorization)
        .filter(
            ModificationAuthorization.file_id == file_id,
            ModificationAuthorization.status == AuthorizationStatus.ACTIVE,
            ModificationAuthorization.expires_at > now,
        )
        .order_by(ModificationAuthorization.created_at.desc())
        .first()
    )


def consume_authorization(
    db: Session,
    authorization: ModificationAuthorization,
) -> None:
    """Mark an authorization as USED so it cannot be reused."""
    authorization.status = AuthorizationStatus.USED
    db.add(authorization)
    db.commit()
    logger.info("Authorization consumed: id=%s", authorization.id)


def expire_authorization(
    db: Session,
    authorization: ModificationAuthorization,
) -> None:
    """Mark an authorization as EXPIRED."""
    authorization.status = AuthorizationStatus.EXPIRED
    db.add(authorization)
    db.commit()
    logger.info("Authorization expired: id=%s", authorization.id)


def expire_stale_authorizations(db: Session) -> int:
    """
    Sweep the database and expire any ACTIVE authorizations whose
    expires_at has passed. Called by the background monitor loop.
    Returns the number of authorizations expired.
    """
    now = datetime.utcnow()
    stale = (
        db.query(ModificationAuthorization)
        .filter(
            ModificationAuthorization.status == AuthorizationStatus.ACTIVE,
            ModificationAuthorization.expires_at <= now,
        )
        .all()
    )
    count = 0
    for auth in stale:
        auth.status = AuthorizationStatus.EXPIRED
        db.add(auth)
        pf = db.query(ProtectedFile).filter(ProtectedFile.id == auth.file_id).first()
        if pf and pf.status == FileStatus.AUTHORIZED_UPDATE:
            pf.status = FileStatus.PROTECTED
            db.add(pf)
        count += 1

    if count:
        db.commit()
        logger.info("Expired %d stale authorization(s)", count)
    return count


def _expire_active_authorizations(db: Session, file_id: int) -> None:
    """Internal: expire all ACTIVE authorizations for a file before creating a new one."""
    active = (
        db.query(ModificationAuthorization)
        .filter(
            ModificationAuthorization.file_id == file_id,
            ModificationAuthorization.status == AuthorizationStatus.ACTIVE,
        )
        .all()
    )
    for auth in active:
        auth.status = AuthorizationStatus.EXPIRED
        db.add(auth)
    if active:
        db.commit()
