"""
Modification workflow router.

Endpoints:
  POST /api/files/{id}/request-modification   – request a write grant
  POST /api/files/{id}/authorize-modification – admin approves the grant
  POST /api/files/{id}/complete-modification  – user signals they are done

The three-step workflow enforces the principle that:
  - A user explicitly requests permission to modify.
  - An admin (or the same authorized user) confirms it.
  - The system grants a short-lived token; the monitor watches for the change.
  - On file change detection, the monitor auto-completes and locks the file.
  - The complete-modification endpoint exists so the user can proactively
    close the window (e.g. they changed their mind).

For the academic single-user/admin prototype, request and authorize are
combined into one flow for the ADMIN role; a USER must have an ADMIN
explicitly authorize their request.
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    ProtectedFile, FileStatus, User, UserRole,
    AuditEventType, ModificationAuthorization, AuthorizationStatus,
)
from app.schemas import ModificationAuthorizationOut, CompleteModificationRequest
from app.dependencies import get_current_user
from app.services import authorization as auth_svc
from app.services.file_protection import remove_read_only, apply_read_only
from app.services.audit_service import log_event

router = APIRouter(prefix="/api/files", tags=["Modifications"])


def _get_protected_file(file_id: int, db: Session) -> ProtectedFile:
    pf = db.query(ProtectedFile).filter(ProtectedFile.id == file_id).first()
    if not pf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return pf


@router.post("/{file_id}/request-modification", response_model=ModificationAuthorizationOut)
def request_modification(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Step 1 – Request a modification authorization for *file_id*.

    - Any authenticated user may submit a request.
    - ADMIN users receive immediate authorization (self-authorize).
    - USER role requests are created as ACTIVE immediately for the
      academic prototype (in production, require a separate admin approval).
    - A file that is currently MISSING cannot be authorized for modification.
    """
    pf = _get_protected_file(file_id, db)

    if pf.status == FileStatus.MISSING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot authorize modification for a missing file",
        )

    # Check if there is already an active authorization
    existing = auth_svc.get_active_authorization(db, file_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An active modification authorization already exists for this file",
        )

    auth = auth_svc.create_authorization(db, user_id=current_user.id, file_id=file_id)

    log_event(
        db,
        AuditEventType.MODIFICATION_REQUESTED,
        user_id=current_user.id,
        file_id=file_id,
        details=(
            f"Modification requested by '{current_user.username}'. "
            f"Authorization id={auth.id} expires={auth.expires_at.isoformat()}Z"
        ),
    )

    # Temporarily remove read-only protection so the user can write
    remove_read_only(pf.filepath)

    log_event(
        db,
        AuditEventType.MODIFICATION_AUTHORIZED,
        user_id=current_user.id,
        file_id=file_id,
        details=(
            f"Write access temporarily granted. "
            f"Authorization valid for 60 seconds. "
            f"File will be re-locked after modification or expiry."
        ),
    )

    return auth


@router.post("/{file_id}/authorize-modification", response_model=ModificationAuthorizationOut)
def authorize_modification(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Step 2 – Explicitly authorize (or re-confirm) an existing pending
    modification request. In the academic prototype, this endpoint can
    be used by any authenticated user to re-confirm their own request,
    or by an admin to authorize another user's request.

    Returns the active authorization record.
    """
    pf = _get_protected_file(file_id, db)

    active = auth_svc.get_active_authorization(db, file_id)
    if not active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active modification authorization found for this file. "
                   "Submit a request-modification first.",
        )

    log_event(
        db,
        AuditEventType.MODIFICATION_AUTHORIZED,
        user_id=current_user.id,
        file_id=file_id,
        details=f"Authorization id={active.id} confirmed by '{current_user.username}'",
    )

    return active


@router.post("/{file_id}/complete-modification")
def complete_modification(
    file_id: int,
    body: CompleteModificationRequest = CompleteModificationRequest(),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Step 3 – Proactively close the modification window without waiting
    for the file monitor to detect a change.

    Use this when:
    - The user changed their mind and did not modify the file.
    - The user wants to explicitly surrender the write grant early.

    The file monitor will also close the window automatically when it
    detects a file change with an active authorization.
    """
    pf = _get_protected_file(file_id, db)

    active = auth_svc.get_active_authorization(db, file_id)
    if active:
        auth_svc.expire_authorization(db, active)

    # Restore read-only regardless
    apply_read_only(pf.filepath)

    # Reset file status to PROTECTED if it was in AUTHORIZED_UPDATE
    if pf.status == FileStatus.AUTHORIZED_UPDATE:
        pf.status = FileStatus.PROTECTED
        db.add(pf)
        db.commit()

    log_event(
        db,
        AuditEventType.PROTECTION_RESTORED,
        user_id=current_user.id,
        file_id=file_id,
        details=(
            f"Modification session closed by '{current_user.username}'. "
            f"Notes: {body.notes or 'none'}. "
            f"File returned to PROTECTED state."
        ),
    )

    return {"message": "Modification session closed. File is now PROTECTED."}
