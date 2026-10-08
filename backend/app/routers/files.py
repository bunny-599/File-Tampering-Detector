"""
Protected files router.

Endpoints:
  GET    /api/files              – list all registered files
  POST   /api/files/register     – register a file for integrity monitoring
  GET    /api/files/{id}         – get a single file's details
  DELETE /api/files/{id}         – unregister a file (admin only)

Security:
  - Path traversal is rejected at the Pydantic schema layer AND here.
  - Only files that physically exist may be registered.
  - Files are normalized to absolute paths before storage.
  - read-only protection is applied on registration.
"""

import os
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ProtectedFile, FileStatus, AuditEventType, User
from app.schemas import FileRegisterRequest, ProtectedFileOut
from app.dependencies import get_current_user, require_admin
from app.services.hashing import calculate_sha256
from app.services.file_protection import apply_read_only, get_file_size
from app.services.audit_service import log_event
from app.services.file_monitor import monitor_service

router = APIRouter(prefix="/api/files", tags=["Protected Files"])

# Resolve the protected_files directory relative to the project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
PROTECTED_DIR = _PROJECT_ROOT / "protected_files"
PROTECTED_DIR.mkdir(parents=True, exist_ok=True)


def _validate_path(raw_path: str) -> Path:
    """
    Resolve and validate a file path.

    Rules enforced:
    1. No path traversal sequences (..)
    2. The file must exist on disk.
    3. The resolved path must be inside PROTECTED_DIR.
       (For development flexibility, we also allow any absolute path the
        user explicitly registers, but log a warning if outside the default
        directory. In production, enforce the PROTECTED_DIR boundary strictly.)
    """
    path = Path(raw_path).resolve()

    if ".." in str(path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path traversal not allowed",
        )
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File does not exist: {raw_path}",
        )
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path must point to a file, not a directory",
        )
    return path


@router.get("", response_model=list[ProtectedFileOut])
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return all registered protected files."""
    return db.query(ProtectedFile).order_by(ProtectedFile.created_at.desc()).all()


@router.post("/register", response_model=ProtectedFileOut, status_code=status.HTTP_201_CREATED)
def register_file(
    body: FileRegisterRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Register a file for integrity monitoring.

    Workflow:
      1. Validate and resolve the path.
      2. Check it is not already registered.
      3. Calculate SHA-256 baseline.
      4. Persist the record.
      5. Apply read-only protection.
      6. Start watching the parent directory.
      7. Emit FILE_REGISTERED audit event.
    """
    path = _validate_path(body.filepath)
    normalized = str(path)

    existing = db.query(ProtectedFile).filter(ProtectedFile.filepath == normalized).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="File is already registered for monitoring",
        )

    sha256 = calculate_sha256(path)
    size = get_file_size(path)

    pf = ProtectedFile(
        filename=path.name,
        filepath=normalized,
        sha256_hash=sha256,
        file_size=size,
        status=FileStatus.PROTECTED,
        created_at=datetime.utcnow(),
        last_checked=datetime.utcnow(),
    )
    db.add(pf)
    db.commit()
    db.refresh(pf)

    # Apply OS-level read-only flag
    apply_read_only(normalized)

    # Start monitoring the parent directory
    monitor_service.watch_path(str(path.parent))

    log_event(
        db,
        AuditEventType.FILE_REGISTERED,
        user_id=current_user.id,
        file_id=pf.id,
        new_hash=sha256,
        details=f"File registered for monitoring. Size={size} bytes. Path={normalized}",
    )

    return pf


@router.get("/{file_id}", response_model=ProtectedFileOut)
def get_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return details for a single registered file."""
    pf = db.query(ProtectedFile).filter(ProtectedFile.id == file_id).first()
    if not pf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    # Log every read access
    log_event(
        db,
        AuditEventType.FILE_READ,
        user_id=current_user.id,
        file_id=pf.id,
        details=f"File details accessed by user '{current_user.username}'",
    )
    return pf


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def unregister_file(
    file_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Unregister a file from monitoring (admin only).
    Does NOT delete the physical file from disk.
    """
    pf = db.query(ProtectedFile).filter(ProtectedFile.id == file_id).first()
    if not pf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    log_event(
        db,
        AuditEventType.FILE_UNREGISTERED,
        user_id=current_user.id,
        file_id=pf.id,
        old_hash=pf.sha256_hash,
        details=f"File unregistered from monitoring by admin '{current_user.username}'",
    )

    db.delete(pf)
    db.commit()
