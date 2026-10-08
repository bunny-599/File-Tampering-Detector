"""
Audit logging service.

Every security-relevant event in the system is written to audit_logs.
The audit log is append-only from the application's perspective –
entries are never updated or deleted through normal workflows.

OS user detection uses getpass.getuser() which reflects the OS account
running the Python process on Windows. It does NOT identify the person
who externally modified a file – that is a forensic/EDR problem beyond
the scope of this application-level tool.
"""

import getpass
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models import AuditLog, AuditEventType

logger = logging.getLogger(__name__)


def log_event(
    db: Session,
    event_type: AuditEventType,
    *,
    user_id: Optional[int] = None,
    file_id: Optional[int] = None,
    old_hash: Optional[str] = None,
    new_hash: Optional[str] = None,
    details: Optional[str] = None,
    process_name: Optional[str] = None,
    include_os_user: bool = True,
) -> AuditLog:
    """
    Persist an audit event to the database.

    Parameters
    ----------
    db           : Active SQLAlchemy session.
    event_type   : One of the AuditEventType enum values.
    user_id      : Application user who triggered the event (None for system events).
    file_id      : Protected file involved in the event.
    old_hash     : SHA-256 hash before the event (for comparison events).
    new_hash     : SHA-256 hash after the event.
    details      : Free-text context string. Do NOT include passwords/tokens.
    process_name : Process name if identifiable.
    include_os_user : Whether to capture the OS-level username of the
                      *monitoring process* (not necessarily the attacker).
    """
    os_user: Optional[str] = None
    if include_os_user:
        try:
            os_user = getpass.getuser()
        except Exception:
            os_user = "unavailable"

    entry = AuditLog(
        user_id=user_id,
        file_id=file_id,
        event_type=event_type,
        old_hash=old_hash,
        new_hash=new_hash,
        timestamp=datetime.utcnow(),
        os_user=os_user,
        process_name=process_name,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    logger.info(
        "AUDIT [%s] file_id=%s user_id=%s",
        event_type.value, file_id, user_id
    )
    return entry
