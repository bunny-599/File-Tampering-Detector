"""
File protection service – Windows-compatible read-only enforcement.

Applies and removes write permissions on protected files using Python's
stat module (which maps to Windows ACL attribute manipulation via
os.chmod).

IMPORTANT SECURITY LIMITATION (documented):
  os.chmod on Windows manipulates the FILE_ATTRIBUTE_READONLY flag.
  A user with Administrator or SYSTEM privileges can override this flag
  without going through this application. This is an application-level
  control, not a kernel-level EDR. It is sufficient to deter casual
  accidental modification and provides a clear forensic signal when
  tampered, but it is NOT equivalent to mandatory access control.
"""

import os
import stat
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def apply_read_only(filepath: str | Path) -> bool:
    """
    Remove write permission bits from *filepath* (set read-only).

    On Windows this sets the FILE_ATTRIBUTE_READONLY flag via the
    POSIX-compatibility layer in Python's os.chmod.

    Returns True on success, False if the operation could not be applied
    (e.g., the process lacks the required privileges).
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning("apply_read_only: file does not exist – %s", filepath)
        return False
    try:
        current_mode = path.stat().st_mode
        # Remove owner/group/other write bits
        read_only_mode = current_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        os.chmod(path, read_only_mode)
        logger.info("Protection applied (read-only): %s", filepath)
        return True
    except PermissionError:
        logger.warning(
            "apply_read_only: insufficient privileges for %s – "
            "file left in current permission state",
            filepath,
        )
        return False
    except OSError as exc:
        logger.error("apply_read_only: OS error for %s – %s", filepath, exc)
        return False


def remove_read_only(filepath: str | Path) -> bool:
    """
    Restore write permission to *filepath* for a short-lived authorized
    modification window.

    Returns True on success, False on failure.
    """
    path = Path(filepath)
    if not path.exists():
        logger.warning("remove_read_only: file does not exist – %s", filepath)
        return False
    try:
        current_mode = path.stat().st_mode
        writable_mode = current_mode | stat.S_IWUSR
        os.chmod(path, writable_mode)
        logger.info("Write permission temporarily granted: %s", filepath)
        return True
    except PermissionError:
        logger.warning(
            "remove_read_only: insufficient privileges for %s", filepath
        )
        return False
    except OSError as exc:
        logger.error("remove_read_only: OS error for %s – %s", filepath, exc)
        return False


def is_read_only(filepath: str | Path) -> bool:
    """Return True if the file currently has no write permission for the owner."""
    path = Path(filepath)
    if not path.exists():
        return False
    mode = path.stat().st_mode
    return not bool(mode & stat.S_IWUSR)


def get_file_size(filepath: str | Path) -> int | None:
    """Return file size in bytes, or None if unavailable."""
    try:
        return Path(filepath).stat().st_size
    except OSError:
        return None
