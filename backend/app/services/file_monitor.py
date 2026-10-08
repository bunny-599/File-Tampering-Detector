"""
File integrity monitoring service using watchdog.

Architecture:
  - A single FileMonitorService singleton runs in a background thread.
  - watchdog's Observer receives OS filesystem events for registered paths.
  - Events are debounced (500 ms) because one file save can generate
    multiple consecutive OS events (write + close + metadata change).
  - On each debounced event the handler:
      1. Waits briefly for the write to settle.
      2. Calculates the current SHA-256 of the affected file.
      3. Looks up the trusted baseline from the database.
      4. Checks for an active modification authorization.
      5. Classifies the event:
            AUTHORIZED_UPDATE   – authorization found, baseline updated
            POSSIBLE_TAMPERING  – no authorization, alert raised
      6. Restores read-only protection after an authorized modification.

Process identification:
  psutil scans open file handles at the moment of detection.
  This may identify the process that currently has the file open, but on
  Windows there is no reliable unprivileged API to determine the *writer*.
  If unavailable: "Process information unavailable" is reported.
  We never fabricate process identity.
"""

import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.database import SessionLocal
from app.models import (
    ProtectedFile, FileStatus,
    AuditEventType, AlertType, AlertSeverity, AlertStatus, Alert,
)
from app.services.hashing import calculate_sha256
from app.services.file_protection import apply_read_only, get_file_size
from app.services.audit_service import log_event
import app.services.authorization as auth_svc

logger = logging.getLogger(__name__)

DEBOUNCE_SECONDS = 0.5
WRITE_SETTLE_SECONDS = 0.3


# ─── Process identification ───────────────────────────────────────────────────

def _get_process_info(filepath: str) -> str:
    """
    Attempt to find which process has *filepath* open using psutil.
    Returns descriptive string; never fabricates data.
    """
    try:
        target = str(Path(filepath).resolve())
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                for f in proc.open_files():
                    if str(Path(f.path).resolve()) == target:
                        return (
                            f"pid={proc.info['pid']} "
                            f"name={proc.info['name']} "
                            f"user={proc.info.get('username', 'unknown')}"
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception as exc:
        logger.debug("Process identification failed: %s", exc)
    return "Process information unavailable"


# ─── Debouncing event handler ─────────────────────────────────────────────────

class _IntegrityEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler with per-path debouncing.
    """

    def __init__(self):
        super().__init__()
        self._pending: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def on_modified(self, event):
        if not event.is_directory:
            self._schedule(event.src_path, "modified")

    def on_created(self, event):
        if not event.is_directory:
            self._schedule(event.src_path, "created")

    def on_deleted(self, event):
        if not event.is_directory:
            self._schedule(event.src_path, "deleted")

    def on_moved(self, event):
        if not event.is_directory:
            self._schedule(event.src_path, "deleted")
            self._schedule(event.dest_path, "created")

    def _schedule(self, filepath: str, event_type: str):
        with self._lock:
            existing = self._pending.get(filepath)
            if existing:
                existing.cancel()
            timer = threading.Timer(
                DEBOUNCE_SECONDS,
                self._dispatch,
                args=(filepath, event_type),
            )
            self._pending[filepath] = timer
            timer.start()

    def _dispatch(self, filepath: str, event_type: str):
        with self._lock:
            self._pending.pop(filepath, None)
        time.sleep(WRITE_SETTLE_SECONDS)
        try:
            _process_event(filepath, event_type)
        except Exception as exc:
            logger.error("Error processing event for %s: %s", filepath, exc, exc_info=True)


# ─── Core event processing ────────────────────────────────────────────────────

def _process_event(filepath: str, event_type: str):
    """
    Integrity decision logic executed for every debounced filesystem event.
    """
    db = SessionLocal()
    try:
        normalized = str(Path(filepath).resolve())

        pf = (
            db.query(ProtectedFile)
            .filter(ProtectedFile.filepath == normalized)
            .first()
        )

        if pf is None:
            logger.debug("Event on unregistered path: %s (%s)", normalized, event_type)
            return

        logger.info(
            "Integrity event: %s | file_id=%s | %s",
            event_type.upper(), pf.id, pf.filename,
        )

        if event_type == "deleted":
            _handle_deletion(db, pf, normalized)
        else:
            _handle_modification(db, pf, normalized)

    finally:
        db.close()


def _handle_deletion(db, pf: ProtectedFile, filepath: str):
    """A registered protected file has disappeared from disk."""
    pf.status = FileStatus.MISSING
    pf.last_checked = datetime.utcnow()
    db.add(pf)
    db.flush()

    log_event(
        db,
        AuditEventType.FILE_DELETED,
        file_id=pf.id,
        old_hash=pf.sha256_hash,
        details=f"Protected file missing from disk: {filepath}",
    )

    alert = Alert(
        file_id=pf.id,
        alert_type=AlertType.FILE_DELETED,
        severity=AlertSeverity.CRITICAL,
        message=(
            f"POSSIBLE UNAUTHORIZED DELETION\n"
            f"File: {pf.filename}\n"
            f"Path: {filepath}\n"
            f"Last trusted SHA-256: {pf.sha256_hash}"
        ),
        status=AlertStatus.OPEN,
    )
    db.add(alert)
    db.commit()
    logger.warning("ALERT: Protected file deleted – %s", filepath)


def _handle_modification(db, pf: ProtectedFile, filepath: str):
    """A registered protected file has been modified or recreated."""
    path = Path(filepath)

    if not path.exists():
        _handle_deletion(db, pf, filepath)
        return

    # Calculate the current hash
    try:
        current_hash = calculate_sha256(filepath)
    except Exception as exc:
        logger.error("Cannot hash %s: %s", filepath, exc)
        return

    now = datetime.utcnow()
    pf.last_checked = now

    # If the hash matches the trusted baseline – no change needed
    if current_hash == pf.sha256_hash:
        logger.info("Hash unchanged for file_id=%s – no action", pf.id)
        db.add(pf)
        db.commit()
        return

    # Hash has changed – check for an active authorization
    active_auth = auth_svc.get_active_authorization(db, pf.id)
    process_info = _get_process_info(filepath)

    if active_auth:
        # ── AUTHORIZED MODIFICATION ──────────────────────────────────────
        logger.info(
            "AUTHORIZED_UPDATE: file_id=%s auth_id=%s",
            pf.id, active_auth.id,
        )
        old_hash = pf.sha256_hash
        pf.sha256_hash = current_hash
        pf.file_size = get_file_size(filepath)
        pf.status = FileStatus.PROTECTED
        pf.last_modified = now
        db.add(pf)
        db.flush()

        # Consume the authorization so it cannot be reused
        auth_svc.consume_authorization(db, active_auth)

        log_event(
            db,
            AuditEventType.AUTHORIZED_UPDATE,
            user_id=active_auth.user_id,
            file_id=pf.id,
            old_hash=old_hash,
            new_hash=current_hash,
            process_name=process_info,
            details=(
                f"Authorized modification completed. "
                f"Authorization id={active_auth.id}. "
                f"Baseline updated."
            ),
        )

        log_event(
            db,
            AuditEventType.BASELINE_UPDATED,
            user_id=active_auth.user_id,
            file_id=pf.id,
            old_hash=old_hash,
            new_hash=current_hash,
            details="Trusted baseline hash updated after authorized modification.",
        )

        # Restore read-only protection
        apply_read_only(filepath)

        log_event(
            db,
            AuditEventType.PROTECTION_RESTORED,
            file_id=pf.id,
            details="File returned to read-only (PROTECTED) state.",
        )

        db.commit()
        logger.info("File returned to PROTECTED state: %s", filepath)

    else:
        # ── UNAUTHORIZED MODIFICATION / POSSIBLE TAMPERING ───────────────
        logger.warning(
            "POSSIBLE TAMPERING: file_id=%s | old=%s | new=%s",
            pf.id, pf.sha256_hash, current_hash,
        )

        # NEVER update the trusted baseline automatically on unauthorized change
        old_hash = pf.sha256_hash
        pf.status = FileStatus.TAMPERED
        pf.last_checked = now
        db.add(pf)
        db.flush()

        log_event(
            db,
            AuditEventType.UNAUTHORIZED_MODIFICATION,
            file_id=pf.id,
            old_hash=old_hash,
            new_hash=current_hash,
            process_name=process_info,
            details=(
                f"File modified without an active authorization. "
                f"Trusted baseline retained. "
                f"Process at detection time: {process_info}"
            ),
        )

        alert = Alert(
            file_id=pf.id,
            alert_type=AlertType.UNAUTHORIZED_MODIFICATION,
            severity=AlertSeverity.CRITICAL,
            message=(
                f"POSSIBLE TAMPERING DETECTED\n"
                f"File: {pf.filename}\n"
                f"Original SHA-256: {old_hash}\n"
                f"Current SHA-256: {current_hash}\n"
                f"Authorization: NOT FOUND\n"
                f"Process: {process_info}"
            ),
            status=AlertStatus.OPEN,
        )
        db.add(alert)
        db.commit()
        logger.warning("ALERT created for possible tampering: file_id=%s", pf.id)


# ─── Monitor Service ──────────────────────────────────────────────────────────

class FileMonitorService:
    """
    Singleton service that manages a watchdog Observer.

    Usage:
        monitor = FileMonitorService()
        monitor.start()
        monitor.watch_path("/path/to/dir")
        # ... application runs ...
        monitor.stop()
    """

    _instance: Optional["FileMonitorService"] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._observer = Observer()
        self._handler = _IntegrityEventHandler()
        self._watched_paths: Set[str] = set()
        self._running = False
        self._sweep_thread: Optional[threading.Thread] = None
        self._initialized = True

    def start(self):
        """Start the watchdog observer and the authorization sweep thread."""
        if self._running:
            return
        self._observer.start()
        self._running = True
        self._sweep_thread = threading.Thread(
            target=self._sweep_loop, daemon=True, name="auth-sweep"
        )
        self._sweep_thread.start()
        logger.info("FileMonitorService started")

    def stop(self):
        """Cleanly stop the observer."""
        if not self._running:
            return
        self._observer.stop()
        self._observer.join()
        self._running = False
        logger.info("FileMonitorService stopped")

    def watch_path(self, directory: str):
        """
        Begin watching *directory* for filesystem events.
        Safe to call multiple times with the same directory.
        """
        resolved = str(Path(directory).resolve())
        if resolved in self._watched_paths:
            return
        self._observer.schedule(self._handler, resolved, recursive=False)
        self._watched_paths.add(resolved)
        logger.info("Now watching directory: %s", resolved)

    def unwatch_path(self, directory: str):
        """Stop watching a specific directory (best-effort)."""
        resolved = str(Path(directory).resolve())
        self._watched_paths.discard(resolved)
        # watchdog does not expose a simple unschedule-by-path API,
        # so we rely on the path set and accept the minor leak.

    @property
    def is_running(self) -> bool:
        return self._running

    def _sweep_loop(self):
        """
        Background thread: every 30 s expire stale authorizations and
        re-check registered files for changes missed by watchdog
        (e.g., network drives or permission-protected directories).
        """
        while self._running:
            time.sleep(30)
            try:
                self._sweep_authorizations()
                self._periodic_hash_check()
            except Exception as exc:
                logger.error("Sweep loop error: %s", exc, exc_info=True)

    def _sweep_authorizations(self):
        db = SessionLocal()
        try:
            count = auth_svc.expire_stale_authorizations(db)
            if count:
                logger.info("Sweep: expired %d stale authorizations", count)
        finally:
            db.close()

    def _periodic_hash_check(self):
        """
        Re-verify all PROTECTED files' hashes against the baseline.
        Catches modifications that watchdog may have missed.
        """
        db = SessionLocal()
        try:
            files = (
                db.query(ProtectedFile)
                .filter(ProtectedFile.status.in_([
                    FileStatus.PROTECTED, FileStatus.TAMPERED
                ]))
                .all()
            )
            for pf in files:
                path = Path(pf.filepath)
                now = datetime.utcnow()

                if not path.exists():
                    if pf.status != FileStatus.MISSING:
                        pf.status = FileStatus.MISSING
                        pf.last_checked = now
                        db.add(pf)
                        db.flush()
                        log_event(
                            db, AuditEventType.FILE_DELETED,
                            file_id=pf.id, old_hash=pf.sha256_hash,
                            details="Periodic check: file missing from disk",
                        )
                        alert = Alert(
                            file_id=pf.id,
                            alert_type=AlertType.FILE_DELETED,
                            severity=AlertSeverity.CRITICAL,
                            message=(
                                f"POSSIBLE UNAUTHORIZED DELETION\n"
                                f"File: {pf.filename}\n"
                                f"Detected during periodic sweep."
                            ),
                            status=AlertStatus.OPEN,
                        )
                        db.add(alert)
                        db.commit()
                    continue

                try:
                    current_hash = calculate_sha256(pf.filepath)
                except Exception:
                    continue

                pf.last_checked = now

                if current_hash != pf.sha256_hash:
                    active_auth = auth_svc.get_active_authorization(db, pf.id)
                    if not active_auth and pf.status != FileStatus.TAMPERED:
                        pf.status = FileStatus.TAMPERED
                        db.add(pf)
                        db.flush()
                        log_event(
                            db, AuditEventType.UNAUTHORIZED_MODIFICATION,
                            file_id=pf.id,
                            old_hash=pf.sha256_hash,
                            new_hash=current_hash,
                            details="Periodic sweep detected hash mismatch without authorization",
                        )
                        alert = Alert(
                            file_id=pf.id,
                            alert_type=AlertType.UNAUTHORIZED_MODIFICATION,
                            severity=AlertSeverity.CRITICAL,
                            message=(
                                f"POSSIBLE TAMPERING DETECTED (periodic sweep)\n"
                                f"File: {pf.filename}\n"
                                f"Original SHA-256: {pf.sha256_hash}\n"
                                f"Current SHA-256: {current_hash}"
                            ),
                            status=AlertStatus.OPEN,
                        )
                        db.add(alert)
                        db.commit()
                else:
                    if pf.status == FileStatus.TAMPERED:
                        # Hash now matches – file was restored
                        pf.status = FileStatus.PROTECTED
                    db.add(pf)
                    db.commit()

        finally:
            db.close()


# Module-level singleton
monitor_service = FileMonitorService()
