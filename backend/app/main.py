"""
SecureFileGuard – FastAPI application entry point.

Startup sequence:
  1. Create all database tables (idempotent).
  2. Seed a default admin account if none exists.
  3. Re-register watchdog watchers for all existing protected files.
  4. Start the file monitor service.

Shutdown sequence:
  1. Stop the file monitor service cleanly.
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.database as _db          # use module reference so tests can patch it
from app.models import Base, User, UserRole, ProtectedFile, FileStatus
from app.utils.security import hash_password
from app.services.file_monitor import monitor_service
from app.routers import auth, files, modifications, alerts, audit, dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger(__name__)

# Default admin credentials – CHANGE in production via environment variables
DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@1234")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup → yield → shutdown."""
    # ── STARTUP ──────────────────────────────────────────────────────────────
    logger.info("SecureFileGuard starting up…")

    # 1. Create DB tables
    Base.metadata.create_all(bind=_db.engine)
    logger.info("Database tables ready")

    # 2. Seed default admin
    db = _db.SessionLocal()
    try:
        admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if not admin:
            admin = User(
                username=DEFAULT_ADMIN_USERNAME,
                password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
            )
            db.add(admin)
            db.commit()
            logger.info("Default admin account created: username='%s'", DEFAULT_ADMIN_USERNAME)
        else:
            logger.info("Admin account already exists: '%s'", admin.username)

        # 3. Re-watch directories for existing protected files
        protected_files = db.query(ProtectedFile).all()
        watched_dirs: set[str] = set()
        for pf in protected_files:
            parent = str(Path(pf.filepath).parent)
            if parent not in watched_dirs:
                monitor_service.watch_path(parent)
                watched_dirs.add(parent)
        if protected_files:
            logger.info(
                "Resumed monitoring for %d registered file(s) across %d director(ies)",
                len(protected_files), len(watched_dirs),
            )
    finally:
        db.close()

    # 4. Start monitor
    monitor_service.start()
    logger.info("File monitor service started")

    yield  # Application is running

    # ── SHUTDOWN ─────────────────────────────────────────────────────────────
    logger.info("SecureFileGuard shutting down…")
    monitor_service.stop()
    logger.info("File monitor stopped. Goodbye.")


# ─── Application factory ─────────────────────────────────────────────────────

app = FastAPI(
    title="SecureFileGuard",
    description=(
        "File Integrity & Tampering Detection System – "
        "an academic CNS project demonstrating SHA-256 baseline monitoring, "
        "role-based authorization, and real-time tampering alerts."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS – allow the Vite dev server; tighten for production
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ─────────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(files.router)
app.include_router(modifications.router)
app.include_router(alerts.router)
app.include_router(audit.router)
app.include_router(dashboard.router)


@app.get("/", tags=["Health"])
def health_check():
    return {
        "service": "SecureFileGuard",
        "status": "running",
        "monitor": monitor_service.is_running,
    }
