"""
Pytest configuration and shared fixtures for SecureFileGuard tests.

Key design:
- StaticPool forces all SQLAlchemy connections to reuse the same
  underlying sqlite3 connection, so create_all, lifespan queries, and
  request-handler queries all see the same in-memory database.
- app.database.engine and app.database.SessionLocal are patched at the
  module level so the lifespan in main.py picks up the test objects
  (main.py now uses _db.engine / _db.SessionLocal via module reference).
- FileMonitorService is mocked to prevent watchdog threads starting.
"""

import os
import pytest
import tempfile
import stat
from unittest.mock import MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("DEFAULT_ADMIN_USERNAME", "testadmin")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdmin@1234")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from app.models import User, UserRole
from app.utils.security import hash_password

# StaticPool: every call to engine.connect() returns the SAME connection
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


def _override_get_db():
    session = TestSession()
    try:
        yield session
    finally:
        session.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture()
def db(reset_db):
    session = TestSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(reset_db):
    mock_monitor = MagicMock()
    mock_monitor.is_running = True

    import app.database as db_mod
    import app.services.file_monitor as fm_mod
    import app.main as main_mod
    import app.routers.files as files_mod

    with patch.object(db_mod, "engine", TEST_ENGINE), \
         patch.object(db_mod, "SessionLocal", TestSession), \
         patch.object(fm_mod, "monitor_service", mock_monitor), \
         patch.object(main_mod, "monitor_service", mock_monitor), \
         patch.object(files_mod, "monitor_service", mock_monitor):
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


@pytest.fixture()
def admin_user(db):
    user = User(
        username="admin",
        password_hash=hash_password("Admin@1234"),
        role=UserRole.ADMIN,
    )
    db.add(user); db.commit(); db.refresh(user)
    return user


@pytest.fixture()
def normal_user(db):
    user = User(
        username="alice",
        password_hash=hash_password("Alice@1234"),
        role=UserRole.USER,
    )
    db.add(user); db.commit(); db.refresh(user)
    return user


@pytest.fixture()
def admin_token(client, admin_user):
    res = client.post("/api/auth/login", json={
        "username": "admin", "password": "Admin@1234",
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture()
def user_token(client, normal_user):
    res = client.post("/api/auth/login", json={
        "username": "alice", "password": "Alice@1234",
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture()
def tmp_file():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write("Computer Networks Security Project")
        path = f.name
    yield path
    try:
        os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
        os.unlink(path)
    except OSError:
        pass
