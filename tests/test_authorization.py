"""
Tests for the modification authorization workflow.

Covers:
- Creating an authorization
- Getting active authorization
- Authorization expiry
- Unauthorized modification detection (no active auth)
- Consuming an authorization (one-time use)
"""

import time
import pytest
from datetime import datetime, timedelta

from app.models import (
    ProtectedFile, FileStatus,
    ModificationAuthorization, AuthorizationStatus,
    User, UserRole,
)
from app.utils.security import hash_password
from app.services import authorization as auth_svc


@pytest.fixture()
def user(db):
    u = User(username="testuser", password_hash=hash_password("Pass@1234"), role=UserRole.USER)
    db.add(u); db.commit(); db.refresh(u)
    return u


@pytest.fixture()
def protected_file(db, tmp_file):
    from app.services.hashing import calculate_sha256
    pf = ProtectedFile(
        filename="report.txt",
        filepath=tmp_file,
        sha256_hash=calculate_sha256(tmp_file),
        file_size=10,
        status=FileStatus.PROTECTED,
    )
    db.add(pf); db.commit(); db.refresh(pf)
    return pf


class TestAuthorizationService:

    def test_create_authorization(self, db, user, protected_file):
        auth = auth_svc.create_authorization(db, user.id, protected_file.id)
        assert auth.status == AuthorizationStatus.ACTIVE
        assert auth.action == "WRITE"
        assert auth.expires_at > datetime.utcnow()
        assert auth.user_id == user.id
        assert auth.file_id == protected_file.id

    def test_file_status_becomes_authorized_update(self, db, user, protected_file):
        auth_svc.create_authorization(db, user.id, protected_file.id)
        db.refresh(protected_file)
        assert protected_file.status == FileStatus.AUTHORIZED_UPDATE

    def test_get_active_authorization_returns_none_when_absent(self, db, protected_file):
        result = auth_svc.get_active_authorization(db, protected_file.id)
        assert result is None

    def test_get_active_authorization_returns_record(self, db, user, protected_file):
        auth_svc.create_authorization(db, user.id, protected_file.id)
        result = auth_svc.get_active_authorization(db, protected_file.id)
        assert result is not None
        assert result.status == AuthorizationStatus.ACTIVE

    def test_expired_authorization_not_returned(self, db, user, protected_file):
        # Create an authorization that expires immediately
        auth = auth_svc.create_authorization(db, user.id, protected_file.id, ttl_seconds=0)
        # Force expiry by setting expires_at in the past
        auth.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.add(auth); db.commit()

        result = auth_svc.get_active_authorization(db, protected_file.id)
        assert result is None

    def test_consume_authorization(self, db, user, protected_file):
        auth = auth_svc.create_authorization(db, user.id, protected_file.id)
        auth_svc.consume_authorization(db, auth)
        db.refresh(auth)
        assert auth.status == AuthorizationStatus.USED

    def test_consumed_auth_not_returned_as_active(self, db, user, protected_file):
        auth = auth_svc.create_authorization(db, user.id, protected_file.id)
        auth_svc.consume_authorization(db, auth)
        result = auth_svc.get_active_authorization(db, protected_file.id)
        assert result is None

    def test_expire_stale_authorizations(self, db, user, protected_file):
        auth = auth_svc.create_authorization(db, user.id, protected_file.id)
        auth.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.add(auth); db.commit()

        count = auth_svc.expire_stale_authorizations(db)
        assert count == 1
        db.refresh(auth)
        assert auth.status == AuthorizationStatus.EXPIRED

    def test_duplicate_authorization_expires_previous(self, db, user, protected_file):
        auth1 = auth_svc.create_authorization(db, user.id, protected_file.id)
        auth2 = auth_svc.create_authorization(db, user.id, protected_file.id)

        db.refresh(auth1)
        db.refresh(auth2)
        assert auth1.status == AuthorizationStatus.EXPIRED
        assert auth2.status == AuthorizationStatus.ACTIVE


class TestModificationAPI:

    def test_request_modification_success(self, client, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()

        res = client.post(
            f"/api/files/{reg['id']}/request-modification",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ACTIVE"
        assert data["action"] == "WRITE"
        assert data["file_id"] == reg["id"]

    def test_request_modification_requires_auth(self, client, tmp_file, admin_token):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()
        res = client.post(f"/api/files/{reg['id']}/request-modification")
        assert res.status_code == 401

    def test_duplicate_request_returns_conflict(self, client, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()
        client.post(
            f"/api/files/{reg['id']}/request-modification",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        res = client.post(
            f"/api/files/{reg['id']}/request-modification",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 409

    def test_complete_modification_closes_session(self, client, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()
        client.post(
            f"/api/files/{reg['id']}/request-modification",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        res = client.post(
            f"/api/files/{reg['id']}/complete-modification",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        assert "PROTECTED" in res.json()["message"]
