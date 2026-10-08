"""
Tests for alerts and audit log endpoints.
"""

import pytest
from app.models import (
    Alert, AlertType, AlertSeverity, AlertStatus,
    AuditLog, AuditEventType,
    ProtectedFile, FileStatus,
    User, UserRole,
)
from app.utils.security import hash_password
from app.services.audit_service import log_event


@pytest.fixture()
def admin_user_and_token(client):
    client.post("/api/auth/register", json={
        "username": "admin2", "password": "Admin@1234", "role": "ADMIN"
    })
    res = client.post("/api/auth/login", json={
        "username": "admin2", "password": "Admin@1234"
    })
    return res.json()["access_token"]


@pytest.fixture()
def sample_alert(db, tmp_file):
    from app.services.hashing import calculate_sha256
    pf = ProtectedFile(
        filename="alert_test.txt",
        filepath=tmp_file,
        sha256_hash=calculate_sha256(tmp_file),
        file_size=10,
        status=FileStatus.TAMPERED,
    )
    db.add(pf); db.commit(); db.refresh(pf)

    alert = Alert(
        file_id=pf.id,
        alert_type=AlertType.UNAUTHORIZED_MODIFICATION,
        severity=AlertSeverity.CRITICAL,
        message="POSSIBLE TAMPERING DETECTED\nFile: alert_test.txt",
        status=AlertStatus.OPEN,
    )
    db.add(alert); db.commit(); db.refresh(alert)
    return alert


class TestAlertsAPI:

    def test_list_alerts_requires_auth(self, client):
        res = client.get("/api/alerts")
        assert res.status_code == 401

    def test_list_alerts_returns_list(self, client, admin_user_and_token):
        res = client.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_list_open_alerts(self, client, admin_user_and_token, sample_alert):
        res = client.get(
            "/api/alerts?status=OPEN",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert len(data) >= 1
        assert all(a["status"] == "OPEN" for a in data)

    def test_get_alert_by_id(self, client, admin_user_and_token, sample_alert):
        res = client.get(
            f"/api/alerts/{sample_alert.id}",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 200
        assert res.json()["id"] == sample_alert.id

    def test_get_nonexistent_alert(self, client, admin_user_and_token):
        res = client.get(
            "/api/alerts/99999",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 404

    def test_resolve_alert(self, client, admin_user_and_token, sample_alert):
        res = client.post(
            f"/api/alerts/{sample_alert.id}/resolve",
            json={"notes": "Investigated – false positive"},
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "RESOLVED"

    def test_resolve_already_resolved_alert_conflict(self, client, admin_user_and_token, sample_alert):
        headers = {"Authorization": f"Bearer {admin_user_and_token}"}
        client.post(f"/api/alerts/{sample_alert.id}/resolve", headers=headers)
        res = client.post(f"/api/alerts/{sample_alert.id}/resolve", headers=headers)
        assert res.status_code == 409

    def test_invalid_status_filter(self, client, admin_user_and_token):
        res = client.get(
            "/api/alerts?status=INVALID",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 400


class TestAuditService:

    def test_log_event_creates_record(self, db):
        entry = log_event(
            db,
            AuditEventType.FILE_REGISTERED,
            details="Test registration event",
        )
        assert entry.id is not None
        assert entry.event_type == AuditEventType.FILE_REGISTERED
        assert entry.details == "Test registration event"

    def test_log_event_with_hashes(self, db):
        old_h = "a" * 64
        new_h = "b" * 64
        entry = log_event(
            db,
            AuditEventType.UNAUTHORIZED_MODIFICATION,
            old_hash=old_h,
            new_hash=new_h,
            details="Tampering detected",
        )
        assert entry.old_hash == old_h
        assert entry.new_hash == new_h

    def test_log_event_captures_os_user(self, db):
        entry = log_event(
            db,
            AuditEventType.AUTH_SUCCESS,
            include_os_user=True,
        )
        assert entry.os_user is not None

    def test_log_event_os_user_optional(self, db):
        entry = log_event(
            db,
            AuditEventType.AUTH_SUCCESS,
            include_os_user=False,
        )
        assert entry.os_user is None


class TestAuditAPI:

    def test_audit_list_requires_auth(self, client):
        res = client.get("/api/audit")
        assert res.status_code == 401

    def test_audit_list_returns_list(self, client, admin_user_and_token):
        res = client.get(
            "/api/audit",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_audit_for_file(self, client, admin_user_and_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        ).json()

        res = client.get(
            f"/api/audit/{reg['id']}",
            headers={"Authorization": f"Bearer {admin_user_and_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert len(data) >= 1
        # The registration event should be in the log
        event_types = [e["event_type"] for e in data]
        assert "FILE_REGISTERED" in event_types
