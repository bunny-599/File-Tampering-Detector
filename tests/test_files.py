"""
Tests for file registration, path traversal prevention, and integrity checks.
"""

import os
import stat
import hashlib
import tempfile
import pytest
from pathlib import Path

from app.services.hashing import calculate_sha256, verify_integrity
from app.models import ProtectedFile, FileStatus


class TestFileRegistrationAPI:

    def test_register_file_success(self, client, admin_token, tmp_file):
        res = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["filename"] == Path(tmp_file).name
        assert data["status"] == "PROTECTED"
        assert len(data["sha256_hash"]) == 64
        assert data["file_size"] > 0

    def test_register_same_file_twice_conflict(self, client, admin_token, tmp_file):
        client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        res = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 409

    def test_register_nonexistent_file(self, client, admin_token):
        res = client.post(
            "/api/files/register",
            json={"filepath": "/no/such/file/ever.txt"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 404

    def test_register_path_traversal_rejected(self, client, admin_token):
        res = client.post(
            "/api/files/register",
            json={"filepath": "../../etc/passwd"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code in (400, 404, 422)

    def test_register_requires_auth(self, client, tmp_file):
        res = client.post("/api/files/register", json={"filepath": tmp_file})
        assert res.status_code == 401

    def test_list_files_returns_registered(self, client, admin_token, tmp_file):
        client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        res = client.get(
            "/api/files",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        paths = [f["filepath"] for f in res.json()]
        assert str(Path(tmp_file).resolve()) in paths

    def test_get_file_by_id(self, client, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()
        res = client.get(
            f"/api/files/{reg['id']}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        assert res.json()["id"] == reg["id"]

    def test_get_nonexistent_file_returns_404(self, client, admin_token):
        res = client.get(
            "/api/files/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 404

    def test_delete_file_as_admin(self, client, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()
        res = client.delete(
            f"/api/files/{reg['id']}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 204

    def test_delete_file_as_user_forbidden(self, client, user_token, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()
        res = client.delete(
            f"/api/files/{reg['id']}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert res.status_code == 403

    def test_sha256_matches_manual_calculation(self, client, admin_token, tmp_file):
        reg = client.post(
            "/api/files/register",
            json={"filepath": tmp_file},
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()

        with open(tmp_file, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()

        assert reg["sha256_hash"] == expected


class TestIntegrityAfterModification:

    def test_unchanged_file_hash_still_matches(self, tmp_file):
        original_hash = calculate_sha256(tmp_file)
        # Read file without changing it
        with open(tmp_file, "r") as f:
            _ = f.read()
        assert calculate_sha256(tmp_file) == original_hash

    def test_modified_file_hash_changes(self, tmp_file):
        original_hash = calculate_sha256(tmp_file)

        # Temporarily make writable, modify, then restore
        current_mode = Path(tmp_file).stat().st_mode
        os.chmod(tmp_file, current_mode | stat.S_IWUSR)
        with open(tmp_file, "w") as f:
            f.write("This content was tampered with!")
        os.chmod(tmp_file, current_mode)

        new_hash = calculate_sha256(tmp_file)
        assert new_hash != original_hash

    def test_verify_integrity_detects_change(self, tmp_file):
        trusted = calculate_sha256(tmp_file)

        current_mode = Path(tmp_file).stat().st_mode
        os.chmod(tmp_file, current_mode | stat.S_IWUSR)
        with open(tmp_file, "w") as f:
            f.write("tampered")
        os.chmod(tmp_file, current_mode)

        assert verify_integrity(tmp_file, trusted) is False
