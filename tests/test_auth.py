"""
Tests for authentication: password hashing, JWT, and auth API endpoints.
"""

import pytest
from app.utils.security import (
    hash_password, verify_password,
    create_access_token, decode_access_token,
)
from datetime import timedelta
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError


# ── Password hashing ─────────────────────────────────────────────────────────

class TestPasswordHashing:

    def test_hash_is_not_plaintext(self):
        hashed = hash_password("MySecret@99")
        assert hashed != "MySecret@99"

    def test_correct_password_verifies(self):
        pw = "Correct@Horse99"
        assert verify_password(pw, hash_password(pw)) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("RightPass@1")
        assert verify_password("WrongPass@1", hashed) is False

    def test_same_password_different_hashes(self):
        # bcrypt salts ensure each hash is unique
        pw = "SamePassword@1"
        assert hash_password(pw) != hash_password(pw)

    def test_empty_password_hashes(self):
        hashed = hash_password("")
        assert verify_password("", hashed) is True

    def test_hash_length_is_reasonable(self):
        hashed = hash_password("test")
        assert len(hashed) > 30


# ── JWT tokens ────────────────────────────────────────────────────────────────

class TestJWT:

    def test_encode_decode_roundtrip(self):
        payload = {"sub": "alice", "role": "USER", "user_id": 1}
        token = create_access_token(payload)
        decoded = decode_access_token(token)
        assert decoded["sub"] == "alice"
        assert decoded["role"] == "USER"

    def test_expired_token_raises(self):
        token = create_access_token(
            {"sub": "alice"},
            expires_delta=timedelta(seconds=-1),
        )
        with pytest.raises(ExpiredSignatureError):
            decode_access_token(token)

    def test_tampered_token_raises(self):
        token = create_access_token({"sub": "alice"})
        tampered = token[:-4] + "xxxx"
        with pytest.raises(InvalidTokenError):
            decode_access_token(tampered)

    def test_completely_invalid_token_raises(self):
        with pytest.raises(InvalidTokenError):
            decode_access_token("not.a.jwt")


# ── Auth API endpoints ────────────────────────────────────────────────────────

class TestAuthAPI:

    def test_register_success(self, client):
        res = client.post("/api/auth/register", json={
            "username": "newuser",
            "password": "Password@1",
            "role": "USER",
        })
        assert res.status_code == 201
        data = res.json()
        assert data["username"] == "newuser"
        assert "password" not in data
        assert "password_hash" not in data

    def test_register_duplicate_username(self, client):
        body = {"username": "dup", "password": "Pass@1234", "role": "USER"}
        client.post("/api/auth/register", json=body)
        res = client.post("/api/auth/register", json=body)
        assert res.status_code == 409

    def test_register_short_username(self, client):
        res = client.post("/api/auth/register", json={
            "username": "ab",
            "password": "Pass@1234",
            "role": "USER",
        })
        assert res.status_code == 422

    def test_register_short_password(self, client):
        res = client.post("/api/auth/register", json={
            "username": "validuser",
            "password": "short",
            "role": "USER",
        })
        assert res.status_code == 422

    def test_login_success(self, client, admin_user):
        res = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "Admin@1234",
        })
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "admin"

    def test_login_wrong_password(self, client, admin_user):
        res = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "WrongPassword@1",
        })
        assert res.status_code == 401

    def test_login_nonexistent_user(self, client):
        res = client.post("/api/auth/login", json={
            "username": "ghost",
            "password": "Pass@1234",
        })
        assert res.status_code == 401

    def test_me_returns_current_user(self, client, admin_token):
        res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
        assert res.status_code == 200
        assert res.json()["username"] == "admin"

    def test_me_without_token_returns_401(self, client):
        res = client.get("/api/auth/me")
        assert res.status_code == 401

    def test_me_with_invalid_token_returns_401(self, client):
        res = client.get("/api/auth/me", headers={"Authorization": "Bearer bad.token.here"})
        assert res.status_code == 401

    def test_password_not_in_response(self, client):
        res = client.post("/api/auth/register", json={
            "username": "secure_user",
            "password": "MyPassword@99",
            "role": "USER",
        })
        body = res.text
        assert "MyPassword@99" not in body
        assert "password_hash" not in body
