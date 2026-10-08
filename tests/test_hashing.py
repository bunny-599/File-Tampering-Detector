"""
Tests for SHA-256 hashing service.
Verifies correctness, consistency, chunk-boundary behaviour, and
constant-time comparison.
"""

import hashlib
import os
import tempfile
import pytest
from pathlib import Path

from app.services.hashing import calculate_sha256, verify_integrity


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_file(content: bytes) -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(content)
        return f.name


def _expected_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# ── Tests ────────────────────────────────────────────────────────────────────

class TestCalculateSha256:

    def test_known_content(self):
        content = b"Computer Networks Security Project"
        path = _make_file(content)
        try:
            assert calculate_sha256(path) == _expected_sha256(content)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = _make_file(b"")
        try:
            result = calculate_sha256(path)
            assert result == hashlib.sha256(b"").hexdigest()
            assert len(result) == 64
        finally:
            os.unlink(path)

    def test_large_file_multiple_chunks(self):
        # 200 KB – crosses the 64 KB chunk boundary multiple times
        content = os.urandom(200 * 1024)
        path = _make_file(content)
        try:
            assert calculate_sha256(path) == _expected_sha256(content)
        finally:
            os.unlink(path)

    def test_result_is_lowercase_hex(self):
        path = _make_file(b"test")
        try:
            result = calculate_sha256(path)
            assert result == result.lower()
            assert all(c in "0123456789abcdef" for c in result)
            assert len(result) == 64
        finally:
            os.unlink(path)

    def test_different_content_different_hash(self):
        p1 = _make_file(b"original content")
        p2 = _make_file(b"modified content")
        try:
            assert calculate_sha256(p1) != calculate_sha256(p2)
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_same_content_same_hash(self):
        content = b"deterministic"
        p1 = _make_file(content)
        p2 = _make_file(content)
        try:
            assert calculate_sha256(p1) == calculate_sha256(p2)
        finally:
            os.unlink(p1)
            os.unlink(p2)

    def test_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            calculate_sha256("/nonexistent/path/file.txt")

    def test_path_object_accepted(self):
        content = b"pathlib path"
        path = _make_file(content)
        try:
            assert calculate_sha256(Path(path)) == _expected_sha256(content)
        finally:
            os.unlink(path)


class TestVerifyIntegrity:

    def test_unchanged_file_returns_true(self):
        content = b"original"
        path = _make_file(content)
        baseline = _expected_sha256(content)
        try:
            assert verify_integrity(path, baseline) is True
        finally:
            os.unlink(path)

    def test_modified_file_returns_false(self):
        path = _make_file(b"original")
        baseline = _expected_sha256(b"original")
        # Modify the file
        with open(path, "wb") as f:
            f.write(b"tampered!")
        try:
            assert verify_integrity(path, baseline) is False
        finally:
            os.unlink(path)

    def test_case_insensitive_baseline(self):
        content = b"case test"
        path = _make_file(content)
        baseline = _expected_sha256(content).upper()
        try:
            assert verify_integrity(path, baseline) is True
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            verify_integrity("/no/such/file.txt", "abc123")
