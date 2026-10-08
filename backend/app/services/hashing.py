"""
SHA-256 file integrity hashing service.

Security principle: files are read in 64 KB chunks so that large files
never need to fit entirely in memory, preventing denial-of-service through
memory exhaustion.

The hash is the cryptographic baseline – any deviation from the stored
hash is evidence of a modification event.
"""

import hashlib
from pathlib import Path


CHUNK_SIZE = 65_536  # 64 KB


def calculate_sha256(filepath: str | Path) -> str:
    """
    Calculate the SHA-256 digest of a file.

    Reads the file in chunks to handle arbitrarily large files efficiently.

    Returns:
        Lowercase hexadecimal SHA-256 digest string (64 characters).

    Raises:
        FileNotFoundError – if the file does not exist at *filepath*.
        PermissionError   – if the process lacks read access.
        OSError           – for other I/O failures.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)

    return digest.hexdigest()


def verify_integrity(filepath: str | Path, trusted_hash: str) -> bool:
    """
    Compare the current SHA-256 of *filepath* against *trusted_hash*.

    Returns True  if the file is unchanged (hashes match).
    Returns False if the hashes differ (possible tampering).
    Raises  FileNotFoundError if the file is missing.
    """
    current = calculate_sha256(filepath)
    # Use constant-time comparison to avoid timing side-channels
    return _constant_time_compare(current, trusted_hash.lower())


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())
