"""
Shared utilities for Cryptify encryption tool.
Consolidates common functions: secure memory handling, key derivation, etc.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _to_bytearray(b):
    """Convert bytes to bytearray, or return empty bytearray if None."""
    return bytearray(b) if b is not None else bytearray()


def secure_erase(barr):
    """
    Overwrite bytearray with zeros to protect sensitive data from memory recovery.
    Best-effort approach: converts bytes-like to bytearray and overwrites.
    """
    if barr is None:
        return
    if not isinstance(barr, (bytearray, memoryview)):
        try:
            barr = bytearray(barr)
        except Exception:
            return
    try:
        for i in range(len(barr)):
            barr[i] = 0
    except Exception:
        pass


def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    """
    Derive AES-256 key from shared secret using HKDF-SHA256.
    Used in ML-KEM encapsulation workflows.
    
    Args:
        shared_secret: The shared secret from KEM encapsulation
        salt: Random salt for key derivation
    
    Returns:
        32-byte AES-256 key
    """
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'mlkem-aes-gcm-v1'
    ).derive(shared_secret)
    return aes_key
