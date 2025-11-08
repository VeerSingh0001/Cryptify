#!/usr/bin/env python3
"""
encryption.py
Encrypt helpers using ML-KEM (liboqs) and AES-GCM with HKDF key derivation.

Exports:
- MLKEMCrypto.encrypt_data_for_recipient(public_key_bytes, plaintext_bytes) -> dict
- MLKEMCrypto.encrypt_data_for_self(public_key_bytes, plaintext_bytes) -> dict
"""

import oqs
import base64
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# secure helpers
def _to_bytearray(b):
    return bytearray(b) if b is not None else bytearray()

def secure_erase(barr):
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

class MLKEMCrypto:
    def __init__(self, kem_algorithm: str = "Kyber768"):
        self.kem_algorithm = kem_algorithm

    def _derive_aes_key(self, shared_secret: bytes, salt: bytes) -> bytes:
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'mlkem-aes-gcm-v1'
        ).derive(shared_secret)
        return aes_key

    def encrypt_data_for_recipient(self, plaintext: bytes, recipient_public_key: bytes) -> dict:
        """Encapsulate to recipient public key and encrypt plaintext with AESGCM."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_public_key)

        try:
            aes_key = self._derive_aes_key(shared_secret, salt)
        finally:
            secure_erase(_to_bytearray(shared_secret))

        try:
            aesgcm = AESGCM(aes_key)
            encrypted = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        finally:
            secure_erase(_to_bytearray(aes_key))

        pkg = {
            "encrypted_data": base64.b64encode(encrypted).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "algorithm": self.kem_algorithm,
            "timestamp": datetime.utcnow().isoformat()
        }
        return pkg

    # Convenience function: same as encrypt_data_for_recipient but name kept for semantics
    def encrypt_data_for_self(self, plaintext: bytes, own_public_key: bytes) -> dict:
        return self.encrypt_data_for_recipient(plaintext, own_public_key)
