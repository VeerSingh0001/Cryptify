import base64
import json
import secrets
from datetime import datetime

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from CompressorDecompressor import CompressorDecompressor
from key_manager import derive_key_argon2
from utils import _to_bytearray, secure_erase, derive_aes_key


class MLKEMCrypto:
    def __init__(self, kem_algorithm: str = "Kyber768"):
        self.kem_algorithm = kem_algorithm
        self.compobj = CompressorDecompressor()

    def encrypt_data_for_recipient(self, infile, recipient_public_key: bytes) -> dict:
        """Encapsulate to recipient public key and encrypt plaintext with AESGCM."""
        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_public_key)

        try:
            aes_key = derive_aes_key(shared_secret, salt)
        finally:
            secure_erase(_to_bytearray(shared_secret))

        try:
            aesgcm = AESGCM(aes_key)
            compressed_plaintext = self.compobj.compress_file(infile)
            print("Encrypting data... ")
            encrypted = aesgcm.encrypt(nonce, compressed_plaintext, associated_data=None)
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

    def reencrypt_data(self, data: dict, key: bytes):
        """Re-encrypt data using symmetric key encryption (AESGCM)."""
        print("Re-encrypting data... ")
        nonce = secrets.token_bytes(12)
        key_bytes = base64.b64encode(key).decode("utf-8")
        aes_key = derive_key_argon2(key_bytes, nonce, 32)
        aesgcm = AESGCM(aes_key)
        data_bytes = json.dumps(data).encode('utf-8')
        # compressed_data_bytes = self.compobj.compress_data(data_bytes)
        cipher_text = aesgcm.encrypt(nonce, data_bytes, associated_data=None)
        enc_data = cipher_text[:5] + nonce + cipher_text[5:]
        return enc_data
