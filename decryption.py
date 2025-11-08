import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs

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

class MLKEMDecryptor:
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

    def decrypt_package(self, package: dict, secret_key: bytes) -> bytes:
        enc = base64.b64decode(package['encrypted_data'])
        ciphertext = base64.b64decode(package['ciphertext'])
        nonce = base64.b64decode(package['nonce'])
        salt = base64.b64decode(package['salt'])

        with oqs.KeyEncapsulation(self.kem_algorithm, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        try:
            aes_key = self._derive_aes_key(shared_secret, salt)
        finally:
            secure_erase(_to_bytearray(shared_secret))

        try:
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, enc, associated_data=None)
            return plaintext
        finally:
            secure_erase(_to_bytearray(aes_key))
