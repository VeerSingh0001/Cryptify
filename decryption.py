import base64
import json

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from CompressorDecompressor import CompressorDecompressor
from key_manager import derive_key_argon2


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
        self.compobj = CompressorDecompressor()

    def _derive_aes_key(self, shared_secret: bytes, salt: bytes) -> bytes:
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'mlkem-aes-gcm-v1'
        ).derive(shared_secret)
        return aes_key

    def decrypt_package(self, package: dict, secret_key: bytes) -> bytes:
        print("Decrypting package...")
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
            # print(plaintext)
            # decompressed_plaintext = self.compobj.decompress_data(plaintext)
            # print(decompressed_plaintext)
            return plaintext
        finally:
            secure_erase(_to_bytearray(aes_key))

    def decrypt_file(self, infile, key):
        """Decryption of file"""
        print("Decrypting file...")
        with open(infile, 'rb') as f:
            data = f.read()
        ciphertext = data[:5] + data[17:]
        nonce = data[5:17]
        key_bytes = base64.b64encode(key).decode("utf-8")
        aes_key = derive_key_argon2(key_bytes, nonce, 32)
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        # print(plaintext)
        pkg_bytes = self.compobj.decompress_data(plaintext)
        pkg = json.loads(pkg_bytes.decode('utf-8'))
        return pkg
