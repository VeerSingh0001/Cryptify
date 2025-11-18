import base64
import json

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from CompressorDecompressor import CompressorDecompressor
from key_manager import derive_key_argon2
from utils import _to_bytearray, secure_erase, derive_aes_key


class MLKEMDecryptor:
    def __init__(self, kem_algorithm: str = "Kyber768"):
        self.kem_algorithm = kem_algorithm
        self.compobj = CompressorDecompressor()

    def decrypt_package(self, package: dict, secret_key: bytes) -> bytes:
        print("Decrypting package...")
        enc = base64.b64decode(package['encrypted_data'])
        ciphertext = base64.b64decode(package['ciphertext'])
        nonce = base64.b64decode(package['nonce'])
        salt = base64.b64decode(package['salt'])

        with oqs.KeyEncapsulation(self.kem_algorithm, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        try:
            aes_key = derive_aes_key(shared_secret, salt)
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
