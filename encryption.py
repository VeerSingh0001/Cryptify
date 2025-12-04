import base64
import json
import os
import secrets
import struct
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
        self.CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB per chunk

    def encrypt_data_for_recipient(self, infile, outfile, recipient_public_key: bytes) -> dict:
        """Encapsulate to recipient public key and encrypt plaintext with AESGCM."""
        salt = secrets.token_bytes(32)
        nonce_prefix = secrets.token_bytes(12)

        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_public_key)

        try:
            aes_key = derive_aes_key(shared_secret, salt)
        finally:
            secure_erase(_to_bytearray(shared_secret))

        # Compress file and get temp file path
        compressed_temp_file = self.compobj.compress_file(infile)

        try:
            aesgcm = AESGCM(aes_key)
            print("Encrypting data...")

            with open(outfile, 'wb') as fout:
                fout.write(nonce_prefix)
                fout.write(struct.pack(">I", self.CHUNK_SIZE))

                chunk_index = 0

                # Read from compressed temp file
                with open(compressed_temp_file, 'rb') as fin:
                    while True:
                        chunk = fin.read(self.CHUNK_SIZE)
                        if not chunk:
                            break  # End of file

                        nonce = nonce_prefix + struct.pack(">I", chunk_index)
                        encrypted_chunk = aesgcm.encrypt(nonce, chunk, associated_data=None)

                        fout.write(struct.pack(">I", len(encrypted_chunk)))
                        fout.write(encrypted_chunk)

                        chunk_index += 1

        finally:
            secure_erase(_to_bytearray(aes_key))
            # Clean up compressed temp file
            if os.path.exists(compressed_temp_file):
                os.unlink(compressed_temp_file)
                print(f"Compressed temp file cleaned up: {compressed_temp_file}")

        pkg = {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce_prefix).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "algorithm": self.kem_algorithm,
            "timestamp": datetime.utcnow().isoformat()
        }
        return pkg

    # Convenience function: same as encrypt_data_for_recipient but name kept for semantics
    def encrypt_data_for_self(self, plaintext, outfile,own_public_key: bytes) -> dict:
        return self.encrypt_data_for_recipient(plaintext, outfile,own_public_key)

    def reencrypt_data(self, data: dict, key: bytes, outfile: str):
        """Re-encrypt data using symmetric key encryption (AESGCM)."""
        print("Re-encrypting data... ")
        nonce_prefix = secrets.token_bytes(12)
        key_bytes = base64.b64encode(key).decode("utf-8")
        aes_key = derive_key_argon2(key_bytes, nonce_prefix, 32)
        aesgcm = AESGCM(aes_key)
        data_bytes = json.dumps(data).encode('utf-8')

        # Track where the metadata section starts
        with open(outfile, "rb") as f:
            f.seek(0, 2)  # Seek to end
            metadata_start_position = f.tell()

        with open(outfile, "ab") as fout:
            # Write a marker to indicate metadata section starts here
            fout.write(b"META")  # 4-byte marker

            # Write the nonce_prefix used for metadata encryption
            fout.write(nonce_prefix)

            # Write chunk size for metadata
            fout.write(struct.pack(">I", self.CHUNK_SIZE))

            chunk_index = 0
            offset = 0
            data_len = len(data_bytes)

            while offset < data_len:
                chunk = data_bytes[offset:offset + self.CHUNK_SIZE]
                nonce = nonce_prefix + struct.pack(">I", chunk_index)
                cipher_text = aesgcm.encrypt(nonce, chunk, associated_data=None)

                fout.write(struct.pack(">I", len(cipher_text)))
                fout.write(cipher_text)
                chunk_index += 1
                offset += self.CHUNK_SIZE

            # Write metadata start position at the very end (8 bytes for large files)
            fout.write(struct.pack(">Q", metadata_start_position))
