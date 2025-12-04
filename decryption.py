import base64
import json
import struct

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
        # Validate that all required fields are present
        required_fields = ['encrypted_data', 'ciphertext', 'nonce', 'salt']
        missing_fields = [field for field in required_fields if field not in package]
        if missing_fields:
            raise ValueError(f"Missing required fields in package: {', '.join(missing_fields)}")

        # Decode all base64-encoded fields
        try:
            encrypted_data = base64.b64decode(package['encrypted_data'])
            ciphertext = base64.b64decode(package['ciphertext'])
            nonce_prefix = base64.b64decode(package['nonce'])
            salt = base64.b64decode(package['salt'])
        except Exception as e:
            raise ValueError(f"Failed to decode base64 data: {str(e)}")

        # Perform KEM decapsulation to recover the shared secret
        try:
            kem_algorithm = package.get('algorithm', self.kem_algorithm)
            with oqs.KeyEncapsulation(kem_algorithm, secret_key=secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
        except Exception as e:
            raise ValueError(f"KEM decapsulation failed: {str(e)}")

        # Derive AES key from shared secret and salt
        try:
            aes_key = derive_aes_key(shared_secret, salt)
        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")
        finally:
            secure_erase(_to_bytearray(shared_secret))

        # Decrypt the chunked data using AES-GCM
        try:
            aesgcm = AESGCM(aes_key)

            # Parse the encrypted data
            offset = 0

            # Read nonce prefix (12 bytes)
            if len(encrypted_data) < 12:
                raise ValueError("Invalid encrypted data: too short for nonce prefix")
            stored_nonce_prefix = encrypted_data[offset:offset + 12]
            offset += 12

            # Verify nonce prefix matches
            if stored_nonce_prefix != nonce_prefix:
                raise ValueError("Nonce prefix mismatch")

            # Read chunk size (4 bytes)
            if len(encrypted_data) < offset + 4:
                raise ValueError("Invalid encrypted data: missing chunk size")
            offset += 4

            # Decrypt all chunks
            decrypted_data = bytearray()
            chunk_index = 0

            while offset < len(encrypted_data):
                # Read encrypted chunk length (4 bytes)
                if len(encrypted_data) < offset + 4:
                    raise ValueError(f"Invalid encrypted data: incomplete chunk length at offset {offset}")
                encrypted_chunk_len = struct.unpack(">I", encrypted_data[offset:offset + 4])[0]
                offset += 4

                # Read encrypted chunk
                if len(encrypted_data) < offset + encrypted_chunk_len:
                    raise ValueError(f"Invalid encrypted data: incomplete chunk at offset {offset}")
                encrypted_chunk = encrypted_data[offset:offset + encrypted_chunk_len]
                offset += encrypted_chunk_len

                # Reconstruct nonce for this chunk
                nonce = nonce_prefix + struct.pack(">I", chunk_index)

                # Decrypt chunk
                try:
                    decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, associated_data=None)
                    decrypted_data.extend(decrypted_chunk)
                except Exception as e:
                    raise ValueError(f"Failed to decrypt chunk {chunk_index}: {str(e)}")

                chunk_index += 1

            # Decompress the decrypted data
            try:
                decompressed_plaintext = self.compobj.decompress_data(bytes(decrypted_data))
                return decompressed_plaintext
            except Exception as e:
                raise ValueError(f"Decompression failed: {str(e)}")

        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"AES-GCM decryption failed: {str(e)}")
        finally:
            secure_erase(_to_bytearray(aes_key))

    def decrypt_file(self, infile, key):
        """Decryption of file"""
        print("Decrypting file...")

        with open(infile, "rb") as fin:
            # Read the nonce prefix (12 bytes)
            nonce_prefix = fin.read(12)
            if len(nonce_prefix) != 12:
                raise ValueError("Invalid file format: missing nonce prefix")

            # Read the chunk size (4 bytes, big-endian unsigned int)
            chunk_size_bytes = fin.read(4)
            if len(chunk_size_bytes) != 4:
                raise ValueError("Invalid file format: missing chunk size")
            chunk_size = struct.unpack(">I", chunk_size_bytes)[0]

            # Derive the same AES key used for encryption
            key_bytes = base64.b64encode(key).decode("utf-8")
            aes_key = derive_key_argon2(key_bytes, nonce_prefix, 32)
            aesgcm = AESGCM(aes_key)

            # Decrypt all chunks
            decrypted_data = bytearray()
            chunk_index = 0

            while True:
                # Read the ciphertext length (4 bytes)
                cipher_len_bytes = fin.read(4)
                if len(cipher_len_bytes) == 0:
                    # End of file reached
                    break
                if len(cipher_len_bytes) != 4:
                    raise ValueError("Invalid file format: incomplete chunk length")

                cipher_len = struct.unpack(">I", cipher_len_bytes)[0]

                # Read the ciphertext
                cipher_text = fin.read(cipher_len)
                if len(cipher_text) != cipher_len:
                    raise ValueError("Invalid file format: incomplete ciphertext chunk")

                # Reconstruct the nonce for this chunk
                nonce = nonce_prefix + struct.pack(">I", chunk_index)

                # Decrypt the chunk
                try:
                    plaintext = aesgcm.decrypt(nonce, cipher_text, associated_data=None)
                    decrypted_data.extend(plaintext)
                except Exception as e:
                    raise ValueError(f"Decryption failed at chunk {chunk_index}: {str(e)}")

                chunk_index += 1

            # Convert decrypted bytes back to dictionary
            try:
                data_str = decrypted_data.decode('utf-8')
                data_dict = json.loads(data_str)
                return data_dict
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse decrypted data as JSON: {str(e)}")
            except UnicodeDecodeError as e:
                raise ValueError(f"Failed to decode decrypted data as UTF-8: {str(e)}")
