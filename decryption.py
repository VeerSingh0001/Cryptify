import base64
import json
import os
import struct
import tempfile

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from CompressorDecompressor import CompressorDecompressor
from key_manager import derive_key_argon2
from utils import _to_bytearray, secure_erase, derive_aes_key


class MLKEMDecryptor:
    def __init__(self, kem_algorithm: str = "Kyber768"):
        self.kem_algorithm = kem_algorithm
        self.compobj = CompressorDecompressor()
        self.CHUNK_SIZE = 256 * 1024  # 256 KB per chunk
        self.WRITE_SIZE = 4 * 1024 * 1024  # 4 MB per chunk

    def decrypt_package(self, package: dict, infile, outfile, secret_key: bytes) -> bytes:
        print("Decrypting package...")

        # Step 1: Read metadata start position to know where encrypted data ends
        with open(infile, 'rb') as f:
            f.seek(-8, 2)  # Seek 8 bytes from end
            metadata_start_position = struct.unpack(">Q", f.read(8))[0]

        # Step 2: Validate required fields in package
        required_fields = ['ciphertext', 'nonce', 'salt']
        missing_fields = [field for field in required_fields if field not in package]
        if missing_fields:
            raise ValueError(f"Missing required fields in package: {', '.join(missing_fields)}")

        # Decode base64-encoded fields from package
        try:
            ciphertext = base64.b64decode(package['ciphertext'])
            nonce_prefix = base64.b64decode(package['nonce'])
            salt = base64.b64decode(package['salt'])
        except Exception as e:
            raise ValueError(f"Failed to decode base64 data: {str(e)}")

        # Step 3: Perform KEM decapsulation to recover the shared secret
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

        # Step 4: Create temp file for decrypted data

        temp_fd, temp_filepath = tempfile.mkstemp(dir='/var/tmp', suffix='.dec')

        try:
            aesgcm = AESGCM(aes_key)

            with (open(infile, 'rb') as fin):
                # Read nonce prefix (12 bytes)
                stored_nonce_prefix = fin.read(12)
                if len(stored_nonce_prefix) < 12:
                    raise ValueError("Invalid encrypted data: too short for nonce prefix")

                # Verify nonce prefix matches
                if stored_nonce_prefix != nonce_prefix:
                    raise ValueError("Nonce prefix mismatch")

                # Read chunk size (4 bytes)
                chunk_size_bytes = fin.read(4)
                if len(chunk_size_bytes) < 4:
                    raise ValueError("Invalid encrypted data: missing chunk size")

                # Decrypt all chunks and write to temp file
                chunk_index = 0
                unencrypted_chunk_buffer = bytearray()
                with os.fdopen(temp_fd, 'wb') as temp_file:
                    while fin.tell() < metadata_start_position:
                        # Read encrypted chunk length (4 bytes)
                        len_bytes = fin.read(4)
                        if not len_bytes or len(len_bytes) < 4:
                            break

                        encrypted_chunk_len = struct.unpack(">I", len_bytes)[0]

                        # Check if reading would go beyond the metadata section
                        if fin.tell() + encrypted_chunk_len > metadata_start_position:
                            break

                        # Read encrypted chunk
                        encrypted_chunk = fin.read(encrypted_chunk_len)
                        if len(encrypted_chunk) < encrypted_chunk_len:
                            raise ValueError(f"Invalid encrypted data: incomplete chunk at index {chunk_index}")

                        # Reconstruct nonce for this chunk
                        nonce = nonce_prefix + struct.pack(">I", chunk_index)

                        # Decrypt chunk
                        try:
                            decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, associated_data=None)
                            unencrypted_chunk_buffer.extend(decrypted_chunk)
                            chunk_index += 1
                            if len(unencrypted_chunk_buffer) >= self.WRITE_SIZE:
                                temp_file.write(unencrypted_chunk_buffer)
                                unencrypted_chunk_buffer.clear()

                        except Exception as e:
                            raise ValueError(f"Failed to decrypt chunk {chunk_index}: {str(e)}")

                        finally:
                            if unencrypted_chunk_buffer:
                                temp_file.write(unencrypted_chunk_buffer)

                        unencrypted_chunk_buffer.clear()

            print(f"Decrypted data stored temporarily at: {temp_filepath}")

            # Step 5: Decompress the decrypted data from temp file
            try:
                decompressed_plaintext = self.compobj.decompress_data(temp_filepath, outfile)
                return decompressed_plaintext
            except Exception as e:
                raise ValueError(f"Decompression failed: {str(e)}")

        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"AES-GCM decryption failed: {str(e)}")

        finally:
            secure_erase(_to_bytearray(aes_key))
            # Clean up temp file after decompression
            if os.path.exists(temp_filepath):
                os.unlink(temp_filepath)
                print(f"Temporary file cleaned up: {temp_filepath}")

    @staticmethod
    def decrypt_file(infile, key):
        """Decryption of file"""
        print("Decrypting file...")

        with open(infile, "rb") as fin:
            # Step 1: Read metadata start position from the last 8 bytes
            fin.seek(-8, 2)  # Seek to 8 bytes before end of file
            metadata_start_position = struct.unpack(">Q", fin.read(8))[0]

            # Step 2: Seek to metadata section
            fin.seek(metadata_start_position)

            # Step 3: Verify metadata marker
            marker = fin.read(4)
            if marker != b"META":
                raise ValueError("Invalid file format: metadata marker not found")

            # Step 4: Read nonce prefix for metadata (12 bytes)
            nonce_prefix = fin.read(12)
            if len(nonce_prefix) != 12:
                raise ValueError("Invalid file format: missing nonce prefix in metadata")

            # Step 5: Read chunk size (4 bytes, big-endian unsigned int)
            chunk_size_bytes = fin.read(4)
            if len(chunk_size_bytes) != 4:
                raise ValueError("Invalid file format: missing chunk size in metadata")

            # Step 6: Derive the same AES key used for encryption
            key_bytes = base64.b64encode(key).decode("utf-8")
            aes_key = derive_key_argon2(key_bytes, nonce_prefix, 32)
            aesgcm = AESGCM(aes_key)

            # Step 7: Calculate the end of metadata section (exclude the last 8 bytes position marker)
            fin.seek(0, 2)  # Go to end of file
            end_position = fin.tell() - 8  # Subtract the 8-byte position marker

            # Step 8: Go back to start reading encrypted metadata chunks
            fin.seek(metadata_start_position + 4 + 12 + 4)  # After marker + nonce + chunk_size

            # Step 9: Decrypt all metadata chunks
            decrypted_data = bytearray()
            chunk_index = 0

            while fin.tell() < end_position:
                # Read the ciphertext length (4 bytes)
                cipher_len_bytes = fin.read(4)
                if len(cipher_len_bytes) == 0:
                    # End of metadata reached
                    break
                if len(cipher_len_bytes) != 4:
                    raise ValueError("Invalid file format: incomplete chunk length in metadata")

                cipher_len = struct.unpack(">I", cipher_len_bytes)[0]

                # Check if we would read beyond the end position
                if fin.tell() + cipher_len > end_position:
                    break

                # Read the ciphertext
                cipher_text = fin.read(cipher_len)
                if len(cipher_text) != cipher_len:
                    raise ValueError("Invalid file format: incomplete ciphertext chunk in metadata")

                # Reconstruct the nonce for this chunk
                nonce = nonce_prefix + struct.pack(">I", chunk_index)

                # Decrypt the chunk
                try:
                    plaintext = aesgcm.decrypt(nonce, cipher_text, associated_data=None)
                    decrypted_data.extend(plaintext)
                except Exception as e:
                    raise ValueError(f"Decryption failed at metadata chunk {chunk_index}: {str(e)}")

                chunk_index += 1

            # Step 10: Convert decrypted bytes back to dictionary
            try:
                data_str = decrypted_data.decode('utf-8')
                data_dict = json.loads(data_str)
                print("Metadata successfully decrypted and parsed")
                return data_dict
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse decrypted metadata as JSON: {str(e)}")
            except UnicodeDecodeError as e:
                raise ValueError(f"Failed to decode decrypted metadata as UTF-8: {str(e)}")
