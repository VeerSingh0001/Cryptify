import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64

class AESFileEncryptor:
    def __init__(self):
        self.key_size = 32  # 256 bits = 32 bytes
        
    def generate_key(self):
        """Generate a random 256-bit AES key"""
        key = AESGCM.generate_key(bit_length=256)
        return key
    
    def save_key(self, key, filename="encryption_key.key"):
        """Save the encryption key to a file"""
        try:
            with open(filename, 'wb') as key_file:
                key_file.write(key)
            print(f"✓ Key saved to: {filename}")
            print(f"  IMPORTANT: Keep this key file safe! You'll need it for decryption.")
        except Exception as e:
            print(f"✗ Error saving key: {e}")
    
    def load_key(self, filename="encryption_key.key"):
        """Load encryption key from a file"""
        try:
            with open(filename, 'rb') as key_file:
                key = key_file.read()
            if len(key) != 32:
                raise ValueError("Invalid key size. Expected 32 bytes for AES-256.")
            print(f"✓ Key loaded from: {filename}")
            return key
        except FileNotFoundError:
            print(f"✗ Key file not found: {filename}")
            return None
        except Exception as e:
            print(f"✗ Error loading key: {e}")
            return None
    
    def encrypt_file(self, input_file, output_file, key):
        """Encrypt a file using AES-GCM"""
        try:
            # Read the file content
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            print(f"\n📄 File to encrypt: {input_file}")
            print(f"   Size: {len(plaintext)} bytes")
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Generate a random 96-bit nonce (12 bytes)
            nonce = os.urandom(12)
            
            # Encrypt the data (this also generates the authentication tag)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Save nonce + ciphertext to output file
            # Format: [12 bytes nonce][encrypted data with tag]
            with open(output_file, 'wb') as f:
                f.write(nonce + ciphertext)
            
            print(f"\n✓ Encryption successful!")
            print(f"   Encrypted file: {output_file}")
            print(f"   Encrypted size: {len(nonce + ciphertext)} bytes")
            print(f"   Nonce (hex): {nonce.hex()}")
            
            return True
            
        except FileNotFoundError:
            print(f"\n✗ Error: File not found - {input_file}")
            return False
        except Exception as e:
            print(f"\n✗ Encryption failed: {e}")
            return False