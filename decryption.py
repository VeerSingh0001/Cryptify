from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESFileDecryptor:
    def decrypt_file(self, input_file, output_file, key):
        """Decrypt a file using AES-GCM"""
        try:
            # Read the encrypted file content
            with open(input_file, 'rb') as f:
                data = f.read()
            
            print(f"\n📄 File to decrypt: {input_file}")
            print(f"   Size: {len(data)} bytes")
            
            # Extract nonce and ciphertext
            nonce = data[:12]  # First 12 bytes are the nonce
            ciphertext = data[12:]  # The rest is the ciphertext
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Decrypt the data
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Save decrypted data to output file
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
            print(f"✓ Decryption successful! Decrypted file saved to: {output_file}")
        except Exception as e:
            print(f"✗ Decryption failed: {e}")