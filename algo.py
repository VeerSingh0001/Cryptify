#!/usr/bin/env python3
"""
ML-KEM Encryption Tool - Dual Mode Version
Supports both self-encryption and recipient encryption.

Modes:
1. Self-Encryption: Encrypt your own files (you decrypt later)
2. Recipient Encryption: Encrypt for someone else (they decrypt)

Features:
- Generate and manage your own keypair
- Export public key to share with others
- Import others' public keys
- Encrypt files for yourself or others
- Decrypt files sent to you
"""

import oqs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import secrets
import base64
import getpass
import sys
import logging
from pathlib import Path
from datetime import datetime
import shutil

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mlkem_tool.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class MLKEMCrypto:
    """Core cryptographic operations using ML-KEM."""

    def __init__(self, kem_algorithm="Kyber768"):
        self.kem_algorithm = kem_algorithm

    def generate_keypair(self):
        """Generate ML-KEM keypair."""
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key

    def encrypt_data(self, data, public_key):
        """Encrypt data using recipient's public key."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        salt = secrets.token_bytes(32)

        # Encapsulate using RECIPIENT'S public key
        with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)

        aes_key = self._derive_key(shared_secret, salt)
        nonce = secrets.token_bytes(12)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'algorithm': self.kem_algorithm,
            'timestamp': datetime.utcnow().isoformat()
        }

    def decrypt_data(self, encrypted_package, secret_key):
        """Decrypt data using your secret key."""
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
        ciphertext = base64.b64decode(encrypted_package['ciphertext'])
        nonce = base64.b64decode(encrypted_package['nonce'])
        tag = base64.b64decode(encrypted_package['tag'])
        salt = base64.b64decode(encrypted_package['salt'])

        # Decapsulate using YOUR secret key
        with oqs.KeyEncapsulation(self.kem_algorithm, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        aes_key = self._derive_key(shared_secret, salt)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return decrypted_data

    def _derive_key(self, shared_secret, salt):
        """Derive AES key using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'mlkem-aes-gcm-v1',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)


class KeyManager:
    """Manage keys and public key registry."""

    def __init__(self, storage_path="~/.mlkem_keys"):
        self.storage_path = Path(storage_path).expanduser()
        self.storage_path.mkdir(exist_ok=True, mode=0o700)

        # Directory for public keys received from others
        self.pubkey_dir = self.storage_path / "public_keys"
        self.pubkey_dir.mkdir(exist_ok=True, mode=0o700)

    def save_keypair(self, public_key, secret_key, key_id, password):
        """Save encrypted keypair."""
        salt = secrets.token_bytes(32)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        encryption_key = kdf.derive(password.encode('utf-8'))

        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_secret = encryptor.update(secret_key) + encryptor.finalize()

        key_data = {
            'version': '1.0',
            'key_type': 'keypair',
            'created': datetime.utcnow().isoformat(),
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'encrypted_secret_key': base64.b64encode(encrypted_secret).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }

        key_file = self.storage_path / f"{key_id}.json"
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)

        key_file.chmod(0o600)
        return str(key_file)

    def load_keypair(self, key_id, password):
        """Load and decrypt keypair."""
        key_file = self.storage_path / f"{key_id}.json"

        if not key_file.exists():
            raise FileNotFoundError(f"Key '{key_id}' not found")

        with open(key_file, 'r') as f:
            key_data = json.load(f)

        public_key = base64.b64decode(key_data['public_key'])
        encrypted_secret = base64.b64decode(key_data['encrypted_secret_key'])
        salt = base64.b64decode(key_data['salt'])
        nonce = base64.b64decode(key_data['nonce'])
        tag = base64.b64decode(key_data['tag'])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        decryption_key = kdf.derive(password.encode('utf-8'))

        cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        secret_key = decryptor.update(encrypted_secret) + decryptor.finalize()

        return public_key, secret_key

    def export_public_key(self, key_id, password, output_file):
        """Export public key to share with others."""
        public_key, _ = self.load_keypair(key_id, password)

        export_data = {
            'version': '1.0',
            'key_type': 'public_only',
            'key_id': key_id,
            'exported': datetime.utcnow().isoformat(),
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'algorithm': 'Kyber768'
        }

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        return output_file

    def import_public_key(self, import_file, recipient_name):
        """Import someone else's public key."""
        with open(import_file, 'r') as f:
            key_data = json.load(f)

        if key_data.get('key_type') != 'public_only':
            raise ValueError("Invalid public key file")

        # Save to public keys directory
        pubkey_file = self.pubkey_dir / f"{recipient_name}.json"
        shutil.copy(import_file, pubkey_file)
        pubkey_file.chmod(0o644)

        return str(pubkey_file)

    def get_public_key(self, recipient_name):
        """Get imported public key by recipient name."""
        pubkey_file = self.pubkey_dir / f"{recipient_name}.json"

        if not pubkey_file.exists():
            raise FileNotFoundError(f"Public key for '{recipient_name}' not found")

        with open(pubkey_file, 'r') as f:
            key_data = json.load(f)

        return base64.b64decode(key_data['public_key'])

    def list_keys(self):
        """List all stored keypairs."""
        keys = []
        for key_file in self.storage_path.glob("*.json"):
            try:
                with open(key_file, 'r') as f:
                    key_data = json.load(f)
                if key_data.get('key_type') == 'keypair':
                    keys.append({
                        'id': key_file.stem,
                        'created': key_data.get('created', 'Unknown'),
                        'version': key_data.get('version', 'Unknown')
                    })
            except:
                pass
        return keys

    def list_public_keys(self):
        """List all imported public keys."""
        keys = []
        for key_file in self.pubkey_dir.glob("*.json"):
            try:
                with open(key_file, 'r') as f:
                    key_data = json.load(f)
                keys.append({
                    'recipient': key_file.stem,
                    'key_id': key_data.get('key_id', 'Unknown'),
                    'imported': key_data.get('exported', 'Unknown')
                })
            except:
                pass
        return keys


class InteractiveMLKEMTool:
    """Interactive menu-driven ML-KEM encryption tool."""

    def __init__(self):
        self.crypto = MLKEMCrypto()
        self.key_manager = KeyManager()

    def clear_screen(self):
        """Clear terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def print_header(self):
        """Print application header."""
        print("\n" + "=" * 70)
        print("           ML-KEM ENCRYPTION TOOL v2.0")
        print("      Post-Quantum Secure File Encryption (Dual Mode)")
        print("=" * 70 + "\n")

    def print_menu(self):
        """Print main menu."""
        print("\n" + "-" * 70)
        print("MAIN MENU")
        print("-" * 70)
        print("YOUR KEYS:")
        print("  1. Generate New Keypair")
        print("  2. Export Public Key (to share with others)")
        print("  3. List Your Keys")
        print()
        print("RECIPIENT KEYS:")
        print("  4. Import Public Key (from someone else)")
        print("  5. List Recipient Public Keys")
        print()
        print("ENCRYPTION/DECRYPTION:")
        print("  6. Encrypt File (for yourself)")
        print("  7. Encrypt File (for recipient)")
        print("  8. Decrypt File")
        print()
        print("OTHER:")
        print("  9. Help")
        print("  10. Exit")
        print("-" * 70)

    def get_password(self, prompt="Enter password: "):
        """Get password from user (hidden input)."""
        return getpass.getpass(f"🔑 {prompt}")

    def get_password_with_confirmation(self):
        """Get password with confirmation."""
        while True:
            password = self.get_password("Enter new password: ")

            if len(password) < 8:
                print("❌ Password must be at least 8 characters!")
                input("Press Enter to try again...")
                continue

            confirm = self.get_password("Confirm password: ")

            if password != confirm:
                print("❌ Passwords don't match! Try again.")
                input("Press Enter to try again...")
                continue

            return password

    def format_size(self, size):
        """Format file size."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def generate_key(self):
        """Generate new keypair."""
        self.clear_screen()
        self.print_header()
        print("🔐 GENERATE NEW KEYPAIR\n")

        key_id = input("Enter Key ID (e.g., 'alice', 'work_key'): ").strip()

        if not key_id:
            print("❌ Key ID cannot be empty!")
            input("\nPress Enter to continue...")
            return

        existing_keys = [k['id'] for k in self.key_manager.list_keys()]
        if key_id in existing_keys:
            print(f"⚠️  Key '{key_id}' already exists!")
            overwrite = input("Do you want to overwrite it? (yes/no): ").strip().lower()
            if overwrite != 'yes':
                print("Operation cancelled.")
                input("\nPress Enter to continue...")
                return

        print("\n⏳ Generating keypair...")
        try:
            public_key, secret_key = self.crypto.generate_keypair()
            print("✓ Keypair generated successfully!")

            print("\n🔒 Set a password to protect your private key:")
            password = self.get_password_with_confirmation()

            print("\n💾 Saving encrypted keypair...")
            key_file = self.key_manager.save_keypair(public_key, secret_key, key_id, password)

            print("\n" + "=" * 70)
            print("✅ SUCCESS!")
            print("=" * 70)
            print(f"Key ID: {key_id}")
            print(f"Location: {key_file}")
            print("\n📝 NEXT STEPS:")
            print("1. Use option 2 to export your public key")
            print("2. Share the exported public key with anyone who wants to send you")
            print("   encrypted files")
            print("3. Keep your password safe - it protects your private key!")
            print("=" * 70)

            logger.info(f"Keypair generated: {key_id}")

        except Exception as e:
            print(f"\n❌ Error generating key: {e}")
            logger.error(f"Key generation failed: {e}")

        input("\nPress Enter to continue...")

    def export_public_key(self):
        """Export public key to share."""
        self.clear_screen()
        self.print_header()
        print("📤 EXPORT PUBLIC KEY\n")

        keys = self.key_manager.list_keys()
        if not keys:
            print("❌ No keys found! Generate a keypair first (option 1).")
            input("\nPress Enter to continue...")
            return

        print("Your keys:")
        for i, key in enumerate(keys, 1):
            print(f"  {i}. {key['id']}")

        key_id = input("\nEnter Key ID to export: ").strip()

        if key_id not in [k['id'] for k in keys]:
            print(f"❌ Key '{key_id}' not found!")
            input("\nPress Enter to continue...")
            return

        output_file = input("Enter output filename (e.g., my_public_key.json): ").strip()
        if not output_file:
            output_file = f"{key_id}_public.json"

        password = self.get_password()

        try:
            exported = self.key_manager.export_public_key(key_id, password, output_file)

            print("\n" + "=" * 70)
            print("✅ PUBLIC KEY EXPORTED!")
            print("=" * 70)
            print(f"File: {exported}")
            print("\n📝 SHARING INSTRUCTIONS:")
            print("1. Send this file to anyone who wants to encrypt files for you")
            print("2. They can use option 4 to import your public key")
            print("3. They can then encrypt files that ONLY YOU can decrypt")
            print("\n⚠️  This file contains ONLY your public key - it's safe to share!")
            print("=" * 70)

            logger.info(f"Public key exported: {key_id} -> {output_file}")

        except ValueError:
            print("\n❌ Wrong password!")
        except Exception as e:
            print(f"\n❌ Export failed: {e}")
            logger.error(f"Export failed: {e}")

        input("\nPress Enter to continue...")

    def import_public_key(self):
        """Import someone else's public key."""
        self.clear_screen()
        self.print_header()
        print("📥 IMPORT PUBLIC KEY\n")

        import_file = input("Enter public key file path: ").strip()

        if not Path(import_file).exists():
            print(f"❌ File not found: {import_file}")
            input("\nPress Enter to continue...")
            return

        recipient_name = input("Enter name for this recipient (e.g., 'bob', 'alice'): ").strip()

        if not recipient_name:
            print("❌ Recipient name cannot be empty!")
            input("\nPress Enter to continue...")
            return

        try:
            imported = self.key_manager.import_public_key(import_file, recipient_name)

            print("\n" + "=" * 70)
            print("✅ PUBLIC KEY IMPORTED!")
            print("=" * 70)
            print(f"Recipient: {recipient_name}")
            print(f"Stored at: {imported}")
            print("\n📝 NEXT STEPS:")
            print(f"Use option 7 to encrypt files for '{recipient_name}'")
            print(f"Only {recipient_name} will be able to decrypt them!")
            print("=" * 70)

            logger.info(f"Public key imported: {recipient_name}")

        except Exception as e:
            print(f"\n❌ Import failed: {e}")
            logger.error(f"Import failed: {e}")

        input("\nPress Enter to continue...")

    def list_keys(self):
        """List your keypairs."""
        self.clear_screen()
        self.print_header()
        print("🔑 YOUR KEYPAIRS\n")

        keys = self.key_manager.list_keys()

        if not keys:
            print("No keypairs found.")
            print("\nGenerate a new keypair using option 1 in the main menu.")
        else:
            print("=" * 70)
            for i, key in enumerate(keys, 1):
                print(f"\n{i}. Key ID: {key['id']}")
                print(f"   Created: {key['created']}")
                print(f"   Version: {key['version']}")
            print("\n" + "=" * 70)
            print(f"Total keypairs: {len(keys)}")

        input("\nPress Enter to continue...")

    def list_public_keys(self):
        """List imported public keys."""
        self.clear_screen()
        self.print_header()
        print("🔑 RECIPIENT PUBLIC KEYS\n")

        keys = self.key_manager.list_public_keys()

        if not keys:
            print("No recipient public keys found.")
            print("\nImport a public key using option 4 in the main menu.")
        else:
            print("=" * 70)
            for i, key in enumerate(keys, 1):
                print(f"\n{i}. Recipient: {key['recipient']}")
                print(f"   Original Key ID: {key['key_id']}")
                print(f"   Imported: {key['imported']}")
            print("\n" + "=" * 70)
            print(f"Total recipient keys: {len(keys)}")

        input("\nPress Enter to continue...")

    def encrypt_for_self(self):
        """Encrypt file for yourself."""
        self.clear_screen()
        self.print_header()
        print("🔒 ENCRYPT FILE (FOR YOURSELF)\n")

        keys = self.key_manager.list_keys()
        if not keys:
            print("❌ No keys found! Generate a keypair first (option 1).")
            input("\nPress Enter to continue...")
            return

        print("Your keys:")
        for i, key in enumerate(keys, 1):
            print(f"  {i}. {key['id']}")

        key_id = input("\nEnter Key ID: ").strip()

        if key_id not in [k['id'] for k in keys]:
            print(f"❌ Key '{key_id}' not found!")
            input("\nPress Enter to continue...")
            return

        input_file = input("Enter input file path: ").strip()

        if not Path(input_file).exists():
            print(f"❌ File not found: {input_file}")
            input("\nPress Enter to continue...")
            return

        output_file = input("Enter output file path (e.g., file.enc): ").strip()
        if not output_file:
            output_file = input_file + ".enc"

        password = self.get_password()

        try:
            print("\n⏳ Loading your public key...")
            public_key, _ = self.key_manager.load_keypair(key_id, password)

            print("📖 Reading file...")
            with open(input_file, 'rb') as f:
                data = f.read()

            file_size = len(data)
            print(f"📊 File size: {self.format_size(file_size)}")

            print("🔐 Encrypting...")
            encrypted_package = self.crypto.encrypt_data(data, public_key)
            encrypted_package['recipient'] = 'self'
            encrypted_package['for_key_id'] = key_id

            print("💾 Saving encrypted file...")
            with open(output_file, 'w') as f:
                json.dump(encrypted_package, f, indent=2)

            output_size = Path(output_file).stat().st_size

            print("\n" + "=" * 70)
            print("✅ ENCRYPTION SUCCESSFUL!")
            print("=" * 70)
            print(f"Output: {output_file}")
            print(f"Encrypted for: YOU (key: {key_id})")
            print(f"Original size: {self.format_size(file_size)}")
            print(f"Encrypted size: {self.format_size(output_size)}")
            print("\n📝 To decrypt: Use option 8 with your key and password")
            print("=" * 70)

            logger.info(f"File encrypted for self: {input_file} -> {output_file}")

        except ValueError:
            print("\n❌ Wrong password!")
        except Exception as e:
            print(f"\n❌ Encryption failed: {e}")
            logger.error(f"Encryption failed: {e}")

        input("\nPress Enter to continue...")

    def encrypt_for_recipient(self):
        """Encrypt file for someone else."""
        self.clear_screen()
        self.print_header()
        print("🔒 ENCRYPT FILE (FOR RECIPIENT)\n")

        recipients = self.key_manager.list_public_keys()
        if not recipients:
            print("❌ No recipient keys found! Import a public key first (option 4).")
            input("\nPress Enter to continue...")
            return

        print("Available recipients:")
        for i, rec in enumerate(recipients, 1):
            print(f"  {i}. {rec['recipient']}")

        recipient_name = input("\nEnter recipient name: ").strip()

        if recipient_name not in [r['recipient'] for r in recipients]:
            print(f"❌ Recipient '{recipient_name}' not found!")
            input("\nPress Enter to continue...")
            return

        input_file = input("Enter input file path: ").strip()

        if not Path(input_file).exists():
            print(f"❌ File not found: {input_file}")
            input("\nPress Enter to continue...")
            return

        output_file = input("Enter output file path (e.g., file.enc): ").strip()
        if not output_file:
            output_file = input_file + ".enc"

        try:
            print(f"\n⏳ Loading {recipient_name}'s public key...")
            public_key = self.key_manager.get_public_key(recipient_name)

            print("📖 Reading file...")
            with open(input_file, 'rb') as f:
                data = f.read()

            file_size = len(data)
            print(f"📊 File size: {self.format_size(file_size)}")

            print(f"🔐 Encrypting for {recipient_name}...")
            encrypted_package = self.crypto.encrypt_data(data, public_key)
            encrypted_package['recipient'] = recipient_name

            print("💾 Saving encrypted file...")
            with open(output_file, 'w') as f:
                json.dump(encrypted_package, f, indent=2)

            output_size = Path(output_file).stat().st_size

            print("\n" + "=" * 70)
            print("✅ ENCRYPTION SUCCESSFUL!")
            print("=" * 70)
            print(f"Output: {output_file}")
            print(f"Encrypted for: {recipient_name.upper()}")
            print(f"Original size: {self.format_size(file_size)}")
            print(f"Encrypted size: {self.format_size(output_size)}")
            print(f"\n📝 Send '{output_file}' to {recipient_name}")
            print(f"⚠️  ONLY {recipient_name} can decrypt this file!")
            print("=" * 70)

            logger.info(f"File encrypted for {recipient_name}: {input_file} -> {output_file}")

        except Exception as e:
            print(f"\n❌ Encryption failed: {e}")
            logger.error(f"Encryption failed: {e}")

        input("\nPress Enter to continue...")

    def decrypt_file(self):
        """Decrypt a file."""
        self.clear_screen()
        self.print_header()
        print("🔓 DECRYPT FILE\n")

        keys = self.key_manager.list_keys()
        if not keys:
            print("❌ No keys found! You need your keypair to decrypt.")
            input("\nPress Enter to continue...")
            return

        print("Your keys:")
        for i, key in enumerate(keys, 1):
            print(f"  {i}. {key['id']}")

        key_id = input("\nEnter Key ID: ").strip()

        if key_id not in [k['id'] for k in keys]:
            print(f"❌ Key '{key_id}' not found!")
            input("\nPress Enter to continue...")
            return

        input_file = input("Enter encrypted file path: ").strip()

        if not Path(input_file).exists():
            print(f"❌ File not found: {input_file}")
            input("\nPress Enter to continue...")
            return

        output_file = input("Enter output file path: ").strip()
        if not output_file:
            output_file = input_file.replace('.enc', '_decrypted')

        password = self.get_password()

        try:
            print("\n⏳ Loading your private key...")
            _, secret_key = self.key_manager.load_keypair(key_id, password)

            print("📖 Reading encrypted file...")
            with open(input_file, 'r') as f:
                encrypted_package = json.load(f)

            recipient = encrypted_package.get('recipient', 'Unknown')
            print(f"📝 File was encrypted for: {recipient}")

            print("🔓 Decrypting...")
            decrypted_data = self.crypto.decrypt_data(encrypted_package, secret_key)

            print("💾 Saving decrypted file...")
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            output_size = len(decrypted_data)

            print("\n" + "=" * 70)
            print("✅ DECRYPTION SUCCESSFUL!")
            print("=" * 70)
            print(f"Output: {output_file}")
            print(f"File size: {self.format_size(output_size)}")
            print("=" * 70)

            logger.info(f"File decrypted: {input_file} -> {output_file}")

        except ValueError:
            print("\n❌ Decryption failed!")
            print("Possible reasons:")
            print("  • Wrong password")
            print("  • File was encrypted for someone else")
            print("  • Corrupted file")
        except Exception as e:
            print(f"\n❌ Decryption failed: {e}")
            logger.error(f"Decryption failed: {e}")

        input("\nPress Enter to continue...")

    def show_help(self):
        """Show help information."""
        self.clear_screen()
        self.print_header()
        print("📖 HELP - ML-KEM ENCRYPTION TOOL\n")
        print("=" * 70)
        print("\n🔑 KEY MANAGEMENT:")
        print()
        print("1. GENERATE NEW KEYPAIR")
        print("   - Creates your public/private keypair")
        print("   - Public key: Share with others")
        print("   - Private key: Keep secret (password protected)")
        print()
        print("2. EXPORT PUBLIC KEY")
        print("   - Exports your public key to a file")
        print("   - Share this file with anyone who wants to send you")
        print("     encrypted files")
        print("   - Safe to share - contains only public key")
        print()
        print("3. LIST YOUR KEYS")
        print("   - Shows all your keypairs")
        print()
        print("4. IMPORT PUBLIC KEY")
        print("   - Import someone else's public key")
        print("   - Required before you can encrypt files for them")
        print()
        print("5. LIST RECIPIENT PUBLIC KEYS")
        print("   - Shows all imported public keys")
        print()
        print("\n🔒 ENCRYPTION:")
        print()
        print("6. ENCRYPT FILE (FOR YOURSELF)")
        print("   - Encrypts files with YOUR public key")
        print("   - Only YOU can decrypt (with your private key)")
        print("   - Use for: Backups, personal files, secure storage")
        print()
        print("7. ENCRYPT FILE (FOR RECIPIENT)")
        print("   - Encrypts files with RECIPIENT's public key")
        print("   - Only RECIPIENT can decrypt (with their private key)")
        print("   - Use for: Sending confidential files to others")
        print()
        print("8. DECRYPT FILE")
        print("   - Decrypts files encrypted with your public key")
        print("   - Requires your private key and password")
        print()
        print("\n📋 EXAMPLE WORKFLOW:")
        print()
        print("Scenario: Alice wants to send encrypted file to Bob")
        print()
        print("BOB'S STEPS:")
        print("  1. Generate keypair (option 1) → Key ID: 'bob'")
        print("  2. Export public key (option 2) → bob_public.json")
        print("  3. Send bob_public.json to Alice")
        print()
        print("ALICE'S STEPS:")
        print("  1. Import Bob's public key (option 4) → Recipient: 'bob'")
        print("  2. Encrypt file for Bob (option 7)")
        print("  3. Send encrypted file to Bob")
        print()
        print("BOB'S STEPS (to decrypt):")
        print("  1. Receive encrypted file from Alice")
        print("  2. Decrypt file (option 8) → Use key 'bob' and password")
        print()
        print("\n🔐 SECURITY NOTES:")
        print()
        print("  • Uses ML-KEM (Kyber768) - Post-quantum secure")
        print("  • Data encrypted with AES-256-GCM")
        print("  • Passwords never stored or logged")
        print("  • Keys stored encrypted in: ~/.mlkem_keys/")
        print("  • Public keys safe to share")
        print("  • NEVER share your private key or password!")
        print()
        print("\n🆘 TROUBLESHOOTING:")
        print()
        print("  Q: Can't decrypt file?")
        print("  A: Check if file was encrypted for YOU (not someone else)")
        print()
        print("  Q: Wrong password error?")
        print("  A: Verify you're using correct password for your key")
        print()
        print("  Q: How to send encrypted files?")
        print("  A: Use option 7 (encrypt for recipient), then send .enc file")
        print()
        print("  Q: Lost password?")
        print("  A: Unfortunately, cannot be recovered. Keep passwords safe!")
        print()
        print("=" * 70)

        input("\nPress Enter to continue...")

    def run(self):
        """Run the interactive application."""
        while True:
            self.clear_screen()
            self.print_header()
            self.print_menu()

            try:
                choice = input("\nSelect option (1-10): ").strip()

                if choice == '1':
                    self.generate_key()
                elif choice == '2':
                    self.export_public_key()
                elif choice == '3':
                    self.list_keys()
                elif choice == '4':
                    self.import_public_key()
                elif choice == '5':
                    self.list_public_keys()
                elif choice == '6':
                    self.encrypt_for_self()
                elif choice == '7':
                    self.encrypt_for_recipient()
                elif choice == '8':
                    self.decrypt_file()
                elif choice == '9':
                    self.show_help()
                elif choice == '10':
                    print("\n👋 Thank you for using ML-KEM Encryption Tool!")
                    print("Stay secure! 🔐\n")
                    break
                else:
                    print("❌ Invalid option! Please select 1-10.")
                    input("Press Enter to continue...")

            except KeyboardInterrupt:
                print("\n\n⚠️  Operation cancelled by user")
                confirm = input("Do you want to exit? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    print("\n👋 Goodbye!\n")
                    break
            except Exception as e:
                print(f"\n❌ Unexpected error: {e}")
                logger.error(f"Unexpected error: {e}")
                input("Press Enter to continue...")


def main():
    """Main entry point."""
    try:
        print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           ML-KEM ENCRYPTION TOOL v2.0                         ║
║           Post-Quantum Secure File Encryption                 ║
║                                                               ║
║           DUAL MODE OPERATION:                                ║
║           • Self-Encryption (encrypt for yourself)            ║
║           • Recipient Encryption (encrypt for others)         ║
║                                                               ║
║           Using ML-KEM (Kyber768) + AES-256-GCM              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """)

        # Check if oqs module is properly installed
        if not hasattr(oqs, 'KeyEncapsulation'):
            print("❌ ERROR: liboqs-python not properly installed!")
            print("\nPlease install from GitHub:")
            print("  pip install git+https://github.com/open-quantum-safe/liboqs-python.git")
            sys.exit(1)

        # Check available KEM algorithms
        try:
            available_kems = oqs.get_enabled_KEM_mechanisms()
            if 'Kyber768' not in available_kems and 'ML-KEM-768' not in available_kems:
                print("⚠️  WARNING: Kyber768/ML-KEM-768 not found!")
                print(f"Available KEMs: {available_kems[:5]}")
                print("\nThe tool may not work correctly.")
                input("Press Enter to continue anyway...")
        except:
            pass

        input("Press Enter to start...")

        app = InteractiveMLKEMTool()
        app.run()

    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()














# #!/usr/bin/env python3
# """
# ML-KEM Encryption Tool - Production Ready Interactive Version
# A secure interactive tool for encrypting and decrypting files using post-quantum cryptography.
#
# Features:
# - Interactive menu-driven interface
# - Secure password input (hidden)
# - File encryption/decryption
# - Key management
# - Progress indicators
# - Error handling
# - Logging
# """
#
# import oqs
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# import os
# import json
# import secrets
# import base64
# import getpass
# import sys
# import logging
# from pathlib import Path
# from datetime import datetime
#
# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler('mlkem_tool.log'),
#         logging.StreamHandler(sys.stdout)
#     ]
# )
# logger = logging.getLogger(__name__)
#
#
# class MLKEMCrypto:
#     """Core cryptographic operations using ML-KEM."""
#
#     def __init__(self, kem_algorithm="Kyber768"):
#         """Initialize with KEM algorithm (Kyber768 = ML-KEM-768)."""
#         self.kem_algorithm = kem_algorithm
#
#     def generate_keypair(self):
#         """Generate ML-KEM keypair."""
#         with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
#             public_key = kem.generate_keypair()
#             secret_key = kem.export_secret_key()
#             return public_key, secret_key
#
#     def encrypt_data(self, data, public_key):
#         """Encrypt data using ML-KEM + AES-GCM."""
#         if isinstance(data, str):
#             data = data.encode('utf-8')
#
#         salt = secrets.token_bytes(32)
#
#         with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
#             ciphertext, shared_secret = kem.encap_secret(public_key)
#
#         aes_key = self._derive_key(shared_secret, salt)
#         nonce = secrets.token_bytes(12)
#
#         cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
#         encryptor = cipher.encryptor()
#         encrypted_data = encryptor.update(data) + encryptor.finalize()
#
#         return {
#             'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
#             'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
#             'nonce': base64.b64encode(nonce).decode('utf-8'),
#             'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
#             'salt': base64.b64encode(salt).decode('utf-8'),
#             'algorithm': self.kem_algorithm,
#             'timestamp': datetime.utcnow().isoformat()
#         }
#
#     def decrypt_data(self, encrypted_package, secret_key):
#         """Decrypt data using ML-KEM + AES-GCM."""
#         encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
#         ciphertext = base64.b64decode(encrypted_package['ciphertext'])
#         nonce = base64.b64decode(encrypted_package['nonce'])
#         tag = base64.b64decode(encrypted_package['tag'])
#         salt = base64.b64decode(encrypted_package['salt'])
#
#         with oqs.KeyEncapsulation(self.kem_algorithm, secret_key=secret_key) as kem:
#             shared_secret = kem.decap_secret(ciphertext)
#
#         aes_key = self._derive_key(shared_secret, salt)
#
#         cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
#         decryptor = cipher.decryptor()
#         decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
#
#         return decrypted_data
#
#     def _derive_key(self, shared_secret, salt):
#         """Derive AES key using HKDF."""
#         hkdf = HKDF(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=salt,
#             info=b'mlkem-aes-gcm-v1',
#             backend=default_backend()
#         )
#         return hkdf.derive(shared_secret)
#
#
# class KeyManager:
#     """Secure key storage and management."""
#
#     def __init__(self, storage_path="~/.mlkem_keys"):
#         """Initialize key manager."""
#         self.storage_path = Path(storage_path).expanduser()
#         self.storage_path.mkdir(exist_ok=True, mode=0o700)
#
#     def save_keypair(self, public_key, secret_key, key_id, password):
#         """Save encrypted keypair."""
#         salt = secrets.token_bytes(32)
#
#         kdf = PBKDF2HMAC(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=salt,
#             iterations=600000,
#             backend=default_backend()
#         )
#         encryption_key = kdf.derive(password.encode('utf-8'))
#
#         nonce = secrets.token_bytes(12)
#         cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
#         encryptor = cipher.encryptor()
#         encrypted_secret = encryptor.update(secret_key) + encryptor.finalize()
#
#         key_data = {
#             'version': '1.0',
#             'created': datetime.utcnow().isoformat(),
#             'public_key': base64.b64encode(public_key).decode('utf-8'),
#             'encrypted_secret_key': base64.b64encode(encrypted_secret).decode('utf-8'),
#             'salt': base64.b64encode(salt).decode('utf-8'),
#             'nonce': base64.b64encode(nonce).decode('utf-8'),
#             'tag': base64.b64encode(encryptor.tag).decode('utf-8')
#         }
#
#         key_file = self.storage_path / f"{key_id}.json"
#         with open(key_file, 'w') as f:
#             json.dump(key_data, f, indent=2)
#
#         key_file.chmod(0o600)
#         return str(key_file)
#
#     def load_keypair(self, key_id, password):
#         """Load and decrypt keypair."""
#         key_file = self.storage_path / f"{key_id}.json"
#
#         if not key_file.exists():
#             raise FileNotFoundError(f"Key '{key_id}' not found")
#
#         with open(key_file, 'r') as f:
#             key_data = json.load(f)
#
#         public_key = base64.b64decode(key_data['public_key'])
#         encrypted_secret = base64.b64decode(key_data['encrypted_secret_key'])
#         salt = base64.b64decode(key_data['salt'])
#         nonce = base64.b64decode(key_data['nonce'])
#         tag = base64.b64decode(key_data['tag'])
#
#         kdf = PBKDF2HMAC(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=salt,
#             iterations=600000,
#             backend=default_backend()
#         )
#         decryption_key = kdf.derive(password.encode('utf-8'))
#
#         cipher = Cipher(algorithms.AES(decryption_key), modes.GCM(nonce, tag), backend=default_backend())
#         decryptor = cipher.decryptor()
#         secret_key = decryptor.update(encrypted_secret) + decryptor.finalize()
#
#         return public_key, secret_key
#
#     def list_keys(self):
#         """List all stored keys."""
#         keys = []
#         for key_file in self.storage_path.glob("*.json"):
#             try:
#                 with open(key_file, 'r') as f:
#                     key_data = json.load(f)
#                 keys.append({
#                     'id': key_file.stem,
#                     'created': key_data.get('created', 'Unknown'),
#                     'version': key_data.get('version', 'Unknown')
#                 })
#             except:
#                 pass
#         return keys
#
#
# class InteractiveMLKEMTool:
#     """Interactive menu-driven ML-KEM encryption tool."""
#
#     def __init__(self):
#         self.crypto = MLKEMCrypto()
#         self.key_manager = KeyManager()
#
#     def clear_screen(self):
#         """Clear terminal screen."""
#         os.system('clear' if os.name != 'nt' else 'cls')
#
#     def print_header(self):
#         """Print application header."""
#         print("\n" + "=" * 70)
#         print("           ML-KEM ENCRYPTION TOOL v1.0")
#         print("           Post-Quantum Secure File Encryption")
#         print("=" * 70 + "\n")
#
#     def print_menu(self):
#         """Print main menu."""
#         print("\n" + "-" * 70)
#         print("MAIN MENU")
#         print("-" * 70)
#         print("1. Generate New Key")
#         print("2. Encrypt File")
#         print("3. Decrypt File")
#         print("4. List All Keys")
#         print("5. Help")
#         print("6. Exit")
#         print("-" * 70)
#
#     def get_password(self, prompt="Enter password: "):
#         """Get password from user (hidden input)."""
#         return getpass.getpass(f"🔑 {prompt}")
#
#     def get_password_with_confirmation(self):
#         """Get password with confirmation."""
#         while True:
#             password = self.get_password("Enter new password: ")
#
#             if len(password) < 8:
#                 print("❌ Password must be at least 8 characters!")
#                 input("Press Enter to try again...")
#                 continue
#
#             confirm = self.get_password("Confirm password: ")
#
#             if password != confirm:
#                 print("❌ Passwords don't match! Try again.")
#                 input("Press Enter to try again...")
#                 continue
#
#             return password
#
#     def format_size(self, size):
#         """Format file size."""
#         for unit in ['B', 'KB', 'MB', 'GB']:
#             if size < 1024.0:
#                 return f"{size:.2f} {unit}"
#             size /= 1024.0
#         return f"{size:.2f} TB"
#
#     def generate_key(self):
#         """Generate new keypair."""
#         self.clear_screen()
#         self.print_header()
#         print("🔐 GENERATE NEW KEY\n")
#
#         key_id = input("Enter Key ID (e.g., 'mykey', 'work_docs'): ").strip()
#
#         if not key_id:
#             print("❌ Key ID cannot be empty!")
#             input("\nPress Enter to continue...")
#             return
#
#         # Check if key already exists
#         existing_keys = [k['id'] for k in self.key_manager.list_keys()]
#         if key_id in existing_keys:
#             print(f"⚠️  Key '{key_id}' already exists!")
#             overwrite = input("Do you want to overwrite it? (yes/no): ").strip().lower()
#             if overwrite != 'yes':
#                 print("Operation cancelled.")
#                 input("\nPress Enter to continue...")
#                 return
#
#         print("\n⏳ Generating keypair (this may take a moment)...")
#         try:
#             public_key, secret_key = self.crypto.generate_keypair()
#             print("✓ Keypair generated successfully!")
#
#             print("\n🔒 Set a password to protect your key:")
#             password = self.get_password_with_confirmation()
#
#             print("\n💾 Saving encrypted keypair...")
#             key_file = self.key_manager.save_keypair(public_key, secret_key, key_id, password)
#
#             print("\n" + "=" * 70)
#             print("✅ SUCCESS!")
#             print("=" * 70)
#             print(f"Key ID: {key_id}")
#             print(f"Location: {key_file}")
#             print("\n⚠️  IMPORTANT: Keep your password safe - it cannot be recovered!")
#             print("=" * 70)
#
#             logger.info(f"Key generated: {key_id}")
#
#         except Exception as e:
#             print(f"\n❌ Error generating key: {e}")
#             logger.error(f"Key generation failed: {e}")
#
#         input("\nPress Enter to continue...")
#
#     def encrypt_file(self):
#         """Encrypt a file."""
#         self.clear_screen()
#         self.print_header()
#         print("🔒 ENCRYPT FILE\n")
#
#         # List available keys
#         keys = self.key_manager.list_keys()
#         if not keys:
#             print("❌ No keys found! Please generate a key first.")
#             input("\nPress Enter to continue...")
#             return
#
#         print("Available keys:")
#         for i, key in enumerate(keys, 1):
#             print(f"  {i}. {key['id']}")
#
#         key_id = input("\nEnter Key ID: ").strip()
#
#         if key_id not in [k['id'] for k in keys]:
#             print(f"❌ Key '{key_id}' not found!")
#             input("\nPress Enter to continue...")
#             return
#
#         input_file = input("Enter input file path: ").strip()
#
#         if not Path(input_file).exists():
#             print(f"❌ File not found: {input_file}")
#             input("\nPress Enter to continue...")
#             return
#
#         output_file = input("Enter output file path (e.g., file.enc): ").strip()
#
#         if not output_file:
#             output_file = input_file + ".enc"
#             print(f"Using default output: {output_file}")
#
#         password = self.get_password()
#
#         try:
#             print("\n⏳ Loading keypair...")
#             public_key, _ = self.key_manager.load_keypair(key_id, password)
#
#             print("📖 Reading file...")
#             with open(input_file, 'rb') as f:
#                 data = f.read()
#
#             file_size = len(data)
#             print(f"📊 File size: {self.format_size(file_size)}")
#
#             print("🔐 Encrypting...")
#             encrypted_package = self.crypto.encrypt_data(data, public_key)
#
#             print("💾 Saving encrypted file...")
#             with open(output_file, 'w') as f:
#                 json.dump(encrypted_package, f, indent=2)
#
#             output_size = Path(output_file).stat().st_size
#
#             print("\n" + "=" * 70)
#             print("✅ ENCRYPTION SUCCESSFUL!")
#             print("=" * 70)
#             print(f"Output file: {output_file}")
#             print(f"Original size: {self.format_size(file_size)}")
#             print(f"Encrypted size: {self.format_size(output_size)}")
#             print(f"Overhead: {self.format_size(output_size - file_size)}")
#             print("=" * 70)
#
#             logger.info(f"File encrypted: {input_file} -> {output_file}")
#
#         except ValueError:
#             print("\n❌ Wrong password!")
#         except Exception as e:
#             print(f"\n❌ Encryption failed: {e}")
#             logger.error(f"Encryption failed: {e}")
#
#         input("\nPress Enter to continue...")
#
#     def decrypt_file(self):
#         """Decrypt a file."""
#         self.clear_screen()
#         self.print_header()
#         print("🔓 DECRYPT FILE\n")
#
#         # List available keys
#         keys = self.key_manager.list_keys()
#         if not keys:
#             print("❌ No keys found! Please generate a key first.")
#             input("\nPress Enter to continue...")
#             return
#
#         print("Available keys:")
#         for i, key in enumerate(keys, 1):
#             print(f"  {i}. {key['id']}")
#
#         key_id = input("\nEnter Key ID: ").strip()
#
#         if key_id not in [k['id'] for k in keys]:
#             print(f"❌ Key '{key_id}' not found!")
#             input("\nPress Enter to continue...")
#             return
#
#         input_file = input("Enter encrypted file path: ").strip()
#
#         if not Path(input_file).exists():
#             print(f"❌ File not found: {input_file}")
#             input("\nPress Enter to continue...")
#             return
#
#         output_file = input("Enter output file path: ").strip()
#
#         if not output_file:
#             output_file = input_file.replace('.enc', '_decrypted')
#             print(f"Using default output: {output_file}")
#
#         password = self.get_password()
#
#         try:
#             print("\n⏳ Loading keypair...")
#             _, secret_key = self.key_manager.load_keypair(key_id, password)
#
#             print("📖 Reading encrypted file...")
#             with open(input_file, 'r') as f:
#                 encrypted_package = json.load(f)
#
#             print("🔓 Decrypting...")
#             decrypted_data = self.crypto.decrypt_data(encrypted_package, secret_key)
#
#             print("💾 Saving decrypted file...")
#             with open(output_file, 'wb') as f:
#                 f.write(decrypted_data)
#
#             output_size = len(decrypted_data)
#
#             print("\n" + "=" * 70)
#             print("✅ DECRYPTION SUCCESSFUL!")
#             print("=" * 70)
#             print(f"Output file: {output_file}")
#             print(f"File size: {self.format_size(output_size)}")
#             print("=" * 70)
#
#             logger.info(f"File decrypted: {input_file} -> {output_file}")
#
#         except ValueError:
#             print("\n❌ Wrong password or corrupted file!")
#         except Exception as e:
#             print(f"\n❌ Decryption failed: {e}")
#             logger.error(f"Decryption failed: {e}")
#
#         input("\nPress Enter to continue...")
#
#     def list_keys(self):
#         """List all stored keys."""
#         self.clear_screen()
#         self.print_header()
#         print("🔑 STORED KEYS\n")
#
#         keys = self.key_manager.list_keys()
#
#         if not keys:
#             print("No keys found.")
#             print("\nGenerate a new key using option 1 in the main menu.")
#         else:
#             print("=" * 70)
#             for i, key in enumerate(keys, 1):
#                 print(f"\n{i}. Key ID: {key['id']}")
#                 print(f"   Created: {key['created']}")
#                 print(f"   Version: {key['version']}")
#             print("\n" + "=" * 70)
#             print(f"Total keys: {len(keys)}")
#
#         input("\nPress Enter to continue...")
#
#     def show_help(self):
#         """Show help information."""
#         self.clear_screen()
#         self.print_header()
#         print("📖 HELP\n")
#         print("=" * 70)
#         print("1. GENERATE NEW KEY")
#         print("   - Creates a new ML-KEM keypair")
#         print("   - Protected with your password")
#         print("   - Password must be at least 8 characters")
#         print()
#         print("2. ENCRYPT FILE")
#         print("   - Encrypts any file using post-quantum cryptography")
#         print("   - Requires a key ID and password")
#         print("   - Creates .enc file with encrypted content")
#         print()
#         print("3. DECRYPT FILE")
#         print("   - Decrypts files encrypted with this tool")
#         print("   - Requires correct key ID and password")
#         print("   - Restores original file")
#         print()
#         print("4. LIST ALL KEYS")
#         print("   - Shows all stored keys")
#         print("   - Displays creation date and version")
#         print()
#         print("SECURITY NOTES:")
#         print("   - Keys are stored in: ~/.mlkem_keys/")
#         print("   - All keys are encrypted with your password")
#         print("   - Passwords are never stored or logged")
#         print("   - Uses ML-KEM (Kyber768) post-quantum algorithm")
#         print("   - Data encrypted with AES-256-GCM")
#         print("=" * 70)
#
#         input("\nPress Enter to continue...")
#
#     def run(self):
#         """Run the interactive application."""
#         while True:
#             self.clear_screen()
#             self.print_header()
#             self.print_menu()
#
#             try:
#                 choice = input("\nSelect option (1-6): ").strip()
#
#                 if choice == '1':
#                     self.generate_key()
#                 elif choice == '2':
#                     self.encrypt_file()
#                 elif choice == '3':
#                     self.decrypt_file()
#                 elif choice == '4':
#                     self.list_keys()
#                 elif choice == '5':
#                     self.show_help()
#                 elif choice == '6':
#                     print("\n👋 Thank you for using ML-KEM Encryption Tool!")
#                     print("Stay secure! 🔐\n")
#                     break
#                 else:
#                     print("❌ Invalid option! Please select 1-6.")
#                     input("Press Enter to continue...")
#
#             except KeyboardInterrupt:
#                 print("\n\n⚠️  Operation cancelled by user")
#                 confirm = input("Do you want to exit? (yes/no): ").strip().lower()
#                 if confirm == 'yes':
#                     print("\n👋 Goodbye!\n")
#                     break
#             except Exception as e:
#                 print(f"\n❌ Unexpected error: {e}")
#                 logger.error(f"Unexpected error: {e}")
#                 input("Press Enter to continue...")
#
#
# def main():
#     """Main entry point."""
#     try:
#         print("""
# ╔═══════════════════════════════════════════════════════════════╗
# ║                                                               ║
# ║           ML-KEM ENCRYPTION TOOL v1.0                         ║
# ║           Post-Quantum Secure File Encryption                 ║
# ║                                                               ║
# ║           Using ML-KEM (Kyber768) + AES-256-GCM              ║
# ║                                                               ║
# ╚═══════════════════════════════════════════════════════════════╝
#         """)
#
#         # Check if oqs module is properly installed
#         if not hasattr(oqs, 'KeyEncapsulation'):
#             print("❌ ERROR: liboqs-python not properly installed!")
#             print("\nPlease install from GitHub:")
#             print("  pip install git+https://github.com/open-quantum-safe/liboqs-python.git")
#             sys.exit(1)
#
#         input("Press Enter to start...")
#
#         app = InteractiveMLKEMTool()
#         app.run()
#
#     except Exception as e:
#         print(f"\n❌ Fatal error: {e}")
#         sys.exit(1)
#
#
# if __name__ == "__main__":
#     main()