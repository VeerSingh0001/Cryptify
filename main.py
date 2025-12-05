import gc
import getpass
import sys
from pathlib import Path

import oqs

from CompressorDecompressor import CompressorDecompressor
from decryption import MLKEMDecryptor
from encryption import MLKEMCrypto
from key_manager import KeyManager
from utils import _to_bytearray, secure_erase


class InteractiveApp:
    def __init__(self):
        self.km = KeyManager()
        self.crypto = MLKEMCrypto()
        self.decryptor = MLKEMDecryptor()
        self.compobj = CompressorDecompressor()

    @staticmethod
    def clear():
        import os
        os.system('clear' if os.name != 'nt' else 'cls')

    @staticmethod
    def pause():
        input("\nPress Enter to continue...")

    @staticmethod
    def print_header():
        print("\n" + "=" * 60)
        print("      ML-KEM ENCRYPTION TOOL - Secure Modular Version")
        print("=" * 60 + "\n")

    def menu(self):
        while True:
            self.clear()
            self.print_header()
            print("1) Generate new keypair")
            print("2) Export public key")
            print("3) Import public key (recipient)")
            print("4) List your keys")
            print("5) List imported recipient public keys")
            print("6) Encrypt file (for yourself)")
            print("7) Encrypt file (for recipient)")
            print("8) Decrypt file")
            print("9) Delete one of your keypairs")
            print("10) Delete a recipient public key")
            print("11) Exit")

            choice = input("\nChoice: ").strip()
            try:
                if choice == '1':
                    self.generate_key()
                elif choice == '2':
                    self.export_public_key()
                elif choice == '3':
                    self.import_public_key()
                elif choice == '4':
                    self.list_keys()
                elif choice == '5':
                    self.list_public_keys()
                elif choice == '6':
                    self.encrypt_for_self()
                elif choice == '7':
                    self.encrypt_for_recipient()
                elif choice == '8':
                    self.decrypt_file()
                elif choice == '9':
                    self.delete_my_key()
                elif choice == '10':
                    self.delete_recipient_key()
                elif choice == '11':
                    print("Goodbye.")
                    break
                else:
                    print("Invalid choice.")
                    self.pause()
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.")
                self.pause()
            except Exception as e:
                print("Error:", e)
                self.pause()

    def generate_key(self):
        kid = input("Enter Key ID: ").strip()
        if not kid:
            print("Key ID cannot be empty.")
            self.pause()
            return
        password = getpass.getpass("Set a password to protect your private key: ")
        if len(password) < 8:
            print("Password should be at least 8 characters.")
            self.pause()
            return

        print("Generating keypair (this may take a moment)...")
        with oqs.KeyEncapsulation("Kyber768") as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

        try:
            path = self.km.save_keypair(public_key, secret_key, kid, password)
            print(f"Keypair saved: {path}")
        finally:
            secure_erase(_to_bytearray(secret_key))

        self.pause()

    def export_public_key(self):
        kid = input("Enter Key ID to export: ").strip()
        out = input("Output filename (leave empty for <keyid>_public.json): ").strip()
        if not out:
            out = f"{kid}_public.json"
        pwd = getpass.getpass("Password: ")
        try:
            path = self.km.export_public_key(kid, pwd, out)
            print(f"Public key exported -> {path}")
        except Exception as e:
            print("Export failed:", e)
        self.pause()

    def import_public_key(self):
        file = input("Enter public key file path: ").strip()
        if not Path(file).exists():
            print("File does not exist.")
            self.pause()
            return
        name = input("Name for recipient (e.g., bob): ").strip()
        try:
            path = self.km.import_public_key(file, name)
            print(f"Imported for recipient '{name}' -> {path}")
        except Exception as e:
            print("Import failed:", e)
        self.pause()

    def list_keys(self):
        keys = self.km.list_keys()
        if not keys:
            print("No keys found.")
        else:
            for i, k in enumerate(keys, 1):
                print(f"{i}. ID: {k['id']}  Created: {k.get('created', 'Unknown')}")
        self.pause()

    def list_public_keys(self):
        keys = self.km.list_public_keys()
        if not keys:
            print("No recipient public keys found.")
        else:
            for i, k in enumerate(keys, 1):
                print(f"{i}. Recipient: {k['recipient']}  Imported: {k.get('exported', 'Unknown')}")
        self.pause()

    def encrypt_for_self(self):
        kid = input("Key ID to encrypt for (your key): ").strip()
        password = getpass.getpass("Password for key: ")
        infile = input("Input file path: ").strip()
        if not Path(infile).exists():
            print("Input file not found.")
            self.pause()
            return
        try:
            public_key, _ = self.km.load_keypair(kid, password)
        except Exception as e:
            print("Load keypair failed:", e)
            self.pause()
            return
        outfile = input("Output (default: <infile>.enc): ").strip()
        if not outfile:
            outfile = infile + ".enc"
        pkg = self.crypto.encrypt_data_for_self(infile, outfile,public_key)
        pkg['recipient'] = 'self'
        pkg['for_key_id'] = kid
        self.crypto.reencrypt_data(data=pkg, key=public_key, outfile=outfile)
        gc.collect()
        print("Encrypted file saved to:", outfile)
        self.pause()

    def encrypt_for_recipient(self):
        recipients = self.km.list_public_keys()
        if not recipients:
            print("No recipient keys imported. Import first.")
            self.pause()
            return
        print("Imported recipients:")
        for i, r in enumerate(recipients, 1):
            print(f"{i}. {r['recipient']}")
        name = input("Recipient name: ").strip()
        try:
            public_key = self.km.get_public_key(name)
        except Exception as e:
            print("Failed to load public key:", e)
            self.pause()
            return
        infile = input("Input file path: ").strip()
        if not Path(infile).exists():
            print("Input file not found.")
            self.pause()
            return
        outfile = input("Output (default: <infile>.enc): ").strip()
        if not outfile:
            outfile = infile + ".enc"
        pkg = self.crypto.encrypt_data_for_recipient(infile, public_key)
        pkg['recipient'] = name
        self.crypto.reencrypt_data(data=pkg, key=public_key, outfile=outfile)
        gc.collect()
        print("Encrypted for", name, "->", outfile)
        self.pause()

    def decrypt_file(self):
        infile = input("Encrypted file path: ").strip()
        if not Path(infile).exists():
            print("File not found.")
            self.pause()
            return
        kid = input("Your Key ID: ").strip()
        pwd = getpass.getpass("Password: ")
        try:
            public_key, secret_key = self.km.load_keypair(kid, pwd)
        except Exception as e:
            print("Load keypair failed:", e)
            self.pause()
            return
        outfile = input("Output filename (default: <infile>: ").strip()
        if not outfile:
            outfile = infile.replace(".enc", "")
        pkg = self.decryptor.decrypt_file(infile, public_key)
        try:
            self.decryptor.decrypt_package(pkg, infile,outfile,secret_key)
        finally:
            secure_erase(_to_bytearray(secret_key))
        print("Decrypted ->", outfile)
        self.pause()

    def delete_my_key(self):
        keys = self.km.list_keys()
        if not keys:
            print("No personal keys found.")
            self.pause()
            return

        print("\nYour keys:")
        for i, k in enumerate(keys, 1):
            print(f"{i}. ID: {k['id']} - Created: {k['created']}")

        kid = input("\nEnter Key ID to delete: ").strip()
        confirm = input(f"Are you sure you want to delete '{kid}'? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            self.pause()
            return

        if self.km.delete_keypair(kid):
            print(f"Key '{kid}' deleted successfully ✅")
        else:
            print("Key not found ❌")

        self.pause()

    def delete_recipient_key(self):
        keys = self.km.list_public_keys()
        if not keys:
            print("No recipient keys imported.")
            self.pause()
            return

        print("\nRecipient Keys:")
        for i, k in enumerate(keys, 1):
            print(f"{i}. {k['recipient']} - Imported: {k['exported']}")

        name = input("\nRecipient name to delete: ").strip()
        confirm = input(f"Delete recipient key '{name}'? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            self.pause()
            return

        if self.km.delete_public_key(name):
            print(f"Recipient key '{name}' removed ✅")
        else:
            print("Recipient key not found ❌")

        self.pause()


def main():
    if not hasattr(oqs, 'KeyEncapsulation'):
        print("ERROR: liboqs-python not installed or not available.")
        print("Install: pip install git+https://github.com/open-quantum-safe/liboqs-python.git")
        sys.exit(1)
    app = InteractiveApp()
    app.menu()


if __name__ == "__main__":
    main()
