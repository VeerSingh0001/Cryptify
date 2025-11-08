#!/usr/bin/env python3
"""
key_manager.py
Secure key storage and public-key import/export.

- Argon2id (argon2-cffi) preferred; falls back to PBKDF2-HMAC-SHA256.
- AES-GCM (cryptography) for encrypting private keys.
- Atomic file writes and best-effort zeroization.
"""

from pathlib import Path
from datetime import datetime
import json
import os
import base64
import secrets
import shutil

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Optional Argon2
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    ARGON2_AVAILABLE = True
except Exception:
    ARGON2_AVAILABLE = False

# -------------------------
# Secure helpers
# -------------------------
def _to_bytearray(b):
    return bytearray(b) if b is not None else bytearray()

def secure_erase(barr):
    """Best-effort overwrite of bytearray or bytes-like (converted to bytearray)."""
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

# -------------------------
# KDFs
# -------------------------
def derive_key_argon2(password: str, salt: bytes, length: int = 32) -> bytes:
    """Argon2id raw derive."""
    pwd = password.encode('utf-8')
    derived = hash_secret_raw(
        secret=pwd,
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MiB
        parallelism=1,
        hash_len=length,
        type=Argon2Type.ID
    )
    secure_erase(_to_bytearray(pwd))
    return derived

def derive_key_pbkdf2(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode('utf-8'))

def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    if ARGON2_AVAILABLE:
        try:
            return derive_key_argon2(password, salt, length)
        except Exception:
            # fallback
            pass
    return derive_key_pbkdf2(password, salt, length)

# -------------------------
# KeyManager class
# -------------------------
class KeyManager:
    def __init__(self, storage_path: str = "~/.mlkem_keys"):
        self.storage_path = Path(storage_path).expanduser()
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.pubkey_dir = self.storage_path / "public_keys"
        self.pubkey_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _atomic_write(self, dest: Path, data: dict):
        tmp = dest.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
        dest.chmod(0o600)

    def save_keypair(self, public_key: bytes, secret_key: bytes, key_id: str, password: str) -> str:
        """Encrypt secret_key with password-derived key and save as JSON."""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        derived = derive_key(password, salt, 32)
        try:
            aesgcm = AESGCM(derived)
            encrypted_secret = aesgcm.encrypt(nonce, secret_key, associated_data=None)
        finally:
            secure_erase(_to_bytearray(derived))

        secure_erase(_to_bytearray(secret_key))

        key_data = {
            "version": "1.2",
            "key_type": "keypair",
            "created": datetime.utcnow().isoformat(),
            "public_key": base64.b64encode(public_key).decode('utf-8'),
            "encrypted_secret_key": base64.b64encode(encrypted_secret).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "kdf": "Argon2id" if ARGON2_AVAILABLE else "PBKDF2-HMAC-SHA256",
            "cipher": "AESGCM"
        }

        key_file = self.storage_path / f"{key_id}.json"
        self._atomic_write(key_file, key_data)
        return str(key_file)

    def load_keypair(self, key_id: str, password: str):
        """Return (public_key, secret_key) bytes. Caller should minimize lifetime of secret_key."""
        key_file = self.storage_path / f"{key_id}.json"
        if not key_file.exists():
            raise FileNotFoundError(f"Key '{key_id}' not found")

        with open(key_file, "r") as f:
            d = json.load(f)

        public_key = base64.b64decode(d['public_key'])
        enc_secret = base64.b64decode(d['encrypted_secret_key'])
        salt = base64.b64decode(d['salt'])
        nonce = base64.b64decode(d['nonce'])

        derived = derive_key(password, salt, 32)
        try:
            aesgcm = AESGCM(derived)
            secret_key = aesgcm.decrypt(nonce, enc_secret, associated_data=None)
        except Exception as e:
            secure_erase(_to_bytearray(derived))
            raise ValueError("Wrong password or corrupted key file") from e
        finally:
            secure_erase(_to_bytearray(derived))

        return public_key, secret_key

    def export_public_key(self, key_id: str, password: str, output_file: str) -> str:
        """Export public key to output_file (JSON)"""
        public_key, _ = self.load_keypair(key_id, password)
        export_data = {
            "version": "1.0",
            "key_type": "public_only",
            "key_id": key_id,
            "exported": datetime.utcnow().isoformat(),
            "public_key": base64.b64encode(public_key).decode('utf-8'),
            "algorithm": "Kyber768"
        }
        outp = Path(output_file)
        with open(outp, "w") as f:
            json.dump(export_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        return str(outp)

    def import_public_key(self, import_file: str, recipient_name: str) -> str:
        with open(import_file, "r") as f:
            d = json.load(f)
        if d.get('key_type') != 'public_only':
            raise ValueError("Invalid public key file")
        dst = self.pubkey_dir / f"{recipient_name}.json"
        shutil.copy(import_file, dst)
        dst.chmod(0o644)
        return str(dst)

    def get_public_key(self, recipient_name: str) -> bytes:
        pubfile = self.pubkey_dir / f"{recipient_name}.json"
        if not pubfile.exists():
            raise FileNotFoundError(f"Public key for '{recipient_name}' not found")
        with open(pubfile, "r") as f:
            d = json.load(f)
        return base64.b64decode(d['public_key'])

    def list_keys(self):
        result = []
        for k in self.storage_path.glob("*.json"):
            try:
                with open(k, "r") as f:
                    d = json.load(f)
                if d.get('key_type') == 'keypair':
                    result.append({"id": k.stem, "created": d.get('created', 'Unknown')})
            except Exception:
                continue
        return result

    def list_public_keys(self):
        result = []
        for k in self.pubkey_dir.glob("*.json"):
            try:
                with open(k, "r") as f:
                    d = json.load(f)
                result.append({"recipient": k.stem, "exported": d.get('exported','Unknown')})
            except Exception:
                continue
        return result
