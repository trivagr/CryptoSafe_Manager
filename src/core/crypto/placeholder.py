import os
import ctypes
import json
from datetime import datetime, timezone
from src.core.crypto.abstract import EncryptionService

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def secure_zero_bytes(data: bytearray):
    length = len(data)
    ptr = (ctypes.c_char * length).from_buffer(data)
    for i in range(length):
        ptr[i] = 0

class AES256EncryptionService(EncryptionService):

    NONCE_SIZE = 12
    VERSION = 1

    def encrypt(self, data: dict) -> bytes:

        key = self._key_manager.get_key()

        nonce = os.urandom(self.NONCE_SIZE)

        package = {
            "version": self.VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "title": data["title"],
            "username": data["username"],
            "password": data["password"],
            "url": data.get("url"),
            "notes": data.get("notes"),
            "category": data.get("category"),
        }

        plaintext = bytearray(json.dumps(
            package,
            sort_keys=True,
            separators=(",", ":")
        ).encode())

        aesgcm = AESGCM(key)

        try:
           ciphertext = aesgcm.encrypt(
                nonce=nonce,
                data=plaintext,
                associated_data=None
            )

        finally:
            secure_zero_bytes(plaintext)

        return nonce + ciphertext

    def decrypt(self, encrypted: bytes) -> dict:

        key = self._key_manager.get_key()

        if len(encrypted) <= self.NONCE_SIZE:
            raise ValueError("Error")

        nonce = encrypted[:self.NONCE_SIZE]
        ciphertext = encrypted[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)

        plaintext = bytearray(aesgcm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None
        ))

        try:
            package = json.loads(plaintext.decode())

        finally:
            secure_zero_bytes(plaintext)

        if package.get("version") != self.VERSION:
            raise ValueError("Unsupported encryption version")

        return package