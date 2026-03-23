import hashlib
from src.core.crypto.placeholder import secure_zero_bytes

class KeyManager:

    def __init__(self):
        self._key = None
        self._unlocked = False

    def unlock_key(self, key : bytes):
        self._key = key
        self._unlocked = True

    def lock_key(self):
        if self._key:
            secure_zero_bytes(bytearray(self._key))
        self._unlocked = False
        self._key = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        temp_bytes = bytearray(password.encode() + salt)
        derived = hashlib.sha256(temp_bytes).digest()
        secure_zero_bytes(temp_bytes)
        return derived

    def limited_use_key(self, func):
        if self._unlocked == False:
            raise ValueError("Ключ недоступен")
        return func(self._key)