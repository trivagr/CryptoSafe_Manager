from src.core.crypto.placeholder import secure_zero_bytes
from src.core.crypto import key_derivation

class KeyManager:

    def __init__(self):
        self._key = None
        self._unlocked = False

    def unlock_key(self, key : bytes):
        self._key = bytearray(key)
        self._unlocked = True

    def lock_key(self):
        if self._key:
            secure_zero_bytes(bytearray(self._key))
        self._unlocked = False
        self._key = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        return key_derivation.key_derive(password, salt)

    def limited_use_key(self, func):
        if self._unlocked == False:
            raise ValueError("Ключ недоступен")
        return func(bytes(self._key))