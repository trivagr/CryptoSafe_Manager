import hashlib
from src.core.crypto.placeholder import secure_zero_bytes

class KeyManager:

    def __init__(self):
        self._key = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        temp_bytes = bytearray(password.encode() + salt)
        derived = hashlib.sha256(temp_bytes).digest()
        secure_zero_bytes(temp_bytes)
        return derived

    def store_key(self):
        return self._key

    def load_key(self):
        if self._key is None:
            raise ValueError("Ключ не установлен. Вызовите derive_key и store_key сначала.")
        return self._key