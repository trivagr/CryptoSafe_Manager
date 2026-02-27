import hashlib

class KeyManager:

    def __init__(self):
        self._key = None

    def derive_key(self, password: str, salt: bytes) -> bytes:
        data = password.encode() + salt
        return hashlib.sha256(data).digest()

    def store_key(self):
        return self._key

    def load_key(self):
        if self._key is None:
            raise ValueError("Ключ не установлен. Вызовите derive_key и store_key сначала.")
        return self._key