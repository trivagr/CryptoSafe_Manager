from src.core.crypto.placeholder import secure_zero_bytes
from src.core.crypto.key_derivation import KeyHashing

class KeyManager:

    def __init__(self, config):
        self.hash = KeyHashing(config)
        self._key = None
        self._unlocked = False

    def unlock(self, password, stored_hash, salt):
        if not self.hash.password_verify(password, stored_hash):
            return False

        self._key = self.hash.derive(password, salt)
        self._unlocked = True
        return True

    def lock(self):
        if self._key:
            secure_zero_bytes(self._key)
        self._key = None
        self._unlocked = False

    def get_key(self):
        if not self._unlocked:
            raise ValueError("Locked")
        return bytes(self._key)