from src.core.crypto.placeholder import secure_zero_bytes
from src.core.crypto.key_derivation import AuthHasher, KeyDeriver

class KeyManager:

    def __init__(self, config):
        self.auth = AuthHasher(config)
        self.derive = KeyDeriver(config)
        self._key = None
        self._unlocked = False

    def unlock(self, password, stored_hash, salt):
        if not self.auth.verify(password, stored_hash):
            return False

        self._key = self.derive.derive(password, salt)
        self._unlocked = True
        return True

    def lock(self):
        if self._key:
            secure_zero_bytes(bytearray(self._key))
        self._key = None
        self._unlocked = False

    def get_key(self):
        if not self._unlocked:
            raise ValueError("Locked")
        return self._key