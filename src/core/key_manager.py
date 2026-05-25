from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.key_derivation import KeyHashing

class KeyManager:

    def __init__(self):
        self.hashing = KeyHashing()
        self.storage = KeyStorage()
        self._unlocked = False

    def unlock(self, password, stored_hash, salt):
        if self._unlocked:
            raise RuntimeError("Already unlocked")

        if not self.hashing.password_verify(password, stored_hash):
            raise ValueError("Invalid login/password")

        key = self.hashing.derive(password, salt)

        self.storage.store_key(key)

        self._unlocked = True
        return True

    def lock(self):
        self.storage.clear_key()
        self._unlocked = False

    def get_key(self):
        if not self._unlocked:
            raise ValueError("Locked")

        key = self.storage.get_key()

        if key is None:
            raise RuntimeError("No key  ")

        return key