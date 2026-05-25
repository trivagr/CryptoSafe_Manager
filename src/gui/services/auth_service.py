import time
from src.core.key_manager import KeyManager


class AuthService:

    def __init__(self):
        self.key_manager = KeyManager()

        self.failed_attempts = 0
        self.session_start = None
        self.session_ttl = 3600  # 1 hour

    def authenticate(self, password: str) -> bool:
        # пока упрощенно (без salt/db)
        ok = self.key_manager.unlock_simple(password)

        if not ok:
            self.failed_attempts += 1
            return False

        self.failed_attempts = 0
        self.session_start = time.time()
        return True

    def is_session_active(self):
        if not self.session_start:
            return False

        return (time.time() - self.session_start) < self.session_ttl

    def session_remaining(self):
        if not self.session_start:
            return 0

        return max(0, self.session_ttl - (time.time() - self.session_start))