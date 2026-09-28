from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


class SessionState(Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"


class StateManager:
    CLIPBOARD_REDACTED_MARKER = "[protected]"

    def __init__(self):
        self.session_state = SessionState.LOCKED
        self.login_timestamp: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self.failed_attempt_count = 0
        self.application_active = True
        self.clipboard_content: Optional[str] = None
        self.clipboard_timer: Optional[datetime] = None
        self.inactivity_timeout = 300
        self.key_cache_timeout = 3600

    def unlock(self):
        now = datetime.now()
        self.session_state = SessionState.UNLOCKED
        self.login_timestamp = now
        self.last_activity = now
        self.application_active = True

    def lock(self):
        self.session_state = SessionState.LOCKED
        self.login_timestamp = None
        self.clipboard_content = None
        self.clipboard_timer = None

    def is_locked(self) -> bool:
        return self.session_state == SessionState.LOCKED

    def is_unlocked(self) -> bool:
        return self.session_state == SessionState.UNLOCKED

    def update_activity(self):
        self.last_activity = datetime.now()

    def get_idle_time(self) -> float:
        if self.last_activity is None:
            return 0
        return (datetime.now() - self.last_activity).total_seconds()

    def should_auto_lock(self) -> bool:
        if self.session_state != SessionState.UNLOCKED or self.last_activity is None:
            return False
        return self.get_idle_time() >= self.inactivity_timeout

    def should_expire_key_cache(self) -> bool:
        if self.session_state != SessionState.UNLOCKED or self.last_activity is None:
            return False
        return self.get_idle_time() >= self.key_cache_timeout

    def set_inactivity_timeout(self, seconds: int):
        self.inactivity_timeout = max(1, int(seconds))

    def set_key_cache_timeout(self, seconds: int):
        self.key_cache_timeout = max(1, int(seconds))

    def set_application_active(self, is_active: bool):
        self.application_active = is_active
        if is_active:
            self.update_activity()

    def register_failed_attempt(self):
        self.failed_attempt_count += 1

    def reset_failed_attempts(self):
        self.failed_attempt_count = 0

    def set_clipboard(self, content: str, timeout_seconds: int = 30, redact: bool = False):
        self.clipboard_content = self.CLIPBOARD_REDACTED_MARKER if redact else content
        if timeout_seconds > 0:
            self.clipboard_timer = datetime.now() + timedelta(seconds=timeout_seconds)
        else:
            self.clipboard_timer = None

    def get_clipboard(self) -> Optional[str]:
        if self.clipboard_timer and datetime.now() >= self.clipboard_timer:
            self.clipboard_content = None
            self.clipboard_timer = None
        return self.clipboard_content

    def clear_clipboard(self):
        self.clipboard_content = None
        self.clipboard_timer = None

    def get_clipboard_remaining_seconds(self) -> int:
        if self.clipboard_timer is None:
            return 0
        remaining = int((self.clipboard_timer - datetime.now()).total_seconds())
        return max(0, remaining)