import threading
from typing import Optional
from src.database.db import DatabaseHelper
from src.core.crypto.abstract import EncryptionService
from src.core.crypto.placeholder import secure_zero_bytes

class StateManager:

    def __init__(self, db: DatabaseHelper, crypto: EncryptionService, key: bytes):
        self._session_locked = True
        self._clipboard_content: Optional[str] = None
        self._clipboard_timer: Optional[threading.Timer] = None
        self._idle_timer: Optional[threading.Timer] = None
        self.db = db
        self.crypto = crypto
        self.key = key
        self._lock = threading.Lock()

    def lock_session(self):
        with self._lock:
            self._session_locked = True

    def unlock_session(self):
        with self._lock:
            self._session_locked = False

    def set_clipboard(self, content: str, timeout: int = 30):
        with self._lock:
            # Обнуляем старое содержимое буфера
            if self._clipboard_content:
                secure_zero_bytes(bytearray(self._clipboard_content.encode()))
            self._clipboard_content = content

            if self._clipboard_timer:
                self._clipboard_timer.cancel()
            self._clipboard_timer = threading.Timer(timeout, self.clear_clipboard)
            self._clipboard_timer.start()

    def get_clipboard(self) -> Optional[str]:
        with self._lock:
            return self._clipboard_content

    def clear_clipboard(self):
        with self._lock:
            if self._clipboard_content:
                secure_zero_bytes(bytearray(self._clipboard_content.encode()))
            self._clipboard_content = None

            if self._clipboard_timer:
                self._clipboard_timer.cancel()
                self._clipboard_timer = None

    def clear_session_key(self):
        with self._lock:
            if self._session_key:
                secure_zero_bytes(bytearray(self._session_key))
                self._session_key = None

    def set_setting(self, key: str, value: str, encrypted: bool = False):

        with self._lock:
            if encrypted:
                value_bytes = value.encode()
                value = self.crypto.encrypt(value_bytes, self.key)
            else:
                value = value

            conn = self.db._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, encrypted=excluded.encrypted;
            """, (key, value, int(encrypted)))
            conn.commit()
            conn.close()

    def get_setting(self, key: str, encrypted: bool = False) -> Optional[str]:

        with self._lock:
            conn = self.db._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT setting_value FROM settings WHERE setting_key=?;
            """, (key,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            value = row[0]
            if encrypted and value is not None:
                value = self.crypto.decrypt(value, self.key).decode()
            return value

    def start_idle_timer(self, timeout: int, callback):

        with self._lock:
            if self._idle_timer:
                self._idle_timer.cancel()
            self._idle_timer = threading.Timer(timeout, callback)
            self._idle_timer.start()

    def reset_idle_timer(self):
        with self._lock:
            if self._idle_timer:
                self._idle_timer.cancel()
                self._idle_timer = None