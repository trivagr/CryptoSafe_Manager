import sqlite3
import threading
from pathlib import Path
from typing import Optional
from src.core.crypto.abstract import EncryptionService
from contextlib import contextmanager
from src.core.crypto.placeholder import secure_zero_bytes


class DatabaseHelper:

    def __init__(self, db_path: Path, crypto: EncryptionService, key: bytes):
        self.db_path = db_path
        self.crypto = crypto
        self.key = key
        self._lock = threading.Lock()

        self._initialize_database()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize_database(self):
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vault_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        username TEXT,
                        encrypted_password BLOB NOT NULL,
                        url TEXT,
                        notes BLOB,
                        created_at TEXT,
                        updated_at TEXT,
                        tags TEXT
                    );
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT,
                        timestamp TEXT,
                        entry_id INTEGER,
                        details TEXT,
                        signature TEXT
                    );
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        setting_key TEXT UNIQUE,
                        setting_value TEXT,
                        encrypted INTEGER DEFAULT 0
                    );
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS key_store (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_type TEXT,
                        salt BLOB,
                        hash BLOB,
                        params TEXT
                    );
                """)

                cursor.execute("PRAGMA user_version = 1;")

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: Optional[str],
        notes: Optional[str],
        created_at: str,
        updated_at: str,
        tags: Optional[str]
    ):
        password_bytes = bytearray(password.encode())
        encrypted_password = self.crypto.encrypt(password_bytes, self.key)
        secure_zero_bytes(password_bytes)

        notes_bytes = bytearray(notes.encode()) if notes else None
        encrypted_notes = self.crypto.encrypt(notes_bytes, self.key) if notes_bytes else None
        if notes_bytes:
            secure_zero_bytes(notes_bytes)

        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO vault_entries
                    (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    title,
                    username,
                    encrypted_password,
                    url,
                    encrypted_notes,
                    created_at,
                    updated_at,
                    tags
                ))

    def get_entry(self, entry_id: int):
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, title, username, encrypted_password, url, notes,
                           created_at, updated_at, tags
                    FROM vault_entries
                    WHERE id = ?;
                """, (entry_id,))
                row = cursor.fetchone()

        if not row:
            return None

        decrypted_password_bytes = bytearray(self.crypto.decrypt(row[3], self.key))
        decrypted_password = decrypted_password_bytes.decode()
        secure_zero_bytes(decrypted_password_bytes)

        decrypted_notes_bytes = bytearray(self.crypto.decrypt(row[5], self.key)) if row[5] else None
        decrypted_notes = decrypted_notes_bytes.decode() if decrypted_notes_bytes else None
        if decrypted_notes_bytes:
            secure_zero_bytes(decrypted_notes_bytes)

        return {
            "id": row[0],
            "title": row[1],
            "username": row[2],
            "password": decrypted_password,
            "url": row[4],
            "notes": decrypted_notes,
            "created_at": row[6],
            "updated_at": row[7],
            "tags": row[8],
        }