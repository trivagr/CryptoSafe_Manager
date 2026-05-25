import sqlite3
import threading
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from src.core.crypto.abstract import EncryptionService


class DatabaseHelper:

    def __init__(self, db_path: Path, crypto: EncryptionService):
        self.db_path = db_path
        self.crypto = crypto

        self._lock = threading.RLock()
        self._transaction_conn = None

        self._initialize_database()

    @contextmanager
    def _connection(self):

        if self._transaction_conn is not None:
            yield self._transaction_conn
            return

        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )

        conn.execute("PRAGMA foreign_keys = ON;")

        try:
            yield conn
            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

    def begin(self):

        if self._transaction_conn is not None:
            raise RuntimeError("Transaction already started")

        self._transaction_conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )

        self._transaction_conn.execute(
            "PRAGMA foreign_keys = ON;"
        )

        self._transaction_conn.execute("BEGIN")

    def commit(self):

        if self._transaction_conn is None:
            raise RuntimeError("No active transaction")

        self._transaction_conn.commit()
        self._transaction_conn.close()

        self._transaction_conn = None

    def rollback(self):

        if self._transaction_conn is None:
            raise RuntimeError("No active transaction")

        self._transaction_conn.rollback()
        self._transaction_conn.close()

        self._transaction_conn = None

    def execute(self, query, params=()):

        with self._lock:

            if self._transaction_conn is not None:

                cursor = self._transaction_conn.cursor()

                cursor.execute(query, params)

                return cursor

            with self._connection() as conn:

                cursor = conn.cursor()

                cursor.execute(query, params)

                return cursor

    def get_database_version(self, cursor):

        cursor.execute("PRAGMA user_version;")

        return cursor.fetchone()[0]

    def migrate_database(self, cursor):

        version = self.get_database_version(cursor)

        if version < 1:

            self.migration_v1(cursor)

            cursor.execute(
                "PRAGMA user_version = 1;"
            )

        if version < 2:

            self.migration_v2(cursor)

            cursor.execute(
                "PRAGMA user_version = 2;"
            )

    def migration_v1(self, cursor):

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                tags TEXT
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deleted_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_entry_id INTEGER,
                encrypted_data BLOB NOT NULL,
                deleted_at TIMESTAMP,
                expires_at TIMESTAMP
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
                key_data BLOB,
                salt BLOB,
                hash TEXT,
                params TEXT,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP
            );
        """)

    def migration_v2(self, cursor):
        pass

    def _initialize_database(self):

        with self._lock:

            with self._connection() as conn:

                cursor = conn.cursor()

                self.migrate_database(cursor)

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: Optional[str],
        notes: Optional[str],
        category: Optional[str],
        created_at: str,
        updated_at: str,
        tags: Optional[str]
    ):

        payload = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": category,
            "version": 1
        }

        encrypted_data = self.crypto.encrypt(payload)

        with self._lock:

            with self._connection() as conn:

                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO vault_entries (
                        encrypted_data,
                        created_at,
                        updated_at,
                        tags
                    )
                    VALUES (?, ?, ?, ?);
                """, (
                    encrypted_data,
                    created_at,
                    updated_at,
                    tags
                ))

    def get_entry(self, entry_id: int):

        with self._lock:

            with self._connection() as conn:

                cursor = conn.cursor()

                cursor.execute("""
                    SELECT
                        id,
                        encrypted_data,
                        created_at,
                        updated_at,
                        tags
                    FROM vault_entries
                    WHERE id = ?;
                """, (entry_id,))

                row = cursor.fetchone()

        if not row:
            return None

        decrypted_data = self.crypto.decrypt(row[1])

        return {
            "id": row[0],
            **decrypted_data,
            "created_at": row[2],
            "updated_at": row[3],
            "tags": row[4]
        }

    def get_active_key(self):

        cursor = self.execute("""
            SELECT salt, hash
            FROM key_store
            WHERE key_type = 'master_key'
            ORDER BY version DESC
            LIMIT 1
        """)

        row = cursor.fetchone()

        if not row:
            raise ValueError("Master key not found")

        return {
            "salt": row[0],
            "hash": row[1]
        }