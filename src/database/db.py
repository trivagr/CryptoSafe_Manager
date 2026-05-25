import sqlite3
import threading
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
import hashlib

from src.core.crypto.abstract import EncryptionService


class DatabaseHelper:

    def __init__(self, db_path: Path, crypto: EncryptionService):
        self.db_path = db_path
        self.crypto = crypto

        self._lock = threading.RLock()
        self._transaction_conn: Optional[sqlite3.Connection] = None

        self._initialize_database()

    # -------------------------
    # CONNECTION
    # -------------------------
    @contextmanager
    def _connection(self):
        conn = None

        with self._lock:
            if self._transaction_conn is not None:
                yield self._transaction_conn
                return

            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode=WAL;")

        try:
            yield conn
            conn.commit()
        except Exception:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    # -------------------------
    # TRANSACTIONS
    # -------------------------
    def begin(self):
        with self._lock:
            if self._transaction_conn is not None:
                raise RuntimeError("Transaction already started")

            self._transaction_conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False
            )
            self._transaction_conn.execute("PRAGMA foreign_keys = ON;")
            self._transaction_conn.execute("PRAGMA journal_mode=WAL;")
            self._transaction_conn.execute("BEGIN")

    def commit(self):
        with self._lock:
            if self._transaction_conn is None:
                raise RuntimeError("No active transaction")

            self._transaction_conn.commit()
            self._transaction_conn.close()
            self._transaction_conn = None

    def rollback(self):
        with self._lock:
            if self._transaction_conn is None:
                raise RuntimeError("No active transaction")

            self._transaction_conn.rollback()
            self._transaction_conn.close()
            self._transaction_conn = None

    # -------------------------
    # EXECUTE
    # -------------------------
    def execute(self, query: str, params: tuple = (), fetch: bool = True):
        with self._lock:
            if self._transaction_conn is not None:
                cur = self._transaction_conn.cursor()
                cur.execute(query, params)
                return cur.fetchall() if fetch else cur.lastrowid

            with self._connection() as conn:
                cur = conn.cursor()
                cur.execute(query, params)
                return cur.fetchall() if fetch else cur.lastrowid

    # -------------------------
    # MIGRATIONS
    # -------------------------
    def _get_version(self, cursor) -> int:
        cursor.execute("PRAGMA user_version;")
        v = cursor.fetchone()[0]
        return v or 0

    def _migration_1(self, cursor):
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_data BLOB NOT NULL,
                title TEXT,
                username TEXT,
                url TEXT,
                notes TEXT,
                category TEXT,
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
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP
            );
        """)

        # AUTH TABLE 👇
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT NOT NULL
            );
        """)

        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS vault_entries_fts USING fts5(
                title,
                url,
                tags
            );
        """)

    def _migration_2(self, cursor):
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vault_created_at
            ON vault_entries(created_at);
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vault_updated_at
            ON vault_entries(updated_at);
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vault_tags
            ON vault_entries(tags);
        """)

    def migrate_database(self, cursor):
        version = self._get_version(cursor)

        if version < 1:
            self._migration_1(cursor)
            version = 1
            cursor.execute("PRAGMA user_version = 1;")

        if version < 2:
            self._migration_2(cursor)
            version = 2
            cursor.execute("PRAGMA user_version = 2;")

    def _initialize_database(self):
        with self._lock:
            with self._connection() as conn:
                self.migrate_database(conn.cursor())

    # -------------------------
    # AUTH SYSTEM 🔐
    # -------------------------
    def _hash(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def set_master_password(self, password: str):
        hashed = self._hash(password)

        with self._connection() as conn:
            cur = conn.cursor()

            cur.execute("DELETE FROM users")
            cur.execute("INSERT INTO users (password_hash) VALUES (?)", (hashed,))

    def check_master_password(self, password: str) -> bool:
        hashed = self._hash(password)

        with self._connection() as conn:
            cur = conn.cursor()

            row = cur.execute(
                "SELECT password_hash FROM users LIMIT 1"
            ).fetchone()

            if not row:
                return False

            return row[0] == hashed

    # -------------------------
    # VAULT OPS
    # -------------------------
    def add_entry(self, title, username, password, url,
                  notes, category, created_at, updated_at, tags):

        payload = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": category,
            "version": 1
        }

        encrypted = self.crypto.encrypt(payload)

        with self._connection() as conn:
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO vault_entries (
                    encrypted_data,
                    title,
                    username,
                    url,
                    notes,
                    category,
                    created_at,
                    updated_at,
                    tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                encrypted,
                title,
                username,
                url,
                notes,
                category,
                created_at,
                updated_at,
                tags
            ))

            return cur.lastrowid

    def delete_entry(self, entry_id: int):
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

    def get_all(self):
        with self._connection() as conn:
            cur = conn.cursor()
            return cur.execute("""
                SELECT id, title, username, url, notes, category
                FROM vault_entries
            """).fetchall()