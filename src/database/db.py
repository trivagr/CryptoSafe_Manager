import hashlib
import json
import queue
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from .models import AuditLog, KeyStore, VaultEntry


class Database:
    SCHEMA_VERSION = 6

    def __init__(self, db_path: str = "cryptosafe.db", pool_size: int = 4):
        self.db_path = db_path
        self.pool_size = max(1, int(pool_size))
        self._connection_pool: "queue.LifoQueue[sqlite3.Connection]" = queue.LifoQueue(maxsize=self.pool_size)
        self._audit_protection_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self._audit_entry_data_decoder: Optional[Callable[[Any], str]] = None
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._acquire_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release_connection(conn)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._get_connection() as conn:
            try:
                conn.execute("BEGIN")
                yield conn
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

    def _acquire_connection(self) -> sqlite3.Connection:
        try:
            return self._connection_pool.get_nowait()
        except queue.Empty:
            return self._create_connection()

    def _release_connection(self, conn: sqlite3.Connection):
        try:
            self._connection_pool.put_nowait(conn)
        except queue.Full:
            conn.close()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def close(self):
        while True:
            try:
                conn = self._connection_pool.get_nowait()
            except queue.Empty:
                break
            conn.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _init_db(self):
        with self._get_connection() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self._create_schema(conn)
                conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            else:
                if version == 1:
                    self._migrate_v1_to_v2(conn)
                    version = 2
                if version == 2:
                    self._migrate_v2_to_v3(conn)
                    version = 3
                if version == 3:
                    self._migrate_v3_to_v4(conn)
                    version = 4
                if version == 4:
                    self._migrate_v4_to_v5(conn)
                    version = 5
                if version == 5:
                    self._migrate_v5_to_v6(conn)
                    version = 6
                conn.execute(f"PRAGMA user_version = {max(version, self.SCHEMA_VERSION)}")
            self._ensure_audit_hardening_schema(conn)
            self._ensure_import_export_schema(conn)

    def _create_schema(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                encrypted_data BLOB,
                url TEXT,
                notes TEXT,
                category TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )
        conn.execute("CREATE INDEX idx_title ON vault_entries(title)")
        conn.execute("CREATE INDEX idx_entries_created_at ON vault_entries(created_at)")
        conn.execute("CREATE INDEX idx_entries_updated_at ON vault_entries(updated_at)")
        conn.execute("CREATE INDEX idx_entries_tags ON vault_entries(tags)")

        conn.execute(
            """
            CREATE TABLE deleted_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_entry_id INTEGER,
                encrypted_data BLOB NOT NULL,
                title TEXT,
                deleted_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX idx_deleted_entries_expires_at ON deleted_entries(expires_at)")

        conn.execute(
            """
            CREATE TABLE audit_log (
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id TEXT NOT NULL,
                source TEXT NOT NULL,
                entry_id INTEGER,
                details TEXT,
                action TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                entry_data BLOB NOT NULL,
                signature TEXT NOT NULL,
                public_key TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX idx_audit_event_type ON audit_log(event_type)")
        conn.execute("CREATE UNIQUE INDEX idx_audit_sequence ON audit_log(sequence_number)")

        conn.execute(
            """
            CREATE TABLE audit_public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX idx_audit_public_keys_active ON audit_public_keys(public_key)")
        self._create_audit_archive_schema(conn)
        self._create_audit_guards(conn)

        conn.execute(
            """
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                encrypted BOOLEAN DEFAULT 0
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL,
                salt BLOB,
                hash TEXT,
                params TEXT,
                last_rotated_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX idx_key_store_type ON key_store(key_type)")
        self._create_import_export_schema(conn)

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(key_store)").fetchall()}
        if "created_at" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN created_at TIMESTAMP")
        if "last_rotated_at" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN last_rotated_at TIMESTAMP")

        now = datetime.now().isoformat()
        conn.execute(
            """
            UPDATE key_store
            SET created_at = COALESCE(created_at, ?),
                last_rotated_at = COALESCE(last_rotated_at, ?)
            """,
            (now, now),
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_updated_at ON vault_entries(updated_at)")

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(key_store)").fetchall()}
        if "key_data" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN key_data BLOB")
        if "version" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN version INTEGER DEFAULT 1")

        rows = conn.execute("SELECT id, key_type, salt, hash, params, key_data FROM key_store").fetchall()
        for row in rows:
            key_data = row["key_data"]
            if key_data is None:
                if row["hash"]:
                    key_data = row["hash"].encode("utf-8")
                elif row["salt"]:
                    key_data = row["salt"]
                elif row["params"]:
                    key_data = row["params"].encode("utf-8")
                else:
                    key_data = b""
                conn.execute("UPDATE key_store SET key_data = ? WHERE id = ?", (key_data, row["id"]))

        conn.execute("UPDATE key_store SET version = COALESCE(version, 1)")

    def _migrate_v3_to_v4(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(vault_entries)").fetchall()}
        if "encrypted_data" not in columns:
            conn.execute("ALTER TABLE vault_entries ADD COLUMN encrypted_data BLOB")
        if "category" not in columns:
            conn.execute("ALTER TABLE vault_entries ADD COLUMN category TEXT NOT NULL DEFAULT ''")

        conn.execute(
            """
            UPDATE vault_entries
            SET encrypted_data = COALESCE(encrypted_data, encrypted_password)
            """
        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_created_at ON vault_entries(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_updated_at ON vault_entries(updated_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_tags ON vault_entries(tags)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deleted_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_entry_id INTEGER,
                encrypted_data BLOB NOT NULL,
                title TEXT,
                deleted_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deleted_entries_expires_at ON deleted_entries(expires_at)")

    def _migrate_v4_to_v5(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "event_type" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN event_type TEXT")
        if "severity" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN severity TEXT")
        if "user_id" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN user_id TEXT")
        if "source" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN source TEXT")
        if "previous_hash" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN previous_hash TEXT")
        if "entry_hash" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
        if "entry_data" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN entry_data BLOB")
        if "public_key" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN public_key TEXT")
        if "sequence_number" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN sequence_number INTEGER")
        if "signature" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN signature TEXT")

        rows = conn.execute(
            """
            SELECT rowid AS audit_rowid, action, timestamp, entry_id, details
            FROM audit_log
            ORDER BY COALESCE(timestamp, ''), rowid
            """
        ).fetchall()
        previous_hash = "0" * 64
        for index, row in enumerate(rows, start=1):
            details_text = row["details"] or ""
            event_payload = {
                "timestamp": row["timestamp"] or datetime.utcnow().isoformat() + "Z",
                "event_type": row["action"] or "legacy_event",
                "severity": "INFO",
                "user_id": "local-user",
                "source": "legacy_migration",
                "entry_id": row["entry_id"],
                "details": {"legacy_details": details_text},
                "sequence_number": index,
                "previous_hash": previous_hash,
            }
            entry_data = json.dumps(event_payload, ensure_ascii=False, sort_keys=True)
            entry_hash = self._compute_hash(entry_data)
            conn.execute(
                """
                UPDATE audit_log
                SET event_type = COALESCE(event_type, ?),
                    severity = COALESCE(severity, ?),
                    user_id = COALESCE(user_id, ?),
                    source = COALESCE(source, ?),
                    previous_hash = COALESCE(previous_hash, ?),
                    entry_hash = COALESCE(entry_hash, ?),
                    entry_data = COALESCE(entry_data, ?),
                    public_key = COALESCE(public_key, ?),
                    sequence_number = COALESCE(sequence_number, ?),
                    signature = COALESCE(signature, ?)
                WHERE rowid = ?
                """,
                (
                    row["action"] or "legacy_event",
                    "INFO",
                    "local-user",
                    "legacy_migration",
                    previous_hash,
                    entry_hash,
                    entry_data,
                    "legacy",
                    index,
                    "legacy",
                    row["audit_rowid"],
                ),
            )
            previous_hash = entry_hash

        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_public_keys_active ON audit_public_keys(public_key)")
        self._create_audit_archive_schema(conn)
        self._create_audit_guards(conn)

    def _migrate_v5_to_v6(self, conn: sqlite3.Connection):
        self._create_import_export_schema(conn)

    def _ensure_audit_hardening_schema(self, conn: sqlite3.Connection):
        self._create_audit_archive_schema(conn)
        self._repair_missing_audit_sequence_numbers(conn)
        self._repair_repeated_previous_hash_audit_rows(conn)
        self._create_audit_guards(conn)
        self._create_audit_security_schema(conn)

    def _ensure_import_export_schema(self, conn: sqlite3.Connection):
        self._create_import_export_schema(conn)

    def _create_import_export_schema(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shared_entries (
                share_id TEXT PRIMARY KEY,
                original_entry_id INTEGER,
                encryption_method TEXT NOT NULL,
                recipient_info TEXT NOT NULL,
                permissions TEXT NOT NULL,
                shared_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                package_checksum TEXT,
                FOREIGN KEY(original_entry_id) REFERENCES vault_entries(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_original_entry_id ON shared_entries(original_entry_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_expires_at ON shared_entries(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_status ON shared_entries(status)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS import_export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                format TEXT NOT NULL,
                encryption_used TEXT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                file_size INTEGER NOT NULL DEFAULT 0,
                checksum TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                details TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_import_export_history_created_at ON import_export_history(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_import_export_history_operation ON import_export_history(operation_type)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                identifier TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                key_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP NOT NULL,
                last_used_at TIMESTAMP,
                revoked_at TIMESTAMP
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_contacts_identifier ON contacts(identifier)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_fingerprint ON contacts(key_fingerprint)")

    def _repair_missing_audit_sequence_numbers(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "sequence_number" not in columns:
            return

        rows = conn.execute(
            """
            SELECT rowid AS audit_rowid
            FROM audit_log
            WHERE sequence_number IS NULL
            ORDER BY COALESCE(timestamp, ''), rowid
            """
        ).fetchall()
        if not rows:
            return

        self._drop_audit_guards(conn)
        max_sequence = conn.execute(
            "SELECT COALESCE(MAX(sequence_number), 0) AS max_sequence FROM audit_log"
        ).fetchone()["max_sequence"]
        next_sequence = int(max_sequence or 0) + 1
        for row in rows:
            conn.execute(
                "UPDATE audit_log SET sequence_number = ? WHERE rowid = ?",
                (next_sequence, row["audit_rowid"]),
            )
            next_sequence += 1

    def _repair_repeated_previous_hash_audit_rows(self, conn: sqlite3.Connection):
        rows = conn.execute(
            """
            SELECT rowid AS audit_rowid, *
            FROM audit_log
            WHERE sequence_number IS NOT NULL
            ORDER BY sequence_number ASC
            """
        ).fetchall()
        if len(rows) < 2:
            return

        repair_start_index = None
        for index in range(1, len(rows)):
            previous_row = rows[index - 1]
            current_row = rows[index]
            if current_row["previous_hash"] == previous_row["entry_hash"]:
                continue
            is_repeated_previous_hash = current_row["previous_hash"] == previous_row["previous_hash"]
            is_signed_audit_row = current_row["signature"] != "legacy" and current_row["public_key"] != "legacy"
            if is_repeated_previous_hash and is_signed_audit_row:
                repair_start_index = index
                break

        if repair_start_index is None:
            return

        self._drop_audit_guards(conn)
        previous_hash = rows[repair_start_index - 1]["entry_hash"]
        for row in rows[repair_start_index:]:
            details = self._parse_audit_details(row["details"])
            payload = {
                "timestamp": str(row["timestamp"] or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
                "event_type": str(row["event_type"] or row["action"] or "legacy_event"),
                "severity": str(row["severity"] or "INFO"),
                "user_id": str(row["user_id"] or "local-user"),
                "source": str(row["source"] or "sequence_repair"),
                "entry_id": row["entry_id"],
                "details": details,
                "sequence_number": int(row["sequence_number"]),
                "previous_hash": previous_hash,
            }
            entry_data = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            entry_hash = self._compute_hash(entry_data)
            conn.execute(
                """
                UPDATE audit_log
                SET previous_hash = ?,
                    entry_hash = ?,
                    entry_data = ?,
                    signature = ?,
                    public_key = ?
                WHERE rowid = ?
                """,
                (
                    previous_hash,
                    entry_hash,
                    entry_data,
                    "legacy",
                    "legacy",
                    row["audit_rowid"],
                ),
            )
            previous_hash = entry_hash

    def _parse_audit_details(self, raw_details: Any) -> Dict[str, Any]:
        if isinstance(raw_details, dict):
            return dict(raw_details)
        try:
            parsed = json.loads(str(raw_details or "{}"))
            return parsed if isinstance(parsed, dict) else {"message": parsed}
        except (TypeError, json.JSONDecodeError):
            return {"legacy_details": str(raw_details or "")}

    def _create_audit_archive_schema(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_archives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP NOT NULL,
                reason TEXT NOT NULL,
                range_start_sequence INTEGER NOT NULL,
                range_end_sequence INTEGER NOT NULL,
                entry_count INTEGER NOT NULL,
                archive_data BLOB NOT NULL,
                archive_hash TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_archives_created_at ON audit_archives(created_at)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_archives_sequence_range ON audit_archives(range_start_sequence, range_end_sequence)"
        )

    def _create_audit_security_schema(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_security_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                related_sequence_number INTEGER,
                details TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_security_log_timestamp ON audit_security_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_security_log_event_type ON audit_security_log(event_type)")

    def _create_audit_guards(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log_is_append_only');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log_is_append_only');
            END
            """
        )

    def _drop_audit_guards(self, conn: sqlite3.Connection):
        conn.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update")
        conn.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_delete")

    def add_entry(self, entry: VaultEntry) -> int:
        with self._get_connection() as conn:
            created_at = entry.created_at.isoformat() if entry.created_at else datetime.now().isoformat()
            updated_at = entry.updated_at.isoformat() if entry.updated_at else datetime.now().isoformat()
            cursor = conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, encrypted_data, url, notes, category, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.title,
                    entry.username,
                    entry.encrypted_password,
                    entry.encrypted_data or entry.encrypted_password,
                    entry.url,
                    entry.notes,
                    entry.category,
                    created_at,
                    updated_at,
                    entry.tags,
                ),
            )
            return cursor.lastrowid

    def get_entry(self, entry_id: int) -> Optional[VaultEntry]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
            return self._row_to_entry(row) if row else None

    def get_all_entries(self) -> List[VaultEntry]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM vault_entries ORDER BY updated_at DESC").fetchall()
            return [self._row_to_entry(row) for row in rows]

    def update_entry(self, entry: VaultEntry):
        if entry.id is None:
            raise ValueError("ID cannot be None")
        entry.updated_at = datetime.now()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title=?, username=?, encrypted_password=?, encrypted_data=?, url=?, notes=?, category=?, updated_at=?, tags=?
                WHERE id=?
                """,
                (
                    entry.title,
                    entry.username,
                    entry.encrypted_password,
                    entry.encrypted_data or entry.encrypted_password,
                    entry.url,
                    entry.notes,
                    entry.category,
                    entry.updated_at.isoformat(),
                    entry.tags,
                    entry.id,
                ),
            )

    def delete_entry(self, entry_id: int):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

    def add_audit_log(
        self,
        action: str,
        timestamp: datetime,
        entry_id: Optional[int] = None,
        details: str = "",
        *,
        event_type: Optional[str] = None,
        severity: str = "INFO",
        user_id: str = "local-user",
        source: str = "unknown",
        previous_hash: str = "",
        entry_hash: str = "",
        entry_data: str = "",
        signature: str = "",
        public_key: str = "",
        sequence_number: Optional[int] = None,
    ) -> int:
        if sequence_number is None:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT COALESCE(MAX(sequence_number), 0) AS max_sequence FROM audit_log"
                ).fetchone()
                sequence_number = int(row["max_sequence"] or 0) + 1

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (
                    sequence_number,
                    timestamp,
                    event_type,
                    severity,
                    user_id,
                    source,
                    entry_id,
                    details,
                    action,
                    previous_hash,
                    entry_hash,
                    entry_data,
                    signature,
                    public_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence_number,
                    timestamp.isoformat(),
                    event_type or action,
                    severity,
                    user_id,
                    source,
                    entry_id,
                    details,
                    action,
                    previous_hash,
                    entry_hash,
                    entry_data,
                    signature,
                    public_key,
                ),
            )
            return int(cursor.lastrowid)

    def get_audit_logs(self, limit: int = 200, offset: int = 0) -> List[AuditLog]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT rowid AS id, * FROM audit_log ORDER BY sequence_number DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return self._rows_to_audit_logs(rows)

    def query_audit_logs(
        self,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: Optional[Any] = None,
        date_to: Optional[Any] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AuditLog]:
        where_clauses = []
        params: List[Any] = []

        normalized_search = str(search_text or "").strip().lower()
        if normalized_search:
            where_clauses.append(
                "(LOWER(event_type) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(user_id) LIKE ? OR LOWER(source) LIKE ? OR LOWER(details) LIKE ?)"
            )
            like_value = f"%{normalized_search}%"
            params.extend([like_value, like_value, like_value, like_value, like_value])

        normalized_event_type = str(event_type or "").strip().lower()
        if normalized_event_type and normalized_event_type not in {"all", "все"}:
            where_clauses.append("LOWER(event_type) = ?")
            params.append(normalized_event_type)

        normalized_severity = str(severity or "").strip().upper()
        if normalized_severity and normalized_severity not in {"ALL", "ВСЕ"}:
            where_clauses.append("severity = ?")
            params.append(normalized_severity)

        normalized_user = str(user_id or "").strip().lower()
        if normalized_user and normalized_user not in {"all", "все"}:
            where_clauses.append("LOWER(user_id) LIKE ?")
            params.append(f"%{normalized_user}%")

        from_dt = self._normalize_audit_datetime(date_from, is_end=False)
        if from_dt is not None:
            where_clauses.append("timestamp >= ?")
            params.append(from_dt.isoformat())

        to_dt = self._normalize_audit_datetime(date_to, is_end=True)
        if to_dt is not None:
            where_clauses.append("timestamp <= ?")
            params.append(to_dt.isoformat())

        query = "SELECT rowid AS id, * FROM audit_log"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        query += " ORDER BY sequence_number DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return self._rows_to_audit_logs(rows)

    def count_audit_logs(
        self,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: Optional[Any] = None,
        date_to: Optional[Any] = None,
    ) -> int:
        where_clauses = []
        params: List[Any] = []

        normalized_search = str(search_text or "").strip().lower()
        if normalized_search:
            where_clauses.append(
                "(LOWER(event_type) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(user_id) LIKE ? OR LOWER(source) LIKE ? OR LOWER(details) LIKE ?)"
            )
            like_value = f"%{normalized_search}%"
            params.extend([like_value, like_value, like_value, like_value, like_value])

        normalized_event_type = str(event_type or "").strip().lower()
        if normalized_event_type and normalized_event_type not in {"all", "все"}:
            where_clauses.append("LOWER(event_type) = ?")
            params.append(normalized_event_type)

        normalized_severity = str(severity or "").strip().upper()
        if normalized_severity and normalized_severity not in {"ALL", "ВСЕ"}:
            where_clauses.append("severity = ?")
            params.append(normalized_severity)

        normalized_user = str(user_id or "").strip().lower()
        if normalized_user and normalized_user not in {"all", "все"}:
            where_clauses.append("LOWER(user_id) LIKE ?")
            params.append(f"%{normalized_user}%")

        from_dt = self._normalize_audit_datetime(date_from, is_end=False)
        if from_dt is not None:
            where_clauses.append("timestamp >= ?")
            params.append(from_dt.isoformat())

        to_dt = self._normalize_audit_datetime(date_to, is_end=True)
        if to_dt is not None:
            where_clauses.append("timestamp <= ?")
            params.append(to_dt.isoformat())

        query = "SELECT COUNT(*) AS total FROM audit_log"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        with self._get_connection() as conn:
            return int(conn.execute(query, tuple(params)).fetchone()["total"])

    def get_audit_log_chain(self, start_sequence: int = 0, limit: Optional[int] = None) -> List[AuditLog]:
        query = "SELECT rowid AS id, * FROM audit_log WHERE sequence_number >= ? ORDER BY sequence_number ASC"
        params: List[Any] = [start_sequence]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return self._rows_to_audit_logs(rows)

    def get_audit_log_by_sequence(self, sequence_number: int) -> Optional[AuditLog]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT rowid AS id, * FROM audit_log WHERE sequence_number = ?",
                (sequence_number,),
            ).fetchone()
            if row is None:
                return None
            return self._rows_to_audit_logs([row])[0]

    def get_latest_audit_log(self) -> Optional[AuditLog]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT rowid AS id, * FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            return self._rows_to_audit_logs([row])[0]

    def register_audit_public_key(self, algorithm: str, public_key: str):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_public_keys (algorithm, public_key, created_at, is_active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(public_key) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    is_active = 1
                """,
                (algorithm, public_key, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )

    def set_audit_protection_callback(self, callback: Optional[Callable[[str, Dict[str, Any]], None]]):
        self._audit_protection_callback = callback

    def set_audit_entry_data_decoder(self, decoder: Optional[Callable[[Any], str]]):
        self._audit_entry_data_decoder = decoder

    def get_audit_retention_policy(self) -> Dict[str, Any]:
        default_policy = {"enabled": True, "max_entries": 10000, "max_age_days": 365}
        stored_policy = self.get_setting("audit.retention_policy", default_policy)
        if not isinstance(stored_policy, dict):
            return dict(default_policy)
        normalized_policy = dict(default_policy)
        normalized_policy.update(stored_policy)
        normalized_policy["enabled"] = bool(normalized_policy.get("enabled", True))
        normalized_policy["max_entries"] = max(1, int(normalized_policy.get("max_entries", 10000) or 10000))
        normalized_policy["max_age_days"] = max(1, int(normalized_policy.get("max_age_days", 365) or 365))
        return normalized_policy

    def set_audit_retention_policy(self, *, max_entries: int = 10000, max_age_days: int = 365, enabled: bool = True):
        self.set_setting(
            "audit.retention_policy",
            {
                "enabled": bool(enabled),
                "max_entries": max(1, int(max_entries)),
                "max_age_days": max(1, int(max_age_days)),
            },
        )

    def get_audit_verification_policy(self) -> Dict[str, Any]:
        default_policy = {
            "interval_seconds": 24 * 60 * 60,
            "recent_entry_limit": 1000,
            "lock_on_tampering": False,
        }
        stored_policy = self.get_setting("audit.verification_policy", default_policy)
        if not isinstance(stored_policy, dict):
            return dict(default_policy)
        normalized_policy = dict(default_policy)
        normalized_policy.update(stored_policy)
        normalized_policy["interval_seconds"] = max(
            60,
            int(normalized_policy.get("interval_seconds", default_policy["interval_seconds"]) or default_policy["interval_seconds"]),
        )
        normalized_policy["recent_entry_limit"] = max(
            1,
            int(normalized_policy.get("recent_entry_limit", default_policy["recent_entry_limit"]) or default_policy["recent_entry_limit"]),
        )
        normalized_policy["lock_on_tampering"] = bool(normalized_policy.get("lock_on_tampering", False))
        return normalized_policy

    def set_audit_verification_policy(
        self,
        *,
        interval_seconds: int = 24 * 60 * 60,
        recent_entry_limit: int = 1000,
        lock_on_tampering: bool = False,
    ):
        self.set_setting(
            "audit.verification_policy",
            {
                "interval_seconds": max(60, int(interval_seconds)),
                "recent_entry_limit": max(1, int(recent_entry_limit)),
                "lock_on_tampering": bool(lock_on_tampering),
            },
        )

    def archive_audit_logs(
        self,
        *,
        max_entries: int = 10000,
        max_age_days: int = 365,
        reason: str = "retention_policy",
        exporter: str = "CryptoSafe Manager",
    ) -> Dict[str, Any]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT rowid AS id, * FROM audit_log ORDER BY sequence_number ASC").fetchall()
            logs = self._rows_to_audit_logs(rows)
            if not logs:
                return {"archived": False, "entry_count": 0}

            latest_archived_end = conn.execute("SELECT MAX(range_end_sequence) AS max_seq FROM audit_archives").fetchone()[
                "max_seq"
            ]
            latest_archived_end = int(latest_archived_end or 0)
            cutoff_timestamp = datetime.now(timezone.utc) - timedelta(days=max(1, int(max_age_days)))

            candidate_end_sequence = 0
            total_logs = len(logs)
            if total_logs > max_entries:
                candidate_end_sequence = logs[total_logs - max_entries - 1].sequence_number

            for log in logs:
                timestamp = log.timestamp
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                if timestamp <= cutoff_timestamp:
                    candidate_end_sequence = max(candidate_end_sequence, int(log.sequence_number))

            if candidate_end_sequence <= latest_archived_end:
                return {"archived": False, "entry_count": 0}

            logs_to_archive = [
                log
                for log in logs
                if latest_archived_end < int(log.sequence_number) <= int(candidate_end_sequence)
            ]
            if not logs_to_archive:
                return {"archived": False, "entry_count": 0}

            from ..core.audit.log_formatters import export_logs_to_json

            archive_data = export_logs_to_json(logs_to_archive, exporter=exporter)
            archive_hash = hashlib.sha256(archive_data.encode("utf-8")).hexdigest()
            created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            cursor = conn.execute(
                """
                INSERT INTO audit_archives (
                    created_at,
                    reason,
                    range_start_sequence,
                    range_end_sequence,
                    entry_count,
                    archive_data,
                    archive_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    reason,
                    int(logs_to_archive[0].sequence_number),
                    int(logs_to_archive[-1].sequence_number),
                    len(logs_to_archive),
                    archive_data,
                    archive_hash,
                ),
            )
            return {
                "archived": True,
                "archive_id": int(cursor.lastrowid),
                "entry_count": len(logs_to_archive),
                "range_start_sequence": int(logs_to_archive[0].sequence_number),
                "range_end_sequence": int(logs_to_archive[-1].sequence_number),
                "archive_hash": archive_hash,
                "reason": reason,
            }

    def get_audit_archives(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, reason, range_start_sequence, range_end_sequence, entry_count, archive_hash
                FROM audit_archives
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def add_audit_security_event(
        self,
        event_type: str,
        *,
        severity: str = "CRITICAL",
        details: Any = "",
        related_sequence_number: Optional[int] = None,
    ) -> int:
        if isinstance(details, str):
            normalized_details = details
        else:
            normalized_details = json.dumps(details, ensure_ascii=False, sort_keys=True)
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_security_log (
                    timestamp,
                    event_type,
                    severity,
                    related_sequence_number,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    str(event_type or ""),
                    str(severity or "CRITICAL"),
                    related_sequence_number,
                    normalized_details,
                ),
            )
            return int(cursor.lastrowid)

    def get_audit_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, event_type, severity, related_sequence_number, details
                FROM audit_security_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
            return [dict(row) for row in rows]

    def try_update_audit_log_entry(self, sequence_number: int, entry_data: str):
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                    (entry_data, sequence_number),
                )
        except sqlite3.DatabaseError as error:
            self._notify_audit_protection_violation(
                "update",
                {"sequence_number": sequence_number, "message": str(error)},
            )
            raise

    def try_delete_audit_log_entry(self, sequence_number: int):
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM audit_log WHERE sequence_number = ?", (sequence_number,))
        except sqlite3.DatabaseError as error:
            self._notify_audit_protection_violation(
                "delete",
                {"sequence_number": sequence_number, "message": str(error)},
            )
            raise

    def try_disable_audit_guards(self):
        self._notify_audit_protection_violation(
            "disable_protection",
            {"message": "Отключение append-only защиты журнала аудита запрещено"},
        )
        raise PermissionError("Отключение append-only защиты журнала аудита запрещено")

    def import_audit_logs(self, entries: List[Dict[str, Any]]):
        with self.transaction() as conn:
            for entry in entries:
                conn.execute(
                    """
                    INSERT INTO audit_log (
                        sequence_number,
                        timestamp,
                        event_type,
                        severity,
                        user_id,
                        source,
                        entry_id,
                        details,
                        action,
                        previous_hash,
                        entry_hash,
                        entry_data,
                        signature,
                        public_key
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(entry.get("sequence_number", 0) or 0),
                        str(entry.get("timestamp", "")),
                        str(entry.get("event_type", entry.get("action", "")) or ""),
                        str(entry.get("severity", "INFO") or "INFO"),
                        str(entry.get("user_id", "local-user") or "local-user"),
                        str(entry.get("source", "unknown") or "unknown"),
                        entry.get("entry_id"),
                        str(entry.get("details", "") or ""),
                        str(entry.get("event_type", entry.get("action", "")) or ""),
                        str(entry.get("previous_hash", "") or ""),
                        str(entry.get("entry_hash", "") or ""),
                        str(entry.get("entry_data", "") or ""),
                        str(entry.get("signature", "") or ""),
                        str(entry.get("public_key", "") or ""),
                    ),
                )

    def add_shared_entry(
        self,
        *,
        share_id: str,
        original_entry_id: Optional[int],
        encryption_method: str,
        recipient_info: str,
        permissions: Dict[str, Any],
        shared_at: datetime,
        expires_at: datetime,
        status: str = "active",
        package_checksum: str = "",
    ):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO shared_entries (
                    share_id,
                    original_entry_id,
                    encryption_method,
                    recipient_info,
                    permissions,
                    shared_at,
                    expires_at,
                    status,
                    package_checksum
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(share_id),
                    original_entry_id,
                    str(encryption_method),
                    str(recipient_info),
                    json.dumps(permissions or {}, ensure_ascii=False, sort_keys=True),
                    shared_at.isoformat(),
                    expires_at.isoformat(),
                    str(status or "active"),
                    str(package_checksum or ""),
                ),
            )

    def get_shared_entries(self, *, limit: int = 100, status: str = "") -> List[Dict[str, Any]]:
        query = "SELECT * FROM shared_entries"
        params: List[Any] = []
        normalized_status = str(status or "").strip()
        if normalized_status:
            query += " WHERE status = ?"
            params.append(normalized_status)
        query += " ORDER BY shared_at DESC LIMIT ?"
        params.append(max(1, int(limit)))
        with self._get_connection() as conn:
            return [dict(row) for row in conn.execute(query, tuple(params)).fetchall()]

    def add_import_export_history(
        self,
        *,
        operation_type: str,
        format: str,
        encryption_used: str,
        entry_count: int,
        file_size: int,
        checksum: str,
        verification_status: str,
        details: Optional[Dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
    ) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO import_export_history (
                    operation_type,
                    format,
                    encryption_used,
                    entry_count,
                    file_size,
                    checksum,
                    verification_status,
                    created_at,
                    details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(operation_type),
                    str(format),
                    str(encryption_used),
                    max(0, int(entry_count)),
                    max(0, int(file_size)),
                    str(checksum),
                    str(verification_status),
                    (created_at or datetime.now(timezone.utc)).isoformat(),
                    json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
                ),
            )
            return int(cursor.lastrowid)

    def get_import_export_history(self, *, limit: int = 100, operation_type: str = "") -> List[Dict[str, Any]]:
        query = "SELECT * FROM import_export_history"
        params: List[Any] = []
        normalized_operation = str(operation_type or "").strip()
        if normalized_operation:
            query += " WHERE operation_type = ?"
            params.append(normalized_operation)
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(max(1, int(limit)))
        with self._get_connection() as conn:
            return [dict(row) for row in conn.execute(query, tuple(params)).fetchall()]

    def upsert_contact(
        self,
        *,
        name: str,
        identifier: str,
        public_key: str,
        key_fingerprint: str,
        status: str = "active",
        last_used_at: Optional[datetime] = None,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO contacts (
                    name,
                    identifier,
                    public_key,
                    key_fingerprint,
                    status,
                    created_at,
                    last_used_at,
                    revoked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(identifier) DO UPDATE SET
                    name = excluded.name,
                    public_key = excluded.public_key,
                    key_fingerprint = excluded.key_fingerprint,
                    status = excluded.status,
                    last_used_at = COALESCE(excluded.last_used_at, contacts.last_used_at),
                    revoked_at = CASE WHEN excluded.status = 'revoked' THEN COALESCE(contacts.revoked_at, ?) ELSE NULL END
                """,
                (
                    str(name),
                    str(identifier),
                    str(public_key),
                    str(key_fingerprint),
                    str(status or "active"),
                    now,
                    last_used_at.isoformat() if last_used_at else None,
                    now,
                ),
            )
            row = conn.execute("SELECT id FROM contacts WHERE identifier = ?", (str(identifier),)).fetchone()
            return int(row["id"])

    def get_contacts(self, *, include_revoked: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM contacts"
        params: List[Any] = []
        if not include_revoked:
            query += " WHERE status != ?"
            params.append("revoked")
        query += " ORDER BY name COLLATE NOCASE ASC LIMIT ?"
        params.append(max(1, int(limit)))
        with self._get_connection() as conn:
            return [dict(row) for row in conn.execute(query, tuple(params)).fetchall()]

    def revoke_contact(self, identifier: str) -> bool:
        revoked_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE contacts
                SET status = 'revoked',
                    revoked_at = ?
                WHERE identifier = ?
                """,
                (revoked_at, str(identifier)),
            )
            return cursor.rowcount > 0

    def backup(self, backup_path: str):
        backup_file = Path(backup_path)
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(self.db_path)
        destination = sqlite3.connect(str(backup_file))
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

    def set_setting(self, key: str, value, encrypted: bool = False):
        serialized = json.dumps(value, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
                """,
                (key, serialized, int(encrypted)),
            )

    def get_setting(self, key: str, default=None):
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT setting_value FROM settings WHERE setting_key = ?",
                (key,),
            ).fetchone()
            if not row:
                return default
            try:
                return json.loads(row["setting_value"])
            except (TypeError, json.JSONDecodeError):
                return row["setting_value"]

    def save_key_store(self, key_store: KeyStore):
        now = datetime.now()
        created_at = (key_store.created_at or now).isoformat()
        last_rotated_at = (key_store.last_rotated_at or now).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store
                (key_type, key_data, version, created_at, salt, hash, params, last_rotated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    key_data = excluded.key_data,
                    version = excluded.version,
                    salt = excluded.salt,
                    hash = excluded.hash,
                    params = excluded.params,
                    last_rotated_at = excluded.last_rotated_at
                """,
                (
                    key_store.key_type,
                    key_store.key_data,
                    key_store.version,
                    created_at,
                    key_store.salt,
                    key_store.hash,
                    key_store.params,
                    last_rotated_at,
                ),
            )

    def get_key_store(self, key_type: str) -> Optional[KeyStore]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM key_store WHERE key_type = ?", (key_type,)).fetchone()
            if not row:
                return None
            return self._row_to_key_store(row)

    def reencrypt_passwords(
        self,
        transform,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        pause_event=None,
    ) -> int:
        with self.transaction() as conn:
            rows = conn.execute("SELECT id, encrypted_password FROM vault_entries ORDER BY id").fetchall()
            total = len(rows)
            if progress_callback is not None:
                progress_callback(0, total)
            for index, row in enumerate(rows, start=1):
                if pause_event is not None:
                    pause_event.wait()
                updated_password = transform(row["encrypted_password"])
                conn.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_password = ?, encrypted_data = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_password, updated_password, datetime.now().isoformat(), row["id"]),
                )
                if progress_callback is not None:
                    progress_callback(index, total)
            return total

    def reencrypt_entry_payloads(
        self,
        transform,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        pause_event=None,
    ) -> int:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT id, encrypted_password, encrypted_data FROM vault_entries ORDER BY id"
            ).fetchall()
            total = len(rows)
            if progress_callback is not None:
                progress_callback(0, total)
            for index, row in enumerate(rows, start=1):
                if pause_event is not None:
                    pause_event.wait()
                updated_password, updated_data = transform(row["encrypted_password"], row["encrypted_data"])
                conn.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_password = ?, encrypted_data = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_password, updated_data, datetime.now().isoformat(), row["id"]),
                )
                if progress_callback is not None:
                    progress_callback(index, total)
            return total

    def reencrypt_audit_entry_payloads(
        self,
        transform,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        pause_event=None,
    ) -> int:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT rowid AS audit_rowid, sequence_number, entry_data FROM audit_log ORDER BY sequence_number ASC"
            ).fetchall()
            total = len(rows)
            if progress_callback is not None:
                progress_callback(0, total)

            self._drop_audit_guards(conn)
            try:
                for index, row in enumerate(rows, start=1):
                    if pause_event is not None:
                        pause_event.wait()
                    updated_entry_data = transform(row["entry_data"])
                    conn.execute(
                        "UPDATE audit_log SET entry_data = ? WHERE rowid = ?",
                        (updated_entry_data, row["audit_rowid"]),
                    )
                    if progress_callback is not None:
                        progress_callback(index, total)
            finally:
                self._create_audit_guards(conn)
            return total

    def _compute_hash(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _rows_to_audit_logs(self, rows) -> List[AuditLog]:
        result: List[AuditLog] = []
        for row in rows:
            data = dict(row)
            if data.get("timestamp"):
                data["timestamp"] = datetime.fromisoformat(data["timestamp"])
            if not data.get("action"):
                data["action"] = data.get("event_type", "")
            data["entry_data"] = self._decode_audit_entry_data(data.get("entry_data", ""))
            if not data.get("details") and data.get("entry_data"):
                try:
                    payload = json.loads(data["entry_data"])
                    data["details"] = json.dumps(payload.get("details", {}), ensure_ascii=False, sort_keys=True)
                except (TypeError, json.JSONDecodeError):
                    data["details"] = ""
            result.append(AuditLog(**data))
        return result

    def _decode_audit_entry_data(self, raw_value: Any) -> str:
        if raw_value is None:
            return ""
        if self._audit_entry_data_decoder is None:
            return raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
        try:
            decoded = self._audit_entry_data_decoder(raw_value)
            return str(decoded or "")
        except Exception:
            return raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)

    def _normalize_audit_datetime(self, raw_value: Any, *, is_end: bool) -> Optional[datetime]:
        if isinstance(raw_value, datetime):
            return raw_value
        if isinstance(raw_value, date):
            return datetime.combine(raw_value, time.max if is_end else time.min)

        value = str(raw_value or "").strip()
        if not value:
            return None

        try:
            parsed_date = datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None

        return datetime.combine(parsed_date, time.max if is_end else time.min)

    def _notify_audit_protection_violation(self, operation: str, details: Dict[str, Any]):
        if self._audit_protection_callback is None:
            return
        try:
            self._audit_protection_callback(operation, dict(details))
        except Exception:
            pass

    def _row_to_entry(self, row: sqlite3.Row) -> VaultEntry:
        data = dict(row)
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("updated_at"):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        return VaultEntry(**data)

    def _row_to_key_store(self, row: sqlite3.Row) -> KeyStore:
        data = dict(row)
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("last_rotated_at"):
            data["last_rotated_at"] = datetime.fromisoformat(data["last_rotated_at"])
        return KeyStore(**data)