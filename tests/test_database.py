import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.db import Database
from src.database.models import KeyStore, VaultEntry


class TestDatabase(unittest.TestCase):  #класс для тестирования функциональности базы данных
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.db_path = self.temp_file.name
        self.db = Database(self.db_path)
        self.test_entry = VaultEntry(
            title="Test Site",
            username="test_user",
            encrypted_password=b"encrypted_test",
            encrypted_data=b"encrypted_test",
            url="https://test.com",
            notes="test notes",
            category="General",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags="test",
        )

    def tearDown(self):  #метод для очистки тестовой среды после каждого теста, который удаляет временный файл базы данных
        self.db.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_add_entry(self):  #тест для проверки добавления записи в базу данных
        entry_id = self.db.add_entry(self.test_entry)
        self.assertIsNotNone(entry_id)
        self.assertGreater(entry_id, 0)

    def test_get_entry(self):  #тест для проверки получения записи из базы данных
        entry_id = self.db.add_entry(self.test_entry)
        loaded = self.db.get_entry(entry_id)

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, self.test_entry.title)
        self.assertEqual(loaded.username, self.test_entry.username)

    def test_get_all_entries(self):  #тест для проверки получения всех записей из базы данных
        self.db.add_entry(self.test_entry)
        self.db.add_entry(self.test_entry)
        self.db.add_entry(self.test_entry)

        entries = self.db.get_all_entries()
        self.assertEqual(len(entries), 3)

    def test_update_entry(self):  #тест для проверки обновления записи
        entry_id = self.db.add_entry(self.test_entry)

        entry = self.db.get_entry(entry_id)
        entry.title = "Updated Title"
        self.db.update_entry(entry)

        updated = self.db.get_entry(entry_id)
        self.assertEqual(updated.title, "Updated Title")

    def test_delete_entry(self):  #тест для проверки удаления записи
        entry_id = self.db.add_entry(self.test_entry)
        self.db.delete_entry(entry_id)

        deleted = self.db.get_entry(entry_id)
        self.assertIsNone(deleted)

    def test_user_version(self):  #тест для проверки, что версия базы данных установлена правильно
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA user_version")
            version = cursor.fetchone()[0]
            self.assertEqual(version, 6)

            archive_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_archives'"
            ).fetchone()
            self.assertIsNotNone(archive_table)
            security_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_security_log'"
            ).fetchone()
            self.assertIsNotNone(security_table)
            shared_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'shared_entries'"
            ).fetchone()
            self.assertIsNotNone(shared_table)
            history_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'import_export_history'"
            ).fetchone()
            self.assertIsNotNone(history_table)
            contacts_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'contacts'"
            ).fetchone()
            self.assertIsNotNone(contacts_table)

            update_trigger = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_audit_log_no_update'"
            ).fetchone()
            delete_trigger = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_audit_log_no_delete'"
            ).fetchone()
            self.assertIsNotNone(update_trigger)
            self.assertIsNotNone(delete_trigger)

    def test_settings_roundtrip(self):  #тест для проверки сохранения и получения настроек из базы данных
        self.db.set_setting("security.password_policy", {"min_length": 12})
        policy = self.db.get_setting("security.password_policy")
        self.assertEqual(policy["min_length"], 12)

    def test_key_store_roundtrip(self):  #тест для проверки сохранения и получения записи из хранилища ключей
        record = KeyStore(
            key_type="auth_hash",
            key_data=b"$argon2id$example",
            version=19,
            hash="$argon2id$example",
            created_at=datetime.now(),
            last_rotated_at=datetime.now(),
        )
        self.db.save_key_store(record)

        loaded = self.db.get_key_store("auth_hash")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.key_type, "auth_hash")
        self.assertEqual(loaded.version, 19)
        self.assertEqual(loaded.key_data, b"$argon2id$example")

    def test_reencrypt_passwords_reports_progress_and_respects_pause(self):
        first_id = self.db.add_entry(
            VaultEntry(
                title="One",
                username="user1",
                encrypted_password=b"one",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )
        second_id = self.db.add_entry(
            VaultEntry(
                title="Two",
                username="user2",
                encrypted_password=b"two",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )

        progress_updates = []
        pause_event = threading.Event()
        pause_event.clear()

        def release_pause():
            time.sleep(0.05)
            pause_event.set()

        threading.Thread(target=release_pause, daemon=True).start()

        updated = self.db.reencrypt_passwords(
            lambda ciphertext: ciphertext + b"!",
            progress_callback=lambda processed, total: progress_updates.append((processed, total)),
            pause_event=pause_event,
        )

        self.assertEqual(updated, 2)
        self.assertEqual(progress_updates[0], (0, 2))
        self.assertEqual(progress_updates[-1], (2, 2))
        self.assertEqual(self.db.get_entry(first_id).encrypted_password, b"one!")
        self.assertEqual(self.db.get_entry(second_id).encrypted_password, b"two!")
        self.assertEqual(self.db.get_entry(first_id).encrypted_data, b"one!")
        self.assertEqual(self.db.get_entry(second_id).encrypted_data, b"two!")

    def test_new_schema_supports_encrypted_data_and_category(self):
        entry_id = self.db.add_entry(self.test_entry)
        loaded = self.db.get_entry(entry_id)

        self.assertEqual(loaded.encrypted_data, b"encrypted_test")
        self.assertEqual(loaded.category, "General")

    def test_migration_v3_to_v4_backfills_encrypted_data(self):
        with self.db._get_connection() as conn:
            conn.execute("PRAGMA user_version = 3")
            conn.execute("DROP TABLE vault_entries")
            conn.execute(
                """
                CREATE TABLE vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    url TEXT,
                    notes TEXT,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    tags TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Legacy",
                    "user",
                    b"legacy-secret",
                    "",
                    "",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    "",
                ),
            )

        migrated = Database(self.db_path)
        entry = migrated.get_entry(1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.encrypted_password, b"legacy-secret")
        self.assertEqual(entry.encrypted_data, b"legacy-secret")
        self.assertEqual(entry.category, "")

    def test_migration_v4_to_v5_backfills_legacy_audit_rows(self):
        legacy_temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        legacy_temp.close()
        initial_db = Database(legacy_temp.name)
        initial_db.close()

        import sqlite3

        legacy_conn = sqlite3.connect(legacy_temp.name)
        try:
            conn = legacy_conn
            conn.execute("PRAGMA user_version = 4")
            conn.execute("DROP TABLE audit_log")
            conn.execute(
                """
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    entry_id INTEGER,
                    details TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO audit_log (action, timestamp, entry_id, details)
                VALUES (?, ?, ?, ?)
                """,
                ("entry_added", datetime.now().isoformat(), 7, "legacy details"),
            )
            conn.commit()
        finally:
            legacy_conn.close()

        migrated = Database(legacy_temp.name)
        try:
            with migrated._get_connection() as conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                row = conn.execute(
                    "SELECT sequence_number, event_type, source, entry_data FROM audit_log"
                ).fetchone()

            self.assertEqual(version, 6)
            self.assertEqual(row["sequence_number"], 1)
            self.assertEqual(row["event_type"], "entry_added")
            self.assertEqual(row["source"], "legacy_migration")
            self.assertIn("legacy details", row["entry_data"])
        finally:
            migrated.close()
            try:
                os.unlink(legacy_temp.name)
            except OSError:
                pass

    def test_existing_v5_audit_rows_with_missing_sequence_are_repaired(self):
        legacy_temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        legacy_temp.close()

        import sqlite3

        legacy_conn = sqlite3.connect(legacy_temp.name)
        try:
            conn = legacy_conn
            conn.execute("PRAGMA user_version = 5")
            conn.execute(
                """
                CREATE TABLE audit_log (
                    sequence_number INTEGER,
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
            conn.execute(
                """
                INSERT INTO audit_log (
                    sequence_number, timestamp, event_type, severity, user_id, source,
                    entry_id, details, action, previous_hash, entry_hash, entry_data,
                    signature, public_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    7,
                    "2026-04-07T10:00:00",
                    "legacy_event",
                    "INFO",
                    "local-user",
                    "legacy_migration",
                    None,
                    "{}",
                    "legacy_event",
                    "0" * 64,
                    "a" * 64,
                    "{}",
                    "legacy",
                    "legacy",
                ),
            )
            conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, event_type, severity, user_id, source,
                    entry_id, details, action, previous_hash, entry_hash, entry_data,
                    signature, public_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-05-16T20:15:19+00:00",
                    "entry_added",
                    "INFO",
                    "local-user",
                    "vault",
                    12,
                    "{}",
                    "entry_added",
                    "a" * 64,
                    "b" * 64,
                    "{}",
                    "signature",
                    "public",
                ),
            )
            conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, event_type, severity, user_id, source,
                    entry_id, details, action, previous_hash, entry_hash, entry_data,
                    signature, public_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-05-16T20:15:30+00:00",
                    "user_logged_out",
                    "INFO",
                    "local-user",
                    "authentication",
                    None,
                    "{}",
                    "user_logged_out",
                    "a" * 64,
                    "c" * 64,
                    "{}",
                    "signature",
                    "public",
                ),
            )
            conn.commit()
        finally:
            legacy_conn.close()

        migrated = Database(legacy_temp.name)
        try:
            migrated.add_audit_log(
                "user_logged_out",
                datetime.now(),
                details="{}",
                event_type="user_logged_out",
                severity="INFO",
                user_id="local-user",
                source="authentication",
                previous_hash="b" * 64,
                entry_hash="c" * 64,
                entry_data="{}",
                signature="signature",
                public_key="public",
            )
            with migrated._get_connection() as conn:
                null_count = conn.execute(
                    "SELECT COUNT(*) AS total FROM audit_log WHERE sequence_number IS NULL"
                ).fetchone()["total"]
                rows = conn.execute(
                    "SELECT sequence_number, event_type, previous_hash, entry_hash, signature FROM audit_log ORDER BY sequence_number DESC"
                ).fetchall()

            self.assertEqual(null_count, 0)
            self.assertEqual(
                [row["event_type"] for row in rows[:4]],
                ["user_logged_out", "user_logged_out", "entry_added", "legacy_event"],
            )
            self.assertEqual([row["sequence_number"] for row in rows[:4]], [10, 9, 8, 7])
            self.assertEqual(rows[1]["signature"], "legacy")
            self.assertEqual(rows[1]["previous_hash"], rows[2]["entry_hash"])
        finally:
            migrated.close()
            try:
                os.unlink(legacy_temp.name)
            except OSError:
                pass

    def test_connection_pool_reuses_connections_between_requests(self):
        with self.db._get_connection() as first_conn:
            first_id = id(first_conn)

        with self.db._get_connection() as second_conn:
            second_id = id(second_conn)

        self.assertEqual(first_id, second_id)

    def test_audit_verification_policy_roundtrip(self):
        self.db.set_audit_verification_policy(interval_seconds=7200, recent_entry_limit=250, lock_on_tampering=True)
        policy = self.db.get_audit_verification_policy()
        self.assertEqual(policy["interval_seconds"], 7200)
        self.assertEqual(policy["recent_entry_limit"], 250)
        self.assertTrue(policy["lock_on_tampering"])

    def test_audit_security_event_roundtrip(self):
        event_id = self.db.add_audit_security_event(
            "audit_verification_failed",
            details={"trigger": "startup", "invalid_entries": 2},
            related_sequence_number=7,
        )
        self.assertGreater(event_id, 0)
        events = self.db.get_audit_security_events(limit=5)
        self.assertEqual(events[0]["event_type"], "audit_verification_failed")
        self.assertEqual(events[0]["related_sequence_number"], 7)
        self.assertIn('"trigger": "startup"', events[0]["details"])

    def test_import_export_history_roundtrip(self):
        history_id = self.db.add_import_export_history(
            operation_type="export",
            format="encrypted_json",
            encryption_used="AES-256-GCM",
            entry_count=3,
            file_size=2048,
            checksum="abc123",
            verification_status="verified",
            details={"selected": True},
        )

        rows = self.db.get_import_export_history(limit=5, operation_type="export")

        self.assertGreater(history_id, 0)
        self.assertEqual(rows[0]["format"], "encrypted_json")
        self.assertEqual(rows[0]["encryption_used"], "AES-256-GCM")
        self.assertEqual(rows[0]["entry_count"], 3)
        self.assertIn('"selected": true', rows[0]["details"])

    def test_shared_entries_roundtrip(self):
        entry_id = self.db.add_entry(self.test_entry)
        shared_at = datetime.now()
        expires_at = datetime.now()

        self.db.add_shared_entry(
            share_id="share-1",
            original_entry_id=entry_id,
            encryption_method="password",
            recipient_info="student@example.test",
            permissions={"read": True, "edit": False},
            shared_at=shared_at,
            expires_at=expires_at,
            package_checksum="checksum",
        )

        rows = self.db.get_shared_entries(limit=5, status="active")

        self.assertEqual(rows[0]["share_id"], "share-1")
        self.assertEqual(rows[0]["original_entry_id"], entry_id)
        self.assertEqual(rows[0]["encryption_method"], "password")
        self.assertIn('"read": true', rows[0]["permissions"])

    def test_contacts_roundtrip_and_revocation(self):
        contact_id = self.db.upsert_contact(
            name="Alice",
            identifier="alice@example.test",
            public_key="public-key",
            key_fingerprint="AA:BB",
        )
        updated_id = self.db.upsert_contact(
            name="Alice Cooper",
            identifier="alice@example.test",
            public_key="rotated-public-key",
            key_fingerprint="CC:DD",
        )

        contacts = self.db.get_contacts(limit=5)
        revoked = self.db.revoke_contact("alice@example.test")
        active_after_revoke = self.db.get_contacts(limit=5)
        all_contacts = self.db.get_contacts(include_revoked=True, limit=5)

        self.assertEqual(contact_id, updated_id)
        self.assertEqual(contacts[0]["name"], "Alice Cooper")
        self.assertEqual(contacts[0]["public_key"], "rotated-public-key")
        self.assertTrue(revoked)
        self.assertEqual(active_after_revoke, [])
        self.assertEqual(all_contacts[0]["status"], "revoked")


if __name__ == "__main__":
    unittest.main()