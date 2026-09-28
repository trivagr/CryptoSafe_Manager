import os
import sys
import tempfile
import time
import tracemalloc
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.events import EventType, event_bus
from src.core.key_manager import KeyManager
from src.core.vault import AESGCMEncryptionService, EntryManager, EntryNotFoundError
from src.database.db import Database


class TestEntryManager(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.database = Database(self.temp_file.name)
        self.key_manager = KeyManager()
        self.key_manager.store_key("active", os.urandom(32))
        self.manager = EntryManager(self.database, AESGCMEncryptionService(self.key_manager))

    def tearDown(self):
        self.key_manager.clear_key()
        self.database.close()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def test_create_and_get_entry_roundtrip(self):
        created = self.manager.create_entry(
            {
                "title": "Example",
                "username": "user@example.com",
                "password": "Secret!123",
                "url": "https://example.com",
                "notes": "Important",
                "category": "Work",
                "tags": ["work", "mail"],
            }
        )

        loaded = self.manager.get_entry(created["id"])

        self.assertEqual(loaded["title"], "Example")
        self.assertEqual(loaded["username"], "user@example.com")
        self.assertEqual(loaded["password"], "Secret!123")
        self.assertEqual(loaded["category"], "Work")
        self.assertEqual(loaded["tags"], "work,mail")

        raw_entry = self.database.get_entry(created["id"])
        self.assertIsNotNone(raw_entry)
        self.assertEqual(raw_entry.encrypted_password, b"")
        self.assertNotIn(b"Secret!123", raw_entry.encrypted_data)

    def test_get_all_entries_returns_decrypted_entries(self):
        self.manager.create_entry({"title": "One", "password": "alpha"})
        self.manager.create_entry({"title": "Two", "password": "beta"})

        entries = self.manager.get_all_entries()

        self.assertEqual(len(entries), 2)
        self.assertEqual({entry["title"] for entry in entries}, {"One", "Two"})

    def test_update_entry_reencrypts_payload(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        updated = self.manager.update_entry(
            created["id"],
            {
                "username": "new-user",
                "password": "NewSecret!456",
                "category": "Updated",
            },
        )

        self.assertEqual(updated["username"], "new-user")
        self.assertEqual(updated["password"], "NewSecret!456")
        self.assertEqual(updated["category"], "Updated")

    def test_create_entry_persists_category(self):
        created = self.manager.create_entry(
            {
                "title": "Categorized",
                "password": "Secret!123",
                "category": "Work",
            }
        )

        loaded = self.manager.get_entry(created["id"])

        self.assertEqual(loaded["category"], "Work")

    def test_delete_entry_soft_deletes_by_default(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        self.manager.delete_entry(created["id"])

        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(created["id"])

        with self.database._get_connection() as conn:
            deleted_row = conn.execute(
                "SELECT original_entry_id, encrypted_data, title FROM deleted_entries WHERE original_entry_id = ?",
                (created["id"],),
            ).fetchone()

        self.assertIsNotNone(deleted_row)
        self.assertEqual(deleted_row["original_entry_id"], created["id"])
        self.assertEqual(deleted_row["title"], "Example")
        self.assertNotIn(b"Secret!123", deleted_row["encrypted_data"])

    def test_delete_entry_can_hard_delete_without_recycle_bin(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        self.manager.delete_entry(created["id"], soft_delete=False)

        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(created["id"])

        with self.database._get_connection() as conn:
            deleted_row = conn.execute(
                "SELECT original_entry_id FROM deleted_entries WHERE original_entry_id = ?",
                (created["id"],),
            ).fetchone()

        self.assertIsNone(deleted_row)

    def test_missing_entry_raises_safe_error(self):
        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(999999)

    def test_create_entry_publishes_event(self):
        received_events = []

        def handler(event):
            received_events.append(event)

        event_bus.subscribe(EventType.ENTRY_ADDED, handler)
        try:
            created = self.manager.create_entry({"title": "Published", "password": "Secret!123"})
        finally:
            event_bus.unsubscribe(EventType.ENTRY_ADDED, handler)

        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0].data["id"], created["id"])

    def test_get_entry_prefers_encrypted_data_from_new_schema(self):
        created = self.manager.create_entry({"title": "Schema", "password": "Secret!123"})
        raw_entry = self.database.get_entry(created["id"])
        self.assertIsNotNone(raw_entry)

        self.assertEqual(raw_entry.encrypted_password, b"")
        self.assertTrue(raw_entry.encrypted_data)

        loaded = self.manager.get_entry(created["id"])
        self.assertEqual(loaded["password"], "Secret!123")

    def test_crud_integration_handles_bulk_entry_lifecycle(self):
        created_ids = []
        for index in range(100):
            created = self.manager.create_entry(
                {
                    "title": f"Entry {index}",
                    "username": f"user{index}@example.com",
                    "password": f"Secret!{index:03d}Aa",
                    "url": f"https://example{index}.com",
                    "notes": f"note-{index}",
                    "category": "Work" if index % 2 == 0 else "Personal",
                    "tags": [f"tag-{index}", "bulk"],
                }
            )
            created_ids.append(created["id"])

        all_entries = self.manager.get_all_entries()
        self.assertEqual(len(all_entries), 100)
        self.assertEqual({entry["id"] for entry in all_entries}, set(created_ids))

        for entry_id in created_ids[:20]:
            updated = self.manager.update_entry(
                entry_id,
                {
                    "title": f"Updated {entry_id}",
                    "password": f"Updated!{entry_id:03d}Bb",
                    "category": "Updated",
                    "notes": f"updated-note-{entry_id}",
                },
            )
            self.assertEqual(updated["category"], "Updated")
            self.assertTrue(updated["title"].startswith("Updated "))
            self.assertTrue(updated["password"].startswith("Updated!"))

        for entry_id in created_ids[:10]:
            self.manager.delete_entry(entry_id)

        remaining_entries = self.manager.get_all_entries()
        self.assertEqual(len(remaining_entries), 90)
        self.assertFalse(any(entry["id"] in set(created_ids[:10]) for entry in remaining_entries))

        with self.database._get_connection() as conn:
            deleted_count = conn.execute("SELECT COUNT(*) AS total FROM deleted_entries").fetchone()["total"]
        self.assertEqual(deleted_count, 10)

        sample_updated = self.manager.get_entry(created_ids[10])
        self.assertEqual(sample_updated["category"], "Updated")
        self.assertEqual(sample_updated["notes"], f"updated-note-{created_ids[10]}")

    def test_future_fields_roundtrip_and_update(self):
        created = self.manager.create_entry(
            {
                "title": "Future-ready",
                "password": "Secret!123",
                "totp_secret": "JBSWY3DPEHPK3PXP",
                "sharing_metadata": {"shared_with": ["alice"], "permission": "read"},
            }
        )

        loaded = self.manager.get_entry(created["id"])
        self.assertEqual(loaded["totp_secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(loaded["sharing_metadata"], {"shared_with": ["alice"], "permission": "read"})

        updated = self.manager.update_entry(
            created["id"],
            {
                "sharing_metadata": {"shared_with": ["alice", "bob"], "permission": "write"},
                "totp_secret": "NB2W45DFOIZA====",
            },
        )

        self.assertEqual(updated["totp_secret"], "NB2W45DFOIZA====")
        self.assertEqual(updated["sharing_metadata"]["permission"], "write")
        self.assertEqual(updated["sharing_metadata"]["shared_with"], ["alice", "bob"])

    def test_search_entries_supports_general_and_field_specific_filters(self):
        self.manager.create_entry(
            {
                "title": "GitHub",
                "username": "octocat",
                "password": "Secret!123",
                "url": "https://github.com",
                "notes": "code hosting",
                "category": "Work",
                "tags": ["dev", "code"],
            }
        )
        self.manager.create_entry(
            {
                "title": "Local Admin",
                "username": "admin",
                "password": "Secret!456",
                "url": "http://localhost",
                "notes": "local server",
                "category": "Home",
                "tags": ["infra", "local"],
            }
        )

        general_results = self.manager.search_entries("github")
        self.assertEqual([entry["title"] for entry in general_results], ["GitHub"])

        field_results = self.manager.search_entries("title:local notes:server")
        self.assertEqual([entry["title"] for entry in field_results], ["Local Admin"])

        category_results = self.manager.search_entries("", category="Work")
        self.assertEqual([entry["title"] for entry in category_results], ["GitHub"])

        tag_results = self.manager.search_entries("tags:infra")
        self.assertEqual([entry["title"] for entry in tag_results], ["Local Admin"])

        explicit_tag_filter_results = self.manager.search_entries("", tag="dev")
        self.assertEqual([entry["title"] for entry in explicit_tag_filter_results], ["GitHub"])

    def test_search_entries_publish_anonymized_audit_event(self):
        self.manager.create_entry(
            {
                "title": "GitHub",
                "username": "octocat",
                "password": "Secret!123",
                "notes": "repository",
            }
        )
        received_events = []

        def handler(event):
            received_events.append(event)

        event_bus.subscribe(EventType.SEARCH_PERFORMED, handler)
        try:
            results = self.manager.search_entries("github")
        finally:
            event_bus.unsubscribe(EventType.SEARCH_PERFORMED, handler)

        self.assertEqual(len(results), 1)
        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0].data["query_length"], 6)
        self.assertEqual(received_events[0].data["result_count"], 1)
        self.assertNotEqual(received_events[0].data["query_hash"], "")
        self.assertNotIn("github", str(received_events[0].data).lower())

    def test_search_entries_supports_fuzzy_matching_for_typos(self):
        self.manager.create_entry(
            {
                "title": "GitHub",
                "username": "octocat",
                "password": "Secret!123",
                "url": "https://github.com",
                "notes": "repository hosting",
                "category": "Work",
            }
        )

        fuzzy_title_results = self.manager.search_entries("githib")
        self.assertEqual([entry["title"] for entry in fuzzy_title_results], ["GitHub"])

        fuzzy_field_results = self.manager.search_entries("title:githib")
        self.assertEqual([entry["title"] for entry in fuzzy_field_results], ["GitHub"])

    def test_search_entries_supports_updated_range_and_password_strength_filters(self):
        weak_entry = self.manager.create_entry(
            {
                "title": "Legacy Router",
                "username": "admin",
                "password": "123456",
                "url": "http://router.local",
                "notes": "old device",
                "category": "Home",
            }
        )
        strong_entry = self.manager.create_entry(
            {
                "title": "Primary Mail",
                "username": "user@example.com",
                "password": "BetterPass!2026",
                "url": "https://mail.example.com",
                "notes": "main inbox",
                "category": "Work",
            }
        )

        with self.database.transaction() as conn:
            conn.execute(
                "UPDATE vault_entries SET updated_at = ? WHERE id = ?",
                (datetime(2026, 3, 30, 12, 0).isoformat(), weak_entry["id"]),
            )
            conn.execute(
                "UPDATE vault_entries SET updated_at = ? WHERE id = ?",
                (datetime(2026, 4, 1, 9, 30).isoformat(), strong_entry["id"]),
            )

        range_results = self.manager.search_entries("", updated_from="2026-04-01", updated_to="2026-04-01")
        self.assertEqual([entry["title"] for entry in range_results], ["Primary Mail"])

        weak_results = self.manager.search_entries("", password_strength="Слабый")
        self.assertEqual([entry["title"] for entry in weak_results], ["Legacy Router"])

        strong_results = self.manager.search_entries("", password_strength="Сильный")
        self.assertEqual([entry["title"] for entry in strong_results], ["Primary Mail"])

    def test_concurrent_operations_preserve_entry_integrity(self):
        def create_entry(index: int):
            return self.manager.create_entry(
                {
                    "title": f"Concurrent {index}",
                    "username": f"user{index}",
                    "password": f"Secret!{index:03d}Aa",
                    "url": f"https://concurrent{index}.example",
                    "notes": f"note-{index}",
                    "category": "Parallel",
                }
            )["id"]

        with ThreadPoolExecutor(max_workers=8) as executor:
            created_ids = list(executor.map(create_entry, range(30)))

        self.assertEqual(len(created_ids), 30)
        self.assertEqual(len(set(created_ids)), 30)

        def update_entry(entry_id: int):
            updated = self.manager.update_entry(
                entry_id,
                {
                    "password": f"Updated!{entry_id:03d}Bb",
                    "notes": f"updated-{entry_id}",
                },
            )
            return updated["id"], updated["notes"]

        with ThreadPoolExecutor(max_workers=8) as executor:
            updated_pairs = list(executor.map(update_entry, created_ids[:15]))

        self.assertEqual(len(updated_pairs), 15)

        def read_entry(entry_id: int):
            entry = self.manager.get_entry(entry_id)
            return entry["id"], entry["title"], entry["category"]

        with ThreadPoolExecutor(max_workers=8) as executor:
            loaded_rows = list(executor.map(read_entry, created_ids))

        self.assertEqual(len(loaded_rows), 30)
        self.assertEqual({row[0] for row in loaded_rows}, set(created_ids))
        self.assertTrue(all(row[1].startswith("Concurrent ") for row in loaded_rows))
        self.assertTrue(all(row[2] == "Parallel" for row in loaded_rows))

        remaining_entries = self.manager.get_all_entries()
        self.assertEqual(len(remaining_entries), 30)
        for entry_id, notes in updated_pairs:
            loaded = self.manager.get_entry(entry_id)
            self.assertEqual(loaded["notes"], notes)

    @pytest.mark.slow
    def test_loading_1000_entries_meets_time_and_memory_requirements(self):
        for index in range(1000):
            self.manager.create_entry(
                {
                    "title": f"Entry {index}",
                    "username": f"user{index}@example.com",
                    "password": f"Strong!{index:04d}AaBb",
                    "url": f"https://example{index}.com",
                    "notes": f"note-{index} github portal",
                    "category": "Work" if index % 2 == 0 else "Personal",
                    "tags": [f"tag-{index % 10}", "bulk"],
                }
            )

        tracemalloc.start()
        started_at = time.perf_counter()
        entries = self.manager.get_all_entries()
        elapsed = time.perf_counter() - started_at
        _current, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(len(entries), 1000)
        self.assertLess(elapsed, 2.0)
        self.assertLess(peak_memory, 50 * 1024 * 1024)

    @pytest.mark.slow
    def test_searching_across_1000_entries_meets_response_budget(self):
        for index in range(1000):
            self.manager.create_entry(
                {
                    "title": f"Portal {index}",
                    "username": f"user{index}@example.com",
                    "password": f"Strong!{index:04d}AaBb",
                    "url": f"https://service{index}.example.com",
                    "notes": "github integration" if index % 2 == 0 else "local access",
                    "category": "Work" if index % 2 == 0 else "Personal",
                    "tags": [f"tag-{index % 10}", "bulk"],
                }
            )

        entries = self.manager.get_all_entries()

        started_at = time.perf_counter()
        results = self.manager.search_entries("github", entries=entries)
        elapsed = time.perf_counter() - started_at

        self.assertEqual(len(entries), 1000)
        self.assertEqual(len(results), 500)
        max_elapsed = 0.5 if sys.gettrace() else 0.2
        self.assertLess(elapsed, max_elapsed)


if __name__ == "__main__":
    unittest.main()