import unittest
from pathlib import Path
from datetime import datetime
from src.core.key_manager import KeyManager
from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import DatabaseHelper
from src.core.state_manager import StateManager

class TestInitialSetupIntegration(unittest.TestCase):

    def setUp(self):
        self.db_path = Path("test_initial_setup.db")
        self.crypto = AES256Placeholder()
        self.key_manager = KeyManager()
        self.master_password = "SuperSecurePassword123!"
        self.salt = b"testsalt12345678"

        self.key = self.key_manager.derive_key(self.master_password, self.salt)
        self.key_manager._key = self.key
        self.db = DatabaseHelper(self.db_path, self.crypto, self.key)
        self.state_manager = StateManager(self.db, self.crypto, self.key)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_initial_setup_flow(self):

        # Проверяем, что база создана и таблицы существуют
        conn = self.db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        expected_tables = ["vault_entries", "audit_log", "settings", "key_store"]
        for table in expected_tables:
            self.assertIn(table, tables)
        conn.close()

        self.db.add_entry(
            title="First Entry",
            username="user1",
            password="password123",
            url="http://example.com",
            notes="Test notes",
            created_at=str(datetime.now()),
            updated_at=str(datetime.now()),
            tags="initial"
        )

        entry = self.db.get_entry(1)
        self.assertEqual(entry["title"], "First Entry")
        self.assertEqual(entry["username"], "user1")
        self.assertEqual(entry["password"], "password123")
        self.assertEqual(entry["notes"], "Test notes")
        self.assertTrue(self.state_manager._session_locked)
        self.state_manager.unlock_session()
        self.assertFalse(self.state_manager._session_locked)


if __name__ == "__main__":
    unittest.main()