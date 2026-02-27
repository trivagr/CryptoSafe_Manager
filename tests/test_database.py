import unittest
from pathlib import Path
from src.database.db import DatabaseHelper
from src.core.crypto.placeholder import AES256Placeholder

class TestDatabaseConnection(unittest.TestCase):

    def setUp(self):
        self.db_path = Path("test_vault.db")
        self.crypto = AES256Placeholder()
        self.key = b"testkey12345678"
        self.db = DatabaseHelper(self.db_path, self.crypto, self.key)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_connection(self):
        conn = self.db._get_connection()
        self.assertIsNotNone(conn)
        conn.close()

    def test_tables_exist(self):
        conn = self.db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        expected_tables = ["vault_entries", "audit_log", "settings", "key_store"]
        for table in expected_tables:
            self.assertIn(table, tables)

if __name__ == "__main__":
    unittest.main()