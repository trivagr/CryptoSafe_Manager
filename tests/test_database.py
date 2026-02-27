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
        # Проверяем, что контекстный менеджер работает без ошибок
        with self.db._connection() as conn:
            self.assertIsNotNone(conn)

    def test_tables_exist(self):
        expected_tables = ["vault_entries", "audit_log", "settings", "key_store"]
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            for table in expected_tables:
                self.assertIn(table, tables)

if __name__ == "__main__":
    unittest.main()