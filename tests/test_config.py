import unittest
from pathlib import Path
from src.core.config import ConfigManager

class TestConfigManagerIntegration(unittest.TestCase):

    def setUp(self):
        self.config = ConfigManager(env="test")

    def test_database_paths(self):
        self.config.ensure_dirs_existe()
        for db_name, filename in self.config.database.items():
            path = self.config.get_db_path(db_name)
            self.assertIsInstance(path, Path)
            self.assertEqual(path.name, filename)
            self.assertTrue(path.parent.exists())

    def test_ui_settings_default(self):
        self.assertEqual(self.config.get_ui_settings("language"), "ru")
        self.assertEqual(self.config.get_ui_settings("theme"), "WHITE")
        self.assertEqual(self.config.get_ui_settings("font_size"), 14)

    def test_set_ui_settings(self):
        updated = self.config.set_ui_settings("language", "en")
        self.assertEqual(updated["language"], "en")

        updated = self.config.set_ui_settings("font_size", 18)
        self.assertEqual(updated["font_size"], 18)

        updated = self.config.set_ui_settings("font_size", "big")
        self.assertEqual(updated["font_size"], 18)

    def test_crypto_settings(self):
        algorithm = self.config.get_crypto_settings("algorithm")
        self.assertEqual(algorithm, "AES256")


if __name__ == "__main__":
    unittest.main()