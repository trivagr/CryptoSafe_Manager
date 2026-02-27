import unittest
import sys
from PyQt5.QtWidgets import QApplication
from src.gui.main_window import MainWindow
from src.database.db import DatabaseHelper
from src.core.crypto.placeholder import AES256Placeholder
from pathlib import Path

class TestMainWindowIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication(sys.argv)

    @classmethod
    def tearDownClass(cls):
        cls.app.quit()

    def setUp(self):
        self.db_path = Path("test_gui.db")
        self.crypto = AES256Placeholder()
        self.key = b"testkey12345678"
        self.db = DatabaseHelper(self.db_path, self.crypto, self.key)
        self.window = MainWindow(self.db, self.crypto, self.key)

    def tearDown(self):
        self.window.close()
        if self.db_path.exists():
            self.db_path.unlink()

    def test_main_window_initialization(self):
        self.assertIsNotNone(self.window)
        self.assertIsNotNone(self.window.centralWidget())
        status_bar = self.window.statusBar()
        self.assertIsNotNone(status_bar)

if __name__ == "__main__":
    unittest.main()