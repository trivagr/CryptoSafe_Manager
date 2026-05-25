from PySide6.QtWidgets import QApplication
import sys

from src.gui.main_window import MainWindow
from src.database.db import DatabaseHelper
from src.core.crypto.key_derivation import KeyHashing
from src.core.key_manager import KeyManager


def main():
    app = QApplication(sys.argv)

    # --------------------
    # CORE
    # --------------------
    key_manager = KeyManager()
    crypto = KeyHashing(key_manager)

    db = DatabaseHelper(db_path="vault.db", crypto=crypto)

    # --------------------
    # GUI
    # --------------------
    window = MainWindow(db=db, crypto=crypto)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()