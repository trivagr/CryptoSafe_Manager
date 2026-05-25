import sys

from PySide6.QtWidgets import (
    QApplication,
    QInputDialog,
    QMessageBox,
)

from src.gui.main_window import MainWindow

from src.database.db import DatabaseHelper

from src.core.key_manager import KeyManager
from src.core.events import EventBus


def main():

    app = QApplication(sys.argv)

    # =====================================================
    # CORE
    # =====================================================

    key_manager = KeyManager()

    event_system = EventBus()

    # =====================================================
    # MASTER PASSWORD
    # =====================================================

    password, ok = QInputDialog.getText(
        None,
        "Unlock Vault",
        "Enter master password:"
    )

    if not ok or not password:

        sys.exit(0)

    try:

        key_manager.unlock(password)

    except Exception as e:

        QMessageBox.critical(
            None,
            "Error",
            str(e)
        )

        sys.exit(1)

    # =====================================================
    # DATABASE
    # =====================================================

    db = DatabaseHelper(
        db_path="vault.db",
        crypto=None
    )

    # =====================================================
    # GUI
    # =====================================================

    window = MainWindow(
        db=db,
        key_manager=key_manager,
        event_system=event_system
    )

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()