import sys

from PySide6.QtWidgets import (
    QApplication,
    QMessageBox,
    QInputDialog,
)

from src.gui.main_window import MainWindow

from src.database.db import DatabaseHelper

from src.core.key_manager import KeyManager
from src.core.events import EventBus
from src.core.crypto.authentication import authenticate


def main():

    app = QApplication(sys.argv)

    # =====================================================
    # DATABASE
    # =====================================================

    db = DatabaseHelper(
        db_path="vault.db",
        crypto=None
    )

    # =====================================================
    # KEY MANAGER
    # =====================================================

    key_manager = KeyManager()

    event_system = EventBus()

    # =====================================================
    # LOAD CREDS
    # =====================================================

    credentials = db.get_master_credentials()

    # =====================================================
    # FIRST START
    # =====================================================

    if credentials is None:

        password, ok = QInputDialog.getText(
            None,
            "Create Master Password",
            "Enter new master password:"
        )

        if not ok or not password:
            sys.exit(0)

        salt = key_manager.hashing.salt_generate()

        password_hash = key_manager.hashing.password_hash(
            password
        )

        db.set_master_password(
            password_hash,
            salt
        )

        credentials = db.get_master_credentials()

        QMessageBox.information(
            None,
            "Success",
            "Master password created"
        )

    # =====================================================
    # LOGIN
    # =====================================================

    password, ok = QInputDialog.getText(
        None,
        "Unlock Vault",
        "Enter master password:"
    )

    if not ok or not password:
        sys.exit(0)

    # =====================================================
    # AUTH
    # =====================================================

    success = authenticate(
        password,
        credentials["password_hash"],
        credentials["salt"]
    )

    if not success:

        QMessageBox.critical(
            None,
            "Error",
            "Authentication failed"
        )

        sys.exit(1)

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