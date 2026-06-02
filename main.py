import sys

from PySide6.QtWidgets import (
    QApplication,
    QMessageBox
)

from src.gui.main_window import MainWindow
from src.gui.dialogs.password_dialog import PasswordDialog

from src.database.db import DatabaseHelper

from src.core.key_manager import KeyManager
from src.core.events import EventBus

from src.core.crypto.authentication import authenticate

from src.core.crypto.placeholder import (
    AES256EncryptionService,
    secure_zero_bytes
)

from src.core.crypto.password_validator import validate_password

from src.core.vault.password_generator import PasswordGenerator

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import WindowsClipboardAdapter


def main():

    app = QApplication(sys.argv)

    key_manager = KeyManager()

    crypto = AES256EncryptionService(
        key_manager
    )

    event_system = EventBus()

    clipboard_adapter = WindowsClipboardAdapter()

    clipboard_service = ClipboardService(
        adapter=clipboard_adapter,
        event_bus=event_system
    )

    db = DatabaseHelper(
        db_path="vault.db",
        crypto=crypto
    )

    credentials = db.get_master_credentials()

    # =====================================================
    # FIRST START
    # =====================================================

    if credentials is None:

        generator = PasswordGenerator()

        reply = QMessageBox.question(
            None,
            "Master Password",
            "Generate master password automatically?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:

            generated_password = generator.generate(
                length=20
            )

            QMessageBox.information(
                None,
                "Generated Password",
                f"Save this password:\n\n{generated_password}"
            )

            password_bytes = bytearray(
                generated_password.encode()
            )

            del generated_password

        else:

            dialog = PasswordDialog(
                "Create Master Password",
                "Enter new master password:"
            )

            if not dialog.exec():
                sys.exit(0)

            password_bytes = dialog.get_password()

            if not password_bytes:
                sys.exit(0)

        password_str = password_bytes.decode()

        try:

            if not validate_password(password_str):

                QMessageBox.critical(
                    None,
                    "Error",
                    "Password too weak"
                )

                secure_zero_bytes(password_bytes)

                del password_bytes

                sys.exit(1)

        finally:

            del password_str

        salt = key_manager.hashing.salt_generate()

        password_hash = key_manager.hashing.hash_password(
            password_bytes
        )

        db.set_master_password(
            password_hash,
            salt
        )

        secure_zero_bytes(password_bytes)

        del password_bytes

        QMessageBox.information(
            None,
            "Success",
            "Master password created"
        )

        credentials = db.get_master_credentials()

    # =====================================================
    # LOGIN
    # =====================================================

    while True:

        dialog = PasswordDialog(
            "Unlock Vault",
            "Enter master password:"
        )

        if not dialog.exec():
            sys.exit(0)

        password_bytes = dialog.get_password()

        if not password_bytes:
            continue

        success = authenticate(
            key_manager,
            password_bytes,
            credentials["password_hash"],
            credentials["salt"]
        )

        secure_zero_bytes(password_bytes)

        del password_bytes

        if success:
            break

        QMessageBox.critical(
            None,
            "Error",
            "Authentication failed"
        )

    # =====================================================
    # GUI
    # =====================================================

    window = MainWindow(
        db=db,
        key_manager=key_manager,
        event_system=event_system,
        clipboard_service=clipboard_service
    )

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":

    main()