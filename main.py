import sys

from PySide6.QtWidgets import (
    QApplication,
    QMessageBox,
    QInputDialog,
    QLineEdit
)

from src.gui.main_window import MainWindow
from src.database.db import DatabaseHelper

from src.core.key_manager import KeyManager
from src.core.events import EventBus

from src.core.crypto.authentication import (
    authenticate
)

from src.core.crypto.placeholder import (
    AES256EncryptionService
)

from src.core.crypto.password_validator import (
    validate_password
)

from src.core.vault.password_generator import (
    PasswordGenerator
)


def main():

    app = QApplication(
        sys.argv
    )

    key_manager = KeyManager()

    crypto = AES256EncryptionService(
        key_manager
    )

    event_system = EventBus()

    db = DatabaseHelper(
        db_path="vault.db",
        crypto=crypto
    )

    credentials = (
        db.get_master_credentials()
    )

    # =====================================================
    # FIRST START
    # =====================================================

    if credentials is None:

        generator = PasswordGenerator()

        reply = QMessageBox.question(

            None,

            "Master Password",

            "Generate master password automatically?",

            QMessageBox.Yes |
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:

            password = (
                generator.generate(
                    length=20
                )
            )

            QMessageBox.information(

                None,

                "Generated Password",

                f"Save this password:\n\n{password}"
            )

        else:

            while True:

                password, ok = (
                    QInputDialog.getText(
                        None,
                        "Create Master Password",
                        "Enter new master password:",
                        QLineEdit.Password
                    )
                )

                if not ok:

                    sys.exit(0)

                if not password:

                    continue

                break

        # ============================================
        # VALIDATE
        # ============================================

        if not validate_password(
            password
        ):

            QMessageBox.critical(

                None,

                "Error",

                "Password too weak"
            )

            sys.exit(1)

        salt = (
            key_manager
            .hashing
            .salt_generate()
        )

        password_hash = (
            key_manager
            .hashing
            .hash_password(
                password
            )
        )

        db.set_master_password(
            password_hash,
            salt
        )

        QMessageBox.information(

            None,

            "Success",

            "Master password created"
        )

        credentials = (
            db.get_master_credentials()
        )

    # =====================================================
    # LOGIN
    # =====================================================

    password, ok = (
        QInputDialog.getText(
            None,
            "Unlock Vault",
            "Enter master password:",
            QLineEdit.Password
        )
    )

    if not ok:

        sys.exit(0)

    if not password:

        sys.exit(0)

    success = authenticate(

        key_manager,

        password,

        credentials[
            "password_hash"
        ],

        credentials[
            "salt"
        ]
    )

    if not success:

        QMessageBox.critical(

            None,

            "Error",

            "Authentication failed"
        )

        sys.exit(1)

    window = MainWindow(

        db=db,

        key_manager=key_manager,

        event_system=event_system
    )

    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":

    main()