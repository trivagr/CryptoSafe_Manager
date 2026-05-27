from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLineEdit,
    QMessageBox,
    QLabel,
    QHeaderView,
    QToolBar,
    QInputDialog
)

from PySide6.QtGui import QAction
from PySide6.QtCore import QEvent, QTimer

from src.gui.services.vault_service import VaultService
from src.gui.dialogs.entry_dialog import EntryDialog

from src.core.crypto.authentication import authenticate, update_activity, session_expired, shutdown
from src.core.crypto.password_change import PasswordChange


class MainWindow(QMainWindow):

    def __init__(
            self,
            db,
            key_manager,
            event_system
    ):

        super().__init__()

        self.session_timer = QTimer()

        self.session_timer.timeout.connect(self.check_session)

        self.session_timer.start(30000)

        self.db = db

        self.key_manager = key_manager

        self.password_change = PasswordChange(
            key_manager=key_manager,
            key_deriver=key_manager.hashing,
            db_helper=db
        )

        self.service = VaultService(
            db,
            key_manager,
            event_system
        )

        self.rows = []

        self.is_locking = False

        self.setWindowTitle(
            "CryptoSafe Manager"
        )

        self.resize(
            1300,
            700
        )

        self.build_ui()

        self.load_entries()

    # =====================================================
    # UI
    # =====================================================

    def build_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )

        layout = QVBoxLayout()

        central.setLayout(layout)

        toolbar = QToolBar()

        self.addToolBar(toolbar)

        self.search_input = QLineEdit()

        self.search_input.setPlaceholderText(
            "Search..."
        )

        self.search_input.textChanged.connect(
            self.search_entries
        )

        toolbar.addWidget(
            QLabel("Search:")
        )

        toolbar.addWidget(
            self.search_input
        )

        toolbar.addSeparator()

        actions = {

            "Add": self.add_entry,
            "Edit": self.edit_entry,
            "Delete": self.delete_entry,
            "Refresh": self.load_entries,
            "Change Password": self.change_password,
            "Logout": self.logout
        }

        for name, handler in actions.items():

            action = QAction(
                name,
                self
            )

            action.triggered.connect(
                handler
            )

            toolbar.addAction(
                action
            )

        self.table = QTableWidget()

        self.table.setColumnCount(7)

        self.table.setHorizontalHeaderLabels([

            "ID",
            "Title",
            "Username",
            "Password",
            "URL",
            "Created",
            "Updated"
        ])

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        layout.addWidget(
            self.table
        )

    # =====================================================
    # LOAD
    # =====================================================

    def load_entries(self):

        self.rows = (
            self.service
            .get_all_entries()
        )

        self.render_table(
            self.rows
        )

    # =====================================================
    # TABLE
    # =====================================================

    def render_table(
            self,
            rows
    ):

        self.table.setRowCount(
            len(rows)
        )

        for row_index, row in enumerate(rows):

            values = [

                row["id"],
                row["title"],
                row["username"],
                row["password"],
                row["url"],
                row["created_at"],
                row["updated_at"]

            ]

            for col, value in enumerate(values):

                self.table.setItem(
                    row_index,
                    col,
                    QTableWidgetItem(
                        str(value)
                    )
                )

    # =====================================================
    # SEARCH
    # =====================================================

    def search_entries(self):

        text = (
            self.search_input
            .text()
            .strip()
        )

        if not text:

            self.render_table(
                self.rows
            )

            return

        rows = (
            self.service
            .search_entries(text)
        )

        self.render_table(rows)

    # =====================================================
    # SELECT
    # =====================================================

    def get_selected_entry(self):

        selected = (
            self.table.selectedItems()
        )

        if not selected:
            return None

        row = selected[0].row()

        entry_id = int(
            self.table.item(
                row,
                0
            ).text()
        )

        for item in self.rows:

            if item["id"] == entry_id:
                return item

        return None

    # =====================================================
    # ADD
    # =====================================================

    def add_entry(self):

        dialog = EntryDialog(
            self.service
        )

        if dialog.exec():
            self.load_entries()

    # =====================================================
    # EDIT
    # =====================================================

    def edit_entry(self):

        entry = self.get_selected_entry()

        if not entry:

            QMessageBox.warning(
                self,
                "Warning",
                "Select entry"
            )

            return

        dialog = EntryDialog(
            self.service,
            entry
        )

        if dialog.exec():
            self.load_entries()

    # =====================================================
    # DELETE
    # =====================================================

    def delete_entry(self):

        entry = self.get_selected_entry()

        if not entry:

            QMessageBox.warning(
                self,
                "Warning",
                "Select entry"
            )

            return

        reply = QMessageBox.question(
            self,
            "Delete",
            f'Delete "{entry["title"]}" ?'
        )

        if reply == QMessageBox.Yes:

            self.service.delete_entry(
                entry["id"]
            )

            self.load_entries()

    # =====================================================
    # CHANGE PASSWORD
    # =====================================================

    def change_password(self):

        old_password, ok = QInputDialog.getText(
            self,
            "Change Password",
            "Current password:",
            QLineEdit.Password
        )

        if not ok:
            return

        new_password, ok = QInputDialog.getText(
            self,
            "Change Password",
            "New password:",
            QLineEdit.Password
        )

        if not ok:
            return

        confirm_password, ok = QInputDialog.getText(
            self,
            "Change Password",
            "Confirm password:",
            QLineEdit.Password
        )

        if not ok:
            return

        try:

            self.password_change.change_password_async(
                old_password=old_password,
                new_password=new_password,
                confirm_password=confirm_password,

                on_done=lambda *_:
                QMessageBox.information(
                    self,
                    "Success",
                    "Password changed"
                ),

                on_error=lambda e:
                QMessageBox.critical(
                    self,
                    "Error",
                    str(e)
                )
            )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Error",
                str(e)
            )

    # =====================================================
    # LOGOUT
    # =====================================================

    def logout(self):

        self.lock_vault()

    # =====================================================
    # MINIMIZE
    # =====================================================

    def changeEvent(self, event):

        if event.type() == QEvent.WindowStateChange:

            update_activity()

            if self.isMinimized():
                self.lock_vault()

        super().changeEvent(event)
    # =====================================================
    # LOCK
    # =====================================================

    def lock_vault(self):

        if self.is_locking:
            return

        self.is_locking = True

        self.key_manager.lock()

        self.hide()

        credentials = (
            self.db.get_master_credentials()
        )

        while True:

            password, ok = QInputDialog.getText(
                self,
                "Vault Locked",
                "Enter master password:",
                QLineEdit.Password
            )

            if not ok:

                self.close()
                return

            if not password:
                continue

            try:

                success = authenticate(
                    self.key_manager,
                    password,
                    credentials["password_hash"],
                    credentials["salt"]
                )

                if not success:

                    QMessageBox.critical(
                        self,
                        "Error",
                        "Wrong password"
                    )

                    continue

                break

            except Exception as e:

                QMessageBox.critical(
                    self,
                    "Error",
                    str(e)
                )

        self.is_locking = False

        self.showNormal()

        self.activateWindow()

        self.raise_()

    def check_session(self):

        SESSION_TIMEOUT = 900

        if session_expired(
                SESSION_TIMEOUT
        ):
            shutdown(self.key_manager)

            QMessageBox.warning(

                self,

                "Session expired",

                "Session timeout exceeded"
            )

            self.close()