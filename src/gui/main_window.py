from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QLineEdit,
    QMessageBox,
    QLabel,
    QHeaderView,
    QToolBar,
)

from PySide6.QtGui import QAction

from src.gui.services.vault_service import VaultService
from src.gui.dialogs.entry_dialog import EntryDialog


class MainWindow(QMainWindow):

    def __init__(
            self,
            db,
            key_manager,
            event_system
    ):
        super().__init__()

        self.service = VaultService(
            db,
            key_manager,
            event_system
        )

        self.rows = []

        self.setWindowTitle("CryptoSafe Manager")
        self.resize(1300, 700)

        self.build_ui()

        self.load_entries()

    # =====================================================
    # UI
    # =====================================================

    def build_ui(self):

        central = QWidget()

        self.setCentralWidget(central)

        layout = QVBoxLayout()

        central.setLayout(layout)

        # =================================================
        # TOOLBAR
        # =================================================

        toolbar = QToolBar()

        self.addToolBar(toolbar)

        self.search_input = QLineEdit()

        self.search_input.setPlaceholderText(
            "Search..."
        )

        self.search_input.textChanged.connect(
            self.search_entries
        )

        toolbar.addWidget(QLabel("Search:"))
        toolbar.addWidget(self.search_input)

        toolbar.addSeparator()

        add_action = QAction("Add", self)
        edit_action = QAction("Edit", self)
        delete_action = QAction("Delete", self)
        refresh_action = QAction("Refresh", self)

        add_action.triggered.connect(self.add_entry)
        edit_action.triggered.connect(self.edit_entry)
        delete_action.triggered.connect(self.delete_entry)
        refresh_action.triggered.connect(self.load_entries)

        toolbar.addAction(add_action)
        toolbar.addAction(edit_action)
        toolbar.addAction(delete_action)
        toolbar.addAction(refresh_action)

        # =================================================
        # TABLE
        # =================================================

        self.table = QTableWidget()

        self.table.setColumnCount(7)

        self.table.setHorizontalHeaderLabels([
            "ID",
            "Title",
            "Username",
            "Password",
            "URL",
            "Created",
            "Updated",
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

        self.table.setAlternatingRowColors(True)

        layout.addWidget(self.table)

        # =================================================
        # BUTTONS
        # =================================================

        buttons = QHBoxLayout()

        self.add_btn = QPushButton("Add")
        self.edit_btn = QPushButton("Edit")
        self.delete_btn = QPushButton("Delete")
        self.refresh_btn = QPushButton("Refresh")

        self.add_btn.clicked.connect(self.add_entry)
        self.edit_btn.clicked.connect(self.edit_entry)
        self.delete_btn.clicked.connect(self.delete_entry)
        self.refresh_btn.clicked.connect(self.load_entries)

        buttons.addWidget(self.add_btn)
        buttons.addWidget(self.edit_btn)
        buttons.addWidget(self.delete_btn)

        buttons.addStretch()

        buttons.addWidget(self.refresh_btn)

        layout.addLayout(buttons)

    # =====================================================
    # LOAD
    # =====================================================

    def load_entries(self):

        self.rows = self.service.get_all_entries()

        self.render_table(self.rows)

    # =====================================================
    # RENDER
    # =====================================================

    def render_table(self, rows):

        self.table.setRowCount(len(rows))

        for row_index, row in enumerate(rows):

            self.table.setItem(
                row_index,
                0,
                QTableWidgetItem(str(row["id"]))
            )

            self.table.setItem(
                row_index,
                1,
                QTableWidgetItem(row["title"])
            )

            self.table.setItem(
                row_index,
                2,
                QTableWidgetItem(row["username"])
            )

            self.table.setItem(
                row_index,
                3,
                QTableWidgetItem(row["password"])
            )

            self.table.setItem(
                row_index,
                4,
                QTableWidgetItem(row["url"])
            )

            self.table.setItem(
                row_index,
                5,
                QTableWidgetItem(
                    str(row["created_at"])
                )
            )

            self.table.setItem(
                row_index,
                6,
                QTableWidgetItem(
                    str(row["updated_at"])
                )
            )

    # =====================================================
    # SEARCH
    # =====================================================

    def search_entries(self):

        text = self.search_input.text().strip()

        if not text:

            self.render_table(self.rows)

            return

        rows = self.service.search_entries(text)

        self.render_table(rows)

    # =====================================================
    # GET SELECTED
    # =====================================================

    def get_selected_entry(self):

        selected = self.table.selectedItems()

        if not selected:
            return None

        row = selected[0].row()

        entry_id = int(
            self.table.item(row, 0).text()
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