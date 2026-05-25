from PySide6.QtWidgets import QMainWindow, QTableView, QLineEdit, QToolBar
from PySide6.QtGui import QAction

from src.gui.models.vault_table_model import VaultTableModel
from src.gui.controllers.vault_controller import VaultController
from src.gui.services.vault_service import VaultService

class MainWindow(QMainWindow):

    def __init__(self, db, crypto):
        super().__init__()

        self.service = VaultService(db, crypto)
        self.model = VaultTableModel(self.service)
        self.controller = VaultController(self.service, self.model)

        # ---------------- UI ----------------
        self.table = QTableView()
        self.table.setModel(self.model)

        self.table.setSelectionMode(self.table.ExtendedSelection)
        self.table.setSortingEnabled(True)

        self.setCentralWidget(self.table)

        # ---------------- Toolbar ----------------
        toolbar = QToolBar()
        self.addToolBar(toolbar)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search...")
        self.search.textChanged.connect(self.controller.search)

        toolbar.addWidget(self.search)

        # refresh
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.controller.refresh)
        toolbar.addAction(refresh_action)