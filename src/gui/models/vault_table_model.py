from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex

class VaultTableModel(QAbstractTableModel):

    HEADERS = ["Title", "Username", "URL", "Updated"]

    def __init__(self, service):
        super().__init__()
        self.service = service
        self.rows = []
        self.filtered_ids = None
        self.password_visible = False

        self.reload()

    # -------------------------
    def reload(self):
        self.rows = self.service.get_all_entries()
        self.layoutChanged.emit()

    # -------------------------
    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 4

    # -------------------------
    def data(self, index, role):
        if not index.isValid():
            return None

        row = self.rows[index.row()]
        col = index.column()

        if role != Qt.DisplayRole:
            return None

        if col == 0:
            return row["title"]

        if col == 1:
            u = row["username"]
            return u[:4] + "••••" if len(u) > 4 else u

        if col == 2:
            from urllib.parse import urlparse
            return urlparse(row["url"]).netloc

        if col == 3:
            return row["updated_at"]

        return None

    # -------------------------
    def toggle_password_visibility(self):
        self.password_visible = not self.password_visible
        self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows), 3))