from PySide6.QtCore import QAbstractTableModel, Qt


class VaultTableModel(QAbstractTableModel):

    def __init__(self, service):
        super().__init__()
        self.service = service
        self.items = self.service.get_all()

    def rowCount(self, parent=None):
        return len(self.items)

    def columnCount(self, parent=None):
        return 6

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        if role == Qt.DisplayRole:
            return str(self.items[index.row()][index.column()])

    def refresh(self):
        self.items = self.service.get_all()
        self.layoutChanged.emit()