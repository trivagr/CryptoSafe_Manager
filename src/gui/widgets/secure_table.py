from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem

class SecureTable(QTableWidget):
    def __init__(self, rows=5, columns=5):
        super().__init__(rows, columns)
        self.setHorizontalHeaderLabels(["Title", "Username", "Password", "URL", "Notes"])
        # Пример тестовых данных
        self.setItem(0, 0, QTableWidgetItem("Example"))
        self.setItem(0, 1, QTableWidgetItem("user@example.com"))
        self.setItem(0, 2, QTableWidgetItem("********"))
