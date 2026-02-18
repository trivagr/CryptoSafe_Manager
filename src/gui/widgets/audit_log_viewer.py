from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout

class AuditLogViewer(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Заглушка для журнала аудита (Спринт 5)"))
        self.setLayout(layout)
