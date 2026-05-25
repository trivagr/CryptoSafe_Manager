from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QPushButton, QVBoxLayout

class EntryDialog(QDialog):

    def __init__(self, service):
        super().__init__()
        self.service = service

        self.setWindowTitle("Entry")

        layout = QVBoxLayout()
        form = QFormLayout()

        self.title = QLineEdit()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.url = QLineEdit()

        form.addRow("Title", self.title)
        form.addRow("Username", self.username)
        form.addRow("Password", self.password)
        form.addRow("URL", self.url)

        self.save = QPushButton("Save")
        self.save.clicked.connect(self.save_entry)

        layout.addLayout(form)
        layout.addWidget(self.save)
        self.setLayout(layout)

    def save_entry(self):
        self.service.db.add_entry(
            self.title.text(),
            self.username.text(),
            self.password.text(),
            self.url.text(),
            "",
            "default",
            None,
            None,
            ""
        )
        self.accept()