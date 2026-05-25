from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QFormLayout,
    QLineEdit,
    QTextEdit,
    QPushButton,
    QHBoxLayout,
)


class EntryDialog(QDialog):

    def __init__(self, service, entry=None):
        super().__init__()

        self.service = service
        self.entry = entry

        self.setWindowTitle("Vault Entry")
        self.resize(500, 400)

        self.build_ui()

    # =====================================================
    # UI
    # =====================================================

    def build_ui(self):

        layout = QVBoxLayout()

        form = QFormLayout()

        self.title_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.url_input = QLineEdit()
        self.notes_input = QTextEdit()

        # EDIT MODE
        if self.entry:

            self.title_input.setText(
                self.entry.get("title", "")
            )

            self.username_input.setText(
                self.entry.get("username", "")
            )

            self.password_input.setText(
                self.entry.get("password", "")
            )

            self.url_input.setText(
                self.entry.get("url", "")
            )

            self.notes_input.setPlainText(
                self.entry.get("notes", "")
            )

        form.addRow("Title", self.title_input)
        form.addRow("Username", self.username_input)
        form.addRow("Password", self.password_input)
        form.addRow("URL", self.url_input)
        form.addRow("Notes", self.notes_input)

        layout.addLayout(form)

        # BUTTONS

        buttons = QHBoxLayout()

        self.save_btn = QPushButton("Save")
        self.cancel_btn = QPushButton("Cancel")

        self.save_btn.clicked.connect(
            self.save_entry
        )

        self.cancel_btn.clicked.connect(
            self.reject
        )

        buttons.addWidget(self.save_btn)
        buttons.addWidget(self.cancel_btn)

        layout.addLayout(buttons)

        self.setLayout(layout)

    # =====================================================
    # SAVE
    # =====================================================

    def save_entry(self):

        data = {
            "title": self.title_input.text(),
            "username": self.username_input.text(),
            "password": self.password_input.text(),
            "url": self.url_input.text(),
            "notes": self.notes_input.toPlainText(),
        }

        # EDIT
        if self.entry:

            self.service.update_entry(
                self.entry["id"],
                data
            )

        # ADD
        else:

            self.service.add_entry(data)

        self.accept()