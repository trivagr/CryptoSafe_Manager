from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton


class PasswordDialog(QDialog):

    def __init__(self, title, label):

        super().__init__()

        self.setWindowTitle(title)

        self.password_bytes = None

        layout = QVBoxLayout()

        self.label = QLabel(label)
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        layout.addWidget(self.password_input)

        self.button = QPushButton("OK")
        self.button.clicked.connect(self.submit)

        layout.addWidget(self.button)

        self.setLayout(layout)

    def submit(self):

        password = self.password_input.text()

        self.password_bytes = bytearray(password.encode())

        self.password_input.clear()

        del password

        self.accept()

    def get_password(self):

        return self.password_bytes