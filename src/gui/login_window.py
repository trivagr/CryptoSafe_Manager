from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel
)


class LoginWindow(QDialog):

    def __init__(self, auth_service):
        super().__init__()

        self.auth_service = auth_service

        self.setWindowTitle("Login")

        layout = QVBoxLayout()

        self.label = QLabel("Enter password")
        layout.addWidget(self.label)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        self.btn = QPushButton("Login")
        self.btn.clicked.connect(self.login)
        layout.addWidget(self.btn)

        self.setLayout(layout)

        self.success = False

    def login(self):
        ok = self.auth_service.authenticate(self.password.text())

        if ok:
            self.success = True
            self.accept()
        else:
            self.label.setText("Wrong password")