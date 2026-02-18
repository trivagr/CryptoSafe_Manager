from PyQt5.QtWidgets import QWidget, QLineEdit, QPushButton, QHBoxLayout

class PasswordEntry(QWidget):
    def __init__(self):
        super().__init__()
        self.input = QLineEdit()
        self.input.setEchoMode(QLineEdit.Password)
        self.show_btn = QPushButton("Показать")
        self.show_btn.setCheckable(True)
        self.show_btn.toggled.connect(self.toggle_password)

        layout = QHBoxLayout()
        layout.addWidget(self.input)
        layout.addWidget(self.show_btn)
        self.setLayout(layout)

    def toggle_password(self, checked):
        if checked:
            self.input.setEchoMode(QLineEdit.Normal)
        else:
            self.input.setEchoMode(QLineEdit.Password)
