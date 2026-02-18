import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMenu, QMenuBar, QStatusBar, QWidget, QVBoxLayout
from gui.widgets.password_entry import PasswordEntry
from gui.widgets.secure_table import SecureTable
from gui.widgets.audit_log_viewer import AuditLogViewer

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoSafe Manager")

        # --- Меню ---
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("Файл")
        file_menu.addAction("Создать")
        file_menu.addAction("Открыть")
        file_menu.addAction("Резервная копия")
        file_menu.addAction("Выход")

        edit_menu = menu_bar.addMenu("Правка")
        edit_menu.addAction("Добавить")
        edit_menu.addAction("Изменить")
        edit_menu.addAction("Удалить")

        view_menu = menu_bar.addMenu("Вид")
        view_menu.addAction("Логи")
        view_menu.addAction("Настройки")

        help_menu = menu_bar.addMenu("Справка")
        help_menu.addAction("О программе")

        # --- Центральный виджет ---
        central = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(SecureTable())
        layout.addWidget(AuditLogViewer())
        central.setLayout(layout)
        self.setCentralWidget(central)

        # --- Строка состояния ---
        self.status = QStatusBar()
        self.status.showMessage("Статус: Вход выполнен | Таймер буфера обмена: заглушка")
        self.setStatusBar(self.status)

# --- Точка входа ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
