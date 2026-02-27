import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from src.gui.widgets.password_entry import PasswordEntry
from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("900x600")

        # ====================
        # Меню
        # ====================
        self.menu = tk.Menu(self)
        self.config(menu=self.menu)

        file_menu = tk.Menu(self.menu, tearoff=0)
        file_menu.add_command(label="Создать", command=self.dummy_action)
        file_menu.add_command(label="Открыть", command=self.dummy_action)
        file_menu.add_command(label="Резервная копия", command=self.dummy_action)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.quit)
        self.menu.add_cascade(label="Файл", menu=file_menu)

        edit_menu = tk.Menu(self.menu, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.dummy_action)
        edit_menu.add_command(label="Изменить", command=self.dummy_action)
        edit_menu.add_command(label="Удалить", command=self.dummy_action)
        self.menu.add_cascade(label="Правка", menu=edit_menu)

        view_menu = tk.Menu(self.menu, tearoff=0)
        view_menu.add_command(label="Логи", command=self.show_logs)
        view_menu.add_command(label="Настройки", command=self.show_settings)
        self.menu.add_cascade(label="Вид", menu=view_menu)

        help_menu = tk.Menu(self.menu, tearoff=0)
        help_menu.add_command(label="Справка", command=self.dummy_action)
        self.menu.add_cascade(label="Справка", menu=help_menu)

        # ====================
        # Центральный виджет таблицы
        # ====================
        self.table = SecureTable(self)
        self.table.pack(fill=tk.BOTH, expand=True)

        # Тестовые данные
        for i in range(5):
            self.table.insert_row({
                "id": i + 1,
                "title": f"Test {i+1}",
                "username": f"user{i+1}",
                "password": "••••••",
                "url": "http://example.com",
                "notes": "Sample note",
                "tags": "test"
            })

        # ====================
        # Строка состояния
        # ====================
        self.status_bar = ttk.Label(self, text="Сессия: заблокирована | Буфер: пуст", relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # ====================
        # Заглушки AuditLog
        # ====================
        self.audit_viewer = AuditLogViewer(self)

    # ====================
    # Заглушки действий
    # ====================
    def dummy_action(self):
        messagebox.showinfo("Info", "Функция пока не реализована")

    def show_logs(self):
        self.audit_viewer.pack(fill=tk.BOTH, expand=True)
        self.audit_viewer.add_entry("Тестовая запись журнала")

    def show_settings(self):
        self.dummy_action()

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()