import tkinter as tk
from tkinter import ttk

class SecureTable(ttk.Treeview):
    """
    Таблица для отображения логинов и паролей
    """
    def __init__(self, parent):
        columns = ("id", "title", "username", "password", "url", "notes", "tags")
        super().__init__(parent, columns=columns, show="headings")

        for col in columns:
            self.heading(col, text=col.capitalize())
            self.column(col, width=100)

        self.pack(fill=tk.BOTH, expand=True)

    def insert_row(self, data: dict):
        values = (data["id"], data["title"], data["username"], data["password"],
                  data["url"], data["notes"], data["tags"])
        self.insert("", tk.END, values=values)