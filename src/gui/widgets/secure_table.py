import tkinter as tk
from tkinter import ttk

class SecureTable(ttk.Frame):
    """
    Таблица для отображения записей хранилища.
    """
    def __init__(self, parent, columns=None):
        super().__init__(parent)
        self.columns = columns or ["ID", "Title", "Username", "Password", "URL", "Notes", "Tags"]
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings")
        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def insert_row(self, row: dict):
        values = [row.get(col.lower(), "") for col in self.columns]
        self.tree.insert("", tk.END, values=values)

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)