import tkinter as tk
from tkinter import ttk

class PasswordEntry(ttk.Frame):
    """
    Поле для пароля с кнопкой показать/скрыть и копированием в буфер
    """
    def __init__(self, parent, **kwargs):
        super().__init__(parent)
        self.var = tk.StringVar()
        self.show = False

        self.entry = ttk.Entry(self, textvariable=self.var, show="*", **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.toggle_btn = ttk.Button(self, text="👁", width=3, command=self.toggle)
        self.toggle_btn.pack(side=tk.LEFT, padx=(2,0))

        self.copy_btn = ttk.Button(self, text="⧉", width=3, command=self.copy)
        self.copy_btn.pack(side=tk.LEFT, padx=(2,0))

    def toggle(self):
        self.show = not self.show
        self.entry.config(show="" if self.show else "*")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.var.get())

    def get(self):
        return self.var.get()

    def set(self, value):
        self.var.set(value)