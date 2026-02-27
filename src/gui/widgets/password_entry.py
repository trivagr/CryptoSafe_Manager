import tkinter as tk
from tkinter import ttk

class PasswordEntry(ttk.Frame):
    """
    Поле ввода пароля с маскировкой и кнопкой показа.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.var = tk.StringVar()
        self.entry = ttk.Entry(self, textvariable=self.var, show="*")
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.show_btn = ttk.Button(self, text="Показать", width=8, command=self.toggle_show)
        self.show_btn.pack(side=tk.RIGHT)
        self._visible = False

    def toggle_show(self):
        self._visible = not self._visible
        self.entry.config(show="" if self._visible else "*")

    def get(self):
        return self.var.get()

    def set(self, value: str):
        self.var.set(value)