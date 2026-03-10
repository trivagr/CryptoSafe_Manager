import tkinter as tk
from tkinter import scrolledtext

class AuditLogViewer(tk.Frame):
    """
    Просмотр журнала действий
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.text = scrolledtext.ScrolledText(self, height=10)
        self.text.pack(fill=tk.BOTH, expand=True)
        self.text.config(state=tk.DISABLED)

    def add_entry(self, message: str):
        self.text.config(state=tk.NORMAL)
        self.text.insert(tk.END, message + "\n")
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)