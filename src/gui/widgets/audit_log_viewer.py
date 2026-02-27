import tkinter as tk
from tkinter import ttk

class AuditLogViewer(ttk.Frame):
    """
    Заглушка просмотра журнала аудита.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.text = tk.Text(self, height=10, state="disabled")
        self.text.pack(fill=tk.BOTH, expand=True)

    def add_entry(self, entry: str):
        self.text.config(state="normal")
        self.text.insert(tk.END, entry + "\n")
        self.text.config(state="disabled")