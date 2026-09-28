import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Frame):  #класс для создания виджета ввода пароля с кнопкой для отображения/скрытия пароля
    def __init__(self, parent, **kwargs):
        super().__init__(parent)
        self.show_password = tk.BooleanVar(value=False)
        self.entry = ttk.Entry(self, show="*", **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.toggle_btn = ttk.Button(self, text="Показ", width=6, command=self.toggle_show)
        self.toggle_btn.pack(side=tk.RIGHT, padx=(4, 0))
        self.show_password.trace_add("write", self._update_visibility)

    def toggle_show(self):  #метод для переключения состояния отображения пароля, который изменяет значение переменной show_password на противоположное
        self.show_password.set(not self.show_password.get())

    def _update_visibility(self, *_args):  #метод для обновления видимости пароля в поле ввода и текста на кнопке в зависимости от значения переменной show_password
        if self.show_password.get():
            self.entry.config(show="")
            self.toggle_btn.config(text="Скрыть")
        else:
            self.entry.config(show="*")
            self.toggle_btn.config(text="Показ")

    def get(self) -> str:  #метод для получения текущего текста из поля ввода пароля
        return self.entry.get()

    def set(self, value: str):  #метод для установки текста в поле ввода пароля, который очищает текущее значение и вставляет новое
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)

    def clear(self):  #метод для очистки поля ввода пароля, который удаляет весь текст
        self.entry.delete(0, tk.END)

    def focus_set(self):  #метод для установки фокуса на поле ввода пароля
        self.entry.focus_set()