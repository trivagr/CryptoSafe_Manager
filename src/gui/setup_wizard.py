import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ..core.crypto.authentication import AuthenticationError, AuthenticationService
from ..core.crypto.key_storage import KeyStorage
from ..database.db import Database


class SetupWizard:
    COLORS = {
        "bg": "#1e1e1e",
        "surface": "#252526",
        "field": "#1b1b1b",
        "ink": "#d4d4d4",
        "muted": "#a6a6a6",
        "accent": "#007acc",
        "line": "#3c3c3c",
        "selection": "#094771",
    }

    def __init__(self, parent, config, auth_service: AuthenticationService):
        self.parent = parent
        self.config = config
        self.auth_service = auth_service

        self.wizard = tk.Toplevel(parent)
        self._apply_theme()
        self.wizard.title("Первоначальная настройка")
        self.wizard.geometry(self._get_screen_limited_geometry(820, 680))
        if hasattr(self.wizard, "minsize"):
            self.wizard.minsize(680, 560)
        self.wizard.transient(parent)
        self.wizard.grab_set()
        self.wizard.resizable(True, True)

        self.master_password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.db_path = tk.StringVar(value=self._get_initial_db_path())
        self.auto_lock_minutes = tk.IntVar(value=self.config.get("security.auto_lock_minutes", 5))
        self.key_cache_timeout_minutes = tk.IntVar(value=self.config.get("security.key_cache_timeout_minutes", 60))

        self.current_step = 0
        self.steps = [
            self._step_welcome,
            self._step_master_password,
            self._step_database_location,
            self._step_finish,
        ]

        self._create_widgets()
        self._show_step(0)
        self.wizard.wait_window()

    def _apply_theme(self):
        colors = self.COLORS
        try:
            self.wizard.configure(bg=colors["bg"])
            style = ttk.Style(self.wizard)
            style.configure("Wizard.TFrame", background=colors["bg"])
            style.configure("WizardCard.TFrame", background=colors["surface"], relief="flat")
            style.configure("WizardTitle.TLabel", background=colors["bg"], foreground="#ffffff", font=("Segoe UI Semibold", 14))
            style.configure("Wizard.TLabel", background=colors["surface"], foreground=colors["ink"])
            style.configure("WizardMuted.TLabel", background=colors["surface"], foreground=colors["muted"])
            style.configure("WizardDialog.TFrame", background=colors["surface"], relief="flat")
            style.configure("WizardDialogTitle.TLabel", background=colors["surface"], foreground="#ffffff", font=("Segoe UI Semibold", 12))
            style.configure("WizardDialogText.TLabel", background=colors["surface"], foreground=colors["ink"])
        except tk.TclError:
            pass

    def _get_screen_limited_geometry(self, width: int, height: int, *, margin: int = 96) -> str:
        try:
            screen_width = int(self.parent.winfo_screenwidth())
            screen_height = int(self.parent.winfo_screenheight())
        except (AttributeError, tk.TclError, TypeError):
            return f"{width}x{height}"
        safe_width = max(520, min(width, screen_width - margin))
        safe_height = max(420, min(height, screen_height - margin))
        return f"{safe_width}x{safe_height}"

    def _parse_geometry_size(self, geometry: str) -> tuple[int, int]:
        try:
            size_part = str(geometry or "").split("+", 1)[0]
            width_text, height_text = size_part.split("x", 1)
            return int(width_text), int(height_text)
        except (TypeError, ValueError):
            return 0, 0

    def _center_dialog(self, dialog):
        try:
            dialog.update_idletasks()
            parent_x = self.wizard.winfo_rootx()
            parent_y = self.wizard.winfo_rooty()
            parent_width = self.wizard.winfo_width()
            parent_height = self.wizard.winfo_height()
            width = dialog.winfo_width()
            height = dialog.winfo_height()
            x = parent_x + max(0, (parent_width - width) // 2)
            y = parent_y + max(0, (parent_height - height) // 2)
            dialog.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

    def _fit_dialog_to_content(self, dialog, *, margin: int = 96):
        try:
            if not dialog.winfo_exists():
                return
            dialog.update_idletasks()
            screen_width = int(dialog.winfo_screenwidth())
            screen_height = int(dialog.winfo_screenheight())
            max_width = max(420, screen_width - margin)
            max_height = max(360, screen_height - margin)
            current_width, current_height = self._parse_geometry_size(dialog.winfo_geometry())
            requested_width = max(dialog.winfo_reqwidth(), current_width)
            requested_height = max(dialog.winfo_reqheight(), current_height)
            target_width = min(max_width, max(current_width, requested_width + 24))
            target_height = min(max_height, max(current_height, requested_height + 24))
            if target_width > current_width or target_height > current_height:
                dialog.geometry(f"{target_width}x{target_height}")
                dialog.update_idletasks()
            try:
                dialog.minsize(min(target_width, max_width), min(target_height, max_height))
            except (AttributeError, tk.TclError):
                pass
            self._center_dialog(dialog)
        except tk.TclError:
            pass

    def _get_initial_db_path(self) -> str:
        configured_path = str(self.config.get("database.path", "") or "").strip()
        if configured_path:
            return configured_path
        return str(Path.home() / ".cryptosafe" / "vault.db")

    def _style_text(self, widget):
        colors = self.COLORS
        try:
            widget.configure(
                bg=colors["surface"],
                fg=colors["ink"],
                insertbackground=colors["ink"],
                selectbackground=colors["selection"],
                selectforeground=colors["ink"],
                highlightthickness=1,
                highlightbackground=colors["line"],
                highlightcolor=colors["accent"],
                relief=tk.FLAT,
                bd=0,
                padx=8,
                pady=8,
            )
        except tk.TclError:
            pass
        return widget

    def _can_use_themed_dialogs(self) -> bool:
        return hasattr(self.wizard, "tk") and hasattr(self.wizard, "wait_window")

    def _show_themed_message(self, title: str, message: str):
        if not self._can_use_themed_dialogs():
            messagebox.showinfo(title, message)
            return

        dialog = tk.Toplevel(self.wizard)
        dialog.configure(bg=self.COLORS["bg"])
        dialog.title(title)
        dialog.transient(self.wizard)
        dialog.grab_set()
        dialog.geometry(self._get_screen_limited_geometry(560, 220))
        dialog.minsize(420, 150)
        dialog.resizable(True, True)

        card = ttk.Frame(dialog, style="WizardDialog.TFrame", padding=(18, 16, 18, 14))
        card.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        ttk.Label(card, text=title, style="WizardDialogTitle.TLabel").pack(fill=tk.X)
        ttk.Label(card, text=message, style="WizardDialogText.TLabel", wraplength=420, justify=tk.LEFT).pack(
            fill=tk.X, pady=(12, 18)
        )
        ttk.Button(card, text="ОК", command=dialog.destroy).pack(anchor=tk.E)
        self._fit_dialog_to_content(dialog)
        dialog.wait_window()

    def _show_themed_error(self, title: str, message: str):
        if not self._can_use_themed_dialogs():
            messagebox.showerror(title, message)
            return
        self._show_themed_message(title, message)

    def _create_widgets(self):
        self.title_label = ttk.Label(self.wizard, text="", style="WizardTitle.TLabel")
        self.title_label.pack(pady=10)

        self.content_frame = ttk.Frame(self.wizard, padding=12, style="WizardCard.TFrame")
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        button_frame = ttk.Frame(self.wizard, style="Wizard.TFrame")
        button_frame.pack(fill=tk.X, padx=20, pady=10)

        self.back_btn = ttk.Button(button_frame, text="< Назад", command=self._prev_step)
        self.back_btn.pack(side=tk.LEFT)

        self.next_btn = ttk.Button(button_frame, text="Далее >", command=self._next_step)
        self.next_btn.pack(side=tk.RIGHT)

        self.finish_btn = ttk.Button(button_frame, text="Готово", command=self._finish)

    def _show_step(self, step: int):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        self.title_label.config(text=f"Шаг {step + 1} из {len(self.steps)}")
        self.steps[step]()
        self.back_btn.config(state=tk.NORMAL if step > 0 else tk.DISABLED)

        if step == len(self.steps) - 1:
            self.next_btn.pack_forget()
            self.finish_btn.pack(side=tk.RIGHT)
        else:
            self.finish_btn.pack_forget()
            self.next_btn.pack(side=tk.RIGHT)

    def _next_step(self):
        if self.current_step == 1 and not self._validate_password():
            return
        if self.current_step == 2 and not self._validate_db_path():
            return

        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self._show_step(self.current_step)

    def _prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._show_step(self.current_step)

    def _step_welcome(self):
        text = self._style_text(tk.Text(self.content_frame, wrap=tk.WORD, height=10, font=("Segoe UI", 10)))
        text.insert(
            "1.0",
            "Добро пожаловать в CryptoSafe Manager.\n\n"
            "Этот мастер поможет:\n"
            "1. Создать мастер-пароль\n"
            "2. Выбрать расположение базы данных хранилища\n"
            "3. Сохранить криптографические параметры\n\n"
            "Нажмите «Далее», чтобы продолжить.",
        )
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)

    def _step_master_password(self):
        ttk.Label(self.content_frame, text="Создание мастер-пароля", style="Wizard.TLabel", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 8)
        )
        ttk.Label(self.content_frame, text="Мастер-пароль", style="Wizard.TLabel").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.master_password, show="*", width=42).pack(
            fill=tk.X, pady=(0, 10)
        )
        ttk.Label(self.content_frame, text="Подтверждение пароля", style="Wizard.TLabel").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.confirm_password, show="*", width=42).pack(
            fill=tk.X, pady=(0, 10)
        )
        ttk.Label(
            self.content_frame,
            text="Используйте длинный пароль с буквами разного регистра, цифрами и специальными символами.",
            style="WizardMuted.TLabel",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(8, 0))

    def _step_database_location(self):
        ttk.Label(self.content_frame, text="Расположение базы данных хранилища", style="Wizard.TLabel", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 8)
        )
        ttk.Label(self.content_frame, text="Путь к файлу базы данных", style="Wizard.TLabel").pack(anchor=tk.W)
        path_frame = ttk.Frame(self.content_frame, style="WizardCard.TFrame")
        path_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Entry(path_frame, textvariable=self.db_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(path_frame, text="Обзор...", command=self._browse_db).pack(side=tk.RIGHT, padx=(5, 0))

    def _step_finish(self):
        text = self._style_text(tk.Text(self.content_frame, wrap=tk.WORD, height=10, font=("Segoe UI", 10)))
        text.insert(
            "1.0",
            f"Все готово к инициализации хранилища.\n\n"
            f"База данных: {self.db_path.get()}\n"
            "Защита: AES-256-GCM для данных и стойкие KDF для мастер-пароля.\n"
            f"Авто-блокировка: {self.auto_lock_minutes.get()} мин\n"
            f"Кэш ключа: {self.key_cache_timeout_minutes.get()} мин\n\n"
            "Нажмите «Готово», чтобы создать хранилище и сохранить мастер-пароль.",
        )
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)

    def _browse_db(self):
        filename = filedialog.asksaveasfilename(
            title="Выберите файл базы данных хранилища",
            defaultextension=".db",
            filetypes=[("База SQLite", "*.db"), ("Все файлы", "*.*")],
        )
        if filename:
            self.db_path.set(filename)

    def _validate_password(self) -> bool:
        if not self.master_password.get():
            self._show_themed_error("Ошибка", "Введите мастер-пароль")
            return False
        if self.master_password.get() != self.confirm_password.get():
            self._show_themed_error("Ошибка", "Пароли не совпадают")
            return False
        return True

    def _validate_db_path(self) -> bool:
        if not self.db_path.get():
            self._show_themed_error("Ошибка", "Укажите путь к файлу базы данных")
            return False
        return True

    def _finish(self):
        if not self._validate_password() or not self._validate_db_path():
            return

        self.config.set("database.path", self.db_path.get())
        pbkdf2_iterations = int(self.config.get("crypto.pbkdf2_iterations", 100000))
        self.config.set("crypto.pbkdf2_iterations", pbkdf2_iterations)
        self.config.set("security.auto_lock_minutes", self.auto_lock_minutes.get())
        self.config.set("security.key_cache_timeout_minutes", self.key_cache_timeout_minutes.get())

        database = Database(self.db_path.get())
        self.auth_service.key_storage = KeyStorage(database)

        try:
            self.auth_service.register_master_password(self.master_password.get())
        except AuthenticationError as error:
            self._show_themed_error("Ошибка", str(error))
            return

        database.set_setting(
            "security.password_policy",
            {
                "min_password_length": self.config.get("security.min_password_length", 12),
                "require_uppercase": self.config.get("security.require_uppercase", True),
                "require_lowercase": self.config.get("security.require_lowercase", True),
                "require_digits": self.config.get("security.require_digits", True),
                "require_special": self.config.get("security.require_special", True),
            },
        )
        database.set_setting(
            "crypto.key_derivation",
            {
                "argon2_time": self.config.get("crypto.argon2_time", 3),
                "argon2_memory": self.config.get("crypto.argon2_memory", 65536),
                "argon2_parallelism": self.config.get("crypto.argon2_parallelism", 4),
                "argon2_hash_len": self.config.get("crypto.argon2_hash_len", 32),
                "pbkdf2_iterations": pbkdf2_iterations,
                "pbkdf2_salt_len": self.config.get("crypto.pbkdf2_salt_len", 16),
                "pbkdf2_key_len": self.config.get("crypto.pbkdf2_key_len", 32),
            },
        )
        database.set_setting("security.auto_lock_timeout_minutes", self.auto_lock_minutes.get())
        database.set_setting("security.key_cache_timeout_minutes", self.key_cache_timeout_minutes.get())
        database.set_setting("security.lock_on_focus_loss", self.config.get("security.lock_on_focus_loss", True))
        database.set_setting("security.lock_on_minimize", self.config.get("security.lock_on_minimize", True))

        self._show_themed_message("Успешно", "Хранилище успешно инициализировано.")
        self.wizard.destroy()