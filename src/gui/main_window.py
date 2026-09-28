import os
import queue
import subprocess
import threading
import tkinter as tk
import ctypes
import json
import sys
import time
from collections import Counter
from contextlib import contextmanager
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import webbrowser
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..core.clipboard import (
    ClipboardAccessError,
    ClipboardMonitor,
    ClipboardService,
    ClipboardStatus,
    create_platform_adapter,
    get_platform_validation_report,
)
from ..core.audit import (
    AuditLogger,
    decrypt_export_package,
    encrypt_export_package,
    export_logs_to_cef,
    export_logs_to_csv,
    export_logs_to_json,
    export_logs_to_pdf,
)
from ..core.config import Config
from ..core.crypto.authentication import AuthenticationError, AuthenticationService
from ..core.crypto.key_derivation import KeyDerivation
from ..core.crypto.key_storage import KeyStorage
from ..core.crypto.password_validator import PasswordValidator
from ..core.crypto.legacy_encryption import LegacyXOREncryptionService
from ..core.events import Event, EventType, event_bus
from ..core.import_export import ExportOptions, ImportOptions, KeyExchangeService, QRCodeService, SharePermissions
from ..core.import_export.exceptions import ImportExportError, ImportValidationError
from ..core.import_export.exporter import VaultExporter
from ..core.import_export.importer import VaultImporter
from ..core.import_export.sharing_service import SharingService
from ..core.key_manager import KeyManager
from ..core.security import (
    ActivityMonitor,
    ActivityMonitorConfig,
    WindowsGlobalHotkeyService,
    get_default_hotkeys,
    PanicMode,
    PanicModeConfig,
    SECURITY_PROFILES,
    explain_security_profile,
    validate_security_settings,
)
from ..core.state_manager import StateManager
from ..core.vault import (
    AESGCMEncryptionService,
    EntryManager,
    EntryNotFoundError,
    PasswordGenerator,
    PasswordGeneratorOptions,
)
from ..database.db import Database
from .setup_wizard import SetupWizard
from .widgets.password_entry import PasswordEntry
from .widgets.secure_table import SecureTable


class EntryView(dict):
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as error:
            raise AttributeError(item) from error


class MainWindow:
    CLIPBOARD_RECOVERY_PENDING_KEY = "runtime.clipboard_recovery_pending"
    AUDIT_PAGE_SIZE = 50
    AUDIT_VERIFICATION_INTERVAL_SECONDS = 24 * 60 * 60
    UI_COLORS = {
        "bg": "#1e1e1e",
        "surface": "#252526",
        "surface_alt": "#2d2d30",
        "surface_soft": "#333333",
        "field": "#1b1b1b",
        "ink": "#d4d4d4",
        "ink_strong": "#ffffff",
        "muted": "#a6a6a6",
        "accent": "#007acc",
        "accent_hover": "#0e8ee9",
        "accent_soft": "#04395e",
        "button": "#2d2d30",
        "button_hover": "#3e3e42",
        "danger": "#f14c4c",
        "danger_soft": "#3a1f1f",
        "warning": "#cca700",
        "line": "#3c3c3c",
        "line_strong": "#5a5a5a",
        "selection": "#094771",
    }

    def __init__(self):
        self._enable_windows_dpi_awareness()
        self.root = tk.Tk()
        self.root.title("CryptoSafe Manager")
        self.root.geometry("1320x820")
        if hasattr(self.root, "minsize"):
            self.root.minsize(1180, 720)

        self.config = Config()
        self._configure_visual_theme()
        selected_vault_path = self._select_startup_vault_path()
        self.config.set("database.path", selected_vault_path)
        self.state = StateManager()
        self.state.set_inactivity_timeout(self.config.get("security.auto_lock_minutes", 5) * 60)
        self.state.set_key_cache_timeout(self.config.get("security.key_cache_timeout_minutes", 60) * 60)
        self.activity_monitor = self._create_activity_monitor()
        self.panic_mode = self._create_panic_mode()

        self.db = Database(selected_vault_path)
        self.key_manager = KeyManager()
        self.key_storage = KeyStorage(self.db)
        self.key_derivation = KeyDerivation(self.config.get("crypto", {}))
        self.password_validator = PasswordValidator(self.config.get("security", {}))
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.crypto = LegacyXOREncryptionService(self.key_manager)
        self.vault_crypto = AESGCMEncryptionService(self.key_manager)
        self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
        self.password_generator = PasswordGenerator()
        self.passwords_visible = False
        self.password_visibility_overrides = {}
        self.search_history = []
        self._favicon_cache = {}
        self._login_prompt_active = False
        self._initial_login_completed = False
        self._clipboard_monitor_warning_shown = False
        self._clipboard_notification_toast = None
        self._system_tray_icon = None
        self._system_tray_visible = False
        self._tray_crypto_operation_active = False
        self._tray_animation_frame = 0
        self._panic_gesture_samples = []
        self._panic_hotkey_poll_active = False
        self._panic_hotkey_pressed = False
        self._global_hotkey_service = None
        self._global_hotkey_status = "not_registered"
        self._ui_task_queue = queue.Queue()
        self._ui_task_pump_active = False
        self._tray_focus_grace_until = 0.0
        self._last_audit_verification_at = None
        self._audit_tampering_notified = False
        self._internal_modal_depth = 0
        self.audit_logger = AuditLogger(self.db, event_bus, key_provider=self.auth_service.get_active_key)
        self.clipboard_service = ClipboardService(
            create_platform_adapter(self.root),
            database=self.db,
            config=self.config,
            state_manager=self.state,
        )
        self.clipboard_monitor = ClipboardMonitor(self.clipboard_service.adapter, self.clipboard_service)
        self._clipboard_status_snapshot = ClipboardStatus(active=False)
        self.clipboard_service.subscribe(self._on_clipboard_status_changed)
        self._setup_clipboard_recovery_tracking()
        self._persist_runtime_settings()
        self._load_password_policy()
        self._load_search_history()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if not self.auth_service.is_initialized():
            SetupWizard(self.root, self.config, self.auth_service)
            if not self.auth_service.is_initialized():
                self._on_close()
                return
            self.db = self.auth_service.key_storage.database
            self.key_storage = self.auth_service.key_storage
            self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
            self.audit_logger.close()
            self.audit_logger = AuditLogger(self.db, event_bus, key_provider=self.auth_service.get_active_key)
            self._persist_runtime_settings()
            self._load_password_policy()
            self.password_visibility_overrides = {}
            self._load_search_history()
            self._sync_active_key_from_auth()

        self._create_menu()
        self._create_toolbar()
        self._create_main_area()
        self._create_statusbar()
        self._start_ui_task_pump()
        self._initialize_system_tray()
        self._run_startup_clipboard_recovery()
        self._setup_events()
        self._setup_activity_tracking()

        self._require_login(initial=True)
        self._initial_login_completed = True
        if not self.auth_service.is_authenticated():
            return
        self._sync_active_key_from_auth()
        self._verify_audit_log_on_startup()
        event_bus.publish(Event(EventType.APP_STARTED, {"component": "main_window"}))
        self._load_entries()
        self._schedule_security_tasks()

    @staticmethod
    def _enable_windows_dpi_awareness():
        if os.name != "nt":
            return
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    def _get_recent_vault_paths(self, current_path: str = "") -> list[str]:
        paths = []
        for path in [current_path, *self.config.get("database.recent_paths", [])]:
            normalized = str(path or "").strip()
            if normalized and normalized not in paths:
                paths.append(normalized)
        return paths[:8]

    def _remember_vault_path(self, path: str):
        normalized = str(path or "").strip()
        if not normalized:
            return
        self.config.set("database.path", normalized)
        recent_paths = [normalized]
        for existing_path in self.config.get("database.recent_paths", []):
            existing = str(existing_path or "").strip()
            if existing and existing != normalized:
                recent_paths.append(existing)
        self.config.set("database.recent_paths", recent_paths[:8])

    def _select_startup_vault_path(self) -> str:
        default_path = str(self.config.get("database.path", "cryptosafe.db"))
        selected = {"path": default_path}

        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Выбор хранилища")
        dialog.geometry(self._get_screen_limited_geometry(1100, 720))
        if hasattr(dialog, "minsize"):
            dialog.minsize(980, 640)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=18, style="App.TFrame")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Выберите хранилище для открытия", style="DialogTitle.TLabel").pack(anchor="w")
        ttk.Label(
            frame,
            text="Сначала выбирается файл хранилища, потом вводится мастер-пароль именно для него.",
            wraplength=960,
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(6, 14))

        listbox = tk.Listbox(
            frame,
            height=12,
            bg=self.UI_COLORS["field"],
            fg=self.UI_COLORS["ink"],
            selectbackground=self.UI_COLORS["selection"],
            selectforeground=self.UI_COLORS["ink"],
            highlightthickness=1,
            highlightbackground=self.UI_COLORS["line"],
            highlightcolor=self.UI_COLORS["accent"],
            relief=tk.FLAT,
            bd=0,
        )
        recent_paths = self._get_recent_vault_paths(default_path)
        for path in recent_paths:
            label = path
            if path == default_path:
                label = f"{path}  (последний)"
            listbox.insert(tk.END, label)
        listbox.pack(fill=tk.BOTH, expand=True)
        if recent_paths:
            listbox.selection_set(0)

        def selected_from_list() -> str:
            selection = listbox.curselection()
            if not selection:
                return selected["path"]
            index = int(selection[0])
            if 0 <= index < len(recent_paths):
                return recent_paths[index]
            return selected["path"]

        def choose_existing():
            path = filedialog.askopenfilename(
                title="Открыть хранилище",
                filetypes=[("База SQLite", "*.db"), ("Все файлы", "*.*")],
                parent=dialog,
            )
            if path:
                selected["path"] = path
                dialog.destroy()

        def create_new():
            path = filedialog.asksaveasfilename(
                title="Создать новое хранилище",
                defaultextension=".db",
                filetypes=[("База SQLite", "*.db"), ("Все файлы", "*.*")],
                parent=dialog,
            )
            if not path:
                return
            if os.path.exists(path):
                self._show_warning(
                    "Создать новое хранилище",
                    "Такой файл уже существует. Чтобы не потерять данные, выберите другой файл или откройте существующее хранилище.",
                    parent=dialog,
                )
                return
            selected["path"] = path
            dialog.destroy()

        def continue_selected():
            selected["path"] = selected_from_list()
            dialog.destroy()

        button_row = ttk.Frame(frame, style="App.TFrame")
        button_row.pack(fill=tk.X, pady=(14, 0))
        ttk.Button(button_row, text="Открыть файл...", style="Ghost.TButton", command=choose_existing).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(button_row, text="Создать новый...", style="Ghost.TButton", command=create_new).pack(side=tk.LEFT, padx=6)
        ttk.Button(button_row, text="Продолжить", style="Accent.TButton", command=continue_selected).pack(side=tk.RIGHT)
        dialog.protocol("WM_DELETE_WINDOW", continue_selected)
        self.root.wait_window(dialog)

        self._remember_vault_path(selected["path"])
        return selected["path"]

    def _persist_runtime_settings(self):
        self.db.set_setting(
            "crypto.key_derivation",
            {
                "argon2_time": self.config.get("crypto.argon2_time", 3),
                "argon2_memory": self.config.get("crypto.argon2_memory", 65536),
                "argon2_parallelism": self.config.get("crypto.argon2_parallelism", 4),
                "argon2_hash_len": self.config.get("crypto.argon2_hash_len", 32),
                "pbkdf2_iterations": self.config.get("crypto.pbkdf2_iterations", 100000),
                "pbkdf2_salt_len": self.config.get("crypto.pbkdf2_salt_len", 16),
                "pbkdf2_key_len": self.config.get("crypto.pbkdf2_key_len", 32),
            },
        )
        self.db.set_setting("security.auto_lock_timeout_minutes", self.config.get("security.auto_lock_minutes", 5))
        self.db.set_setting("security.key_cache_timeout_minutes", self.config.get("security.key_cache_timeout_minutes", 60))
        self.db.set_setting("security.lock_on_focus_loss", self.config.get("security.lock_on_focus_loss", True))
        self.db.set_setting("security.lock_on_minimize", self.config.get("security.lock_on_minimize", True))
        self.db.set_setting("security.clipboard", self.clipboard_service.get_settings(), encrypted=True)

    def _setup_clipboard_recovery_tracking(self):
        self._startup_clipboard_recovery_pending = bool(
            self.db.get_setting(self.CLIPBOARD_RECOVERY_PENDING_KEY, False)
        )
        self._startup_clipboard_recovery_performed = False
        self._startup_clipboard_recovery_failed = False
        self.db.set_setting(self.CLIPBOARD_RECOVERY_PENDING_KEY, True)

    def _flush_audit_logger(self, *, warn: bool = False) -> bool:
        if not hasattr(self, "audit_logger") or self.audit_logger is None:
            return True
        if not hasattr(self.audit_logger, "flush"):
            return True
        try:
            self.audit_logger.flush()
            return True
        except Exception as error:
            if warn:
                self._show_warning(
                    "Журнал аудита",
                    f"Не удалось сразу записать последние события аудита: {error}",
                )
            return False

    def _run_startup_clipboard_recovery(self):
        if not getattr(self, "_startup_clipboard_recovery_pending", False):
            return
        self._startup_clipboard_recovery_performed = True
        cleared = self._clear_system_clipboard(sync_service=False)
        if hasattr(self, "clipboard_service"):
            self.clipboard_service.clear(reason="startup_recovery", publish_event=False)
        self._startup_clipboard_recovery_failed = not cleared
        if self._startup_clipboard_recovery_failed and hasattr(self, "clipboard_service"):
            if hasattr(self.clipboard_service, "_last_clear_reason"):
                self.clipboard_service._last_clear_reason = "startup_recovery"
            if hasattr(self.clipboard_service, "_last_clear_failed"):
                self.clipboard_service._last_clear_failed = True
            if hasattr(self.clipboard_service, "last_clear_reason"):
                self.clipboard_service.last_clear_reason = "startup_recovery"
            if hasattr(self.clipboard_service, "last_clear_failed"):
                self.clipboard_service.last_clear_failed = True
        if self._startup_clipboard_recovery_failed:
            self._handle_clipboard_clear_failure()

    def _clear_clipboard_recovery_pending(self):
        if hasattr(self, "db"):
            self.db.set_setting(self.CLIPBOARD_RECOVERY_PENDING_KEY, False)

    def _load_password_policy(self):
        policy = self.db.get_setting("security.password_policy", {})
        if not isinstance(policy, dict):
            return
        self.password_validator.min_length = policy.get("min_password_length", self.password_validator.min_length)
        self.password_validator.require_uppercase = policy.get(
            "require_uppercase", self.password_validator.require_uppercase
        )
        self.password_validator.require_lowercase = policy.get(
            "require_lowercase", self.password_validator.require_lowercase
        )
        self.password_validator.require_digits = policy.get("require_digits", self.password_validator.require_digits)
        self.password_validator.require_special = policy.get(
            "require_special", self.password_validator.require_special
        )

    def _load_search_history(self):
        loaded_history = self.db.get_setting("ui.search_history", [])
        if not isinstance(loaded_history, list):
            self.search_history = []
            return
        self.search_history = [
            str(item).strip()
            for item in loaded_history
            if isinstance(item, str) and str(item).strip()
        ][:10]

    def _verify_audit_log_on_startup(self):
        if not hasattr(self, "audit_logger") or not hasattr(self.audit_logger, "verify_integrity"):
            return
        verification_result = self.run_audit_verification(manual=False, recent_only=False, trigger="startup")
        self._audit_integrity_status = verification_result

    def _configure_visual_theme(self):
        colors = self.UI_COLORS
        try:
            if hasattr(self.root, "configure"):
                self.root.configure(bg=colors["bg"])
            elif hasattr(self.root, "config"):
                self.root.config(bg=colors["bg"])
            for option, value in {
                "*Menu.background": colors["surface"],
                "*Menu.foreground": colors["ink"],
                "*Menu.activeBackground": colors["selection"],
                "*Menu.activeForeground": colors["ink"],
                "*Menu.selectColor": colors["accent"],
                "*Listbox.background": colors["field"],
                "*Listbox.foreground": colors["ink"],
                "*Listbox.selectBackground": colors["selection"],
                "*Listbox.selectForeground": colors["ink"],
                "*TCombobox*Listbox.background": colors["field"],
                "*TCombobox*Listbox.foreground": colors["ink"],
                "*TCombobox*Listbox.selectBackground": colors["selection"],
                "*TCombobox*Listbox.selectForeground": colors["ink"],
            }.items():
                self.root.option_add(option, value)
            style = ttk.Style(self.root)
        except (AttributeError, tk.TclError):
            return
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        base_font = ("Segoe UI", 10)
        title_font = ("Segoe UI Semibold", 18)
        section_font = ("Segoe UI Semibold", 10)

        style.configure(".", font=base_font)
        style.map(".", foreground=[("disabled", "#6f6f6f")])
        style.configure("TFrame", background=colors["bg"])
        style.configure("App.TFrame", background=colors["bg"])
        style.configure("Surface.TFrame", background=colors["surface"], relief="flat", borderwidth=1)
        style.configure("TopBar.TFrame", background=colors["surface"], relief="solid", borderwidth=1)
        style.configure("Status.TFrame", background=colors["surface_alt"], relief="flat")
        style.configure("AppTitle.TLabel", background=colors["surface"], foreground=colors["ink_strong"], font=title_font)
        style.configure("AppSubtitle.TLabel", background=colors["surface"], foreground=colors["muted"])
        style.configure("Section.TLabel", background=colors["surface"], foreground=colors["ink_strong"], font=section_font)
        style.configure("DialogTitle.TLabel", background=colors["bg"], foreground=colors["ink_strong"], font=("Segoe UI Semibold", 13))
        style.configure("DialogCard.TFrame", background=colors["surface"], borderwidth=1, relief="flat")
        style.configure("DialogHeader.TLabel", background=colors["surface"], foreground=colors["ink_strong"], font=("Segoe UI Semibold", 12))
        style.configure("DialogBody.TLabel", background=colors["surface"], foreground=colors["ink"])
        style.configure("AccentIcon.TLabel", background=colors["accent"], foreground=colors["ink_strong"], font=("Segoe UI Semibold", 12), padding=(8, 4))
        style.configure("WarningIcon.TLabel", background=colors["warning"], foreground="#1e1e1e", font=("Segoe UI Semibold", 12), padding=(8, 4))
        style.configure("DangerIcon.TLabel", background=colors["danger"], foreground=colors["ink_strong"], font=("Segoe UI Semibold", 12), padding=(8, 4))
        style.configure("Muted.TLabel", background=colors["bg"], foreground=colors["muted"])
        style.configure("Status.TLabel", background=colors["surface_alt"], foreground=colors["muted"])
        style.configure("TLabel", background=colors["bg"], foreground=colors["ink"])
        style.configure(
            "TButton",
            background=colors["button"],
            foreground=colors["ink"],
            focuscolor=colors["accent"],
            padding=(12, 7),
            borderwidth=1,
            bordercolor=colors["line"],
            lightcolor=colors["line"],
            darkcolor=colors["line"],
            relief="flat",
        )
        style.map(
            "TButton",
            background=[("disabled", colors["surface_alt"]), ("active", colors["button_hover"]), ("pressed", colors["accent_soft"])],
            bordercolor=[("focus", colors["accent"]), ("active", colors["line_strong"])],
            foreground=[("disabled", "#6f6f6f")],
        )
        style.configure("Accent.TButton", background=colors["accent"], foreground=colors["ink_strong"], padding=(13, 7), bordercolor=colors["accent"])
        style.map("Accent.TButton", background=[("active", colors["accent_hover"]), ("pressed", colors["accent"])])
        style.configure("Ghost.TButton", background=colors["button"], foreground=colors["ink"], padding=(12, 7), bordercolor=colors["line"])
        style.map("Ghost.TButton", background=[("active", colors["button_hover"]), ("pressed", colors["accent"])])
        style.configure("Danger.TButton", background=colors["danger_soft"], foreground=colors["danger"], padding=(12, 7), bordercolor="#6e2a2a")
        style.map("Danger.TButton", background=[("active", "#44212a"), ("pressed", "#44212a")])
        style.configure(
            "TEntry",
            fieldbackground=colors["field"],
            background=colors["field"],
            foreground=colors["ink"],
            insertcolor=colors["ink"],
            bordercolor=colors["line"],
            lightcolor=colors["line"],
            darkcolor=colors["line"],
            padding=7,
            borderwidth=1,
        )
        style.map(
            "TEntry",
            fieldbackground=[("disabled", colors["surface_alt"]), ("readonly", colors["field"])],
            bordercolor=[("focus", colors["accent"]), ("active", colors["line_strong"])],
        )
        style.configure(
            "TCombobox",
            fieldbackground=colors["field"],
            background=colors["button"],
            foreground=colors["ink"],
            arrowcolor=colors["ink"],
            bordercolor=colors["line"],
            lightcolor=colors["line"],
            darkcolor=colors["line"],
            padding=7,
            borderwidth=1,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", colors["field"]), ("disabled", colors["surface_alt"])],
            background=[("active", colors["button_hover"]), ("pressed", colors["button_hover"])],
            bordercolor=[("focus", colors["accent"]), ("active", colors["line_strong"])],
            foreground=[("disabled", "#6f6f6f"), ("readonly", colors["ink"])],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=colors["field"],
            background=colors["field"],
            foreground=colors["ink"],
            insertcolor=colors["ink"],
            bordercolor=colors["line"],
            arrowcolor=colors["ink"],
            padding=7,
            borderwidth=1,
        )
        style.configure("TCheckbutton", background=colors["bg"], foreground=colors["ink"], focuscolor=colors["accent"])
        style.map(
            "TCheckbutton",
            background=[("active", colors["bg"])],
            foreground=[("disabled", "#6f6f6f"), ("active", colors["ink_strong"])],
        )
        style.configure("TLabelframe", background=colors["surface"], foreground=colors["ink"], bordercolor=colors["line"])
        style.configure("TLabelframe.Label", background=colors["surface"], foreground=colors["muted"])
        style.configure("TPanedwindow", background=colors["bg"])
        style.configure(
            "TScrollbar",
            background=colors["button"],
            troughcolor=colors["field"],
            bordercolor=colors["bg"],
            arrowcolor=colors["muted"],
            relief="flat",
        )
        style.map("TScrollbar", background=[("active", colors["button_hover"])])
        style.configure(
            "TProgressbar",
            background=colors["accent"],
            troughcolor=colors["field"],
            bordercolor=colors["line"],
            lightcolor=colors["accent"],
            darkcolor=colors["accent"],
        )
        style.configure(
            "Vault.Treeview",
            background=colors["surface"],
            fieldbackground=colors["surface"],
            foreground=colors["ink"],
            bordercolor=colors["line"],
            rowheight=34,
            borderwidth=1,
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=colors["surface_alt"],
            foreground=colors["ink_strong"],
            font=("Segoe UI Semibold", 10),
            padding=(10, 8),
            borderwidth=1,
            bordercolor=colors["line"],
        )
        style.map(
            "Vault.Treeview",
            background=[
                ("selected", colors["selection"]),
                ("active", colors["surface_alt"]),
                ("focus", colors["surface"]),
            ],
            foreground=[
                ("selected", colors["ink_strong"]),
                ("active", colors["ink"]),
                ("focus", colors["ink"]),
            ],
        )
        style.map(
            "Vault.Treeview.Heading",
            background=[
                ("active", colors["button_hover"]),
                ("pressed", colors["selection"]),
            ],
            foreground=[
                ("active", colors["ink_strong"]),
                ("pressed", colors["ink_strong"]),
            ],
        )

    def _create_tk_menu(self, parent, **kwargs):
        colors = self.UI_COLORS
        menu = tk.Menu(
            parent,
            background=colors["surface"],
            foreground=colors["ink"],
            activebackground=colors["selection"],
            activeforeground=colors["ink"],
            disabledforeground="#5f6877",
            borderwidth=0,
            relief=tk.FLAT,
            **kwargs,
        )
        return menu

    def _create_menu(self):
        menubar = self._create_tk_menu(self.root)
        self._menubar = menubar
        self.root.config(menu=menubar)

        file_menu = self._create_tk_menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        self._populate_file_menu(file_menu)

        entry_menu = self._create_tk_menu(menubar, tearoff=0)
        menubar.add_cascade(label="Записи", menu=entry_menu)
        self._populate_entry_menu(entry_menu)

        security_menu = self._create_tk_menu(menubar, tearoff=0)
        menubar.add_cascade(label="Безопасность", menu=security_menu)
        self._populate_security_menu(security_menu)

        help_menu = self._create_tk_menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        self._populate_help_menu(help_menu)

    def _populate_file_menu(self, menu):
        menu.add_command(label="Новое хранилище", command=self.new_database)
        menu.add_command(label="Открыть хранилище", command=self.open_database)
        menu.add_command(label="Резервная копия", command=self.backup)
        menu.add_separator()
        menu.add_command(label="Экспорт хранилища", command=self.show_export_dialog)
        menu.add_command(label="Импорт хранилища", command=self.show_import_dialog)
        menu.add_separator()
        menu.add_command(label="Заблокировать", command=self._lock_vault)
        menu.add_command(label="Разблокировать", command=self._unlock_vault)
        menu.add_command(label="Выход", command=self._on_close)

    def _populate_entry_menu(self, menu):
        menu.add_command(label="Добавить", command=self.add_entry)
        menu.add_command(label="Изменить", command=self.edit_entry)
        menu.add_command(label="Удалить", command=self.delete_entry)
        menu.add_command(label="Показать пароль", command=self.show_selected_password)
        menu.add_command(label="Скопировать пароль", command=self.copy_selected_password)
        menu.add_command(label="Скопировать логин", command=self.copy_selected_username)
        menu.add_command(label="Скопировать запись", command=self.copy_selected_all)
        menu.add_separator()
        menu.add_command(label="Поделиться записью", command=self.show_share_dialog)

    def _populate_security_menu(self, menu):
        menu.add_command(label="Очистить буфер обмена", command=self.clear_clipboard_from_ui)
        menu.add_command(label="Просмотр буфера обмена", command=self.show_clipboard_preview_dialog)
        menu.add_command(label="Диагностика буфера обмена", command=self.show_clipboard_diagnostics)
        menu.add_separator()
        menu.add_command(label="Паник-режим", command=lambda: self.activate_panic_mode("menu"))
        menu.add_separator()
        menu.add_command(label="Сменить мастер-пароль", command=self.change_master_password)
        menu.add_command(label="Настройки", command=self.show_settings)
        menu.add_command(label="Журнал аудита", command=self.show_logs)
        menu.add_command(label="Обмен ключами / QR", command=self.show_key_exchange_dialog)

    def _populate_help_menu(self, menu):
        menu.add_command(label="О программе", command=self.show_about)

    def _create_visible_menu_bar(self):
        menu_bar = ttk.Frame(self.root, style="TopBar.TFrame")
        menu_bar.pack(side=tk.TOP, fill=tk.X, padx=18, pady=(10, 0), ipady=2)
        menu_specs = [
            ("Файл", self._populate_file_menu),
            ("Записи", self._populate_entry_menu),
            ("Безопасность", self._populate_security_menu),
            ("Справка", self._populate_help_menu),
        ]
        self._visible_menu_buttons = []
        for label, populate in menu_specs:
            button = ttk.Menubutton(menu_bar, text=label, style="Ghost.TButton")
            menu = self._create_tk_menu(button, tearoff=0)
            populate(menu)
            button.configure(menu=menu)
            button.pack(side=tk.LEFT, padx=(0, 6), pady=4)
            self._visible_menu_buttons.append(button)

    def _create_toolbar(self):
        toolbar = ttk.Frame(self.root, style="App.TFrame")
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=18, pady=(8, 10))

        top_bar = ttk.Frame(toolbar, style="TopBar.TFrame")
        top_bar.pack(fill=tk.X, pady=(0, 10), ipady=8)
        ttk.Label(top_bar, text="CryptoSafe", style="AppTitle.TLabel").pack(side=tk.LEFT, padx=(14, 14))
        ttk.Button(top_bar, text="Заблокировать", style="Danger.TButton", command=self._lock_vault).pack(
            side=tk.RIGHT, padx=(4, 14)
        )
        ttk.Button(top_bar, text="Разблокировать", style="Ghost.TButton", command=self._unlock_vault).pack(
            side=tk.RIGHT, padx=4
        )

        actions_row = ttk.Frame(toolbar, style="App.TFrame")
        actions_row.pack(fill=tk.X, pady=(0, 8))
        exchange_row = ttk.Frame(toolbar, style="App.TFrame")
        exchange_row.pack(fill=tk.X, pady=(0, 8))
        search_row = ttk.Frame(toolbar, style="App.TFrame")
        search_row.pack(fill=tk.X, pady=(0, 8))
        filters_row = ttk.Frame(toolbar, style="App.TFrame")
        filters_row.pack(fill=tk.X)

        ttk.Label(actions_row, text="Записи", style="TLabel").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions_row, text="Добавить", style="Ghost.TButton", command=self.add_entry).pack(side=tk.LEFT, padx=3)
        ttk.Button(actions_row, text="Изменить", style="Ghost.TButton", command=self.edit_entry).pack(side=tk.LEFT, padx=3)
        ttk.Button(actions_row, text="Удалить", style="Ghost.TButton", command=self.delete_entry).pack(side=tk.LEFT, padx=3)
        ttk.Button(actions_row, text="Показать пароль", style="Ghost.TButton", command=self.show_selected_password).pack(
            side=tk.LEFT, padx=(14, 3)
        )
        ttk.Button(actions_row, text="Скопировать пароль", style="Ghost.TButton", command=self.copy_selected_password).pack(side=tk.LEFT, padx=3)
        self.password_toggle_text = tk.StringVar(value="Показать пароли")
        ttk.Button(actions_row, text="Скопировать логин", style="Ghost.TButton", command=self.copy_selected_username).pack(side=tk.LEFT, padx=3)
        ttk.Button(actions_row, text="Скопировать запись", style="Ghost.TButton", command=self.copy_selected_all).pack(side=tk.LEFT, padx=3)
        ttk.Button(actions_row, text="Очистить буфер", style="Ghost.TButton", command=self.clear_clipboard_from_ui).pack(side=tk.LEFT, padx=(14, 3))
        ttk.Button(actions_row, textvariable=self.password_toggle_text, style="Ghost.TButton", command=self._toggle_password_visibility).pack(
            side=tk.LEFT, padx=3
        )

        ttk.Label(exchange_row, text="Обмен данными", style="TLabel").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(exchange_row, text="Экспорт", style="Ghost.TButton", command=self.show_export_dialog).pack(side=tk.LEFT, padx=3)
        ttk.Button(exchange_row, text="Импорт", style="Ghost.TButton", command=self.show_import_dialog).pack(side=tk.LEFT, padx=3)
        ttk.Button(exchange_row, text="Поделиться", style="Ghost.TButton", command=self.show_share_dialog).pack(side=tk.LEFT, padx=3)
        ttk.Button(exchange_row, text="QR / Ключи", style="Ghost.TButton", command=self.show_key_exchange_dialog).pack(side=tk.LEFT, padx=3)

        ttk.Label(search_row, text="Поиск", style="TLabel").pack(side=tk.LEFT, padx=(0, 10))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.search_entry = ttk.Entry(search_row, textvariable=self.search_var, width=38)
        self.search_entry.pack(side=tk.LEFT, padx=3)
        self.search_entry.bind("<Escape>", lambda _event: self._clear_search())
        self.search_entry.bind("<Return>", self._commit_search_query)
        self.search_entry.bind("<FocusOut>", self._remember_current_search)
        self.search_history_button = ttk.Button(search_row, text="История", style="Ghost.TButton", command=self._show_search_history_menu)
        self.search_history_button.pack(side=tk.LEFT, padx=(6, 3))
        ttk.Button(search_row, text="Сбросить", style="Ghost.TButton", command=self._clear_search).pack(side=tk.LEFT, padx=(3, 10))
        self.search_status_var = tk.StringVar(value="Найдено: 0")
        ttk.Label(search_row, textvariable=self.search_status_var, style="Muted.TLabel").pack(side=tk.LEFT, padx=(4, 0))
        ttk.Label(filters_row, text="Фильтры", style="TLabel").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(filters_row, text="Категория", style="TLabel").pack(side=tk.LEFT, padx=(0, 4))
        self.category_filter_var = tk.StringVar(value="Все")
        self.category_filter = ttk.Combobox(
            filters_row,
            textvariable=self.category_filter_var,
            state="readonly",
            width=12,
            values=["Все"],
        )
        self.category_filter.pack(side=tk.LEFT, padx=3)
        self.category_filter.bind("<<ComboboxSelected>>", lambda _event: self._apply_entry_filter())
        ttk.Label(filters_row, text="Тег", style="TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.tag_filter_var = tk.StringVar()
        self.tag_filter_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.tag_filter_entry = ttk.Entry(filters_row, textvariable=self.tag_filter_var, width=12)
        self.tag_filter_entry.pack(side=tk.LEFT, padx=3)
        ttk.Label(filters_row, text="Дата с", style="TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.updated_from_var = tk.StringVar()
        self.updated_from_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.updated_from_entry = ttk.Entry(filters_row, textvariable=self.updated_from_var, width=10)
        self.updated_from_entry.pack(side=tk.LEFT, padx=3)
        ttk.Label(filters_row, text="по", style="TLabel").pack(side=tk.LEFT, padx=(4, 4))
        self.updated_to_var = tk.StringVar()
        self.updated_to_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.updated_to_entry = ttk.Entry(filters_row, textvariable=self.updated_to_var, width=10)
        self.updated_to_entry.pack(side=tk.LEFT, padx=3)
        ttk.Label(filters_row, text="Сила", style="TLabel").pack(side=tk.LEFT, padx=(12, 4))
        self.password_strength_filter_var = tk.StringVar(value="Все")
        self.password_strength_filter = ttk.Combobox(
            filters_row,
            textvariable=self.password_strength_filter_var,
            state="readonly",
            width=10,
            values=["Все", "Слабый", "Средний", "Сильный"],
        )
        self.password_strength_filter.pack(side=tk.LEFT, padx=3)
        self.password_strength_filter.bind("<<ComboboxSelected>>", lambda _event: self._apply_entry_filter())
        self._update_search_history_button()

    def _create_main_area(self):
        main_frame = ttk.Frame(self.root, style="Surface.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 12))

        table_header = ttk.Frame(main_frame, style="Surface.TFrame")
        table_header.pack(fill=tk.X, padx=12, pady=(10, 6))
        ttk.Label(table_header, text="Записи хранилища", style="Section.TLabel").pack(side=tk.LEFT)

        columns = [
            {"id": "title", "label": "Название", "width": 180},
            {"id": "username", "label": "Имя пользователя", "width": 180},
            {"id": "password", "label": "Пароль", "width": 150},
            {"id": "category", "label": "Категория", "width": 140},
            {"id": "url", "label": "URL", "width": 260},
            {"id": "updated_at", "label": "Обновлено", "width": 160},
        ]
        self.table = SecureTable(main_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        self.table.bind_primary_click(self._handle_table_click)
        self._create_table_context_menu()

    def _create_table_context_menu(self):
        self.table_menu = self._build_table_context_menu()
        self.table.bind_context_menu(self._show_table_context_menu)

    def _build_table_context_menu(self):
        menu = self._create_tk_menu(self.root, tearoff=0)
        menu.add_command(label="Изменить", command=self.edit_entry)
        menu.add_command(label="Удалить", command=self.delete_entry)
        menu.add_separator()
        menu.add_command(label="Показать пароль", command=self.show_selected_password)
        menu.add_command(label="Скопировать пароль", command=self.copy_selected_password)
        menu.add_command(label="Скопировать логин", command=self.copy_selected_username)
        menu.add_command(label="Скопировать запись", command=self.copy_selected_all)
        menu.add_command(label="Очистить буфер обмена", command=self.clear_clipboard_from_ui)
        return menu

    def _show_table_context_menu(self, event):
        selected = self.table.ensure_row_selected_at_y(event.y)
        if not selected:
            return
        try:
            menu_exists = bool(getattr(self, "table_menu", None)) and self.table_menu.winfo_exists()
        except tk.TclError:
            menu_exists = False
        if not menu_exists:
            self.table_menu = self._build_table_context_menu()
        try:
            self.table_menu.tk_popup(event.x_root, event.y_root)
        except tk.TclError:
            return
        finally:
            try:
                self.table_menu.grab_release()
            except tk.TclError:
                pass

    def _create_statusbar(self):
        statusbar = ttk.Frame(self.root, style="Status.TFrame")
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(statusbar, text="Заблокировано", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT, padx=(14, 8), pady=7)

        self.clipboard_label = ttk.Label(statusbar, text="Буфер обмена: пуст", style="Status.TLabel")
        self.clipboard_label.pack(side=tk.LEFT, padx=(18, 8), pady=7)
        self.clipboard_details_label = ttk.Label(statusbar, text="", style="Status.TLabel")
        self.clipboard_details_label.pack(side=tk.LEFT, padx=5, pady=7)
        self.clipboard_notice_label = ttk.Label(statusbar, text="", style="Status.TLabel")
        self.clipboard_notice_label.pack(side=tk.LEFT, padx=10, pady=7)
        self.clipboard_preview_button = ttk.Button(
            statusbar,
            text="Просмотр",
            style="Ghost.TButton",
            command=self.show_clipboard_preview_dialog,
        )
        self.clipboard_preview_button.pack(side=tk.RIGHT, padx=(5, 14), pady=5)
        self.clipboard_preview_button.state(["disabled"])

        ttk.Label(statusbar, text="v2.0").pack(side=tk.RIGHT, padx=5)

    def _setup_events(self):
        event_bus.subscribe(EventType.ENTRY_ADDED, self._on_entry_changed)
        event_bus.subscribe(EventType.ENTRY_UPDATED, self._on_entry_changed)
        event_bus.subscribe(EventType.ENTRY_DELETED, self._on_entry_changed)
        event_bus.subscribe(EventType.USER_LOGGED_IN, self._on_user_logged_in_event)
        event_bus.subscribe(EventType.USER_LOGGED_OUT, self._on_user_logged_out_event)
        event_bus.subscribe(EventType.CLIPBOARD_COPIED, lambda _event: self._refresh_clipboard_status())
        event_bus.subscribe(EventType.CLIPBOARD_CLEARED, lambda _event: self._refresh_clipboard_status())
        event_bus.subscribe(EventType.VAULT_LOCKED, self._on_vault_locked_event)

    def _on_user_logged_in_event(self, _event):
        self._set_status("Разблокировано")
        self._update_system_tray_status()

    def _on_user_logged_out_event(self, _event):
        self._set_status("Заблокировано")

    def _on_vault_locked_event(self, event):
        if event.data.get("preserve_clipboard", False):
            return
        self.clipboard_service.clear(reason="vault_locked")

    def _setup_activity_tracking(self):
        for sequence in ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>"):
            self.root.bind_all(sequence, self._on_activity, add="+")
        self.root.bind_all("<KeyPress>", self._handle_hotkey_keypress, add="+")
        self.root.bind("<FocusIn>", self._on_focus_in, add="+")
        self.root.bind("<FocusOut>", self._on_focus_out, add="+")
        self.root.bind("<Unmap>", self._on_unmap, add="+")
        self.root.bind("<Map>", self._on_map, add="+")
        self._register_keyboard_shortcuts()
        self._register_global_panic_hotkey()
        self._start_windows_panic_hotkey_poll()
        self.root.bind_all("<Motion>", self._record_panic_gesture, add="+")

    def _register_keyboard_shortcuts(self) -> None:
        for binding in get_default_hotkeys().values():
            if binding.action == "toggle_passwords":
                continue
            self.root.bind_all(binding.tk_sequence, lambda event, action=binding.action: self._handle_shortcut(action, event), add="+")
        self.root.bind_all("<Control-Shift-P>", self._toggle_password_visibility, add="+")
        self.root.bind_all("<Control-Shift-p>", self._toggle_password_visibility, add="+")
        self.root.bind_all("<Control-Alt-p>", lambda event: self._handle_shortcut("panic_mode", event), add="+")
        self.root.bind_all("<Control-Alt-P>", lambda event: self._handle_shortcut("panic_mode", event), add="+")

    def _register_global_panic_hotkey(self) -> None:
        if getattr(self, "_global_hotkey_service", None) is not None:
            self._global_hotkey_service.stop()
        service = WindowsGlobalHotkeyService(self.root, self._handle_global_hotkey)
        self._global_hotkey_service = service
        panic_hotkey = self.config.get("security.panic_hotkey", "Ctrl+Shift+Esc")
        if service.register(panic_hotkey, "panic_mode"):
            self._global_hotkey_status = f"registered:{panic_hotkey}"
            return
        fallback_hotkey = "Ctrl+Alt+P"
        if panic_hotkey != fallback_hotkey and service.register(fallback_hotkey, "panic_mode"):
            self._global_hotkey_status = f"fallback:{fallback_hotkey}"
            return
        self._global_hotkey_status = "not_registered"

    def _handle_global_hotkey(self, action: str) -> None:
        if action == "panic_mode":
            self.activate_panic_mode("global_hotkey")

    def _handle_hotkey_keypress(self, event=None):
        key = str(getattr(event, "keysym", "") or "").lower()
        state = int(getattr(event, "state", 0) or 0)
        ctrl = bool(state & 0x0004)
        shift = bool(state & 0x0001)
        alt = bool(state & 0x0008 or state & 0x0080 or state & 0x20000)
        if ctrl and shift and key == "p":
            return self._toggle_password_visibility(event)
        if ctrl and shift and key in {"escape", "esc"}:
            return self._handle_shortcut("panic_mode", event)
        if ctrl and alt and key == "p":
            return self._handle_shortcut("panic_mode", event)
        return None

    def _handle_shortcut(self, action: str, event=None):
        if action in {"add_entry", "edit_entry", "delete_entry"} and self._is_text_input_focused():
            return None
        handlers = {
            "panic_mode": lambda: self.activate_panic_mode("hotkey"),
            "lock_vault": lambda: self._lock_vault(show_dialog=False),
            "unlock_vault": self._unlock_vault,
            "focus_search": self._focus_search,
            "add_entry": self.add_entry,
            "edit_entry": self.edit_entry,
            "delete_entry": self.delete_entry,
            "clear_clipboard": self.clear_clipboard_from_ui,
            "open_settings": self.show_settings,
        }
        handler = handlers.get(action)
        if handler is None:
            return None
        handler()
        return "break"

    def _is_text_input_focused(self) -> bool:
        try:
            focused = self.root.focus_get()
        except Exception:
            return False
        input_types = (tk.Entry, tk.Text, ttk.Entry, ttk.Spinbox, ttk.Combobox)
        return isinstance(focused, input_types)

    def _start_windows_panic_hotkey_poll(self) -> None:
        if os.name != "nt" or getattr(self, "_panic_hotkey_poll_active", False):
            return
        self._panic_hotkey_poll_active = True
        self._poll_windows_panic_hotkey()

    def _poll_windows_panic_hotkey(self) -> None:
        if not getattr(self, "_panic_hotkey_poll_active", False):
            return
        try:
            user32 = ctypes.windll.user32
            ctrl_down = bool(user32.GetAsyncKeyState(0x11) & 0x8000)
            shift_down = bool(user32.GetAsyncKeyState(0x10) & 0x8000)
            alt_down = bool(user32.GetAsyncKeyState(0x12) & 0x8000)
            escape_down = bool(user32.GetAsyncKeyState(0x1B) & 0x8000)
            p_down = bool(user32.GetAsyncKeyState(ord("P")) & 0x8000)
            pressed = (ctrl_down and shift_down and escape_down) or (ctrl_down and alt_down and p_down)
            if pressed and not getattr(self, "_panic_hotkey_pressed", False):
                self._panic_hotkey_pressed = True
                self.activate_panic_mode("windows_hotkey")
            elif not pressed:
                self._panic_hotkey_pressed = False
        except Exception:
            self._panic_hotkey_poll_active = False
            return
        try:
            self.root.after(100, self._poll_windows_panic_hotkey)
        except Exception:
            self._panic_hotkey_poll_active = False

    def _get_keyboard_shortcuts(self) -> dict[str, str]:
        shortcuts = {binding.label: binding.action for binding in get_default_hotkeys().values()}
        shortcuts.update(
            {
                "Ctrl+Alt+P": "panic_mode_fallback",
                "Enter": "confirm_dialog_or_search",
                "Escape": "cancel_dialog_or_clear_search",
                "ArrowUp/ArrowDown": "navigate_tables_and_lists",
                "Tab/Shift+Tab": "move_between_controls",
            }
        )
        return shortcuts

    def _get_accessibility_summary(self) -> dict[str, object]:
        return {
            "keyboard_only": True,
            "screen_reader_labels": True,
            "destructive_confirmations": True,
            "security_state_colors": True,
            "long_operation_progress": True,
            "shortcuts": self._get_keyboard_shortcuts(),
        }

    def _create_activity_monitor(self) -> ActivityMonitor:
        return ActivityMonitor(
            lambda: self._lock_vault(show_dialog=False),
            ActivityMonitorConfig(
                timeout_seconds=self.config.get("security.auto_lock_minutes", 5) * 60,
                check_interval_seconds=1.0,
                sensitivity=self.config.get("security.activity_sensitivity", "medium"),
                device_profile=self.config.get("security.device_profile", "desktop"),
            ),
        )

    def _create_panic_mode(self) -> PanicMode:
        panic = PanicMode(
            PanicModeConfig(
                hotkey=self.config.get("security.panic_hotkey", "Ctrl+Shift+Esc"),
                close_application=bool(self.config.get("security.panic_close_application", False)),
                hide_windows=True,
                clear_clipboard=True,
                stealth_mode=bool(self.config.get("security.panic_stealth_mode", False)),
            ),
            event_bus=event_bus,
        )
        panic.register_handler("clear_clipboard", lambda: self._clear_system_clipboard(sync_service=True))
        panic.register_handler("lock_vault", lambda: self._lock_vault(show_dialog=False))
        panic.register_handler("hide_window", self._hide_windows_for_panic)
        panic.register_handler("wipe_view_state", self._clear_sensitive_view_state)
        if bool(self.config.get("security.panic_stealth_mode", False)):
            panic.register_handler("stealth_actions", self._execute_panic_stealth_actions)
        return panic

    def _hide_windows_for_panic(self):
        for child in self._get_panic_child_windows():
            try:
                child.grab_release()
            except Exception:
                pass
            try:
                child.destroy()
                continue
            except Exception:
                pass
            try:
                child.withdraw()
            except Exception:
                pass
        try:
            self.root.withdraw()
        except tk.TclError:
            pass

    def _get_panic_child_windows(self):
        try:
            children = list(self.root.winfo_children())
        except Exception:
            return []
        windows = []
        for child in children:
            if child is self.root:
                continue
            try:
                if isinstance(child, tk.Toplevel) or child.winfo_toplevel() is child:
                    windows.append(child)
            except Exception:
                continue
        return windows

    def _record_panic_gesture(self, event=None):
        if not bool(self.config.get("security.panic_gesture_enabled", True)):
            return
        if hasattr(self, "panic_mode") and getattr(self.panic_mode, "activated", False):
            return
        x_position = getattr(event, "x_root", None)
        if x_position is None:
            x_position = getattr(event, "x", None)
        y_position = getattr(event, "y_root", None)
        if x_position is None or y_position is None:
            return

        now = time.monotonic()
        samples = list(getattr(self, "_panic_gesture_samples", []))
        samples.append((now, int(x_position), int(y_position)))
        samples = [sample for sample in samples if now - sample[0] <= 1.5][-12:]
        self._panic_gesture_samples = samples
        if self._is_panic_shake_gesture(samples):
            self._panic_gesture_samples = []
            self.activate_panic_mode("mouse_gesture")

    def _is_panic_shake_gesture(self, samples: list[tuple[float, int, int]]) -> bool:
        if len(samples) < 5:
            return False
        x_values = [sample[1] for sample in samples]
        y_values = [sample[2] for sample in samples]
        if max(max(x_values) - min(x_values), max(y_values) - min(y_values)) < 90:
            return False
        directions = []
        previous_x, previous_y = x_values[0], y_values[0]
        for current_x, current_y in zip(x_values[1:], y_values[1:]):
            delta_x = current_x - previous_x
            delta_y = current_y - previous_y
            previous_x, previous_y = current_x, current_y
            delta = delta_x if abs(delta_x) >= abs(delta_y) else delta_y
            if abs(delta) >= 35:
                directions.append(1 if delta > 0 else -1)
        if len(directions) < 4:
            return False
        reversals = sum(1 for previous, current in zip(directions, directions[1:]) if previous != current)
        return reversals >= 3

    def _execute_panic_stealth_actions(self):
        if bool(self.config.get("security.panic_fake_error", True)):
            try:
                messagebox.showerror("Ошибка приложения", "В приложении произошла непредвиденная ошибка.")
            except Exception:
                pass

        decoy_command = str(self.config.get("security.panic_decoy_command", "") or "").strip()
        if decoy_command:
            try:
                subprocess.Popen(decoy_command, shell=True)
            except Exception:
                pass

        redirect_url = str(self.config.get("security.panic_redirect_url", "") or "").strip()
        if redirect_url:
            try:
                webbrowser.open(redirect_url)
            except Exception:
                pass

    def activate_panic_mode(self, method: str = "manual"):
        if not hasattr(self, "panic_mode"):
            self.panic_mode = self._create_panic_mode()
        if getattr(self.panic_mode, "activated", False):
            result = self.panic_mode.activate(method=method)
            self._show_panic_notification(method)
            return result
        result = self.panic_mode.activate(
            method=method,
            details={
                "authenticated": bool(self.auth_service.is_authenticated()),
                "window_state": self._safe_root_state(),
            },
        )
        self._last_panic_result = result
        self._flush_audit_logger()
        if result.activated and not self.config.get("security.panic_stealth_mode", False):
            self._show_panic_notification(method)
        if self.config.get("security.panic_close_application", False):
            self._on_close()
        return result

    def _show_panic_notification(self, method: str) -> None:
        self._restore_main_window(force_rebuild_menu=True)
        status = getattr(self, "_global_hotkey_status", "not_registered")
        if status.startswith("registered:"):
            hotkey_text = status.split(":", 1)[1]
        elif status.startswith("fallback:"):
            hotkey_text = status.split(":", 1)[1]
        else:
            hotkey_text = "Ctrl+Shift+Esc внутри приложения"
        message = (
            "Паник-режим сработал.\n\n"
            "- хранилище заблокировано;\n"
            "- буфер обмена очищен;\n"
            "- открытые окна закрыты;\n"
            "- расшифрованное состояние очищено.\n\n"
            f"Способ запуска: {method}.\n"
            f"Рабочая горячая клавиша паник-режима: {hotkey_text}.\n\n"
            "Чтобы продолжить работу, нажмите «Разблокировать» и введите мастер-пароль."
        )
        try:
            self._show_warning("Паник-режим", message)
        except Exception:
            pass
        self._restore_main_window_chrome(force_rebuild=True)

    def recover_from_panic_mode(self):
        if hasattr(self, "panic_mode"):
            self.panic_mode.reset_for_recovery()
        self._restore_main_window(force_rebuild_menu=True)
        return self._unlock_vault()

    def _safe_root_state(self) -> str:
        try:
            return str(self.root.state())
        except Exception:
            return "unknown"

    def _schedule_security_tasks(self):
        self._check_security_timers()
        self._run_periodic_audit_verification_if_due()
        self._run_scheduled_audit_exports_if_due()
        self.root.after(1000, self._schedule_security_tasks)

    def _check_security_timers(self):
        activity_should_lock = False
        if hasattr(self, "activity_monitor") and self.auth_service.is_authenticated():
            activity_should_lock = self.activity_monitor.tick()
        if activity_should_lock:
            return
        if self.state.should_auto_lock() or self.state.should_expire_key_cache() or self.key_storage.is_cache_expired():
            self._lock_vault(show_dialog=False)
        clipboard_tick_result = None
        if hasattr(self, "clipboard_service") and hasattr(self, "clipboard_monitor"):
            clipboard_tick_result = self.clipboard_service.tick()
            try:
                self.clipboard_monitor.poll()
                self._clipboard_monitor_warning_shown = False
            except Exception:
                if not self._clipboard_monitor_warning_shown:
                    self._clipboard_monitor_warning_shown = True
                    event_bus.publish(
                        Event(
                            EventType.CLIPBOARD_ERROR,
                            {
                                "operation": "monitor_poll",
                                "error_code": "monitor_unavailable",
                            },
                        )
                    )
                    self._show_warning(
                        "Мониторинг буфера обмена",
                        "Не удалось проверить состояние буфера обмена. Защита продолжит работу в ограниченном режиме.",
                    )
        elif self.state.clipboard_timer and self.state.get_clipboard() is None:
            self._clear_system_clipboard()
            event_bus.publish(Event(EventType.CLIPBOARD_CLEARED, {}))
            clipboard_tick_result = "timeout"
        if clipboard_tick_result == "timeout" and self._should_lock_after_clipboard_clear():
            self._lock_vault(show_dialog=False)
        if clipboard_tick_result == "timeout":
            self._handle_clipboard_clear_failure()
        self._refresh_clipboard_status()

    def _on_activity(self, _event=None):
        if self.state.is_unlocked():
            self.state.update_activity()
            if hasattr(self, "activity_monitor"):
                source = self._activity_source_from_event(_event)
                self.activity_monitor.record_activity(source)
            self.key_storage.touch_cached_key(self.state.key_cache_timeout)

    def _activity_source_from_event(self, event=None) -> str:
        event_type = str(getattr(event, "type", "") or "")
        if "Key" in event_type:
            return "keyboard"
        if "Button" in event_type or "Motion" in event_type:
            return "mouse"
        if "Focus" in event_type:
            return "focus"
        return "user"

    def _initialize_system_tray(self):
        try:
            import pystray  # type: ignore
        except Exception:
            self._system_tray_icon = None
            return

        image = self._build_system_tray_icon_image("locked")
        menu = self._build_system_tray_menu(pystray)
        try:
            self._system_tray_icon = pystray.Icon("cryptosafe-manager", image, "CryptoSafe Manager", menu)
            self._system_tray_icon.run_detached()
        except Exception:
            self._system_tray_icon = None

    def _build_system_tray_menu(self, pystray_module):
        def tray_action(callback):
            def run(_icon, _item):
                self._tray_focus_grace_until = time.monotonic() + 5.0
                self._run_on_ui_thread(callback)

            return run

        return pystray_module.Menu(
            pystray_module.MenuItem("Показать окно", tray_action(self._restore_from_system_tray)),
            pystray_module.MenuItem("Заблокировать хранилище", tray_action(lambda: self._lock_vault(show_dialog=False))),
            pystray_module.MenuItem("Разблокировать хранилище", tray_action(self._unlock_vault)),
            pystray_module.MenuItem("Быстрый поиск", tray_action(self._show_tray_quick_search)),
            pystray_module.MenuItem("Очистить буфер обмена", tray_action(self.clear_clipboard_from_ui)),
            pystray_module.MenuItem("Паник-режим", tray_action(lambda: self.activate_panic_mode("tray"))),
            pystray_module.MenuItem("Настройки", tray_action(self.show_settings)),
            pystray_module.MenuItem("Выход", tray_action(self._on_close)),
        )

    def _run_on_ui_thread(self, callback):
        if not hasattr(self, "_ui_task_queue"):
            callback()
            return
        self._ui_task_queue.put(callback)

    def _start_ui_task_pump(self):
        if getattr(self, "_ui_task_pump_active", False):
            return
        self._ui_task_pump_active = True
        self._process_ui_task_queue()

    def _process_ui_task_queue(self):
        if not getattr(self, "_ui_task_pump_active", False):
            return
        task_queue = getattr(self, "_ui_task_queue", None)
        if task_queue is not None:
            while True:
                try:
                    callback = task_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    callback()
                except Exception:
                    pass
        try:
            self.root.after(50, self._process_ui_task_queue)
        except Exception:
            self._ui_task_pump_active = False

    def _get_system_tray_menu_labels(self) -> list[str]:
        return [
            "Показать окно",
            "Заблокировать хранилище",
            "Разблокировать хранилище",
            "Быстрый поиск",
            "Очистить буфер обмена",
            "Паник-режим",
            "Настройки",
            "Выход",
        ]

    def _build_system_tray_icon_image(self, state: str, animation_frame: int = 0):
        from PIL import Image, ImageDraw  # type: ignore

        colors = {
            "locked": ("#7f1d1d", "#f87171"),
            "unlocked": ("#064e3b", "#34d399"),
            "alert": ("#7f1d1d", "#f87171"),
            "crypto": ("#064e3b", "#34d399" if animation_frame % 2 == 0 else "#facc15"),
        }
        fill, accent = colors.get(state, colors["locked"])
        image = Image.new("RGB", (16, 16), color=fill)
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((1, 1, 14, 14), radius=3, fill=fill, outline=accent)
        draw.rectangle((5, 7, 11, 12), fill="#f8fafc")
        draw.arc((4, 3, 12, 9), start=0, end=180, fill="#f8fafc", width=2)
        if state == "crypto":
            draw.ellipse((11, 1, 15, 5), fill=accent)
        return image

    def _get_system_tray_state(self, status: Optional[ClipboardStatus] = None) -> str:
        if getattr(self, "_tray_crypto_operation_active", False):
            return "crypto"
        status = status or self._get_clipboard_status()
        if (
            getattr(status, "last_clear_failed", False)
            or getattr(status, "external_change_detected", False)
            or getattr(status, "suspicious_activity", False)
        ):
            return "alert"
        auth_service = getattr(self, "auth_service", None)
        if auth_service is not None and auth_service.is_authenticated():
            return "unlocked"
        state = getattr(self, "state", None)
        if state is not None and getattr(state, "is_unlocked", lambda: False)():
            return "unlocked"
        return "locked"

    def _build_system_tray_title(self, status: Optional[ClipboardStatus] = None) -> str:
        status = status or self._get_clipboard_status()
        vault_state = "разблокировано" if self.auth_service.is_authenticated() else "заблокировано"
        if getattr(self, "_tray_crypto_operation_active", False):
            return f"CryptoSafe Manager: хранилище {vault_state}, криптооперация"
        if not status.active:
            return f"CryptoSafe Manager: хранилище {vault_state}, буфер обмена пуст"
        data_type_label = self._format_clipboard_data_type(status.data_type)
        delivery_text = self._format_clipboard_delivery_mode(status.delivery_mode)
        if status.remaining_seconds > 0:
            return f"CryptoSafe Manager: хранилище {vault_state}, {data_type_label}, {delivery_text}, осталось {status.remaining_seconds} сек"
        return f"CryptoSafe Manager: хранилище {vault_state}, {data_type_label}, {delivery_text}"

    def _update_system_tray_status(self, status: Optional[ClipboardStatus] = None):
        tray_icon = getattr(self, "_system_tray_icon", None)
        if tray_icon is None:
            return
        try:
            state = self._get_system_tray_state(status)
            if state == "crypto":
                self._tray_animation_frame = getattr(self, "_tray_animation_frame", 0) + 1
            tray_icon.icon = self._build_system_tray_icon_image(state, getattr(self, "_tray_animation_frame", 0))
            tray_icon.title = self._build_system_tray_title(status)
        except Exception:
            return

    def _set_crypto_operation_active(self, active: bool) -> None:
        self._tray_crypto_operation_active = bool(active)
        self._update_system_tray_status()

    @contextmanager
    def _crypto_operation_status(self):
        self._set_crypto_operation_active(True)
        try:
            yield
        finally:
            self._set_crypto_operation_active(False)

    def _show_tray_quick_search(self):
        if not self.auth_service.is_authenticated():
            self._restore_from_system_tray()
            messagebox.showwarning("Хранилище заблокировано", "Сначала разблокируйте хранилище, затем используйте быстрый поиск.")
            return
        query = simpledialog.askstring("Быстрый поиск", "Введите текст для поиска:")
        if query is None:
            return
        self._apply_tray_quick_search(query)

    def _apply_tray_quick_search(self, query: str) -> None:
        self._restore_from_system_tray()
        if hasattr(self, "search_var"):
            self.search_var.set(str(query or "").strip())
        self._remember_search_query(str(query or ""))
        self._apply_entry_filter()
        self._focus_search()

    def _show_in_system_tray(self):
        if getattr(self, "_system_tray_icon", None) is None or getattr(self, "_system_tray_visible", False):
            return
        try:
            self.root.withdraw()
        except Exception:
            return
        self._system_tray_visible = True
        self._update_system_tray_status()

    def _rebuild_main_menu(self):
        old_menubar = getattr(self, "_menubar", None)
        try:
            self.root.config(menu="")
        except tk.TclError:
            pass
        if old_menubar is not None:
            try:
                old_menubar.destroy()
            except tk.TclError:
                pass
        self._create_menu()
        try:
            self.root.update_idletasks()
        except tk.TclError:
            pass

    def _restore_main_window_chrome(self, *, force_rebuild: bool = False):
        if force_rebuild:
            self._rebuild_main_menu()
            return
        menubar = getattr(self, "_menubar", None)
        if menubar is None:
            if hasattr(self, "_create_tk_menu") and hasattr(getattr(self, "root", None), "tk"):
                self._rebuild_main_menu()
            return
        try:
            if not menubar.winfo_exists():
                self._rebuild_main_menu()
                return
            self.root.config(menu=menubar)
        except tk.TclError:
            self._rebuild_main_menu()

    def _restore_main_window(self, *, force_rebuild_menu: bool = False):
        try:
            self.root.deiconify()
            self.root.state("normal")
            self._restore_main_window_chrome(force_rebuild=force_rebuild_menu)
        except Exception:
            return False
        try:
            self.root.lift()
        except Exception:
            pass
        try:
            self.root.update_idletasks()
        except Exception:
            pass
        if force_rebuild_menu:
            for delay_ms in (50, 250):
                try:
                    self.root.after(delay_ms, lambda: self._restore_main_window_chrome(force_rebuild=True))
                except tk.TclError:
                    break
        return True

    def _restore_from_system_tray(self):
        if getattr(self, "_system_tray_icon", None) is None:
            return
        if not self._restore_main_window():
            return
        self._system_tray_visible = False
        self._update_system_tray_status()

    def _shutdown_system_tray(self):
        tray_icon = getattr(self, "_system_tray_icon", None)
        if tray_icon is None:
            return
        try:
            tray_icon.stop()
        except Exception:
            pass
        self._system_tray_icon = None
        self._system_tray_visible = False

    @contextmanager
    def _suspend_focus_lock_for_internal_dialog(self):
        self._internal_modal_depth = getattr(self, "_internal_modal_depth", 0) + 1
        try:
            yield
        finally:
            self._internal_modal_depth = max(0, getattr(self, "_internal_modal_depth", 0) - 1)
            if getattr(self, "_internal_modal_depth", 0) == 0 and hasattr(self, "state"):
                self.state.set_application_active(True)

    def _is_internal_modal_active(self) -> bool:
        if getattr(self, "_internal_modal_depth", 0) > 0:
            return True
        try:
            grab_current = self.root.grab_current()
        except (AttributeError, tk.TclError):
            return False
        except KeyError:
            # ttk.Combobox creates an internal "popdown" window that Tkinter
            # sometimes cannot map back to a Python widget. Treat it as an
            # internal modal so focus-loss auto-lock does not crash callbacks.
            return True
        return grab_current is not None

    def _show_messagebox(self, kind: str, title: str, message: str, **kwargs):
        kwargs.setdefault("parent", self.root)
        with self._suspend_focus_lock_for_internal_dialog():
            if self._can_use_themed_dialogs():
                return self._show_themed_messagebox(kind, title, message, **kwargs)
            return getattr(messagebox, kind)(title, message, **kwargs)

    def _show_warning(self, title: str, message: str, **kwargs):
        return self._show_messagebox("showwarning", title, message, **kwargs)

    def _show_error(self, title: str, message: str, **kwargs):
        return self._show_messagebox("showerror", title, message, **kwargs)

    def _show_info(self, title: str, message: str, **kwargs):
        return self._show_messagebox("showinfo", title, message, **kwargs)

    def _ask_yes_no(self, title: str, message: str, **kwargs) -> bool:
        return bool(self._show_messagebox("askyesno", title, message, **kwargs))

    def _ask_string(self, title: str, prompt: str, **kwargs):
        kwargs.setdefault("parent", self.root)
        with self._suspend_focus_lock_for_internal_dialog():
            if self._can_use_themed_dialogs():
                return self._show_themed_string_prompt(title, prompt, **kwargs)
            return simpledialog.askstring(title, prompt, **kwargs)

    def _can_use_themed_dialogs(self) -> bool:
        return hasattr(self.root, "tk") and hasattr(self.root, "wait_window")

    def _center_dialog(self, dialog, parent=None):
        try:
            dialog.update_idletasks()
            owner = parent if parent is not None else self.root
            parent_x = owner.winfo_rootx()
            parent_y = owner.winfo_rooty()
            parent_width = owner.winfo_width()
            parent_height = owner.winfo_height()
            width = dialog.winfo_width()
            height = dialog.winfo_height()
            x = parent_x + max(0, (parent_width - width) // 2)
            y = parent_y + max(0, (parent_height - height) // 2)
            dialog.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

    def _parse_geometry_size(self, geometry: str) -> tuple[int, int]:
        try:
            size_part = str(geometry or "").split("+", 1)[0]
            width_text, height_text = size_part.split("x", 1)
            return int(width_text), int(height_text)
        except (TypeError, ValueError):
            return 0, 0

    def _fit_dialog_to_content(self, dialog, parent=None, *, margin: int = 96):
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
            self._center_dialog(dialog, parent)
        except tk.TclError:
            pass

    def _schedule_dialog_fit(self, dialog, parent=None):
        def fit():
            self._fit_dialog_to_content(dialog, parent)

        for delay_ms in (0, 80, 250):
            try:
                if delay_ms == 0:
                    dialog.after_idle(fit)
                else:
                    dialog.after(delay_ms, fit)
            except tk.TclError:
                break

    def _get_screen_limited_geometry(self, width: int, height: int, *, margin: int = 96) -> str:
        try:
            screen_width = int(self.root.winfo_screenwidth())
            screen_height = int(self.root.winfo_screenheight())
        except (AttributeError, tk.TclError, TypeError):
            return f"{width}x{height}"
        safe_width = max(420, min(width, screen_width - margin))
        safe_height = max(360, min(height, screen_height - margin))
        return f"{safe_width}x{safe_height}"

    def _show_themed_messagebox(self, kind: str, title: str, message: str, **kwargs):
        parent = kwargs.get("parent") or self.root
        is_question = kind == "askyesno"
        result = {"value": False if is_question else None}

        dialog = tk.Toplevel(parent)
        self._prepare_dialog(dialog)
        dialog.title(title)
        dialog.transient(parent)
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.geometry(self._get_screen_limited_geometry(560, 240))
        dialog.minsize(420, 150)

        card = ttk.Frame(dialog, style="DialogCard.TFrame", padding=(18, 16, 18, 14))
        card.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        icon_text = {"showerror": "!", "showwarning": "!", "showinfo": "i", "askyesno": "?"}.get(kind, "i")
        icon_style = "DangerIcon.TLabel" if kind == "showerror" else "WarningIcon.TLabel" if kind == "showwarning" else "AccentIcon.TLabel"

        header = ttk.Frame(card, style="DialogCard.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(header, text=icon_text, style=icon_style, anchor="center").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(header, text=title, style="DialogHeader.TLabel").pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(
            card,
            text=str(message),
            style="DialogBody.TLabel",
            wraplength=460,
            justify=tk.LEFT,
        ).pack(fill=tk.X, pady=(14, 18))

        buttons = ttk.Frame(card, style="DialogCard.TFrame")
        buttons.pack(fill=tk.X)

        def close(value):
            result["value"] = value
            dialog.destroy()

        if is_question:
            ttk.Button(buttons, text="Нет", style="Ghost.TButton", command=lambda: close(False)).pack(side=tk.RIGHT, padx=(8, 0))
            ttk.Button(buttons, text="Да", style="Accent.TButton", command=lambda: close(True)).pack(side=tk.RIGHT)
        else:
            ttk.Button(buttons, text="ОК", style="Accent.TButton", command=lambda: close(None)).pack(side=tk.RIGHT)

        dialog.protocol("WM_DELETE_WINDOW", lambda: close(False if is_question else None))
        self._fit_dialog_to_content(dialog, parent)
        dialog.wait_window()
        return result["value"]

    def _show_themed_string_prompt(self, title: str, prompt: str, **kwargs):
        parent = kwargs.get("parent") or self.root
        result = {"value": None}

        dialog = tk.Toplevel(parent)
        self._prepare_dialog(dialog)
        dialog.title(title)
        dialog.transient(parent)
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.geometry(self._get_screen_limited_geometry(600, 240))
        dialog.minsize(460, 170)

        card = ttk.Frame(dialog, style="DialogCard.TFrame", padding=(18, 16, 18, 14))
        card.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        ttk.Label(card, text=title, style="DialogHeader.TLabel").pack(fill=tk.X)
        ttk.Label(card, text=prompt, style="DialogBody.TLabel", wraplength=480, justify=tk.LEFT).pack(fill=tk.X, pady=(12, 8))

        value_var = tk.StringVar(value=str(kwargs.get("initialvalue", "") or ""))
        entry = ttk.Entry(card, textvariable=value_var, show=kwargs.get("show", ""), width=56)
        entry.pack(fill=tk.X, pady=(0, 16))

        buttons = ttk.Frame(card, style="DialogCard.TFrame")
        buttons.pack(fill=tk.X)

        def submit(_event=None):
            result["value"] = value_var.get()
            dialog.destroy()

        def cancel(_event=None):
            result["value"] = None
            dialog.destroy()

        ttk.Button(buttons, text="Отмена", style="Ghost.TButton", command=cancel).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(buttons, text="ОК", style="Accent.TButton", command=submit).pack(side=tk.RIGHT)
        dialog.bind("<Return>", submit)
        dialog.bind("<Escape>", cancel)
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        self._fit_dialog_to_content(dialog, parent)
        entry.focus_set()
        entry.selection_range(0, tk.END)
        dialog.wait_window()
        return result["value"]

    def _ask_saveas_filename(self, **kwargs):
        kwargs.setdefault("parent", self.root)
        with self._suspend_focus_lock_for_internal_dialog():
            return filedialog.asksaveasfilename(**kwargs)

    def _ask_open_filename(self, **kwargs):
        kwargs.setdefault("parent", self.root)
        with self._suspend_focus_lock_for_internal_dialog():
            return filedialog.askopenfilename(**kwargs)

    def _ask_open_filenames(self, **kwargs):
        kwargs.setdefault("parent", self.root)
        with self._suspend_focus_lock_for_internal_dialog():
            return filedialog.askopenfilenames(**kwargs)

    def _ask_directory(self, **kwargs):
        kwargs.setdefault("parent", self.root)
        with self._suspend_focus_lock_for_internal_dialog():
            return filedialog.askdirectory(**kwargs)

    def _prepare_dialog(self, dialog):
        colors = self.UI_COLORS
        try:
            dialog.configure(bg=colors["bg"])
        except tk.TclError:
            pass
        try:
            dialog.resizable(True, True)
        except (AttributeError, tk.TclError):
            pass
        self._apply_accessibility_metadata(dialog)
        parent = getattr(dialog, "master", None) or getattr(self, "root", None)
        if parent is not None and hasattr(dialog, "after_idle"):
            self._schedule_dialog_fit(dialog, parent)
        return dialog

    def _apply_accessibility_metadata(self, widget, *, role: str = "dialog"):
        try:
            widget.configure(takefocus=True)
        except Exception:
            pass
        try:
            widget.option_add("*TakeFocus", 1)
        except Exception:
            pass
        try:
            widget.bind("<Alt-F4>", lambda _event: None, add="+")
        except Exception:
            pass
        try:
            setattr(widget, "_cryptosafe_accessibility_role", role)
            setattr(widget, "_cryptosafe_keyboard_navigation", True)
        except Exception:
            pass
        return widget

    def _style_text_widget(self, widget):
        colors = self.UI_COLORS
        try:
            widget.configure(
                bg=colors["surface"],
                fg=colors["ink"],
                insertbackground=colors["ink"],
                relief=tk.FLAT,
                bd=0,
                highlightthickness=1,
                highlightbackground=colors["line"],
                highlightcolor=colors["accent"],
                selectbackground=colors["selection"],
                selectforeground=colors["ink"],
                padx=8,
                pady=8,
            )
        except tk.TclError:
            pass
        return widget

    def _create_scrollable_dialog_body(self, dialog) -> ttk.Frame:
        container = ttk.Frame(dialog, style="App.TFrame")
        container.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(
            container,
            bg=self.UI_COLORS["bg"],
            highlightthickness=0,
            bd=0,
        )
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        body = ttk.Frame(canvas, style="App.TFrame")
        body_window = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def sync_scroll_region(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def sync_body_width(event):
            canvas.itemconfigure(body_window, width=event.width)

        def scroll_units_from_event(event):
            if getattr(event, "num", None) == 4:
                return -3
            if getattr(event, "num", None) == 5:
                return 3
            delta = getattr(event, "delta", 0)
            if delta == 0:
                return 0
            return -1 * max(-8, min(8, int(delta / 120) if abs(delta) >= 120 else (1 if delta > 0 else -1)))

        def is_inside_scroll_area(widget) -> bool:
            while widget is not None:
                if widget is container:
                    return True
                try:
                    widget = widget.master
                except AttributeError:
                    return False
            return False

        wheel_bindings = []

        def bind_mousewheel(_event=None):
            if wheel_bindings:
                return
            for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                bind_id = canvas.bind_all(sequence, on_mousewheel, add="+")
                wheel_bindings.append((sequence, bind_id))

        body.bind("<Configure>", sync_scroll_region)
        canvas.bind("<Configure>", sync_body_width)

        def on_mousewheel(event):
            try:
                if not canvas.winfo_exists() or not is_inside_scroll_area(getattr(event, "widget", None)):
                    return None
            except tk.TclError:
                return None
            units = scroll_units_from_event(event)
            if units:
                canvas.yview_scroll(units, "units")
                return "break"
            return None

        def unbind_mousewheel(_event=None):
            while wheel_bindings:
                sequence, bind_id = wheel_bindings.pop()
                try:
                    script = str(canvas.tk.call("bind", "all", sequence) or "")
                    if bind_id and script:
                        filtered_script = "\n".join(line for line in script.splitlines() if bind_id not in line)
                        canvas.tk.call("bind", "all", sequence, filtered_script)
                except (AttributeError, tk.TclError, TypeError):
                    pass

        bind_mousewheel()
        dialog.bind("<Destroy>", unbind_mousewheel, add="+")
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        return body

    def _create_dialog_button_bar(self, dialog) -> ttk.Frame:
        bar = ttk.Frame(dialog, style="App.TFrame")
        bar.pack(fill=tk.X, padx=12, pady=(8, 12))
        return bar

    def _on_focus_in(self, _event=None):
        self.state.set_application_active(True)

    def _on_focus_out(self, _event=None):
        if self._is_internal_modal_active():
            self.state.set_application_active(True)
            return
        self.state.set_application_active(False)
        delay_ms = 1500 if getattr(self, "_system_tray_icon", None) is not None else 150
        self.root.after(delay_ms, self._lock_if_application_inactive)

    def _on_unmap(self, _event=None):
        self.state.set_application_active(False)
        self.root.after(100, self._lock_if_window_minimized)

    def _on_map(self, _event=None):
        self.state.set_application_active(True)
        self._system_tray_visible = False
        self._restore_main_window_chrome()
        if getattr(self, "_initial_login_completed", False):
            self.root.after(100, self._prompt_unlock_if_needed)

    def _lock_if_application_inactive(self):
        if self._is_internal_modal_active():
            self.state.set_application_active(True)
            return
        if time.monotonic() < getattr(self, "_tray_focus_grace_until", 0.0):
            try:
                self.root.after(500, self._lock_if_application_inactive)
            except Exception:
                pass
            return
        try:
            app_has_focus = self.root.focus_displayof() is not None
            is_iconic = self.root.state() == "iconic"
        except tk.TclError:
            return

        if app_has_focus or is_iconic:
            return

        self.state.set_application_active(False)
        if self.config.get("security.lock_on_focus_loss", True) and self.auth_service.is_authenticated():
            self._lock_vault(show_dialog=False, preserve_clipboard=True, reason="focus_loss")

    def _lock_if_window_minimized(self):
        try:
            window_state = self.root.state()
        except tk.TclError:
            return

        if window_state not in {"iconic", "withdrawn"}:
            return

        self.state.set_application_active(False)
        if self.config.get("security.lock_on_minimize", True) and self.auth_service.is_authenticated():
            self._lock_vault(show_dialog=False)

    def _prompt_unlock_if_needed(self, *, force: bool = False):
        if self._login_prompt_active:
            return
        if not force and not getattr(self, "_initial_login_completed", False):
            return
        if not self.auth_service.is_initialized():
            return
        if self.auth_service.is_authenticated():
            return

        self._require_login()
        if self.auth_service.is_authenticated():
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            self._load_entries()

    def _should_lock_after_clipboard_clear(self) -> bool:
        if self.state.application_active:
            return False
        if not self.config.get("security.lock_on_focus_loss", True):
            return False
        return self.auth_service.is_authenticated()

    def _set_status(self, text: str):
        self.status_label.config(text=text)

    def _on_clipboard_status_changed(self, status: ClipboardStatus):
        previous_status = getattr(self, "_clipboard_status_snapshot", ClipboardStatus(active=False))
        self._clipboard_status_snapshot = status
        self._sync_clipboard_row_marker(previous_status, status)
        self._update_clipboard_notice(previous_status, status)
        self._update_clipboard_notification_area(previous_status, status)
        self._update_system_tray_status(status)
        self._handle_clipboard_security_alert(previous_status, status)
        self._refresh_clipboard_status(status)

    def _refresh_clipboard_status(self, status: Optional[ClipboardStatus] = None):
        status = status or self._get_clipboard_status()
        if not status.active:
            self.clipboard_label.config(text="Буфер обмена: пуст")
            if hasattr(self, "clipboard_details_label"):
                self.clipboard_details_label.config(text="")
            if hasattr(self, "clipboard_preview_button"):
                self.clipboard_preview_button.state(["disabled"])
            return

        data_type_label = self._format_clipboard_data_type(status.data_type)
        if status.remaining_seconds > 0:
            status_text = f"Буфер обмена: {data_type_label} ({status.remaining_seconds} сек)"
        else:
            status_text = f"Буфер обмена: {data_type_label}"
        self.clipboard_label.config(text=status_text)

        details_parts = []
        if status.delivery_mode == "memory_only":
            details_parts.append("Режим: внутренняя память")
        if status.source_label:
            details_parts.append(f"Источник: {status.source_label}")
        if status.preview:
            details_parts.append(f"Просмотр: {status.preview}")
        if status.suspicious_activity:
            details_parts.append("Обнаружена подозрительная активность")
        if status.blocked_future_copies:
            details_parts.append("Дальнейшее копирование временно заблокировано")
        elif status.warning_emitted and status.remaining_seconds > 0:
            details_parts.append(f"Скоро очистка: {status.remaining_seconds} сек")
        if hasattr(self, "clipboard_details_label"):
            self.clipboard_details_label.config(text=" | ".join(details_parts))
        if hasattr(self, "clipboard_preview_button"):
            self.clipboard_preview_button.state(["!disabled"])

    def _get_clipboard_status(self) -> ClipboardStatus:
        if hasattr(self, "clipboard_service"):
            return self.clipboard_service.get_status()

        state = getattr(self, "state", None)
        if state is None:
            return getattr(self, "_clipboard_status_snapshot", ClipboardStatus(active=False))

        clipboard_value = state.get_clipboard()
        if not clipboard_value:
            return ClipboardStatus(active=False)

        remaining_seconds = 0
        if state.clipboard_timer is not None:
            remaining_seconds = max(0, int((state.clipboard_timer - datetime.now()).total_seconds()))
        return ClipboardStatus(
            active=True,
            data_type="password",
            preview="***",
            remaining_seconds=remaining_seconds,
        )

    def _format_clipboard_data_type(self, data_type: str) -> str:
        mapping = {
            "password": "пароль",
            "username": "логин",
            "entry": "запись",
            "text": "текст",
        }
        return mapping.get(str(data_type or "").strip().lower(), "данные")

    def _format_clipboard_delivery_mode(self, delivery_mode: str) -> str:
        if str(delivery_mode or "").strip().lower() == "memory_only":
            return "внутренняя память"
        return "системный буфер"

    def _should_show_clipboard_notification_area(self) -> bool:
        if not self._clipboard_notifications_enabled():
            return False
        try:
            window_state = self.root.state()
        except tk.TclError:
            return False
        if window_state in {"iconic", "withdrawn"}:
            return True
        try:
            return self.root.focus_displayof() is None
        except tk.TclError:
            return False

    def _build_clipboard_notification_message(self, previous_status: ClipboardStatus, status: ClipboardStatus) -> str:
        if status.active:
            data_type = self._format_clipboard_data_type(status.data_type)
            mode_label = self._format_clipboard_delivery_mode(status.delivery_mode)
            if previous_status.active:
                return f"Буфер обмена обновлён: {data_type} ({mode_label})"
            return f"Буфер обмена: скопирован {data_type} ({mode_label})"

        if previous_status.active:
            clear_reason = None
            clear_failed = False
            if hasattr(self, "clipboard_service"):
                clear_reason = self.clipboard_service.get_last_clear_reason()
                clear_failed = self.clipboard_service.did_last_clear_fail()
            if clear_failed:
                return self._build_clipboard_clear_failure_text(clear_reason)
            return self._format_clipboard_clear_reason(clear_reason)

        return ""

    def _show_clipboard_notification_area_message(self, message: str):
        if not message:
            return
        existing_toast = getattr(self, "_clipboard_notification_toast", None)
        if existing_toast is not None:
            try:
                existing_toast.destroy()
            except Exception:
                pass
        try:
            toast = tk.Toplevel(self.root)
            self._prepare_dialog(toast)
            toast.overrideredirect(True)
            toast.attributes("-topmost", True)
            ttk.Label(toast, text=message, justify=tk.LEFT).pack(ipadx=10, ipady=6)
            toast.update_idletasks()
            x_position = max(40, toast.winfo_screenwidth() - 380)
            y_position = max(40, toast.winfo_screenheight() - 120)
            toast.geometry(f"+{x_position}+{y_position}")
            toast.after(4000, toast.destroy)
            self._clipboard_notification_toast = toast
        except Exception:
            self._clipboard_notification_toast = None

    def _update_clipboard_notification_area(self, previous_status: ClipboardStatus, status: ClipboardStatus):
        if not self._should_show_clipboard_notification_area():
            return
        message = self._build_clipboard_notification_message(previous_status, status)
        if message:
            self._show_clipboard_notification_area_message(message)

    def _get_clipboard_preset_labels(self) -> dict[str, str]:
        return {
            "standard": "Стандартный",
            "secure": "Безопасный",
            "public_computer": "Публичный компьютер",
            "custom": "Пользовательский",
        }

    def _get_clipboard_preset_key_from_label(self, label: str) -> str:
        normalized_label = str(label or "").strip()
        for preset_key, preset_label in self._get_clipboard_preset_labels().items():
            if preset_label == normalized_label:
                return preset_key
        return "custom"

    def _get_clipboard_preset_label(self, preset: str) -> str:
        preset_key = str(preset or "custom").strip().lower() or "custom"
        return self._get_clipboard_preset_labels().get(preset_key, self._get_clipboard_preset_labels()["custom"])

    def _detect_clipboard_preset(
        self,
        *,
        timeout_seconds: int,
        notifications_enabled: bool,
        security_level: str,
        blocked_on_suspicious: bool,
        delivery_mode: str = "system",
    ) -> str:
        for preset_key, preset_settings in ClipboardService.PRESETS.items():
            if (
                preset_settings["timeout_seconds"] == int(timeout_seconds)
                and preset_settings["notifications_enabled"] == bool(notifications_enabled)
                and preset_settings["security_level"] == str(security_level).strip().lower()
                and preset_settings["blocked_on_suspicious"] == bool(blocked_on_suspicious)
                and preset_settings.get("delivery_mode", "system") == str(delivery_mode).strip().lower()
            ):
                return preset_key
        return "custom"

    def _apply_clipboard_preset_to_vars(
        self,
        preset: str,
        *,
        timeout_var,
        notifications_var,
        security_level_var,
        blocked_var,
        delivery_mode_var,
    ) -> bool:
        normalized_preset = str(preset or "").strip().lower()
        preset_settings = ClipboardService.PRESETS.get(normalized_preset)
        if preset_settings is None:
            return False
        timeout_var.set(preset_settings["timeout_seconds"])
        notifications_var.set(preset_settings["notifications_enabled"])
        security_level_var.set(preset_settings["security_level"])
        blocked_var.set(preset_settings["blocked_on_suspicious"])
        delivery_mode_var.set(preset_settings.get("delivery_mode", "system"))
        return True

    def _build_clipboard_settings_summary(
        self,
        *,
        timeout_seconds: int,
        notifications_enabled: bool,
        security_level: str,
        blocked_on_suspicious: bool,
        delivery_mode: str = "system",
        allowed_applications: str = "",
    ) -> str:
        security_labels = {
            "basic": "базовый",
            "advanced": "повышенный",
            "paranoid": "параноидальный",
        }
        notifications_text = "включены" if notifications_enabled else "выключены"
        blocked_text = "с блокировкой копирования" if blocked_on_suspicious else "без блокировки копирования"
        level_text = security_labels.get(str(security_level or "").strip().lower(), "базовый")
        delivery_text = self._format_clipboard_delivery_mode(delivery_mode)
        allowed_text = "все приложения"
        normalized_allowed = [item.strip() for item in str(allowed_applications or "").split(",") if item.strip()]
        if normalized_allowed:
            allowed_text = ", ".join(normalized_allowed)
        return (
            f"Автоочистка: {int(timeout_seconds)} сек | "
            f"Уведомления: {notifications_text} | "
            f"Уровень: {level_text} | "
            f"Режим: {delivery_text} | "
            f"{blocked_text} | "
            f"Разрешённые приложения: {allowed_text}"
        )

    def _clipboard_notifications_enabled(self) -> bool:
        if hasattr(self, "clipboard_service"):
            return bool(self.clipboard_service.get_settings().get("notifications_enabled", True))
        return bool(self.config.get("security.clipboard_notifications", True))

    def _format_clipboard_clear_reason(self, clear_reason: str) -> str:
        normalized_reason = str(clear_reason or "").strip().lower()
        reason_map = {
            "monitor_warning": "Буфер обмена очищен из-за подозрительной активности",
            "startup_recovery": "Буфер обмена очищен при запуске после нештатного завершения",
            "timeout": "Буфер обмена очищен автоматически",
            "vault_locked": "Буфер обмена очищен при блокировке хранилища",
            "replacement": "Буфер обмена заменён новым содержимым",
            "manual": "Буфер обмена очищен вручную",
        }
        return reason_map.get(normalized_reason, "Буфер обмена очищен")

    def _build_clipboard_security_alert_text(self, status: ClipboardStatus) -> str:
        message_parts = ["Обнаружена подозрительная активность вокруг буфера обмена."]
        if status.source_label:
            message_parts.append(f"Источник: {status.source_label}.")
        if status.preview:
            message_parts.append(f"Текущее содержимое: {status.preview}.")
        if status.blocked_future_copies:
            message_parts.append("Следующие операции копирования временно заблокированы настройками безопасности.")
        else:
            message_parts.append("Время жизни содержимого буфера обмена сокращено до минимума.")
        return " ".join(message_parts)

    def _build_clipboard_clear_failure_text(self, clear_reason: str) -> str:
        reason_text = self._format_clipboard_clear_reason(clear_reason)
        return (
            f"{reason_text}, но системный буфер обмена мог сохраниться. "
            "Очистите буфер обмена вручную в системе."
        )

    def _update_clipboard_notice(self, previous_status: ClipboardStatus, status: ClipboardStatus):
        if not hasattr(self, "clipboard_notice_label"):
            return
        if not self._clipboard_notifications_enabled():
            self.clipboard_notice_label.config(text="")
            return

        notice_text = ""
        if status.active and not previous_status.active:
            notice_text = f"Скопировано: {self._format_clipboard_data_type(status.data_type)}"
        elif status.active and status.warning_emitted and not previous_status.warning_emitted:
            notice_text = f"Буфер обмена будет очищен через {status.remaining_seconds} сек"
        elif not status.active and previous_status.active:
            clear_reason = ""
            if hasattr(self, "clipboard_service"):
                clear_reason = self.clipboard_service.get_last_clear_reason() or ""
            notice_text = self._format_clipboard_clear_reason(clear_reason)
            if hasattr(self, "clipboard_service") and self.clipboard_service.did_last_clear_fail():
                notice_text = self._build_clipboard_clear_failure_text(clear_reason)
        elif status.blocked_future_copies and not previous_status.blocked_future_copies:
            notice_text = "Копирование временно заблокировано настройками безопасности"

        self.clipboard_notice_label.config(text=notice_text)

    def _handle_clipboard_security_alert(self, previous_status: ClipboardStatus, status: ClipboardStatus):
        if not self._clipboard_notifications_enabled():
            return
        if not status.suspicious_activity or previous_status.suspicious_activity:
            return
        self._show_warning(
            "Безопасность буфера обмена",
            self._build_clipboard_security_alert_text(status),
        )

    def _handle_clipboard_clear_failure(self):
        if not hasattr(self, "clipboard_service"):
            return
        if not self.clipboard_service.did_last_clear_fail():
            return
        clear_reason = self.clipboard_service.get_last_clear_reason() or ""
        warning_text = self._build_clipboard_clear_failure_text(clear_reason)
        if hasattr(self, "clipboard_notice_label") and self._clipboard_notifications_enabled():
            self.clipboard_notice_label.config(text=warning_text)
        self._show_warning(
            "Очистка буфера обмена",
            warning_text,
        )

    def _sync_clipboard_row_marker(self, previous_status: ClipboardStatus, status: ClipboardStatus):
        previous_entry_id = previous_status.source_entry_id if previous_status.active else None
        current_entry_id = status.source_entry_id if status.active else None
        if previous_entry_id == current_entry_id and previous_status.active == status.active:
            return
        if hasattr(self, "table") and hasattr(self, "entry_manager"):
            self._apply_entry_filter()

    def _format_entry_title_for_table(self, entry) -> str:
        title = str(entry.get("title", ""))
        status = self._get_clipboard_status()
        if status.active and status.source_entry_id == entry.get("id"):
            return f"{title} [В буфере]"
        return title

    def _set_system_clipboard(self, value: str):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.root.update()
        except tk.TclError:
            pass

    def _clear_system_clipboard(self, *, sync_service: bool = True) -> bool:
        cleared = False
        root_error = False
        try:
            self.root.clipboard_clear()
            self.root.update()
            cleared = True
        except tk.TclError:
            root_error = True
        windows_cleared = self._clear_windows_clipboard()
        cleared = cleared or windows_cleared
        if sync_service and hasattr(self, "clipboard_service"):
            self.clipboard_service.clear(reason="manual", publish_event=False)
        if root_error and not windows_cleared:
            return False
        return cleared

    def _clear_windows_clipboard(self) -> bool:
        if os.name != "nt":
            return False

        try:
            user32 = ctypes.windll.user32
        except AttributeError:
            return False

        if not user32.OpenClipboard(None):
            return False
        try:
            user32.EmptyClipboard()
        finally:
            user32.CloseClipboard()
        return True

    def clear_clipboard_from_ui(self):
        status = self._get_clipboard_status()
        if not status.active and not getattr(self.state, "get_clipboard", lambda: None)():
            self._show_info("Буфер обмена", "Буфер обмена уже пуст.")
            return

        if self._clear_system_clipboard(sync_service=False):
            if hasattr(self, "clipboard_service"):
                self.clipboard_service.clear(reason="manual")
                self._handle_clipboard_clear_failure()
            else:
                self._update_clipboard_notice(ClipboardStatus(active=True), ClipboardStatus(active=False))
            self._refresh_clipboard_status()
            self._show_info("Буфер обмена", "Буфер обмена очищен вручную.")
            return

        self._show_warning(
            "Буфер обмена",
            "Не удалось очистить буфер обмена автоматически. Очистите его вручную в системе.",
        )

    def _reauthenticate_for_sensitive_action(self, action_name: str) -> bool:
        password = self._ask_string(
            "Подтверждение",
            f"Введите мастер-пароль для действия «{action_name}»:",
            show="*",
        )
        if password is None:
            return False
        if self.auth_service.authenticate(password):
            if hasattr(self, "key_manager"):
                self.key_manager.store_key("active", self.auth_service.get_active_key())
            return True
        self._show_error("Ошибка аутентификации", "Неверный мастер-пароль.")
        return False

    def _get_full_clipboard_value_for_preview(self) -> str:
        if not self._reauthenticate_for_sensitive_action("Показать содержимое буфера обмена"):
            return ""
        if not hasattr(self, "clipboard_service"):
            return ""
        return self.clipboard_service.reveal_current_text()

    def show_clipboard_preview_dialog(self):
        status = self._get_clipboard_status()
        if not status.active:
            self._show_info("Буфер обмена", "Буфер обмена пуст.")
            return

        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Просмотр буфера обмена")
        dialog.geometry("560x340")
        if hasattr(dialog, "minsize"):
            dialog.minsize(520, 320)

        ttk.Label(dialog, text=f"Тип данных: {self._format_clipboard_data_type(status.data_type)}").pack(
            anchor=tk.W, padx=10, pady=(12, 4)
        )
        source_text = status.source_label or "Не указан"
        ttk.Label(dialog, text=f"Источник: {source_text}").pack(anchor=tk.W, padx=10, pady=4)
        ttk.Label(dialog, text=f"Маскированный просмотр: {status.preview or 'Нет данных'}", wraplength=420).pack(
            anchor=tk.W, padx=10, pady=4
        )
        ttk.Label(
            dialog,
            text=f"Режим доставки: {self._format_clipboard_delivery_mode(status.delivery_mode)}",
            wraplength=420,
        ).pack(anchor=tk.W, padx=10, pady=4)
        remaining_text = f"{status.remaining_seconds} сек" if status.remaining_seconds > 0 else "до ручной очистки"
        ttk.Label(dialog, text=f"Осталось времени: {remaining_text}").pack(anchor=tk.W, padx=10, pady=4)

        revealed_value_var = tk.StringVar(value="Полное значение скрыто")
        ttk.Label(dialog, textvariable=revealed_value_var, wraplength=420, justify=tk.LEFT).pack(
            anchor=tk.W, padx=10, pady=(10, 6)
        )

        def reveal_full_value():
            full_value = self._get_full_clipboard_value_for_preview()
            if not full_value:
                self._show_warning("Буфер обмена", "Содержимое буфера обмена уже очищено.", parent=dialog)
                dialog.destroy()
                return
            revealed_value_var.set(f"Полное значение: {full_value}")

        ttk.Button(dialog, text="Показать полностью", command=reveal_full_value).pack(pady=(6, 4))
        ttk.Button(dialog, text="Закрыть", command=dialog.destroy).pack(pady=4)

    def _require_login(self, initial: bool = False):
        self._login_prompt_active = True
        while not self.auth_service.is_authenticated():
            password = self._ask_string(
                "Мастер-пароль",
                "Введите мастер-пароль, чтобы разблокировать хранилище:",
                show="*",
            )
            if password is None:
                if initial:
                    self._on_close()
                self._login_prompt_active = False
                return

            try:
                if self.auth_service.authenticate(password):
                    self.key_manager.store_key("active", self.auth_service.get_active_key())
                    event_bus.publish(Event(EventType.VAULT_UNLOCKED, {}))
                    break
            except AuthenticationError as error:
                self._show_error("Ошибка аутентификации", str(error))
                continue

            remaining = self.auth_service.get_lockout_remaining_seconds()
            self._show_warning(
                "Доступ запрещён",
                f"Неверный мастер-пароль. Повторите попытку примерно через {remaining} сек."
                if remaining
                else "Неверный мастер-пароль.",
            )

        self._set_status("Разблокировано")
        self.state.update_activity()
        self.key_storage.touch_cached_key(self.state.key_cache_timeout)
        self._login_prompt_active = False

    def _sync_active_key_from_auth(self) -> bool:
        if not hasattr(self, "auth_service") or not hasattr(self, "key_manager"):
            return False
        if not self.auth_service.is_authenticated():
            return False
        active_key = self.auth_service.get_active_key()
        if not active_key:
            return False
        self.key_manager.store_key("active", active_key)
        return True

    def _load_entries(self):
        if not self.auth_service.is_authenticated():
            self._all_entries = []
            self.table.clear()
            if hasattr(self, "search_status_var"):
                self.search_status_var.set("Найдено: 0")
            return

        entries = self.entry_manager.get_all_entries()
        self.password_visibility_overrides = {}
        self._all_entries = entries
        self._update_category_filter_options()
        self._apply_entry_filter()

    def _clear_sensitive_view_state(self):
        # Очищаем расшифрованные данные и состояние показа паролей при блокировке.
        self._all_entries = []
        self.passwords_visible = False
        self.password_visibility_overrides = {}
        if hasattr(self, "table"):
            self.table.clear()
        if hasattr(self, "password_toggle_text"):
            self.password_toggle_text.set("Показать пароли")
        if hasattr(self, "search_status_var"):
            self.search_status_var.set("Найдено: 0")

    def _apply_entry_filter(self):
        raw_entries = getattr(self, "_all_entries", [])
        query = getattr(self, "search_var", None)
        search_text = query.get().strip() if query is not None else ""
        category_filter = getattr(self, "category_filter_var", None)
        selected_category = category_filter.get().strip() if category_filter is not None else "Все"
        tag_filter_var = getattr(self, "tag_filter_var", None)
        updated_from_var = getattr(self, "updated_from_var", None)
        updated_to_var = getattr(self, "updated_to_var", None)
        password_strength_var = getattr(self, "password_strength_filter_var", None)
        filtered_entries = self.entry_manager.search_entries(
            search_text,
            selected_category,
            raw_entries,
            updated_from=updated_from_var.get().strip() if updated_from_var is not None else "",
            updated_to=updated_to_var.get().strip() if updated_to_var is not None else "",
            password_strength=password_strength_var.get().strip() if password_strength_var is not None else "",
            tag=tag_filter_var.get().strip() if tag_filter_var is not None else "",
        )

        data = []
        for entry in filtered_entries:
            data.append(
                {
                    "id": entry["id"],
                    "title": self._format_entry_title_for_table(entry),
                    "username": self._mask_username(entry["username"]),
                    "password": self._format_password_for_table(entry["password"], entry["id"]),
                    "category": entry["category"],
                    "url": self._format_url_for_table(entry["url"]),
                    "updated_at": entry["updated_at"].strftime("%Y-%m-%d %H:%M") if entry["updated_at"] else "",
                    "_password_plain": entry["password"],
                    "_search_username": entry["username"],
                    "_search_url": entry["url"],
                    "_search_notes": entry["notes"],
                }
            )

        self.table.set_data(data)
        if hasattr(self, "search_status_var"):
            self.search_status_var.set(f"Найдено: {len(filtered_entries)} из {len(raw_entries)}")

    def _update_category_filter_options(self):
        if not hasattr(self, "category_filter"):
            return

        categories = sorted(
            {
                str(entry.get("category", "")).strip()
                for entry in getattr(self, "_all_entries", [])
                if str(entry.get("category", "")).strip()
            }
        )
        values = ["Все", *categories]
        self.category_filter.configure(values=values)

        current_value = self.category_filter_var.get().strip()
        if current_value not in values:
            self.category_filter_var.set("Все")

    def _clear_search(self):
        if hasattr(self, "search_var"):
            self.search_var.set("")
        if hasattr(self, "category_filter_var"):
            self.category_filter_var.set("Все")
        if hasattr(self, "tag_filter_var"):
            self.tag_filter_var.set("")
        if hasattr(self, "updated_from_var"):
            self.updated_from_var.set("")
        if hasattr(self, "updated_to_var"):
            self.updated_to_var.set("")
        if hasattr(self, "password_strength_filter_var"):
            self.password_strength_filter_var.set("Все")
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()

    def _toggle_password_visibility(self, _event=None):
        self.passwords_visible = not self.passwords_visible
        self.password_visibility_overrides = {}
        if hasattr(self, "password_toggle_text"):
            self.password_toggle_text.set("Скрыть пароли" if self.passwords_visible else "Показать пароли")
        self._apply_entry_filter()
        return "break"

    def _handle_table_click(self, event):
        cell = self.table.get_cell_at(event.x, event.y)
        if not cell or cell["column_id"] != "password":
            return

        entry_id = cell["row"]["id"]
        current_visibility = self._is_password_visible(entry_id)
        self.password_visibility_overrides[entry_id] = not current_visibility
        self._apply_entry_filter()
        self.table.ensure_row_selected_at_y(event.y)
        return "break"

    def _focus_search(self, _event=None):
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, tk.END)
        return "break"

    def _commit_search_query(self, _event=None):
        self._remember_search_query(getattr(self, "search_var", tk.StringVar()).get())
        return "break"

    def _remember_current_search(self, _event=None):
        self._remember_search_query(getattr(self, "search_var", tk.StringVar()).get())

    def _remember_search_query(self, query: str):
        normalized_query = str(query or "").strip()
        if not normalized_query:
            return

        updated_history = [item for item in self.search_history if item != normalized_query]
        updated_history.insert(0, normalized_query)
        self.search_history = updated_history[:10]
        self.db.set_setting("ui.search_history", self.search_history)
        self._update_search_history_button()

    def _update_search_history_button(self):
        if not hasattr(self, "search_history_button"):
            return
        if self.search_history:
            self.search_history_button.state(["!disabled"])
        else:
            self.search_history_button.state(["disabled"])

    def _show_search_history_menu(self):
        if not self.search_history or not hasattr(self, "search_history_button"):
            return

        history_menu = self._create_tk_menu(self.root, tearoff=0)
        for query in self.search_history:
            history_menu.add_command(
                label=query,
                command=lambda value=query: self._apply_search_history_item(value),
            )

        try:
            history_menu.tk_popup(
                self.search_history_button.winfo_rootx(),
                self.search_history_button.winfo_rooty() + self.search_history_button.winfo_height(),
            )
        finally:
            history_menu.grab_release()

    def _apply_search_history_item(self, query: str):
        if hasattr(self, "search_var"):
            self.search_var.set(query)
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, tk.END)

    def _mask_username(self, username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return username
        return f"{username[:4]}{'*' * max(4, len(username) - 4)}"

    def _is_password_visible(self, entry_id: int) -> bool:
        return self.password_visibility_overrides.get(entry_id, self.passwords_visible)

    def _format_password_for_table(self, password: str, entry_id: Optional[int] = None) -> str:
        if not password:
            return ""
        is_visible = self.passwords_visible if entry_id is None else self._is_password_visible(entry_id)
        if is_visible:
            return f"{password}  🙈"
        return f"{'•' * max(8, min(len(password), 16))}  👁"

    def _format_url_for_table(self, url: str) -> str:
        if not url:
            return ""
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        if "://" not in url:
            parsed = urlparse(f"https://{url}")
            if parsed.netloc:
                return parsed.netloc
        return url

    def _encrypt_password(self, password: str) -> bytes:
        return self.crypto.encrypt(password.encode("utf-8"))

    def _decrypt_password(self, encrypted_password: bytes) -> str:
        if isinstance(encrypted_password, str):
            return encrypted_password
        return self.crypto.decrypt(encrypted_password).decode("utf-8")

    def _build_entry_dialog(self, title: str, entry=None):
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title(title)
        dialog.geometry(self._get_screen_limited_geometry(920, 900))
        if hasattr(dialog, "minsize"):
            dialog.minsize(860, 820)
        dialog.transient(self.root)
        dialog.grab_set()

        body = self._create_scrollable_dialog_body(dialog)

        ttk.Label(body, text="Название").pack(anchor=tk.W, padx=12, pady=(10, 2))
        title_entry = ttk.Entry(body, width=60)
        title_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(body, text="Имя пользователя").pack(anchor=tk.W, padx=12, pady=(8, 2))
        username_entry = ttk.Entry(body, width=60)
        username_entry.pack(fill=tk.X, padx=8, pady=2)
        ttk.Label(body, text="Подсказка логина").pack(anchor=tk.W, padx=12, pady=(4, 2))
        username_suggestion = ttk.Combobox(body, state="readonly", width=57, values=[])
        username_suggestion.pack(fill=tk.X, padx=8, pady=(0, 2))
        username_suggestion.bind(
            "<<ComboboxSelected>>",
            lambda _event: self._apply_username_suggestion(username_entry, username_suggestion.get()),
        )

        ttk.Label(body, text="Пароль").pack(anchor=tk.W, padx=12, pady=(8, 2))
        password_entry = PasswordEntry(body, width=50)
        password_entry.pack(fill=tk.X, padx=8, pady=2)
        ttk.Button(
            body,
            text="Сгенерировать пароль",
            command=lambda: self._open_password_generator_dialog(dialog, password_entry),
        ).pack(anchor=tk.E, padx=8, pady=(0, 4))
        strength_var = tk.StringVar(value="Сложность пароля: не задан")
        ttk.Label(body, textvariable=strength_var).pack(anchor=tk.W, padx=12, pady=(0, 4))

        ttk.Label(body, text="URL").pack(anchor=tk.W, padx=12, pady=(8, 2))
        url_entry = ttk.Entry(body, width=60)
        url_entry.pack(fill=tk.X, padx=8, pady=2)
        favicon_status = tk.StringVar(value="Иконка сайта: не выбрана")
        favicon_label = ttk.Label(body, textvariable=favicon_status, compound=tk.LEFT)
        favicon_label.pack(anchor=tk.W, padx=12, pady=(0, 4))

        ttk.Label(body, text="Категория").pack(anchor=tk.W, padx=12, pady=(8, 2))
        category_entry = ttk.Entry(body, width=60)
        category_entry.pack(fill=tk.X, padx=8, pady=2)
        ttk.Label(body, text="Теги").pack(anchor=tk.W, padx=12, pady=(8, 2))
        tags_entry = ttk.Entry(body, width=60)
        tags_entry.pack(fill=tk.X, padx=8, pady=2)
        clipboard_policy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            body,
            text="Запретить копирование этой записи в буфер обмена",
            variable=clipboard_policy_var,
        ).pack(anchor=tk.W, padx=12, pady=(6, 2))

        ttk.Label(body, text="Заметки").pack(anchor=tk.W, padx=12, pady=(8, 2))
        notes_text = self._style_text_widget(tk.Text(body, height=7, width=60))
        notes_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 12))

        if entry:
            title_entry.insert(0, entry["title"])
            username_entry.insert(0, entry["username"])
            password_entry.set(entry["password"])
            url_entry.insert(0, entry["url"])
            category_entry.insert(0, entry["category"])
            tags_entry.insert(0, entry.get("tags", ""))
            clipboard_policy_var.set(str(entry.get("clipboard_policy", "allow")).strip().lower() == "never")
            notes_text.insert("1.0", entry["notes"])

        password_entry.entry.bind(
            "<KeyRelease>",
            lambda _event: self._on_password_entry_changed(dialog, password_entry, strength_var),
        )
        url_entry.bind("<KeyRelease>", lambda _event: self._schedule_favicon_preview(dialog, url_entry))
        url_entry.bind("<FocusOut>", lambda _event: self._schedule_favicon_preview(dialog, url_entry))
        url_entry.bind(
            "<KeyRelease>",
            lambda _event: self._schedule_username_suggestions(dialog, url_entry, username_entry),
            add="+",
        )
        url_entry.bind(
            "<FocusOut>",
            lambda _event: self._schedule_username_suggestions(dialog, url_entry, username_entry),
            add="+",
        )
        self._update_password_strength(password_entry, strength_var)
        dialog.category_entry = category_entry
        dialog.tags_entry = tags_entry
        dialog.clipboard_policy_var = clipboard_policy_var
        dialog.strength_var = strength_var
        dialog.password_was_generated = False
        dialog.favicon_status = favicon_status
        dialog.favicon_label = favicon_label
        dialog.favicon_image = None
        dialog.favicon_after_id = None
        dialog.favicon_request_token = None
        dialog.username_suggestion = username_suggestion
        dialog.username_suggestion_after_id = None
        dialog.button_bar = self._create_dialog_button_bar(dialog)
        self._schedule_favicon_preview(dialog, url_entry, delay_ms=0)
        self._schedule_username_suggestions(dialog, url_entry, username_entry, delay_ms=0)
        return dialog, title_entry, username_entry, password_entry, url_entry, notes_text

    def _collect_entry_form(self, dialog, title_entry, username_entry, password_entry, url_entry, notes_text):
        title = title_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        url = url_entry.get().strip()
        category_entry = getattr(dialog, "category_entry", None)
        category = category_entry.get().strip() if category_entry is not None else ""
        tags_entry = getattr(dialog, "tags_entry", None)
        tags = tags_entry.get().strip() if tags_entry is not None else ""
        notes = notes_text.get("1.0", tk.END).strip()
        clipboard_policy_var = getattr(dialog, "clipboard_policy_var", None)
        clipboard_policy = "never" if clipboard_policy_var is not None and clipboard_policy_var.get() else "allow"

        if not title or not password:
            raise ValueError("Поля «Название» и «Пароль» обязательны.")

        if url and not self._is_valid_url(url):
            raise ValueError("URL имеет некорректный формат.")

        if not getattr(dialog, "password_was_generated", False) and not self.password_generator.is_strong_enough(password):
            raise ValueError(
                "Слишком слабый пароль. Усильте его вручную или воспользуйтесь генератором паролей."
            )

        return title, username, password, url, notes, category, tags, clipboard_policy

    def _schedule_username_suggestions(self, dialog, url_entry, username_entry, delay_ms: int = 250):
        if not hasattr(dialog, "username_suggestion"):
            return
        after_id = getattr(dialog, "username_suggestion_after_id", None)
        if after_id:
            try:
                dialog.after_cancel(after_id)
            except tk.TclError:
                pass

        def run_suggestions():
            dialog.username_suggestion_after_id = None
            self._update_username_suggestions(dialog, url_entry.get().strip(), username_entry)

        dialog.username_suggestion_after_id = dialog.after(delay_ms, run_suggestions)

    def _update_username_suggestions(self, dialog, raw_url: str, username_entry):
        suggestion_widget = getattr(dialog, "username_suggestion", None)
        if suggestion_widget is None:
            return

        suggestions = self._suggest_usernames_for_url(raw_url)
        suggestion_widget.configure(values=suggestions)
        if suggestions:
            suggestion_widget.set(suggestions[0])
            if not username_entry.get().strip() and self._has_existing_domain_username(raw_url):
                self._apply_username_suggestion(username_entry, suggestions[0])
        else:
            suggestion_widget.set("")

    def _apply_username_suggestion(self, username_entry, suggestion: str):
        value = str(suggestion or "").strip()
        if not value:
            return
        username_entry.delete(0, tk.END)
        username_entry.insert(0, value)

    def _suggest_usernames_for_url(self, raw_url: str):
        host = self._extract_normalized_host(raw_url)
        if not host:
            return []

        base_domain = self._extract_base_domain(host)
        suggestions = []

        for entry in getattr(self, "_all_entries", []):
            entry_host = self._extract_normalized_host(entry.get("url", ""))
            if not entry_host:
                continue
            if entry_host == host or self._extract_base_domain(entry_host) == base_domain:
                username = str(entry.get("username", "")).strip()
                if username and username not in suggestions:
                    suggestions.append(username)

        if host == "localhost" or host.endswith(".local"):
            generated = ["admin", "root", "user"]
        else:
            generated = [
                f"admin@{base_domain}",
                f"support@{base_domain}",
                f"info@{base_domain}",
                base_domain.split(".", 1)[0],
                "admin",
            ]

        for item in generated:
            if item and item not in suggestions:
                suggestions.append(item)
        return suggestions[:5]

    def _has_existing_domain_username(self, raw_url: str) -> bool:
        host = self._extract_normalized_host(raw_url)
        if not host:
            return False
        base_domain = self._extract_base_domain(host)
        for entry in getattr(self, "_all_entries", []):
            entry_host = self._extract_normalized_host(entry.get("url", ""))
            if entry_host and (entry_host == host or self._extract_base_domain(entry_host) == base_domain):
                if str(entry.get("username", "")).strip():
                    return True
        return False

    def _extract_normalized_host(self, raw_url: str) -> str:
        value = str(raw_url or "").strip()
        if not value:
            return ""
        candidate = value if "://" in value else f"https://{value}"
        parsed = urlparse(candidate)
        host = (parsed.netloc or parsed.path).strip().lower()
        if ":" in host:
            host = host.split(":", 1)[0]
        return host

    def _extract_base_domain(self, host: str) -> str:
        parts = [part for part in str(host or "").split(".") if part]
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return str(host or "")

    def _schedule_favicon_preview(self, dialog, url_entry, delay_ms: int = 250):
        if not hasattr(dialog, "favicon_status"):
            return
        after_id = getattr(dialog, "favicon_after_id", None)
        if after_id:
            try:
                dialog.after_cancel(after_id)
            except tk.TclError:
                pass

        def run_preview():
            dialog.favicon_after_id = None
            self._update_favicon_preview(dialog, url_entry.get().strip())

        dialog.favicon_after_id = dialog.after(delay_ms, run_preview)

    def _update_favicon_preview(self, dialog, raw_url: str):
        favicon_request = self._build_favicon_request(raw_url)
        if favicon_request is None:
            self._set_dialog_favicon_placeholder(dialog, "Иконка сайта: не выбрана")
            return

        host = favicon_request["host"]
        cached_image = self._favicon_cache.get(host)
        if cached_image is not None:
            self._set_dialog_favicon_image(dialog, cached_image, host)
            return

        self._set_dialog_favicon_placeholder(dialog, f"Иконка сайта: {host}")
        request_token = f"{host}:{raw_url}"
        dialog.favicon_request_token = request_token

        def worker():
            image_data = self._download_favicon_image(favicon_request["service_url"])

            def apply_result():
                if getattr(dialog, "favicon_request_token", None) != request_token:
                    return
                if image_data is None:
                    self._set_dialog_favicon_placeholder(dialog, f"Иконка сайта: {host}")
                    return
                self._favicon_cache[host] = image_data
                self._set_dialog_favicon_image(dialog, image_data, host)

            try:
                dialog.after(0, apply_result)
            except tk.TclError:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _build_favicon_request(self, raw_url: str):
        value = str(raw_url or "").strip()
        if not value:
            return None

        candidate = value if "://" in value else f"https://{value}"
        parsed = urlparse(candidate)
        host = (parsed.netloc or parsed.path).strip().lower()
        if not host:
            return None

        if ":" in host:
            host = host.split(":", 1)[0]

        if not host:
            return None

        service_url = f"https://www.google.com/s2/favicons?sz=64&domain_url=https://{host}"
        return {"host": host, "service_url": service_url}

    def _download_favicon_image(self, service_url: str) -> Optional[str]:
        try:
            request = Request(service_url, headers={"User-Agent": "CryptoSafe-Manager/1.0"})
            with urlopen(request, timeout=3) as response:
                image_bytes = response.read()
        except (OSError, URLError, ValueError):
            return None

        if not image_bytes:
            return None
        return b64encode(image_bytes).decode("ascii")

    def _set_dialog_favicon_placeholder(self, dialog, text: str):
        status_var = getattr(dialog, "favicon_status", None)
        label = getattr(dialog, "favicon_label", None)
        if status_var is not None:
            status_var.set(text)
        if label is not None:
            label.configure(image="")
        dialog.favicon_image = None

    def _set_dialog_favicon_image(self, dialog, image_data: str, host: str):
        label = getattr(dialog, "favicon_label", None)
        status_var = getattr(dialog, "favicon_status", None)
        if label is None or status_var is None:
            return

        try:
            image = tk.PhotoImage(data=image_data)
        except tk.TclError:
            self._set_dialog_favicon_placeholder(dialog, f"Иконка сайта: {host}")
            return

        dialog.favicon_image = image
        label.configure(image=image)
        status_var.set(f"Иконка сайта: {host}")

    def _get_selected_entry(self):
        selected = self.table.get_selected()
        if not selected:
            return None
        try:
            entry = self.entry_manager.get_entry(selected["id"])
            entry["encrypted_password"] = entry["password"]
            return EntryView(entry)
        except EntryNotFoundError:
            return None

    def _get_selected_entries(self):
        entries = []
        for selected in self.table.get_selected_items():
            try:
                entry = self.entry_manager.get_entry(selected["id"])
                entry["encrypted_password"] = entry["password"]
                entries.append(EntryView(entry))
            except EntryNotFoundError:
                continue
        return entries

    def _get_single_selected_entry(self, action_name: str):
        selected_entries = self._get_selected_entries()
        if not selected_entries:
            self._show_warning("Предупреждение", f"Выберите запись для действия «{action_name}».")
            return None
        if len(selected_entries) > 1:
            self._show_warning("Предупреждение", f"Для действия «{action_name}» нужно выбрать только одну запись.")
            return None
        return selected_entries[0]

    def _on_entry_changed(self, _event):
        self._load_entries()

    def _generate_entry_password(
        self,
        dialog,
        password_entry: PasswordEntry,
        options: PasswordGeneratorOptions | None = None,
    ):
        password = self.password_generator.generate(options or PasswordGeneratorOptions())
        password_entry.set(password)
        password_entry.show_password.set(True)
        dialog.password_was_generated = True
        strength_var = getattr(dialog, "strength_var", None)
        if strength_var is not None:
            self._update_password_strength(password_entry, strength_var)

    def _open_password_generator_dialog(self, parent_dialog, password_entry: PasswordEntry):
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Параметры генерации пароля")
        dialog.geometry(self._get_screen_limited_geometry(560, 520))
        if hasattr(dialog, "minsize"):
            dialog.minsize(460, 420)
        dialog.transient(parent_dialog)
        dialog.grab_set()

        length_var = tk.IntVar(value=16)
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)
        ambiguous_var = tk.BooleanVar(value=False)

        ttk.Label(dialog, text="Длина пароля").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=8, to=64, textvariable=length_var).pack(fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(dialog, text="Включать заглавные буквы", variable=uppercase_var).pack(
            anchor=tk.W, padx=10, pady=(12, 2)
        )
        ttk.Checkbutton(dialog, text="Включать строчные буквы", variable=lowercase_var).pack(
            anchor=tk.W, padx=10, pady=2
        )
        ttk.Checkbutton(dialog, text="Включать цифры", variable=digits_var).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(dialog, text="Включать символы", variable=symbols_var).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(dialog, text="Исключить неоднозначные символы", variable=ambiguous_var).pack(
            anchor=tk.W, padx=10, pady=(12, 2)
        )

        def generate():
            options = PasswordGeneratorOptions(
                length=length_var.get(),
                include_uppercase=uppercase_var.get(),
                include_lowercase=lowercase_var.get(),
                include_digits=digits_var.get(),
                include_symbols=symbols_var.get(),
                exclude_ambiguous=ambiguous_var.get(),
            )
            try:
                self._generate_entry_password(parent_dialog, password_entry, options)
            except (ValueError, RuntimeError) as error:
                self._show_error("Ошибка", str(error), parent=dialog)
                return
            dialog.destroy()

        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(18, 10))
        ttk.Button(button_frame, text="Сгенерировать", command=generate).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 8))

    def _on_password_entry_changed(self, dialog, password_entry: PasswordEntry, strength_var: tk.StringVar):
        dialog.password_was_generated = False
        self._update_password_strength(password_entry, strength_var)

    def _update_password_strength(self, password_entry: PasswordEntry, strength_var: tk.StringVar):
        strength_var.set(f"Сложность пароля: {self._describe_password_strength(password_entry.get())}")

    def _describe_password_strength(self, password: str) -> str:
        if not password:
            return "не задан"
        if len(password) < 8:
            return "слабый"
        if self.password_generator.is_strong_enough(password):
            return "сильный"
        if len(password) >= 10:
            return "средний"
        return "слабый"

    def _is_valid_url(self, url: str) -> bool:
        candidate = url if "://" in url else f"https://{url}"
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            return False
        hostname = parsed.netloc
        if not hostname:
            return False
        if hostname == "localhost":
            return True
        return "." in hostname

    def _rotate_vault_entries(self, old_key: bytes, new_key: bytes):
        self._flush_audit_logger()
        old_crypto = LegacyXOREncryptionService()
        new_crypto = LegacyXOREncryptionService()
        old_vault_crypto = AESGCMEncryptionService()
        new_vault_crypto = AESGCMEncryptionService()
        progress_dialog = tk.Toplevel(self.root)
        self._prepare_dialog(progress_dialog)
        progress_dialog.title("Смена мастер-пароля")
        progress_dialog.geometry(self._get_screen_limited_geometry(640, 280))
        if hasattr(progress_dialog, "minsize"):
            progress_dialog.minsize(560, 240)
        progress_dialog.transient(self.root)
        progress_dialog.grab_set()

        status_var = tk.StringVar(value="Подготовка к пере-шифрованию записей...")
        progress_var = tk.DoubleVar(value=0)
        pause_button_text = tk.StringVar(value="Пауза")
        progress_queue: queue.Queue = queue.Queue()
        pause_event = threading.Event()
        pause_event.set()
        state = {"paused": False, "processed": 0, "total": 0, "error": None, "stage": "vault"}
        visible_since = time.monotonic()
        minimum_visible_seconds = 1.2

        ttk.Label(progress_dialog, text="Пере-шифрование хранилища", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, padx=12, pady=(12, 6)
        )
        ttk.Label(progress_dialog, textvariable=status_var, wraplength=380, justify=tk.LEFT).pack(
            anchor=tk.W, padx=12, pady=(0, 10)
        )
        progressbar = ttk.Progressbar(progress_dialog, variable=progress_var, maximum=1, mode="determinate")
        progressbar.pack(fill=tk.X, padx=12, pady=(0, 12))

        button_frame = ttk.Frame(progress_dialog)
        button_frame.pack(fill=tk.X, padx=12, pady=(0, 12))

        def update_status():
            suffix = " (пауза)" if state["paused"] else ""
            stage_label = "записей хранилища" if state["stage"] == "vault" else "журнала аудита"
            if state["total"] == 0:
                status_var.set(f"Пере-шифрование {stage_label}...{suffix}")
            else:
                status_var.set(f"Пере-шифрование {stage_label}: {state['processed']} из {state['total']}{suffix}")

        def toggle_pause():
            state["paused"] = not state["paused"]
            if state["paused"]:
                pause_event.clear()
                pause_button_text.set("Продолжить")
            else:
                pause_event.set()
                pause_button_text.set("Пауза")
            update_status()

        pause_button = ttk.Button(button_frame, textvariable=pause_button_text, command=toggle_pause)
        pause_button.pack(side=tk.RIGHT)
        progress_dialog.protocol("WM_DELETE_WINDOW", lambda: None)

        def transform(legacy_ciphertext: bytes, encrypted_payload: bytes) -> tuple[bytes, bytes]:
            updated_legacy = legacy_ciphertext
            if legacy_ciphertext:
                plaintext = old_crypto.decrypt(legacy_ciphertext, old_key)
                updated_legacy = new_crypto.encrypt(plaintext, new_key)

            updated_payload = encrypted_payload
            if encrypted_payload:
                try:
                    plaintext_payload = old_vault_crypto.decrypt(encrypted_payload, old_key)
                    updated_payload = new_vault_crypto.encrypt(plaintext_payload, new_key)
                except Exception:
                    updated_payload = encrypted_payload

            return updated_legacy, updated_payload

        def worker():
            try:
                self.db.reencrypt_entry_payloads(
                    transform,
                    progress_callback=lambda processed, total: progress_queue.put(("progress", "vault", processed, total)),
                    pause_event=pause_event,
                )
                if hasattr(self, "audit_logger") and hasattr(self.audit_logger, "reencrypt_entry_payloads"):
                    self._flush_audit_logger()
                    self.audit_logger.reencrypt_entry_payloads(
                        old_key,
                        new_key,
                        progress_callback=lambda processed, total: progress_queue.put(("progress", "audit", processed, total)),
                        pause_event=pause_event,
                    )
                    self._flush_audit_logger()
                progress_queue.put(("done",))
            except Exception as error:
                progress_queue.put(("error", str(error)))

        def poll_progress():
            try:
                while True:
                    message = progress_queue.get_nowait()
                    kind = message[0]
                    if kind == "progress":
                        _, stage, processed, total = message
                        state["stage"] = stage
                        state["processed"] = processed
                        state["total"] = total
                        progressbar.configure(maximum=max(total, 1))
                        progress_var.set(processed if total else 0)
                        update_status()
                    elif kind == "done":
                        pause_button.state(["disabled"])
                        status_var.set(
                            "Пере-шифрование завершено."
                            if state["total"]
                            else "Записей для пере-шифрования не найдено."
                        )
                        progressbar.configure(maximum=max(state["total"], 1))
                        progress_var.set(max(state["total"], 1))
                        remaining_ms = max(0, int((minimum_visible_seconds - (time.monotonic() - visible_since)) * 1000))
                        progress_dialog.after(remaining_ms, progress_dialog.destroy)
                        return
                    elif kind == "error":
                        state["error"] = message[1]
                        progress_dialog.destroy()
                        return
            except queue.Empty:
                pass

            if progress_dialog.winfo_exists():
                progress_dialog.after(100, poll_progress)

        def start_worker():
            threading.Thread(target=worker, daemon=True).start()
            poll_progress()

        progress_dialog.update_idletasks()
        progress_dialog.after(150, start_worker)
        progress_dialog.wait_window()

        if state["error"] is not None:
            raise RuntimeError(state["error"])

    def new_database(self):
        new_path = self._ask_saveas_filename(
            title="Создать новое хранилище",
            defaultextension=".db",
            filetypes=[("База SQLite", "*.db"), ("Все файлы", "*.*")],
        )
        if not new_path:
            return

        if os.path.exists(new_path):
            self._show_warning(
                "Создать новое хранилище",
                "Такой файл уже существует. Чтобы не потерять данные, выберите другое имя или откройте существующее хранилище.",
            )
            return
        self._remember_vault_path(new_path)
        if self.audit_logger:
            self.audit_logger.close()
        self.db.close()
        self.db = Database(new_path)
        self.key_storage = KeyStorage(self.db)
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
        self.audit_logger = AuditLogger(self.db, event_bus, key_provider=self.auth_service.get_active_key)
        self._persist_runtime_settings()
        self._load_password_policy()
        SetupWizard(self.root, self.config, self.auth_service)
        if not self.auth_service.is_initialized():
            return
        self.key_manager.store_key("active", self.auth_service.get_active_key())
        self._load_entries()

    def open_database(self):
        path = self._ask_open_filename(
            title="Открыть базу хранилища",
            filetypes=[("База SQLite", "*.db"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        self._remember_vault_path(path)
        if self.audit_logger:
            self.audit_logger.close()
        self.db.close()
        self.db = Database(path)
        self.key_storage = KeyStorage(self.db)
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
        self.audit_logger = AuditLogger(self.db, event_bus, key_provider=self.auth_service.get_active_key)
        self._persist_runtime_settings()
        self._load_password_policy()
        if not self.auth_service.is_initialized():
            SetupWizard(self.root, self.config, self.auth_service)
            if not self.auth_service.is_initialized():
                return
        self._lock_vault(show_dialog=False)
        self._require_login()
        if self.auth_service.is_authenticated():
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            self._load_entries()

    def backup(self):
        backup_path = self._ask_saveas_filename(
            title="Создать резервную копию хранилища",
            defaultextension=".db",
            filetypes=[("База SQLite", "*.db"), ("Все файлы", "*.*")],
        )
        if not backup_path:
            return
        self.db.backup(backup_path)
        self._show_info("Резервная копия", "Резервная копия успешно создана.")

    def add_entry(self):
        if not self.auth_service.is_authenticated():
            self._require_login()
        if not self.auth_service.is_authenticated():
            return
        dialog, title_entry, username_entry, password_entry, url_entry, notes_text = self._build_entry_dialog("Добавить запись")

        def save():
            try:
                title, username, password, url, notes, category, tags, clipboard_policy = self._collect_entry_form(
                    dialog, title_entry, username_entry, password_entry, url_entry, notes_text
                )
            except ValueError as error:
                self._show_error("Ошибка", str(error), parent=dialog)
                return

            try:
                self.entry_manager.create_entry(
                    {
                        "title": title,
                        "username": username,
                        "password": password,
                        "url": url,
                        "category": category,
                        "notes": notes,
                        "tags": tags,
                        "clipboard_policy": clipboard_policy,
                    }
                )
            except Exception as error:
                self._show_error("Ошибка сохранения", str(error), parent=dialog)
                return
            dialog.destroy()
            self._load_entries()

        ttk.Button(dialog.button_bar, text="Сохранить", style="Ghost.TButton", command=save).pack(side=tk.RIGHT)

    def edit_entry(self):
        entry = self._get_single_selected_entry("Изменить")
        if not entry:
            self._show_warning("Предупреждение", "Выберите запись для редактирования.")
            return

        dialog, title_entry, username_entry, password_entry, url_entry, notes_text = self._build_entry_dialog(
            "Редактировать запись",
            entry,
        )

        def save():
            try:
                title, username, password, url, notes, category, tags, clipboard_policy = self._collect_entry_form(
                    dialog, title_entry, username_entry, password_entry, url_entry, notes_text
                )
            except ValueError as error:
                self._show_error("Ошибка", str(error), parent=dialog)
                return

            try:
                self.entry_manager.update_entry(
                    entry["id"],
                    {
                        "title": title,
                        "username": username,
                        "password": password,
                        "url": url,
                        "category": category,
                        "notes": notes,
                        "tags": tags,
                        "clipboard_policy": clipboard_policy,
                    },
                )
            except Exception as error:
                self._show_error("Ошибка сохранения", str(error), parent=dialog)
                return
            dialog.destroy()
            self._load_entries()

        ttk.Button(dialog.button_bar, text="Сохранить изменения", style="Ghost.TButton", command=save).pack(side=tk.RIGHT)

    def delete_entry(self):
        selected_items = self.table.get_selected_items()
        if len(selected_items) > 1:
            if not self._ask_yes_no("Подтверждение", f"Удалить выбранные записи ({len(selected_items)})?"):
                return
            for selected in selected_items:
                self.entry_manager.delete_entry(selected["id"])
            return
        selected = self.table.get_selected()
        if not selected:
            self._show_warning("Предупреждение", "Выберите запись для удаления.")
            return
        if self._ask_yes_no("Подтверждение", f"Удалить запись «{selected['title']}»?"):
            self.entry_manager.delete_entry(selected["id"])

    def show_selected_password(self):
        entry = self._get_single_selected_entry("Показать пароль")
        if not entry:
            self._show_warning("Предупреждение", "Сначала выберите запись.")
            return
        self._show_info("Пароль", self._decrypt_password(entry.encrypted_password))
        self._on_activity()

    def copy_selected_password(self):
        entry = self._get_single_selected_entry("Скопировать пароль")
        if not entry:
            self._show_warning("Предупреждение", "Сначала выберите запись.")
            return
        password = self._decrypt_password(entry.encrypted_password)
        try:
            self.clipboard_service.copy_text(
                password,
                data_type="password",
                source_entry_id=entry.id,
                source_label=entry.title,
                application_name=self._get_clipboard_application_name(),
                entry_clipboard_policy=self._get_entry_clipboard_policy(entry),
            )
        except ClipboardAccessError as error:
            self._show_error("Ошибка буфера обмена", str(error))
            return
        self._on_activity()

    def copy_selected_username(self):
        entry = self._get_single_selected_entry("Скопировать логин")
        if not entry:
            self._show_warning("Предупреждение", "Сначала выберите запись.")
            return
        username = str(entry.get("username", "")).strip()
        if not self._copy_entry_to_clipboard(
            username,
            data_type="username",
            entry=entry,
            action_name="Скопировать логин",
        ):
            return
        self._on_activity()

    def copy_selected_all(self):
        entry = self._get_single_selected_entry("Скопировать запись")
        if not entry:
            self._show_warning("Предупреждение", "Сначала выберите запись.")
            return

        payload_parts = [
            f"Название: {entry.title}",
            f"Логин: {entry.username}",
            f"Пароль: {self._decrypt_password(entry.encrypted_password)}",
        ]
        if entry.get("url"):
            payload_parts.append(f"URL: {entry.url}")
        if entry.get("notes"):
            payload_parts.append(f"Заметки: {entry.notes}")

        if not self._copy_entry_to_clipboard(
            "\n".join(payload_parts),
            data_type="entry",
            entry=entry,
            action_name="Скопировать запись",
        ):
            return
        self._on_activity()

    def _copy_entry_to_clipboard(self, value: str, *, data_type: str, entry, action_name: str) -> bool:
        normalized_value = str(value or "")
        if not normalized_value.strip():
            self._show_warning("Предупреждение", f"Для действия «{action_name}» нет данных.")
            return False
        try:
            self.clipboard_service.copy_text(
                normalized_value,
                data_type=data_type,
                source_entry_id=entry.id,
                source_label=entry.title,
                application_name=self._get_clipboard_application_name(),
                entry_clipboard_policy=self._get_entry_clipboard_policy(entry),
            )
        except ClipboardAccessError as error:
            self._show_error("Ошибка буфера обмена", str(error))
            return False
        return True

    def _build_vault_exporter(self) -> VaultExporter:
        return VaultExporter(self.entry_manager, database=self.db, event_bus=event_bus)

    def _build_vault_importer(self) -> VaultImporter:
        return VaultImporter(self.entry_manager, database=self.db, event_bus=event_bus)

    def _build_sharing_service(self) -> SharingService:
        return SharingService(self.entry_manager, database=self.db, event_bus=event_bus)

    def _resolve_selected_export_entry_ids(self, selected_only: bool, selected_entry_ids: Optional[list[int]] = None) -> Optional[list[int]]:
        if not selected_only:
            return None
        if selected_entry_ids is not None:
            return [int(entry_id) for entry_id in selected_entry_ids]
        return [entry["id"] for entry in self._get_selected_entries()]

    def build_vault_export_preview(
        self,
        *,
        selected_only: bool = False,
        excluded_fields: Optional[list[str]] = None,
        selected_entry_ids: Optional[list[int]] = None,
    ) -> dict:
        entry_ids = self._resolve_selected_export_entry_ids(selected_only, selected_entry_ids)
        entries = self._build_vault_exporter().get_entries_for_export(ExportOptions(entry_ids=entry_ids))
        fields = {"title", "username", "password", "url", "notes", "category", "tags"}
        excluded = {str(field).strip() for field in (excluded_fields or []) if str(field).strip()}
        return {
            "entry_count": len(entries),
            "mode": "selected" if selected_only else "full",
            "included_fields": sorted(fields.difference(excluded)),
            "excluded_fields": sorted(excluded),
            "titles": [str(entry.get("title", "")) for entry in entries[:10]],
        }

    def _build_export_include_fields(self, excluded_fields: Optional[list[str]] = None) -> list[str]:
        fields = ["title", "username", "password", "url", "notes", "category", "tags"]
        excluded = {str(field).strip() for field in (excluded_fields or []) if str(field).strip()}
        return [field for field in fields if field not in excluded]

    def preview_vault_import_file(self, source_path: str, *, import_format: str, password: str = "") -> dict:
        with open(source_path, "rb") as handle:
            payload = handle.read()
        importer = self._build_vault_importer()
        normalized_format = self.detect_vault_import_format(source_path, payload) if str(import_format or "auto").strip().lower() == "auto" else str(import_format or "encrypted_json").strip().lower()
        if normalized_format in {"bitwarden", "bitwarden_json"} and self.detect_vault_import_format(source_path, payload) == "bitwarden_encrypted_json":
            normalized_format = "bitwarden_encrypted_json"
        options = ImportOptions(format=normalized_format, mode="dry-run", duplicate_strategy="skip")
        if normalized_format == "share_package":
            preview = self._preview_share_package_payload(payload, password)
            entry = preview.get("entry", {})
            return {
                "validated": 1,
                "mode": "dry-run",
                "format": normalized_format,
                "titles": [str(entry.get("title", ""))],
                "share_id": preview.get("share_id", ""),
                "permissions": preview.get("permissions", {}),
            }
        if normalized_format in {"encrypted_json", "json"}:
            if not password:
                raise ImportValidationError("Для зашифрованного JSON нужен пароль экспорта")
            entries = importer.preview_encrypted_json(payload, password, options)
        elif normalized_format == "bitwarden_encrypted_json":
            if not password:
                raise ImportValidationError("Для зашифрованного JSON Bitwarden нужен пароль экспорта")
            entries = importer.preview_bitwarden_encrypted_json(payload, password, options)
        else:
            entries = importer.preview_plaintext(payload, options)
        return {
            "validated": len(entries),
            "mode": "dry-run",
            "format": normalized_format,
            "titles": [str(entry.get("title", "")) for entry in entries[:10]],
        }

    def detect_vault_import_format(self, source_path: str = "", payload: bytes | str = b"") -> str:
        raw = payload if isinstance(payload, bytes) else str(payload).encode("utf-8", errors="ignore")
        text = raw[:4096].decode("utf-8-sig", errors="ignore").strip()
        lowered_path = str(source_path or "").lower()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                if parsed.get("cryptosafe_export"):
                    return "encrypted_json"
                if parsed.get("cryptosafe_share"):
                    return "share_package"
                if parsed.get("encrypted") is True and parsed.get("passwordProtected") is True and parsed.get("data"):
                    return "bitwarden_encrypted_json"
                if isinstance(parsed.get("items"), list):
                    return "bitwarden_json"
        first_line = text.splitlines()[0].strip().lower() if text.splitlines() else ""
        if {"url", "username", "password", "extra", "name", "grouping"}.issubset(set(item.strip() for item in first_line.split(","))):
            return "lastpass_csv"
        if lowered_path.endswith(".json"):
            return "encrypted_json"
        if lowered_path.endswith(".csv"):
            return "csv"
        raise ImportValidationError("Не удалось определить формат импорта. Выберите формат вручную.")

    def get_share_history_status(self, *, limit: int = 20) -> list[dict]:
        if not hasattr(self, "db") or not hasattr(self.db, "get_shared_entries"):
            return []
        rows = self.db.get_shared_entries(limit=limit)
        now = datetime.now(timezone.utc)
        history = []
        for row in rows:
            item = dict(row)
            status = str(item.get("status", "active") or "active")
            expires_at = item.get("expires_at")
            try:
                expires_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                if expires_dt.tzinfo is None:
                    expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                if status == "active" and expires_dt < now:
                    status = "expired"
            except (TypeError, ValueError):
                pass
            item["computed_status"] = status
            history.append(item)
        return history

    def _get_share_package_encryption_method(self, package_payload: str | bytes) -> str:
        raw_text = package_payload.decode("utf-8-sig", errors="ignore") if isinstance(package_payload, bytes) else str(package_payload)
        try:
            package = json.loads(raw_text)
        except json.JSONDecodeError as error:
            raise ImportValidationError("Файл пакета доступа повреждён или не является JSON.") from error
        if not isinstance(package, dict) or not package.get("cryptosafe_share"):
            raise ImportValidationError("Файл не является пакетом доступа CryptoSafe.")
        encryption = package.get("encryption", {})
        return str(encryption.get("method", "password") or "password").strip().lower()

    def _preview_share_package_payload(self, package_payload: str | bytes, secret: str) -> dict:
        method = self._get_share_package_encryption_method(package_payload)
        if method == "password":
            if not secret:
                raise ImportValidationError("Для пакета доступа нужен пароль пакета.")
            return self._build_sharing_service().preview_password_share_package(package_payload, secret)
        if not secret:
            raise ImportValidationError("Для пакета доступа с публичным ключом нужен приватный ключ.")
        return self._build_sharing_service().preview_public_key_share_package(package_payload, secret)

    def _import_share_package_payload(self, package_payload: str | bytes, secret: str) -> dict:
        method = self._get_share_package_encryption_method(package_payload)
        if method == "password":
            if not secret:
                raise ImportValidationError("Для пакета доступа нужен пароль пакета.")
            return self._build_sharing_service().import_password_share_package(package_payload, secret)
        if not secret:
            raise ImportValidationError("Для пакета доступа с публичным ключом нужен приватный ключ.")
        return self._build_sharing_service().import_public_key_share_package(package_payload, secret)

    def export_vault_encrypted_json_to_path(
        self,
        target_path: str,
        password: str,
        *,
        selected_only: bool = False,
        selected_entry_ids: Optional[list[int]] = None,
        compression: bool = True,
        include_fields: Optional[list[str]] = None,
        encryption_strength: int = 256,
    ) -> bool:
        entry_ids = self._resolve_selected_export_entry_ids(selected_only, selected_entry_ids)
        if selected_only and not entry_ids:
            self._show_warning("Экспорт хранилища", "Выберите записи для выборочного экспорта.")
            return False
        with self._crypto_operation_status():
            payload = self._build_vault_exporter().export_encrypted_json(
                password,
                ExportOptions(
                    entry_ids=entry_ids,
                    include_fields=include_fields,
                    encryption_strength=encryption_strength,
                    compression=compression,
                ),
            )
            self._write_audit_export_file(target_path, payload)
        self._show_info("Экспорт хранилища", "Зашифрованный экспорт хранилища успешно сохранён.")
        return True

    def export_vault_csv_to_path(
        self,
        target_path: str,
        *,
        selected_only: bool = False,
        selected_entry_ids: Optional[list[int]] = None,
        include_fields: Optional[list[str]] = None,
    ) -> bool:
        if not self._ask_yes_no(
            "Экспорт CSV",
            "CSV сохраняет данные в открытом виде. Продолжить только если файл будет защищён отдельно?",
        ):
            return False
        entry_ids = self._resolve_selected_export_entry_ids(selected_only, selected_entry_ids)
        if selected_only and not entry_ids:
            self._show_warning("Экспорт CSV", "Выберите записи для выборочного экспорта.")
            return False
        payload = self._build_vault_exporter().export_csv(
            ExportOptions(format="csv", entry_ids=entry_ids, include_fields=include_fields, plaintext_allowed=True),
        )
        self._write_audit_export_file(target_path, payload)
        self._show_info("Экспорт CSV", "CSV-экспорт хранилища сохранён.")
        return True

    def export_vault_public_key_json_to_path(
        self,
        target_path: str,
        public_key: str,
        *,
        selected_only: bool = False,
        selected_entry_ids: Optional[list[int]] = None,
        include_fields: Optional[list[str]] = None,
    ) -> bool:
        entry_ids = self._resolve_selected_export_entry_ids(selected_only, selected_entry_ids)
        if selected_only and not entry_ids:
            self._show_warning("Экспорт хранилища", "Выберите записи для выборочного экспорта.")
            return False
        with self._crypto_operation_status():
            payload = self._build_vault_exporter().export_encrypted_json_for_public_key(
                public_key,
                ExportOptions(entry_ids=entry_ids, include_fields=include_fields, compression=True),
            )
            self._write_audit_export_file(target_path, payload)
        self._show_info("Экспорт хранилища", "Экспорт хранилища с публичным ключом успешно сохранён.")
        return True

    def export_vault_bitwarden_encrypted_json_to_path(
        self,
        target_path: str,
        password: str,
        *,
        selected_only: bool = False,
        selected_entry_ids: Optional[list[int]] = None,
        include_fields: Optional[list[str]] = None,
    ) -> bool:
        entry_ids = self._resolve_selected_export_entry_ids(selected_only, selected_entry_ids)
        if selected_only and not entry_ids:
            self._show_warning("Экспорт Bitwarden", "Выберите записи для выборочного экспорта.")
            return False
        with self._crypto_operation_status():
            payload = self._build_vault_exporter().export_bitwarden_encrypted_json(
                password,
                ExportOptions(format="bitwarden_encrypted_json", entry_ids=entry_ids, include_fields=include_fields),
            )
            self._write_audit_export_file(target_path, payload)
        self._show_info("Экспорт Bitwarden", "Зашифрованный Bitwarden JSON успешно сохранён.")
        return True

    def export_vault_password_manager_to_path(
        self,
        target_path: str,
        *,
        export_format: str,
        selected_only: bool = False,
        selected_entry_ids: Optional[list[int]] = None,
        include_fields: Optional[list[str]] = None,
    ) -> bool:
        if not self._ask_yes_no(
            "Экспорт менеджера паролей",
            "Формат Bitwarden/LastPass сохраняет миграционный файл в открытом виде. Продолжить?",
        ):
            return False
        entry_ids = self._resolve_selected_export_entry_ids(selected_only, selected_entry_ids)
        if selected_only and not entry_ids:
            self._show_warning("Экспорт хранилища", "Выберите записи для выборочного экспорта.")
            return False
        with self._crypto_operation_status():
            options = ExportOptions(format=export_format, entry_ids=entry_ids, include_fields=include_fields, plaintext_allowed=True)
            if export_format == "bitwarden_json":
                payload = self._build_vault_exporter().export_bitwarden_json(options)
            elif export_format == "lastpass_csv":
                payload = self._build_vault_exporter().export_lastpass_csv(options)
            else:
                raise ValueError("Неподдерживаемый формат экспорта менеджера паролей")
            self._write_audit_export_file(target_path, payload)
        self._show_info("Экспорт менеджера паролей", "Миграционный экспорт сохранён.")
        return True

    def import_vault_file(
        self,
        source_path: str,
        *,
        import_format: str,
        password: str = "",
        mode: str = "dry-run",
        duplicate_strategy: str = "skip",
    ) -> dict:
        with open(source_path, "rb") as handle:
            payload = handle.read()
        importer = self._build_vault_importer()
        normalized_format = self.detect_vault_import_format(source_path, payload) if str(import_format or "auto").strip().lower() == "auto" else str(import_format or "encrypted_json").strip().lower()
        if normalized_format in {"bitwarden", "bitwarden_json"} and self.detect_vault_import_format(source_path, payload) == "bitwarden_encrypted_json":
            normalized_format = "bitwarden_encrypted_json"
        options = ImportOptions(format=normalized_format, mode=mode, duplicate_strategy=duplicate_strategy)
        with self._crypto_operation_status():
            if normalized_format == "share_package":
                if mode == "dry-run":
                    preview = self.preview_vault_import_file(source_path, import_format=normalized_format, password=password)
                    result = {"validated": preview.get("validated", 0), "created": 0, "updated": 0, "skipped": 0}
                else:
                    result = self._import_share_package_payload(payload, password)
                    result.setdefault("validated", 1)
                    result.setdefault("updated", 0)
                    result.setdefault("skipped", 0)
            elif normalized_format in {"encrypted_json", "json"}:
                if not password:
                    raise ImportValidationError("Для зашифрованного JSON нужен пароль экспорта")
                result = importer.import_encrypted_json(payload, password, options)
            elif normalized_format == "bitwarden_encrypted_json":
                if not password:
                    raise ImportValidationError("Для зашифрованного JSON Bitwarden нужен пароль экспорта")
                result = importer.import_bitwarden_encrypted_json(payload, password, options)
            else:
                result = importer.import_plaintext(payload, options)
        if mode != "dry-run":
            self._load_entries()
        self._show_info(
            "Импорт хранилища",
            (
                f"Проверено: {result.get('validated', 0)}; "
                f"создано: {result.get('created', 0)}; "
                f"обновлено: {result.get('updated', 0)}; "
                f"пропущено: {result.get('skipped', 0)}."
            ),
        )
        return result

    def share_selected_entry_to_path(
        self,
        target_path: str,
        *,
        recipient: str,
        password: str,
        expires_in_days: int = 7,
        read: bool = True,
        edit: bool = False,
    ) -> bool:
        entry = self._get_single_selected_entry("Поделиться записью")
        if not entry:
            return False
        package = self._build_sharing_service().create_password_share_package(
            entry_id=entry["id"],
            recipient=recipient,
            password=password,
            permissions=SharePermissions(read=read, edit=edit, expires_in_days=expires_in_days),
        )
        self._write_audit_export_file(target_path, package)
        self._show_info("Поделиться записью", "Зашифрованный пакет доступа сохранён.")
        return True

    def share_selected_entry_public_key_to_path(
        self,
        target_path: str,
        *,
        recipient: str,
        public_key: str,
        expires_in_days: int = 7,
        read: bool = True,
        edit: bool = False,
    ) -> bool:
        entry = self._get_single_selected_entry("Поделиться записью")
        if not entry:
            return False
        package = self._build_sharing_service().create_public_key_share_package(
            entry_id=entry["id"],
            recipient=recipient,
            public_key=public_key,
            permissions=SharePermissions(read=read, edit=edit, expires_in_days=expires_in_days),
        )
        self._write_audit_export_file(target_path, package)
        self._show_info("Поделиться записью", "Пакет доступа с публичным ключом сохранён.")
        return True

    def generate_key_exchange_payload_text(self, *, identifier: str, public_key: str) -> str:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        return service.serialize_qr_payload(service.build_qr_payload(identifier=identifier, public_key=public_key))

    def generate_key_exchange_key_pair(self) -> dict:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        return service.generate_key_pair()

    def generate_key_exchange_qr_svg_text(self, *, identifier: str, public_key: str) -> str:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        qr_service = QRCodeService(service)
        return "\n\n".join(qr_service.generate_key_exchange_svgs(identifier=identifier, public_key=public_key))

    def generate_key_exchange_qr_pngs(self, *, identifier: str, public_key: str) -> list[bytes]:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        qr_service = QRCodeService(service)
        return qr_service.generate_key_exchange_pngs(identifier=identifier, public_key=public_key)

    def scan_key_exchange_payload_from_camera(self) -> str:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        camera_scanner = getattr(self, "qr_camera_scanner", None)
        return QRCodeService(service, camera_scanner=camera_scanner).scan_from_camera()

    def generate_share_package_qr_pngs(self, *, package_payload: str, label: str = "share-package") -> list[bytes]:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        qr_service = QRCodeService(service)
        return qr_service.generate_data_payload_pngs(
            payload_type="cryptosafe_share_package",
            label=label or "share-package",
            data=str(package_payload or ""),
        )

    def generate_key_exchange_file_bundle(self, *, identifier: str, output_dir: str) -> dict:
        safe_identifier = "".join(character if character.isalnum() or character in {"-", "_"} else "-" for character in identifier).strip("-")
        safe_identifier = safe_identifier or "local-user"
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_name = f"key-exchange-{safe_identifier}-{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        key_pair = service.generate_key_pair()
        payload = service.serialize_qr_payload(
            service.build_qr_payload(identifier=identifier, public_key=key_pair["public_key"])
        )
        qr_service = QRCodeService(service)
        qr_svgs = qr_service.generate_qr_svgs(payload)
        qr_pngs = qr_service.generate_qr_pngs(payload)

        private_key_path = os.path.join(output_dir, f"{base_name}-private-key.pem")
        payload_path = os.path.join(output_dir, f"{base_name}-public-payload.json")
        qr_paths = []
        self._write_audit_export_file(private_key_path, key_pair["private_key"])
        self._write_audit_export_file(payload_path, payload)
        for index, svg in enumerate(qr_svgs, start=1):
            suffix = "" if len(qr_svgs) == 1 else f"-part-{index:02d}"
            qr_path = os.path.join(output_dir, f"{base_name}-qr{suffix}.svg")
            self._write_audit_export_file(qr_path, svg)
            qr_paths.append(qr_path)
        return {
            "fingerprint": key_pair["fingerprint"],
            "private_key_path": private_key_path,
            "payload_path": payload_path,
            "qr_paths": qr_paths,
            "qr_pngs": qr_pngs,
            "expires_at": json.loads(payload)["expires_at"],
        }

    def import_key_exchange_payload_text(self, payload_text: str, *, contact_name: str = "") -> int | None:
        service = KeyExchangeService(database=self.db, event_bus=event_bus)
        payload = service.parse_qr_payload(payload_text)
        contact_id = service.remember_contact(payload, name=contact_name)
        self._show_info("Обмен ключами", "Контакт и публичный ключ сохранены.")
        return contact_id

    def _get_export_format_descriptions(self) -> dict[str, dict[str, str]]:
        return {
            "encrypted_json": {
                "label": "Зашифрованный JSON",
                "description": "Основной безопасный формат CryptoSafe: AES-GCM, метаданные, проверка целостности, пароль экспорта.",
                "extension": ".json",
            },
            "public_key_json": {
                "label": "JSON с публичным ключом",
                "description": "Гибридное шифрование RSA-OAEP/AES-GCM для получателя с публичным ключом.",
                "extension": ".json",
            },
            "bitwarden_encrypted_json": {
                "label": "Зашифрованный JSON Bitwarden",
                "description": "JSON с защитой паролем для импорта в Bitwarden: данные зашифрованы, открытый текст не пишется в файл.",
                "extension": ".json",
            },
        }

    def show_export_dialog(self):
        if not self._reauthenticate_for_sensitive_action("Экспорт хранилища"):
            return False
        if not self._can_use_themed_dialogs():
            return self._show_export_dialog_fallback()

        formats = self._get_export_format_descriptions()
        result = {"value": False}
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Экспорт хранилища")
        dialog.geometry(self._get_screen_limited_geometry(1040, 780))
        if hasattr(dialog, "minsize"):
            dialog.minsize(940, 700)
        dialog.transient(self.root)
        dialog.grab_set()

        body = self._create_scrollable_dialog_body(dialog)
        content = ttk.Frame(body, style="App.TFrame", padding=16)
        content.pack(fill=tk.BOTH, expand=True)
        ttk.Label(content, text="Экспорт хранилища", style="DialogTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(
            content,
            text="Настройте формат, состав данных и параметры шифрования. Перед сохранением проверьте предпросмотр.",
            style="Muted.TLabel",
            wraplength=920,
        ).pack(anchor=tk.W, pady=(6, 14))

        left = ttk.Frame(content, style="App.TFrame")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 12))
        right = ttk.Frame(content, style="App.TFrame")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        format_label_to_key = {description["label"]: key for key, description in formats.items()}
        format_key_to_label = {key: description["label"] for key, description in formats.items()}
        format_var = tk.StringVar(value=format_key_to_label["encrypted_json"])
        selected_only_var = tk.BooleanVar(value=False)
        compression_var = tk.BooleanVar(value=True)
        strength_var = tk.StringVar(value="256")
        password_var = tk.StringVar()
        public_key_var = tk.StringVar()
        field_vars = {
            "title": tk.BooleanVar(value=True),
            "username": tk.BooleanVar(value=True),
            "password": tk.BooleanVar(value=True),
            "url": tk.BooleanVar(value=True),
            "notes": tk.BooleanVar(value=True),
            "category": tk.BooleanVar(value=True),
            "tags": tk.BooleanVar(value=True),
        }
        field_labels = {
            "title": "Название",
            "username": "Логин",
            "password": "Пароль",
            "url": "URL",
            "notes": "Заметки",
            "category": "Категория",
            "tags": "Теги",
        }
        export_entries = self._build_vault_exporter().get_entries_for_export(ExportOptions())
        selected_entry_ids = {int(entry.get("id")) for entry in self._get_selected_entries()}
        if not selected_entry_ids:
            selected_entry_ids = {int(entry.get("id")) for entry in export_entries}

        ttk.Label(left, text="Формат", style="DialogHeader.TLabel").pack(anchor=tk.W, pady=(0, 6))
        format_box = ttk.Combobox(
            left,
            textvariable=format_var,
            state="readonly",
            values=list(format_label_to_key.keys()),
            width=34,
        )
        format_box.pack(fill=tk.X, pady=(0, 8))
        description_var = tk.StringVar()
        ttk.Label(left, textvariable=description_var, style="DialogBody.TLabel", wraplength=420, justify=tk.LEFT).pack(
            fill=tk.X, pady=(0, 14)
        )

        ttk.Label(left, text="Состав экспорта", style="DialogHeader.TLabel").pack(anchor=tk.W, pady=(0, 6))
        ttk.Checkbutton(left, text="Только выбранные записи", variable=selected_only_var).pack(anchor=tk.W, pady=2)
        ttk.Label(left, text="Записи для выборочного экспорта", style="TLabel").pack(anchor=tk.W, pady=(8, 4))
        entry_tree = ttk.Treeview(
            left,
            columns=("checked", "title", "username"),
            show="headings",
            height=7,
            selectmode="browse",
            style="Vault.Treeview",
        )
        entry_tree.heading("checked", text="✓")
        entry_tree.heading("title", text="Название")
        entry_tree.heading("username", text="Логин")
        entry_tree.column("checked", width=44, anchor=tk.CENTER, stretch=False)
        entry_tree.column("title", width=190)
        entry_tree.column("username", width=160)
        for entry in export_entries:
            entry_id = int(entry.get("id"))
            entry_tree.insert(
                "",
                tk.END,
                iid=str(entry_id),
                values=("☑" if entry_id in selected_entry_ids else "☐", entry.get("title", ""), entry.get("username", "")),
            )
        entry_tree.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(left, text="Клик по строке переключает чекбокс.", style="Muted.TLabel").pack(anchor=tk.W, pady=(0, 8))
        fields_frame = ttk.Frame(left, style="App.TFrame")
        fields_frame.pack(fill=tk.X, pady=(8, 14))
        for index, (field, variable) in enumerate(field_vars.items()):
            ttk.Checkbutton(fields_frame, text=field_labels.get(field, field), variable=variable).grid(
                row=index // 2,
                column=index % 2,
                sticky="w",
                padx=(0, 18),
                pady=2,
            )

        ttk.Label(left, text="Шифрование", style="DialogHeader.TLabel").pack(anchor=tk.W, pady=(0, 6))
        ttk.Label(left, text="Пароль экспорта", style="TLabel").pack(anchor=tk.W)
        password_entry = ttk.Entry(left, textvariable=password_var, show="*")
        password_entry.pack(fill=tk.X, pady=(2, 8))
        ttk.Label(left, text="Публичный ключ получателя", style="TLabel").pack(anchor=tk.W)
        public_key_entry = ttk.Entry(left, textvariable=public_key_var)
        public_key_entry.pack(fill=tk.X, pady=(2, 8))
        ttk.Label(left, text="Стойкость шифрования", style="TLabel").pack(anchor=tk.W)
        strength_box = ttk.Combobox(left, textvariable=strength_var, state="readonly", values=["256", "128"], width=10)
        strength_box.pack(anchor=tk.W, pady=(2, 8))
        ttk.Checkbutton(left, text="Сжатие GZIP", variable=compression_var).pack(anchor=tk.W, pady=(2, 8))

        ttk.Label(right, text="Предпросмотр", style="DialogHeader.TLabel").pack(anchor=tk.W, pady=(0, 6))
        preview_text = self._style_text_widget(tk.Text(right, wrap=tk.WORD, height=22))
        preview_text.pack(fill=tk.BOTH, expand=True)

        button_bar = ttk.Frame(dialog, style="App.TFrame")
        button_bar.pack(fill=tk.X, padx=16, pady=(0, 16))

        def selected_include_fields() -> list[str]:
            return [field for field, variable in field_vars.items() if variable.get()]

        def selected_excluded_fields() -> list[str]:
            return [field for field, variable in field_vars.items() if not variable.get()]

        def selected_dialog_entry_ids() -> list[int]:
            return sorted(selected_entry_ids)

        def toggle_export_entry(item_id: str):
            try:
                entry_id = int(item_id)
            except (TypeError, ValueError):
                return
            if entry_id in selected_entry_ids:
                selected_entry_ids.remove(entry_id)
                checked = "☐"
            else:
                selected_entry_ids.add(entry_id)
                checked = "☑"
            values = list(entry_tree.item(str(entry_id), "values"))
            if values:
                values[0] = checked
                entry_tree.item(str(entry_id), values=values)
            refresh_preview()

        def toggle_export_entry_from_event(event):
            item_id = entry_tree.identify_row(event.y)
            if item_id:
                toggle_export_entry(item_id)
            return "break"

        def refresh_preview(*_args):
            normalized = format_label_to_key.get(format_var.get(), format_var.get())
            info = formats.get(normalized, formats["encrypted_json"])
            description_var.set(info["description"])
            password_entry.state(["!disabled"] if normalized in {"encrypted_json", "bitwarden_encrypted_json"} else ["disabled"])
            public_key_entry.state(["!disabled"] if normalized == "public_key_json" else ["disabled"])
            strength_box.state(["!disabled"] if normalized == "encrypted_json" else ["disabled"])

            try:
                preview = self.build_vault_export_preview(
                    selected_only=selected_only_var.get(),
                    excluded_fields=selected_excluded_fields(),
                    selected_entry_ids=selected_dialog_entry_ids(),
                )
                mode_labels = {"selected": "выбранные записи", "full": "все записи"}
                included_field_labels = [field_labels.get(field, field) for field in preview["included_fields"]]
                excluded_field_labels = [field_labels.get(field, field) for field in preview["excluded_fields"]]
                lines = [
                    f"Формат: {info['label']}",
                    "Безопасность: шифрование включено по умолчанию",
                    f"Режим: {mode_labels.get(preview['mode'], preview['mode'])}",
                    f"Записей: {preview['entry_count']}",
                    f"Отмечено в списке: {len(selected_entry_ids)}",
                    f"Поля: {', '.join(included_field_labels)}",
                    f"Исключено: {', '.join(excluded_field_labels) or 'нет'}",
                    f"Стойкость: {strength_var.get()} бит" if normalized == "encrypted_json" else "Стойкость: не применяется",
                    f"Сжатие: {'да' if compression_var.get() and normalized == 'encrypted_json' else 'нет'}",
                    "",
                    "Первые записи:",
                    *[f"- {title}" for title in preview["titles"]],
                ]
            except Exception as error:
                lines = [f"Предпросмотр недоступен: {error}"]
            preview_text.config(state=tk.NORMAL)
            preview_text.delete("1.0", tk.END)
            preview_text.insert("1.0", "\n".join(lines))
            preview_text.config(state=tk.DISABLED)

        def choose_target_and_export():
            normalized = format_label_to_key.get(format_var.get(), format_var.get())
            if not selected_include_fields():
                self._show_warning("Экспорт хранилища", "Выберите хотя бы одно поле для экспорта.", parent=dialog)
                return
            if normalized in {"encrypted_json", "bitwarden_encrypted_json"} and not password_var.get():
                self._show_warning("Экспорт хранилища", "Введите пароль экспорта.", parent=dialog)
                return
            if normalized == "public_key_json" and not public_key_var.get().strip():
                self._show_warning("Экспорт хранилища", "Вставьте публичный ключ получателя.", parent=dialog)
                return
            extension = formats[normalized]["extension"]
            target_path = self._ask_saveas_filename(
                title="Экспорт хранилища",
                defaultextension=extension,
                filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")],
                parent=dialog,
            )
            if not target_path:
                return
            include_fields = selected_include_fields()
            selected_only = selected_only_var.get()
            selected_ids = selected_dialog_entry_ids()
            try:
                if normalized == "encrypted_json":
                    result["value"] = self.export_vault_encrypted_json_to_path(
                        target_path,
                        password_var.get(),
                        selected_only=selected_only,
                        selected_entry_ids=selected_ids,
                        compression=compression_var.get(),
                        include_fields=include_fields,
                        encryption_strength=int(strength_var.get()),
                    )
                elif normalized == "public_key_json":
                    result["value"] = self.export_vault_public_key_json_to_path(
                        target_path,
                        public_key_var.get().strip(),
                        selected_only=selected_only,
                        selected_entry_ids=selected_ids,
                        include_fields=include_fields,
                    )
                elif normalized == "bitwarden_encrypted_json":
                    result["value"] = self.export_vault_bitwarden_encrypted_json_to_path(
                        target_path,
                        password_var.get(),
                        selected_only=selected_only,
                        selected_entry_ids=selected_ids,
                        include_fields=include_fields,
                    )
                else:
                    raise ValueError("Неподдерживаемый безопасный формат экспорта")
            except Exception as error:
                self._show_error("Экспорт хранилища", str(error), parent=dialog)
                return
            if result["value"]:
                dialog.destroy()

        for variable in [format_var, selected_only_var, compression_var, strength_var, password_var, public_key_var, *field_vars.values()]:
            variable.trace_add("write", refresh_preview)
        format_box.bind("<<ComboboxSelected>>", refresh_preview)
        entry_tree.bind("<ButtonRelease-1>", toggle_export_entry_from_event)
        ttk.Button(button_bar, text="Обновить предпросмотр", style="Ghost.TButton", command=refresh_preview).pack(side=tk.LEFT)
        ttk.Button(button_bar, text="Отмена", style="Ghost.TButton", command=dialog.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(button_bar, text="Экспортировать", style="Accent.TButton", command=choose_target_and_export).pack(side=tk.RIGHT)

        refresh_preview()
        dialog.wait_window()
        return result["value"]

    def _show_export_dialog_fallback(self):
        export_format = self._ask_string(
            "Экспорт хранилища",
            "Формат: encrypted_json, public_key_json или bitwarden_encrypted_json",
            initialvalue="encrypted_json",
        )
        if not export_format:
            return False
        normalized_format = str(export_format).strip().lower()
        selected_only = self._ask_yes_no("Экспорт хранилища", "Экспортировать только выбранные записи?")
        include_fields = self._build_export_include_fields([])
        if normalized_format in {"encrypted_json", "json"}:
            password = self._ask_string("Пароль экспорта", "Введите пароль для файла экспорта:", show="*")
            if not password:
                return False
            target_path = self._ask_saveas_filename(
                title="Экспорт хранилища",
                defaultextension=".json",
                filetypes=[("CryptoSafe JSON", "*.json"), ("Все файлы", "*.*")],
            )
            if not target_path:
                return False
            return self.export_vault_encrypted_json_to_path(target_path, password, selected_only=selected_only, include_fields=include_fields)
        if normalized_format == "public_key_json":
            public_key = self._ask_string("Публичный ключ", "Вставьте публичный RSA-ключ получателя:")
            if not public_key:
                return False
            target_path = self._ask_saveas_filename(
                title="Экспорт хранилища с публичным ключом",
                defaultextension=".json",
                filetypes=[("CryptoSafe JSON", "*.json"), ("Все файлы", "*.*")],
            )
            if not target_path:
                return False
            return self.export_vault_public_key_json_to_path(target_path, public_key, selected_only=selected_only, include_fields=include_fields)
        if normalized_format in {"bitwarden_encrypted_json", "bitwarden"}:
            password = self._ask_string("Пароль экспорта", "Введите пароль для зашифрованного JSON Bitwarden:", show="*")
            if not password:
                return False
            target_path = self._ask_saveas_filename(
                title="Экспорт зашифрованного JSON Bitwarden",
                defaultextension=".json",
                filetypes=[("Bitwarden JSON", "*.json"), ("Все файлы", "*.*")],
            )
            if not target_path:
                return False
            return self.export_vault_bitwarden_encrypted_json_to_path(
                target_path,
                password,
                selected_only=selected_only,
                include_fields=include_fields,
            )
        self._show_error("Экспорт хранилища", "Поддерживаются зашифрованный JSON, JSON с публичным ключом и зашифрованный JSON Bitwarden.")
        return False

    def show_import_dialog(self):
        if not self._reauthenticate_for_sensitive_action("Импорт хранилища"):
            return False
        if not self._can_use_themed_dialogs():
            return self._show_import_dialog_fallback()

        result = {"value": False}
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Импорт хранилища")
        dialog.geometry(self._get_screen_limited_geometry(1040, 760))
        if hasattr(dialog, "minsize"):
            dialog.minsize(940, 680)
        dialog.transient(self.root)
        dialog.grab_set()

        body = self._create_scrollable_dialog_body(dialog)
        content = ttk.Frame(body, style="App.TFrame", padding=16)
        content.pack(fill=tk.BOTH, expand=True)
        ttk.Label(content, text="Импорт хранилища", style="DialogTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(
            content,
            text="Выберите файл, проверьте автоопределение и предпросмотр. По умолчанию импорт не применяется, пока вы явно не выберете режим.",
            style="Muted.TLabel",
            wraplength=920,
        ).pack(anchor=tk.W, pady=(6, 14))

        top = ttk.Frame(content, style="App.TFrame")
        top.pack(fill=tk.X, pady=(0, 12))
        source_var = tk.StringVar()
        format_labels = {
            "auto": "Авто",
            "encrypted_json": "Зашифрованный JSON",
            "share_package": "Пакет доступа CryptoSafe",
            "csv": "CSV",
            "lastpass_csv": "LastPass CSV",
            "bitwarden_json": "Bitwarden JSON",
            "bitwarden_encrypted_json": "Зашифрованный Bitwarden JSON",
        }
        format_label_to_key = {label: key for key, label in format_labels.items()}
        mode_labels = {
            "dry-run": "Только предпросмотр",
            "merge": "Добавить/обновить",
            "replace": "Заменить",
        }
        mode_label_to_key = {label: key for key, label in mode_labels.items()}
        duplicate_labels = {
            "skip": "Пропускать",
            "replace": "Заменять",
        }
        duplicate_label_to_key = {label: key for key, label in duplicate_labels.items()}
        format_var = tk.StringVar(value=format_labels["auto"])
        mode_var = tk.StringVar(value=mode_labels["dry-run"])
        duplicate_var = tk.StringVar(value=duplicate_labels["skip"])
        password_var = tk.StringVar()
        detected_var = tk.StringVar(value="Формат ещё не определён")

        ttk.Label(top, text="Файл", style="TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        source_entry = ttk.Entry(top, textvariable=source_var)
        source_entry.grid(row=0, column=1, sticky="we", pady=4)
        top.grid_columnconfigure(1, weight=1)

        def browse_file():
            path = self._ask_open_filename(
                title="Импорт хранилища",
                filetypes=[("Поддерживаемые файлы", "*.json *.csv"), ("Все файлы", "*.*")],
                parent=dialog,
            )
            if path:
                source_var.set(path)
                refresh_detected_format()
                refresh_preview()

        ttk.Button(top, text="Выбрать...", style="Ghost.TButton", command=browse_file).grid(row=0, column=2, padx=(8, 0), pady=4)

        ttk.Label(top, text="Формат", style="TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(
            top,
            textvariable=format_var,
            state="readonly",
            values=list(format_labels.values()),
            width=24,
        ).grid(row=1, column=1, sticky="w", pady=4)
        ttk.Label(top, textvariable=detected_var, style="Muted.TLabel").grid(row=1, column=2, sticky="w", padx=(8, 0), pady=4)

        ttk.Label(top, text="Режим", style="TLabel").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Combobox(
            top,
            textvariable=mode_var,
            state="readonly",
            values=list(mode_labels.values()),
            width=24,
        ).grid(row=2, column=1, sticky="w", pady=4)

        ttk.Label(top, text="Дубликаты", style="TLabel").grid(row=2, column=2, sticky="w", padx=(8, 8), pady=4)
        ttk.Combobox(
            top,
            textvariable=duplicate_var,
            state="readonly",
            values=list(duplicate_labels.values()),
            width=14,
        ).grid(row=2, column=3, sticky="w", pady=4)

        ttk.Label(top, text="Пароль", style="TLabel").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        password_entry = ttk.Entry(top, textvariable=password_var, show="*")
        password_entry.grid(row=3, column=1, sticky="we", pady=4)

        preview_text = self._style_text_widget(tk.Text(content, wrap=tk.WORD, height=18))
        preview_text.pack(fill=tk.BOTH, expand=True, pady=(6, 12))

        def selected_format() -> str:
            chosen = format_label_to_key.get(format_var.get(), str(format_var.get() or "auto").strip().lower())
            if chosen != "auto":
                return chosen
            path = source_var.get().strip()
            if not path:
                return "auto"
            with open(path, "rb") as handle:
                return self.detect_vault_import_format(path, handle.read())

        def refresh_detected_format(*_args):
            path = source_var.get().strip()
            if not path:
                detected_var.set("Формат ещё не определён")
                return
            try:
                with open(path, "rb") as handle:
                    detected = self.detect_vault_import_format(path, handle.read())
                detected_var.set(f"Автоопределение: {format_labels.get(detected, detected)}")
            except Exception as error:
                detected_var.set(f"Автоопределение: {error}")

        def refresh_preview(*_args):
            path = source_var.get().strip()
            lines = []
            if not path:
                lines = ["Выберите файл для предпросмотра."]
            elif not os.path.exists(path):
                lines = ["Файл не найден."]
            else:
                try:
                    fmt = selected_format()
                    if fmt == "share_package" and not password_var.get():
                        with open(path, "rb") as handle:
                            method = self._get_share_package_encryption_method(handle.read())
                        if method == "password":
                            lines = ["Определён пакет доступа CryptoSafe. Введите пароль пакета, чтобы показать предпросмотр."]
                        else:
                            lines = ["Определён пакет доступа CryptoSafe. Введите приватный ключ, чтобы показать предпросмотр."]
                    elif fmt in {"encrypted_json", "json"} and not password_var.get():
                        lines = ["Определён зашифрованный JSON. Введите пароль, чтобы показать предпросмотр."]
                    elif fmt == "bitwarden_encrypted_json" and not password_var.get():
                        lines = ["Определён зашифрованный Bitwarden JSON. Введите пароль экспорта, чтобы показать предпросмотр."]
                    else:
                        preview = self.preview_vault_import_file(
                            path,
                            import_format=fmt,
                            password=password_var.get(),
                        )
                        lines = [
                            f"Формат: {format_labels.get(preview['format'], preview['format'])}",
                            f"Режим: {mode_var.get()}",
                            f"Дубликаты: {duplicate_var.get()}",
                            f"Проверено записей: {preview['validated']}",
                            "",
                            "Первые записи:",
                            *[f"- {title}" for title in preview["titles"]],
                        ]
                except Exception as error:
                    lines = [f"Предпросмотр недоступен: {error}"]
            preview_text.config(state=tk.NORMAL)
            preview_text.delete("1.0", tk.END)
            preview_text.insert("1.0", "\n".join(lines))
            preview_text.config(state=tk.DISABLED)

        def apply_import():
            path = source_var.get().strip()
            if not path:
                self._show_warning("Импорт хранилища", "Выберите файл импорта.", parent=dialog)
                return
            try:
                fmt = selected_format()
                result["value"] = self.import_vault_file(
                    path,
                    import_format=fmt,
                    password=password_var.get(),
                    mode=mode_label_to_key.get(mode_var.get(), mode_var.get()),
                    duplicate_strategy=duplicate_label_to_key.get(duplicate_var.get(), duplicate_var.get()),
                )
            except Exception as error:
                self._show_error("Импорт хранилища", str(error), parent=dialog)
                return
            dialog.destroy()

        button_bar = ttk.Frame(dialog, style="App.TFrame")
        button_bar.pack(fill=tk.X, padx=16, pady=(0, 16))
        ttk.Button(button_bar, text="Предпросмотр", style="Ghost.TButton", command=refresh_preview).pack(side=tk.LEFT)
        ttk.Button(button_bar, text="Отмена", style="Ghost.TButton", command=dialog.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(button_bar, text="Импортировать", style="Accent.TButton", command=apply_import).pack(side=tk.RIGHT)

        for variable in (source_var, format_var, mode_var, duplicate_var, password_var):
            variable.trace_add("write", refresh_preview)
        source_var.trace_add("write", refresh_detected_format)
        refresh_preview()
        dialog.wait_window()
        return result["value"]

    def _show_import_dialog_fallback(self):
        import_format = self._ask_string(
            "Импорт хранилища",
            "Формат: auto, encrypted_json, share_package, csv, lastpass_csv или bitwarden_json",
            initialvalue="auto",
        )
        if not import_format:
            return False
        source_path = self._ask_open_filename(
            title="Импорт хранилища",
            filetypes=[("Поддерживаемые файлы", "*.json *.csv"), ("Все файлы", "*.*")],
        )
        if not source_path:
            return False
        mode = "merge" if self._ask_yes_no("Импорт хранилища", "Применить импорт сейчас? Нет = только предпросмотр.") else "dry-run"
        password = ""
        if str(import_format).strip().lower() in {"encrypted_json", "json", "share_package", "auto"}:
            password = self._ask_string("Секрет импорта", "Введите пароль файла экспорта, пароль пакета доступа или приватный ключ, если он нужен:", show="*") or ""
        try:
            return self.import_vault_file(source_path, import_format=import_format, password=password, mode=mode)
        except ImportExportError as error:
            self._show_error("Импорт хранилища", str(error))
            return False

    def show_share_dialog(self):
        if not self._reauthenticate_for_sensitive_action("Поделиться записью"):
            return False
        entry = self._get_single_selected_entry("Поделиться записью")
        if not entry:
            return False
        if not self._can_use_themed_dialogs():
            return self._show_share_dialog_fallback(entry)

        result = {"value": False}
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Поделиться записью")
        dialog.geometry(self._get_screen_limited_geometry(980, 720))
        if hasattr(dialog, "minsize"):
            dialog.minsize(880, 640)
        dialog.transient(self.root)
        dialog.grab_set()

        body = self._create_scrollable_dialog_body(dialog)
        content = ttk.Frame(body, style="App.TFrame", padding=16)
        content.pack(fill=tk.BOTH, expand=True)
        ttk.Label(content, text="Поделиться записью", style="DialogTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(
            content,
            text=f"Запись: {entry.get('title', '')}. Настройте получателя, права, срок и способ передачи.",
            style="Muted.TLabel",
            wraplength=880,
        ).pack(anchor=tk.W, pady=(6, 14))

        left = ttk.Frame(content, style="App.TFrame")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 12))
        right = ttk.Frame(content, style="App.TFrame")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        method_labels = {
            "password": "Пароль",
            "public_key": "Публичный ключ",
        }
        method_label_to_key = {label: key for key, label in method_labels.items()}
        delivery_labels = {
            "file": "Файл",
            "qr": "QR",
        }
        delivery_label_to_key = {label: key for key, label in delivery_labels.items()}
        recipient_var = tk.StringVar()
        method_var = tk.StringVar(value=method_labels["password"])
        delivery_var = tk.StringVar(value=delivery_labels["file"])
        expiration_var = tk.IntVar(value=7)
        read_var = tk.BooleanVar(value=True)
        edit_var = tk.BooleanVar(value=False)
        password_var = tk.StringVar()
        public_key_var = tk.StringVar()

        ttk.Label(left, text="Получатель", style="DialogHeader.TLabel").pack(anchor=tk.W, pady=(0, 6))
        ttk.Entry(left, textvariable=recipient_var).pack(fill=tk.X, pady=(0, 10))
        ttk.Label(left, text="Метод шифрования", style="TLabel").pack(anchor=tk.W)
        ttk.Combobox(left, textvariable=method_var, state="readonly", values=list(method_labels.values()), width=24).pack(anchor=tk.W, pady=(2, 10))
        ttk.Label(left, text="Доставка", style="TLabel").pack(anchor=tk.W)
        ttk.Combobox(left, textvariable=delivery_var, state="readonly", values=list(delivery_labels.values()), width=24).pack(anchor=tk.W, pady=(2, 10))
        ttk.Label(left, text="Срок действия, дней (1-30)", style="TLabel").pack(anchor=tk.W)
        ttk.Spinbox(left, from_=1, to=30, textvariable=expiration_var, width=8).pack(anchor=tk.W, pady=(2, 10))
        ttk.Checkbutton(left, text="Право на чтение", variable=read_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(left, text="Право на изменение", variable=edit_var).pack(anchor=tk.W, pady=2)

        ttk.Label(left, text="Пароль пакета доступа", style="TLabel").pack(anchor=tk.W, pady=(12, 2))
        password_entry = ttk.Entry(left, textvariable=password_var, show="*")
        password_entry.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(left, text="Публичный ключ получателя", style="TLabel").pack(anchor=tk.W, pady=(8, 2))
        public_key_entry = ttk.Entry(left, textvariable=public_key_var)
        public_key_entry.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(right, text="История отправки", style="DialogHeader.TLabel").pack(anchor=tk.W, pady=(0, 6))
        history_text = self._style_text_widget(tk.Text(right, wrap=tk.WORD, height=18))
        history_text.pack(fill=tk.BOTH, expand=True)

        def refresh_controls(*_args):
            if method_label_to_key.get(method_var.get(), method_var.get()) == "password":
                password_entry.state(["!disabled"])
                public_key_entry.state(["disabled"])
            else:
                password_entry.state(["disabled"])
                public_key_entry.state(["!disabled"])
            lines = []
            for item in self.get_share_history_status(limit=8):
                lines.append(
                    f"- {item.get('recipient_info', '')} | {item.get('encryption_method', '')} | "
                    f"{item.get('computed_status', item.get('status', ''))} | до {item.get('expires_at', '')}"
                )
            if not lines:
                lines = ["История отправки пока пустая."]
            history_text.config(state=tk.NORMAL)
            history_text.delete("1.0", tk.END)
            history_text.insert("1.0", "\n".join(lines))
            history_text.config(state=tk.DISABLED)

        def create_share():
            recipient = recipient_var.get().strip()
            if not recipient:
                self._show_warning("Поделиться записью", "Укажите получателя.", parent=dialog)
                return
            if not read_var.get() and not edit_var.get():
                self._show_warning("Поделиться записью", "Выберите хотя бы одно право доступа.", parent=dialog)
                return
            target_path = self._ask_saveas_filename(
                title="Сохранить пакет доступа",
                defaultextension=".cs-share.json",
                filetypes=[("Пакет доступа CryptoSafe", "*.json"), ("Все файлы", "*.*")],
                parent=dialog,
            )
            if not target_path:
                return
            try:
                if method_label_to_key.get(method_var.get(), method_var.get()) == "public_key":
                    public_key = public_key_var.get().strip()
                    if not public_key:
                        self._show_warning("Поделиться записью", "Вставьте публичный ключ получателя.", parent=dialog)
                        return
                    result["value"] = self.share_selected_entry_public_key_to_path(
                        target_path,
                        recipient=recipient,
                        public_key=public_key,
                        expires_in_days=expiration_var.get(),
                        read=read_var.get(),
                        edit=edit_var.get(),
                    )
                else:
                    password = password_var.get()
                    if not password:
                        self._show_warning("Поделиться записью", "Введите пароль пакета доступа.", parent=dialog)
                        return
                    result["value"] = self.share_selected_entry_to_path(
                        target_path,
                        recipient=recipient,
                        password=password,
                        expires_in_days=expiration_var.get(),
                        read=read_var.get(),
                        edit=edit_var.get(),
                    )
            except Exception as error:
                self._show_error("Поделиться записью", str(error), parent=dialog)
                return
            if result["value"]:
                if delivery_label_to_key.get(delivery_var.get(), delivery_var.get()) == "qr":
                    try:
                        with open(target_path, "r", encoding="utf-8") as handle:
                            package_payload = handle.read()
                        pngs = self.generate_share_package_qr_pngs(package_payload=package_payload, label=recipient)
                        self._show_qr_png_preview("QR пакета доступа", pngs, parent=dialog)
                        return
                    except Exception as error:
                        self._show_error("Поделиться записью", f"Package сохранён, но QR не создан: {error}", parent=dialog)
                        return
                dialog.destroy()

        for variable in (method_var, delivery_var, expiration_var, read_var, edit_var):
            variable.trace_add("write", refresh_controls)
        refresh_controls()
        button_bar = ttk.Frame(dialog, style="App.TFrame")
        button_bar.pack(fill=tk.X, padx=16, pady=(0, 16))
        ttk.Button(button_bar, text="Обновить историю", style="Ghost.TButton", command=refresh_controls).pack(side=tk.LEFT)
        ttk.Button(button_bar, text="Отмена", style="Ghost.TButton", command=dialog.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(button_bar, text="Создать пакет", style="Accent.TButton", command=create_share).pack(side=tk.RIGHT)
        dialog.wait_window()
        return result["value"]

    def _show_share_dialog_fallback(self, entry):
        recipient = self._ask_string("Поделиться записью", "Получатель:")
        if not recipient:
            return False
        method = self._ask_string("Поделиться записью", "Метод: password или public_key", initialvalue="password")
        if not method:
            return False
        target_path = self._ask_saveas_filename(
            title="Сохранить пакет доступа",
            defaultextension=".cs-share.json",
            filetypes=[("Пакет доступа CryptoSafe", "*.json"), ("Все файлы", "*.*")],
        )
        if not target_path:
            return False
        if str(method).strip().lower() == "public_key":
            public_key = self._ask_string("Публичный ключ", "Вставьте публичный RSA-ключ получателя:")
            if not public_key:
                return False
            return self.share_selected_entry_public_key_to_path(
                target_path,
                recipient=recipient,
                public_key=public_key,
                expires_in_days=7,
            )
        password = self._ask_string("Пароль пакета доступа", "Пароль для получателя:", show="*")
        if not password:
            return False
        return self.share_selected_entry_to_path(
            target_path,
            recipient=recipient,
            password=password,
            expires_in_days=7,
        )

    def _show_qr_png_preview(self, title: str, pngs: list[bytes], *, parent=None):
        if not pngs:
            self._show_warning(title, "QR не создан.", parent=parent)
            return None
        preview = tk.Toplevel(parent or self.root)
        self._prepare_dialog(preview)
        preview.title(title)
        preview.geometry(self._get_screen_limited_geometry(620, 720))
        if hasattr(preview, "minsize"):
            preview.minsize(560, 620)
        if parent is not None:
            preview.transient(parent)

        content = ttk.Frame(preview, style="App.TFrame", padding=16)
        content.pack(fill=tk.BOTH, expand=True)
        ttk.Label(content, text=title, style="DialogTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(
            content,
            text=f"Показан QR 1 из {len(pngs)}. Полный пакет доступа уже сохранён в файл.",
            style="Muted.TLabel",
            wraplength=540,
        ).pack(anchor=tk.W, pady=(6, 14))
        image = tk.PhotoImage(data=b64encode(pngs[0]).decode("ascii"))
        qr_label = ttk.Label(content, image=image, anchor="center")
        qr_label.image = image
        qr_label.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        ttk.Button(content, text="Закрыть", style="Ghost.TButton", command=preview.destroy).pack(anchor=tk.E)
        return preview

    def show_key_exchange_dialog(self):
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Обмен ключами / QR")
        dialog.geometry(self._get_screen_limited_geometry(980, 760))
        if hasattr(dialog, "minsize"):
            dialog.minsize(900, 680)
        body = self._create_scrollable_dialog_body(dialog)
        content = ttk.Frame(body, style="App.TFrame")
        content.pack(fill=tk.BOTH, expand=True, padx=14, pady=14)
        auto_refresh_var = tk.BooleanVar(value=True)
        last_bundle = {"identifier": "", "output_dir": "", "after_id": None}
        qr_preview = ttk.Label(content, text="QR появится здесь после генерации", anchor="center", style="Muted.TLabel")
        qr_preview.pack(fill=tk.X, pady=(0, 10))
        qr_status = ttk.Label(content, text="", style="Muted.TLabel")
        qr_status.pack(fill=tk.X, pady=(0, 8))
        text = self._style_text_widget(tk.Text(content, wrap=tk.WORD, height=12))
        text.pack(fill=tk.BOTH, expand=True)
        controls = ttk.Frame(dialog, style="App.TFrame")
        controls.pack(fill=tk.X, padx=14, pady=(0, 14))

        def show_qr_preview(pngs: list[bytes]):
            if not pngs:
                qr_preview.configure(text="QR не создан", image="")
                qr_preview.image = None
                qr_status.configure(text="")
                return
            image = tk.PhotoImage(data=b64encode(pngs[0]).decode("ascii"))
            qr_preview.configure(image=image, text="")
            qr_preview.image = image
            qr_status.configure(text=f"Показан QR 1 из {len(pngs)}. QR действителен 5 минут; автообновление обновит пакет обмена.")

        def cancel_auto_refresh():
            after_id = last_bundle.get("after_id")
            if after_id:
                try:
                    self.root.after_cancel(after_id)
                except Exception:
                    pass
                last_bundle["after_id"] = None

        def schedule_auto_refresh():
            cancel_auto_refresh()
            if not auto_refresh_var.get() or not last_bundle.get("identifier") or not last_bundle.get("output_dir"):
                return
            try:
                last_bundle["after_id"] = self.root.after(240000, refresh_generated_qr)
            except Exception:
                last_bundle["after_id"] = None

        def refresh_generated_qr():
            if not last_bundle.get("identifier") or not last_bundle.get("output_dir"):
                return
            try:
                bundle = self.generate_key_exchange_file_bundle(
                    identifier=last_bundle["identifier"],
                    output_dir=last_bundle["output_dir"],
                )
                show_qr_preview(bundle.get("qr_pngs", []))
                text.delete("1.0", tk.END)
                text.insert("1.0", self._format_key_exchange_bundle_summary(bundle))
            except ImportExportError as error:
                self._show_error("Обмен ключами", str(error), parent=dialog)
                return
            schedule_auto_refresh()

        def generate():
            identifier = self._ask_string("Обмен ключами", "Идентификатор контакта:", initialvalue="local-user")
            if not identifier:
                return
            output_dir = self._ask_directory(title="Куда сохранить ключи и QR?")
            if not output_dir:
                return
            try:
                bundle = self.generate_key_exchange_file_bundle(identifier=identifier, output_dir=output_dir)
                show_qr_preview(bundle.get("qr_pngs", []))
            except ImportExportError as error:
                self._show_error("Обмен ключами", str(error), parent=dialog)
                return
            last_bundle["identifier"] = identifier
            last_bundle["output_dir"] = output_dir
            text.delete("1.0", tk.END)
            text.insert("1.0", self._format_key_exchange_bundle_summary(bundle))
            schedule_auto_refresh()

        def import_payload():
            payload_text = text.get("1.0", tk.END).strip()
            contact_name = self._ask_string("Обмен ключами", "Имя контакта:", initialvalue="")
            try:
                self.import_key_exchange_payload_text(payload_text, contact_name=contact_name or "")
            except ImportExportError as error:
                self._show_error("Обмен ключами", str(error), parent=dialog)

        def scan_camera():
            try:
                payload_text = self.scan_key_exchange_payload_from_camera()
            except ImportExportError as error:
                self._show_error("QR-камера", str(error), parent=dialog)
                return
            text.delete("1.0", tk.END)
            text.insert("1.0", payload_text)
            qr_status.configure(text="Пакет обмена получен со сканера камеры. Проверьте отпечаток и импортируйте.")

        def copy_payload():
            payload_text = text.get("1.0", tk.END).strip()
            if not payload_text:
                self._show_warning("Обмен ключами", "Нет пакета обмена для копирования.", parent=dialog)
                return
            try:
                self.clipboard_service.copy_text(
                    payload_text,
                    data_type="qr_payload",
                    source_label="key-exchange",
                    application_name=self._get_clipboard_application_name(),
                )
            except ClipboardAccessError as error:
                self._show_error("Буфер обмена", str(error), parent=dialog)
                return
            self._show_info("Обмен ключами", "Пакет обмена скопирован в буфер с автоочисткой.", parent=dialog)

        def import_qr_svg():
            file_paths = self._ask_open_filenames(
                title="Импорт QR SVG",
                filetypes=[("SVG QR", "*.svg"), ("Все файлы", "*.*")],
            )
            if not file_paths:
                return
            contact_name = self._ask_string("Обмен ключами", "Имя контакта:", initialvalue="")
            try:
                service = KeyExchangeService(database=self.db, event_bus=event_bus)
                payload_text = QRCodeService(service).parse_qr_svg_files(list(file_paths))
                self.import_key_exchange_payload_text(payload_text, contact_name=contact_name or "")
            except ImportExportError as error:
                self._show_error("Обмен ключами", str(error), parent=dialog)

        dialog.protocol("WM_DELETE_WINDOW", lambda: (cancel_auto_refresh(), dialog.destroy()))
        ttk.Checkbutton(controls, text="Автообновлять QR каждые 4 минуты", variable=auto_refresh_var, command=schedule_auto_refresh).pack(side=tk.LEFT, padx=3)
        ttk.Button(controls, text="Сгенерировать пакет", style="Ghost.TButton", command=generate).pack(side=tk.LEFT, padx=3)
        ttk.Button(controls, text="Сканировать камерой", style="Ghost.TButton", command=scan_camera).pack(side=tk.LEFT, padx=3)
        ttk.Button(controls, text="Импортировать пакет", style="Ghost.TButton", command=import_payload).pack(side=tk.LEFT, padx=3)
        ttk.Button(controls, text="Импортировать QR SVG", style="Ghost.TButton", command=import_qr_svg).pack(side=tk.LEFT, padx=3)
        ttk.Button(controls, text="Копировать пакет", style="Ghost.TButton", command=copy_payload).pack(side=tk.LEFT, padx=3)
        ttk.Button(controls, text="Закрыть", style="Ghost.TButton", command=lambda: (cancel_auto_refresh(), dialog.destroy())).pack(side=tk.RIGHT, padx=3)
        return dialog

    def _format_key_exchange_bundle_summary(self, bundle: dict) -> str:
        qr_list = "\n".join(f"- {path}" for path in bundle.get("qr_paths", []))
        return (
            "Файлы обмена ключами созданы.\n\n"
            f"Отпечаток: {bundle.get('fingerprint', '')}\n"
            f"Действительно до: {bundle.get('expires_at', '')}\n\n"
            "Файл приватного ключа - храните его в секрете:\n"
            f"{bundle.get('private_key_path', '')}\n\n"
            "Публичный файл пакета обмена: его можно безопасно передать:\n"
            f"{bundle.get('payload_path', '')}\n\n"
            "Файлы QR SVG:\n"
            f"{qr_list}\n"
        )

    def _get_entry_clipboard_policy(self, entry) -> str:
        return str(entry.get("clipboard_policy", "allow") or "allow").strip().lower()

    def _get_clipboard_application_name(self) -> str:
        application_name = os.path.basename(sys.argv[0] or "").strip()
        if application_name.lower().endswith(".py"):
            return "cryptosafe-manager"
        if application_name.lower().endswith(".exe"):
            application_name = application_name[:-4]
        return application_name or "cryptosafe-manager"

    def _parse_audit_details(self, details: str) -> dict[str, str]:
        parsed_details: dict[str, str] = {}
        raw_details = str(details or "").strip()
        if raw_details.startswith("{") and raw_details.endswith("}"):
            try:
                payload = json.loads(raw_details)
                if isinstance(payload, dict):
                    for key, value in payload.items():
                        parsed_details[str(key).strip()] = str(value).strip()
                    return parsed_details
            except (TypeError, json.JSONDecodeError):
                pass
        for chunk in str(details or "").split(", "):
            if "=" not in chunk:
                continue
            key, value = chunk.split("=", 1)
            parsed_details[str(key).strip()] = str(value).strip()
        return parsed_details

    def _format_audit_action(self, action: str) -> str:
        action_labels = {
            "entry_added": "Добавление записи",
            "entry_viewed": "Просмотр записи",
            "entry_updated": "Обновление записи",
            "entry_deleted": "Удаление записи",
            "user_logged_in": "Вход в хранилище",
            "user_login_failed": "Неуспешный вход",
            "user_logged_out": "Выход из хранилища",
            "password_changed": "Смена мастер-пароля",
            "clipboard_copied": "Копирование в буфер обмена",
            "clipboard_cleared": "Очистка буфера обмена",
            "clipboard_error": "Ошибка буфера обмена",
            "vault_locked": "Блокировка хранилища",
            "vault_unlocked": "Разблокировка хранилища",
            "settings_changed": "Изменение настроек",
            "search_performed": "Поиск по хранилищу",
            "app_started": "Запуск приложения",
            "app_shutdown": "Завершение приложения",
            "audit_log_exported": "Экспорт журнала аудита",
            "audit_log_archived": "Архивирование журнала аудита",
            "audit_log_protection_triggered": "Срабатывание защиты журнала аудита",
            "audit_verification_passed": "Проверка аудита пройдена",
            "audit_verification_failed": "Проверка аудита не пройдена",
            "panic_mode_activated": "Паник-режим включён",
            "panic_mode_deactivated": "Паник-режим восстановлен",
        }
        return action_labels.get(str(action or "").strip(), str(action or ""))

    def _format_audit_details(self, action: str, details: str) -> str:
        parsed_details = self._parse_audit_details(details)
        if not parsed_details:
            return str(details or "")

        if action == "clipboard_copied":
            detail_parts = []
            if parsed_details.get("data_type"):
                detail_parts.append(f"тип={self._format_clipboard_data_type(parsed_details['data_type'])}")
            if parsed_details.get("entry_id") not in {None, "", "None"}:
                detail_parts.append(f"entry={parsed_details['entry_id']}")
            if parsed_details.get("source_label"):
                detail_parts.append(f"источник={parsed_details['source_label']}")
            if parsed_details.get("timeout_seconds"):
                detail_parts.append(f"таймаут={parsed_details['timeout_seconds']} сек")
            if parsed_details.get("delivery_mode"):
                detail_parts.append(f"режим={self._format_clipboard_delivery_mode(parsed_details['delivery_mode'])}")
            return ", ".join(detail_parts)

        if action == "clipboard_cleared":
            clear_reason = parsed_details.get("reason", "")
            detail_parts = [self._format_clipboard_clear_reason(clear_reason)]
            if parsed_details.get("monitor_reason"):
                detail_parts.append(f"деталь={parsed_details['monitor_reason']}")
            if parsed_details.get("data_type"):
                detail_parts.append(f"тип={self._format_clipboard_data_type(parsed_details['data_type'])}")
            if parsed_details.get("entry_id") not in {None, "", "None"}:
                detail_parts.append(f"entry={parsed_details['entry_id']}")
            if parsed_details.get("observed_length"):
                detail_parts.append(f"наблюдаемая длина={parsed_details['observed_length']}")
            return " | ".join(part for part in detail_parts if part)

        if action == "clipboard_error":
            operation_map = {
                "copy": "операция копирования",
                "clear": "операция очистки",
                "monitor_poll": "проверка мониторинга",
            }
            error_map = {
                "empty_value": "пустое значение",
                "invalid_content": "недопустимое содержимое",
                "value_too_large": "превышен безопасный лимит данных",
                "blocked_on_suspicious": "копирование заблокировано защитой",
                "entry_copy_disabled": "копирование запрещено политикой записи",
                "application_not_allowed": "приложение не входит в список разрешённых",
                "vault_locked": "хранилище заблокировано",
                "adapter_write_failed": "сбой записи через системный адаптер",
                "adapter_clear_failed": "сбой системной очистки буфера обмена",
                "monitor_unavailable": "мониторинг буфера обмена недоступен",
            }
            detail_parts = []
            if parsed_details.get("operation"):
                detail_parts.append(operation_map.get(parsed_details["operation"], parsed_details["operation"]))
            if parsed_details.get("error_code"):
                detail_parts.append(error_map.get(parsed_details["error_code"], parsed_details["error_code"]))
            if parsed_details.get("data_type"):
                detail_parts.append(f"тип={self._format_clipboard_data_type(parsed_details['data_type'])}")
            if parsed_details.get("clear_reason"):
                detail_parts.append(self._format_clipboard_clear_reason(parsed_details["clear_reason"]))
            if parsed_details.get("entry_id") not in {None, "", "None"}:
                detail_parts.append(f"entry={parsed_details['entry_id']}")
            if parsed_details.get("application_name"):
                detail_parts.append(f"приложение={parsed_details['application_name']}")
            return " | ".join(detail_parts)

        if action == "settings_changed":
            detail_parts = []
            if parsed_details.get("scope"):
                detail_parts.append(f"область={parsed_details['scope']}")
            if parsed_details.get("changed_keys"):
                detail_parts.append(f"изменения={parsed_details['changed_keys']}")
            return " | ".join(detail_parts)

        if action == "search_performed":
            detail_parts = []
            if parsed_details.get("query_length"):
                detail_parts.append(f"длина запроса={parsed_details['query_length']}")
            if parsed_details.get("category"):
                detail_parts.append(f"категория={parsed_details['category']}")
            if parsed_details.get("tag"):
                detail_parts.append(f"тег={parsed_details['tag']}")
            if parsed_details.get("result_count"):
                detail_parts.append(f"результатов={parsed_details['result_count']}")
            return " | ".join(detail_parts)

        if action in {"audit_verification_passed", "audit_verification_failed"}:
            detail_parts = []
            if parsed_details.get("total_entries"):
                detail_parts.append(f"всего={parsed_details['total_entries']}")
            if parsed_details.get("valid_entries"):
                detail_parts.append(f"валидных={parsed_details['valid_entries']}")
            if parsed_details.get("invalid_entries"):
                detail_parts.append(f"ошибок={parsed_details['invalid_entries']}")
            if parsed_details.get("chain_breaks"):
                detail_parts.append(f"разрывов цепочки={parsed_details['chain_breaks']}")
            return " | ".join(detail_parts)

        if action == "audit_log_exported":
            detail_parts = []
            if parsed_details.get("format"):
                detail_parts.append(f"формат={parsed_details['format']}")
            if parsed_details.get("record_count"):
                detail_parts.append(f"записей={parsed_details['record_count']}")
            if parsed_details.get("path"):
                detail_parts.append(f"путь={parsed_details['path']}")
            return " | ".join(detail_parts)

        if action == "audit_log_archived":
            detail_parts = []
            if parsed_details.get("entry_count"):
                detail_parts.append(f"архивировано={parsed_details['entry_count']}")
            if parsed_details.get("range_start_sequence") and parsed_details.get("range_end_sequence"):
                detail_parts.append(
                    f"диапазон={parsed_details['range_start_sequence']}-{parsed_details['range_end_sequence']}"
                )
            if parsed_details.get("reason"):
                detail_parts.append(f"причина={parsed_details['reason']}")
            return " | ".join(detail_parts)

        if action == "audit_log_protection_triggered":
            detail_parts = []
            if parsed_details.get("operation"):
                detail_parts.append(f"операция={parsed_details['operation']}")
            if parsed_details.get("sequence_number"):
                detail_parts.append(f"sequence={parsed_details['sequence_number']}")
            if parsed_details.get("message"):
                detail_parts.append(str(parsed_details["message"]))
            return " | ".join(detail_parts)

        return str(details or "")

    def _format_audit_log_line(self, log) -> str:
        timestamp = self._format_audit_timestamp(getattr(log, "timestamp", None))
        action_text = self._format_audit_action(log.action)
        details_text = self._format_audit_details(log.action, log.details)
        entry_text = f"entry={log.entry_id}" if log.entry_id is not None else "entry=-"
        if details_text:
            return f"{timestamp} | {action_text} | {entry_text} | {details_text}"
        return f"{timestamp} | {action_text} | {entry_text}"

    def _format_audit_timestamp(self, timestamp) -> str:
        if timestamp is None:
            return ""
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                return timestamp
        if getattr(timestamp, "tzinfo", None) is not None:
            timestamp = timestamp.astimezone()
        return timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def _build_audit_log_view_model(
        self,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: str = "",
        date_to: str = "",
        page: int = 1,
        page_size: Optional[int] = None,
    ) -> dict:
        normalized_page_size = max(1, int(page_size or self.AUDIT_PAGE_SIZE))
        normalized_page = max(1, int(page or 1))
        offset = (normalized_page - 1) * normalized_page_size
        logs = self.db.query_audit_logs(
            search_text=search_text,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            date_from=date_from,
            date_to=date_to,
            limit=normalized_page_size,
            offset=offset,
        )
        total_count = self.db.count_audit_logs(
            search_text=search_text,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            date_from=date_from,
            date_to=date_to,
        )
        total_pages = max(1, (total_count + normalized_page_size - 1) // normalized_page_size)
        current_page = min(normalized_page, total_pages)
        if current_page != normalized_page:
            return self._build_audit_log_view_model(
                search_text=search_text,
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                date_from=date_from,
                date_to=date_to,
                page=current_page,
                page_size=normalized_page_size,
            )
        return {
            "logs": logs,
            "page": current_page,
            "page_size": normalized_page_size,
            "total_count": total_count,
            "total_pages": total_pages,
        }

    def _get_audit_log_sort_value(self, log, sort_column: str):
        if sort_column == "sequence_number":
            return int(getattr(log, "sequence_number", 0) or 0)
        if sort_column == "timestamp":
            return getattr(log, "timestamp", datetime.min)
        if sort_column == "entry_id":
            return int(getattr(log, "entry_id", -1) if getattr(log, "entry_id", None) is not None else -1)
        if sort_column == "severity":
            severity_order = {"INFO": 0, "WARN": 1, "ERROR": 2, "CRITICAL": 3}
            return severity_order.get(str(getattr(log, "severity", "INFO")).upper(), 0)
        if sort_column == "event_type":
            return str(getattr(log, "event_type", getattr(log, "action", "")) or "")
        if sort_column == "source":
            return str(getattr(log, "source", "") or "")
        if sort_column == "user_id":
            return str(getattr(log, "user_id", "") or "")
        return str(getattr(log, sort_column, "") or "")

    def _sort_audit_logs(self, logs: list, sort_column: str, descending: bool = False) -> list:
        return sorted(
            list(logs),
            key=lambda log: self._get_audit_log_sort_value(log, sort_column),
            reverse=bool(descending),
        )

    def _build_audit_tree_rows(self, logs: list) -> list[tuple]:
        rows = []
        for log in logs:
            rows.append(
                (
                    str(getattr(log, "sequence_number", getattr(log, "id", ""))),
                    (
                        getattr(log, "sequence_number", getattr(log, "id", "")),
                        self._format_audit_timestamp(getattr(log, "timestamp", None)),
                        self._format_audit_action(log.action),
                        getattr(log, "severity", "INFO"),
                        getattr(log, "source", "unknown"),
                        getattr(log, "user_id", "local-user"),
                        getattr(log, "entry_id", "-"),
                    ),
                )
            )
        return rows

    def _build_audit_event_frequency(self, logs: list, limit: int = 8) -> list[dict]:
        counter = Counter()
        for log in logs:
            event_type = str(getattr(log, "event_type", getattr(log, "action", "")) or "unknown")
            counter[event_type] += 1
        ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        return [
            {
                "event_type": event_type,
                "count": count,
                "label": self._format_audit_action(event_type),
            }
            for event_type, count in ordered[: max(1, int(limit))]
        ]

    def _filter_audit_logs_by_days(self, logs: list, days: int, *, now: Optional[datetime] = None) -> list:
        reference = now or datetime.now()
        cutoff = reference - timedelta(days=max(1, int(days)))
        filtered_logs = []
        for log in logs:
            timestamp = getattr(log, "timestamp", None)
            if timestamp is None:
                continue
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    continue
            if getattr(timestamp, "tzinfo", None) is not None and getattr(reference, "tzinfo", None) is None:
                timestamp = timestamp.replace(tzinfo=None)
            if timestamp >= cutoff:
                filtered_logs.append(log)
        return filtered_logs

    def _build_audit_dashboard_lines(self, logs: list, *, total_count: int) -> list[str]:
        integrity_status = getattr(self, "_audit_integrity_status", {}) or {}
        verified = bool(integrity_status.get("verified", False))
        invalid_entries = len(integrity_status.get("invalid_entries", []))
        chain_breaks = len(integrity_status.get("chain_breaks", []))
        critical_count = sum(1 for log in logs if str(getattr(log, "severity", "")).upper() == "CRITICAL")
        warn_count = sum(1 for log in logs if str(getattr(log, "severity", "")).upper() == "WARN")
        unique_users = len({str(getattr(log, "user_id", "local-user")) for log in logs})

        archive_count = 0
        if hasattr(self, "db") and hasattr(self.db, "get_audit_archives"):
            try:
                archive_count = len(self.db.get_audit_archives(limit=100))
            except Exception:
                archive_count = 0

        security_event_count = 0
        if hasattr(self, "db") and hasattr(self.db, "get_audit_security_events"):
            try:
                security_event_count = len(self.db.get_audit_security_events(limit=100))
            except Exception:
                security_event_count = 0

        lines = [
            "Сводка журнала аудита",
            f"Записей в текущем представлении: {len(logs)} из {total_count}",
            f"Статус целостности: {'валиден' if verified else 'требует внимания'}",
            f"Ошибок проверки: {invalid_entries}, разрывов цепочки: {chain_breaks}",
            f"Критических событий: {critical_count}, предупреждений: {warn_count}",
            f"Уникальных пользователей: {unique_users}",
            f"Архивов журнала: {archive_count}, security events: {security_event_count}",
        ]
        for days in (7, 30, 90):
            window_logs = self._filter_audit_logs_by_days(logs, days)
            window_frequency = self._build_audit_event_frequency(window_logs, limit=3)
            top_window = ", ".join(f"{item['label']}: {item['count']}" for item in window_frequency) or "нет событий"
            lines.append(f"Частота событий за {days} дней: {top_window}")
        top_events = self._build_audit_event_frequency(logs, limit=3)
        if top_events:
            lines.append("Топ событий:")
            for item in top_events:
                lines.append(f"- {item['label']}: {item['count']}")
        return lines

    def _render_audit_frequency_chart(self, canvas, logs: list):
        if canvas is None:
            return
        if hasattr(canvas, "delete"):
            canvas.delete("all")
        chart_logs = self._filter_audit_logs_by_days(logs, 30) or logs
        frequency = self._build_audit_event_frequency(chart_logs, limit=6)
        if not frequency or not hasattr(canvas, "create_rectangle"):
            return

        chart_width = int(canvas.cget("width")) if hasattr(canvas, "cget") else 520
        bar_height = 20
        gap = 10
        label_width = min(320, max(220, chart_width // 3))
        left = label_width + 12
        top = 12
        usable_width = max(80, chart_width - left - 52)
        max_count = max(item["count"] for item in frequency) or 1

        for index, item in enumerate(frequency):
            y1 = top + index * (bar_height + gap)
            y2 = y1 + bar_height
            width = int((item["count"] / max_count) * usable_width)
            if hasattr(canvas, "create_text"):
                canvas.create_text(
                    8,
                    y1 + bar_height / 2,
                    anchor="w",
                    text=item["label"][:32],
                    fill=self.UI_COLORS["muted"],
                )
            canvas.create_rectangle(left, y1, left + width, y2, fill=self.UI_COLORS["accent"], outline="")
            if hasattr(canvas, "create_text"):
                count_x = min(left + width + 8, chart_width - 32)
                canvas.create_text(count_x, y1 + bar_height / 2, anchor="w", text=str(item["count"]), fill=self.UI_COLORS["ink"])

    def _build_audit_log_detail_lines(self, log) -> list[str]:
        parsed_details = self._parse_audit_details(getattr(log, "details", ""))
        details_payload = str(getattr(log, "entry_data", "") or "")
        verification_status = "не проверено"
        if hasattr(self, "audit_logger") and hasattr(self.audit_logger, "signer"):
            if getattr(log, "signature", "") and getattr(log, "public_key", ""):
                try:
                    is_valid = self.audit_logger.signer.verify(
                        details_payload.encode("utf-8"),
                        getattr(log, "signature", ""),
                        getattr(log, "public_key", ""),
                    )
                    verification_status = "валидна" if is_valid else "невалидна"
                except Exception:
                    verification_status = "ошибка проверки"

        lines = [
            f"Последовательность: {getattr(log, 'sequence_number', '-')}",
            f"Время: {self._format_audit_timestamp(getattr(log, 'timestamp', None))}",
            f"Событие: {getattr(log, 'event_type', getattr(log, 'action', ''))}",
            f"Серьёзность: {getattr(log, 'severity', 'INFO')}",
            f"Пользователь: {getattr(log, 'user_id', 'local-user')}",
            f"Источник: {getattr(log, 'source', 'unknown')}",
            f"ID записи: {getattr(log, 'entry_id', '-')}",
            f"Статус подписи: {verification_status}",
            f"Предыдущий хэш: {getattr(log, 'previous_hash', '')}",
            f"Текущий хэш: {getattr(log, 'entry_hash', '')}",
            "",
            "Структурированные детали:",
        ]
        if getattr(log, "event_type", getattr(log, "action", "")) == "user_login_failed":
            lines.insert(10, f"IP: {parsed_details.get('ip', 'не указано')}")
            lines.insert(11, f"Время неуспешной попытки: {self._format_audit_timestamp(getattr(log, 'timestamp', None))}")
        if parsed_details:
            for key, value in parsed_details.items():
                lines.append(f"- {key}: {value}")
        else:
            lines.append(str(getattr(log, "details", "") or "{}"))
        if details_payload:
            try:
                formatted_payload = json.dumps(json.loads(details_payload), ensure_ascii=False, indent=2, sort_keys=True)
            except (TypeError, json.JSONDecodeError):
                formatted_payload = details_payload
            lines.extend(["", "Подписанный JSON:", formatted_payload])
        return lines

    def _highlight_vault_entry_from_audit_log(self, log) -> bool:
        entry_id = getattr(log, "entry_id", None)
        if entry_id is None or not hasattr(self, "table"):
            return False
        table_rows = getattr(self.table, "data", [])
        tree = getattr(self.table, "tree", None)
        for index, row in enumerate(table_rows):
            if str(row.get("id")) != str(entry_id):
                continue
            if tree is not None:
                item_id = str(index)
                if hasattr(tree, "selection_set"):
                    tree.selection_set(item_id)
                if hasattr(tree, "focus"):
                    tree.focus(item_id)
                if hasattr(tree, "see"):
                    tree.see(item_id)
            if hasattr(self, "_set_status"):
                self._set_status(f"Выбрана связанная запись хранилища: #{entry_id}")
            return True
        return False

    def _build_failed_login_investigation_text(self, log) -> str:
        parsed_details = self._parse_audit_details(getattr(log, "details", ""))
        timestamp = self._format_audit_timestamp(getattr(log, "timestamp", None))
        return (
            "Неуспешный вход\n"
            f"Время: {timestamp}\n"
            f"IP: {parsed_details.get('ip', 'не указано')}\n"
            f"Детали: {parsed_details or '{}'}"
        )

    def _get_audit_log_context_actions(self, log) -> list[dict]:
        actions = []
        event_type = getattr(log, "event_type", getattr(log, "action", ""))
        if event_type.startswith("entry_") and getattr(log, "entry_id", None) is not None:
            actions.append({"id": "show_vault_entry", "label": "Показать связанную запись"})
        if event_type == "user_login_failed":
            actions.append({"id": "inspect_failed_login", "label": "Исследовать неуспешный вход"})
        return actions

    def _apply_audit_log_context_action(self, log, action_id: str):
        if action_id == "show_vault_entry":
            if not self._highlight_vault_entry_from_audit_log(log):
                self._show_info(
                    "Журнал аудита",
                    "Связанная запись хранилища не найдена в текущем списке.",
                )
            return
        if action_id == "inspect_failed_login":
            self._show_info(
                "Неуспешный вход",
                self._build_failed_login_investigation_text(log),
            )

    def _get_audit_logs_for_export(
        self,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: str = "",
        date_to: str = "",
    ) -> list:
        total_count = self.db.count_audit_logs(
            search_text=search_text,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            date_from=date_from,
            date_to=date_to,
        )
        return self.db.query_audit_logs(
            search_text=search_text,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            date_from=date_from,
            date_to=date_to,
            limit=max(1, total_count),
            offset=0,
        )

    def _build_audit_export_payload(self, logs, export_format: str):
        public_key = ""
        if hasattr(self, "audit_logger") and hasattr(self.audit_logger, "signer"):
            try:
                public_key = self.audit_logger.signer.public_key_hex
            except Exception:
                public_key = ""

        normalized_format = str(export_format or "").strip().lower()
        if normalized_format == "json":
            return export_logs_to_json(logs, public_key=public_key)
        if normalized_format == "csv":
            return export_logs_to_csv(logs)
        if normalized_format == "cef":
            return export_logs_to_cef(logs)
        if normalized_format == "pdf":
            return export_logs_to_pdf(logs)
        raise ValueError(f"Unsupported audit export format: {export_format}")

    def _audit_export_contains_sensitive_data(self, logs) -> bool:
        for log in logs:
            event_type = str(getattr(log, "event_type", getattr(log, "action", "")) or "")
            details_text = str(getattr(log, "details", "") or "")
            if getattr(log, "entry_id", None) is not None:
                return True
            if event_type.startswith("entry_") or event_type.startswith("clipboard_"):
                return True
            if details_text and details_text != "{}":
                return True
        return False

    def _encrypt_audit_export_payload(self, payload, export_format: str):
        active_key = self.auth_service.get_active_key() if hasattr(self, "auth_service") else None
        if not active_key:
            raise AuthenticationError("Активный ключ недоступен для шифрования экспорта аудита")
        return encrypt_export_package(
            payload,
            export_format=export_format,
            encryption_service=self.vault_crypto,
            key=active_key,
        )

    def _decrypt_audit_export_payload(self, package_payload):
        active_key = self.auth_service.get_active_key() if hasattr(self, "auth_service") else None
        if not active_key:
            raise AuthenticationError("Активный ключ недоступен для расшифровки экспорта аудита")
        return decrypt_export_package(
            package_payload,
            encryption_service=self.vault_crypto,
            key=active_key,
        )

    def _get_audit_export_schedule_policy(self) -> dict:
        default_directory = os.path.join(os.path.expanduser("~"), ".cryptosafe", "scheduled-audit-exports")
        default_policy = {
            "enabled": False,
            "interval_seconds": 24 * 60 * 60,
            "formats": ["json"],
            "export_directory": default_directory,
            "max_age_days": 30,
            "max_files": 20,
            "include_verification_report": True,
            "last_run_at": "",
        }
        if not hasattr(self, "db") or not hasattr(self.db, "get_setting"):
            return dict(default_policy)
        stored_policy = self.db.get_setting("audit.export_schedule_policy", default_policy)
        if not isinstance(stored_policy, dict):
            return dict(default_policy)
        normalized = dict(default_policy)
        normalized.update(stored_policy)
        normalized["enabled"] = bool(normalized.get("enabled", False))
        normalized["interval_seconds"] = max(300, int(normalized.get("interval_seconds", default_policy["interval_seconds"]) or default_policy["interval_seconds"]))
        raw_formats = normalized.get("formats", ["json"])
        if not isinstance(raw_formats, list):
            raw_formats = ["json"]
        normalized_formats = [str(item).strip().lower() for item in raw_formats if str(item).strip().lower() in {"json", "csv", "cef", "pdf"}]
        normalized["formats"] = normalized_formats or ["json"]
        normalized["export_directory"] = str(normalized.get("export_directory", default_directory) or default_directory)
        raw_max_age_days = normalized.get("max_age_days", default_policy["max_age_days"])
        raw_max_files = normalized.get("max_files", default_policy["max_files"])
        normalized["max_age_days"] = max(1, int(default_policy["max_age_days"] if raw_max_age_days is None else raw_max_age_days))
        normalized["max_files"] = max(1, int(default_policy["max_files"] if raw_max_files is None else raw_max_files))
        normalized["include_verification_report"] = bool(normalized.get("include_verification_report", True))
        normalized["last_run_at"] = str(normalized.get("last_run_at", "") or "")
        return normalized

    def _save_audit_export_schedule_policy(self, policy: dict):
        if not hasattr(self, "db") or not hasattr(self.db, "set_setting"):
            return
        self.db.set_setting("audit.export_schedule_policy", dict(policy))

    def _build_scheduled_audit_export_path(self, export_directory: str, export_format: str, exported_at: datetime) -> str:
        extension_map = {"json": ".json", "csv": ".csv", "cef": ".cef", "pdf": ".pdf"}
        timestamp = exported_at.strftime("%Y%m%d-%H%M%S")
        filename = f"audit-log-{timestamp}{extension_map.get(export_format, '.txt')}"
        return os.path.join(export_directory, filename)

    def _write_audit_export_file(self, target_path: str, output_payload):
        target_directory = os.path.dirname(target_path)
        if target_directory:
            os.makedirs(target_directory, exist_ok=True)
        if isinstance(output_payload, bytes):
            with open(target_path, "wb") as handle:
                handle.write(output_payload)
        else:
            with open(target_path, "w", encoding="utf-8", newline="") as handle:
                handle.write(output_payload)

    def _cleanup_scheduled_audit_exports(self, export_directory: str, *, max_age_days: int, max_files: int):
        if not os.path.isdir(export_directory):
            return
        now = datetime.now()
        threshold = now.timestamp() - max(1, int(max_age_days)) * 24 * 60 * 60
        export_files = []
        for file_name in os.listdir(export_directory):
            if not file_name.startswith("audit-") and not file_name.startswith("verification-report-"):
                continue
            full_path = os.path.join(export_directory, file_name)
            if not os.path.isfile(full_path):
                continue
            try:
                modified_at = os.path.getmtime(full_path)
            except OSError:
                continue
            export_files.append((full_path, modified_at))

        for full_path, modified_at in export_files:
            if modified_at < threshold:
                try:
                    os.remove(full_path)
                except OSError:
                    pass

        remaining_files = []
        for full_path, modified_at in export_files:
            if os.path.exists(full_path):
                remaining_files.append((full_path, modified_at))
        remaining_files.sort(key=lambda item: item[1], reverse=True)
        for full_path, _modified_at in remaining_files[max(1, int(max_files)) :]:
            try:
                os.remove(full_path)
            except OSError:
                pass

    def _export_audit_logs_to_path(
        self,
        target_path: str,
        export_format: str,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: str = "",
        date_to: str = "",
        scheduled: bool = False,
    ) -> bool:
        logs = self._get_audit_logs_for_export(
            search_text=search_text,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            date_from=date_from,
            date_to=date_to,
        )
        if not logs:
            if not scheduled:
                self._show_info("Экспорт аудита", "Для выбранных фильтров журнал аудита пуст.")
            return False

        normalized_format = str(export_format or "").strip().lower()
        payload = self._build_audit_export_payload(logs, normalized_format)
        export_encrypted = self._audit_export_contains_sensitive_data(logs)
        output_payload = self._encrypt_audit_export_payload(payload, normalized_format) if export_encrypted else payload
        self._write_audit_export_file(target_path, output_payload)

        event_bus.publish(
            Event(
                EventType.AUDIT_LOG_EXPORTED,
                {
                    "format": normalized_format,
                    "record_count": len(logs),
                    "path": os.path.basename(target_path),
                    "date_from": date_from,
                    "date_to": date_to,
                    "encrypted": export_encrypted,
                    "scheduled": scheduled,
                },
            )
        )
        if not scheduled:
            self._show_info(
                "Экспорт аудита",
                (
                    f"Журнал аудита экспортирован в формате {normalized_format.upper()} "
                    f"и {'зашифрован' if export_encrypted else 'сохранён без шифрования'}."
                ),
            )
        return True

    def export_audit_logs(
        self,
        export_format: str,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: str = "",
        date_to: str = "",
    ) -> bool:
        if not self._reauthenticate_for_sensitive_action("Экспорт журнала аудита"):
            return False

        normalized_format = str(export_format or "").strip().lower()
        extension_map = {
            "json": ".json",
            "csv": ".csv",
            "cef": ".cef",
            "pdf": ".pdf",
        }
        target_path = self._ask_saveas_filename(
            title="Экспорт журнала аудита",
            defaultextension=extension_map.get(normalized_format, ".txt"),
            filetypes=[
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("CEF", "*.cef"),
                ("PDF", "*.pdf"),
                ("Все файлы", "*.*"),
            ],
        )
        if not target_path:
            return False
        return self._export_audit_logs_to_path(
            target_path,
            normalized_format,
            search_text=search_text,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            date_from=date_from,
            date_to=date_to,
            scheduled=False,
        )

    def _get_audit_verification_policy(self) -> dict:
        default_policy = {
            "interval_seconds": self.AUDIT_VERIFICATION_INTERVAL_SECONDS,
            "recent_entry_limit": 1000,
            "lock_on_tampering": False,
        }
        if not hasattr(self, "db") or not hasattr(self.db, "get_audit_verification_policy"):
            return dict(default_policy)
        try:
            stored_policy = self.db.get_audit_verification_policy()
        except Exception:
            return dict(default_policy)
        if not isinstance(stored_policy, dict):
            return dict(default_policy)
        normalized_policy = dict(default_policy)
        normalized_policy.update(stored_policy)
        normalized_policy["interval_seconds"] = max(
            60,
            int(
                normalized_policy.get("interval_seconds", default_policy["interval_seconds"])
                or default_policy["interval_seconds"]
            ),
        )
        normalized_policy["recent_entry_limit"] = max(
            1,
            int(
                normalized_policy.get("recent_entry_limit", default_policy["recent_entry_limit"])
                or default_policy["recent_entry_limit"]
            ),
        )
        normalized_policy["lock_on_tampering"] = bool(normalized_policy.get("lock_on_tampering", False))
        return normalized_policy

    def _get_recent_audit_verification_range(self) -> tuple[int, Optional[int]]:
        policy = self._get_audit_verification_policy()
        recent_entry_limit = int(policy.get("recent_entry_limit", 1000))
        if not hasattr(self, "db") or not hasattr(self.db, "get_latest_audit_log"):
            return 0, recent_entry_limit
        latest_log = self.db.get_latest_audit_log()
        if latest_log is None or getattr(latest_log, "sequence_number", None) is None:
            return 0, recent_entry_limit
        latest_sequence = int(getattr(latest_log, "sequence_number", 0) or 0)
        start_sequence = max(1, latest_sequence - recent_entry_limit + 1)
        return start_sequence, recent_entry_limit

    def _record_audit_security_event(self, result: dict, *, trigger: str):
        if not hasattr(self, "db") or not hasattr(self.db, "add_audit_security_event"):
            return
        invalid_entries = result.get("invalid_entries", [])
        chain_breaks = result.get("chain_breaks", [])
        related_sequence = None
        if invalid_entries:
            related_sequence = invalid_entries[0].get("sequence_number")
        elif chain_breaks:
            related_sequence = chain_breaks[0].get("sequence_number")
        self.db.add_audit_security_event(
            "audit_verification_failed",
            severity="CRITICAL",
            details={
                "trigger": trigger,
                "total_entries": result.get("total_entries", 0),
                "valid_entries": result.get("valid_entries", 0),
                "invalid_entries": invalid_entries,
                "chain_breaks": chain_breaks,
                "recovery_options": result.get("recovery_options", []),
            },
            related_sequence_number=related_sequence,
        )

    def _build_audit_verification_failure_message(self, result: dict, *, trigger: str) -> str:
        invalid_count = len(result.get("invalid_entries", []))
        chain_break_count = len(result.get("chain_breaks", []))
        if trigger == "periodic":
            prefix = "Периодическая проверка журнала аудита обнаружила нарушение целостности."
        elif trigger == "startup":
            prefix = "При запуске обнаружены признаки нарушения целостности журнала аудита."
        else:
            prefix = "Проверка журнала аудита обнаружила нарушение целостности."
        return (
            f"{prefix}\n"
            f"Ошибок подписи/хэша: {invalid_count}\n"
            f"Разрывов цепочки: {chain_break_count}\n"
            "Подробности сохранены в отдельном журнале безопасности."
        )

    def _handle_audit_verification_failure(self, result: dict, *, manual: bool, trigger: str):
        self._record_audit_security_event(result, trigger=trigger)
        should_notify = manual or not getattr(self, "_audit_tampering_notified", False)
        if should_notify:
            self._show_warning(
                "Проверка аудита",
                self._build_audit_verification_failure_message(result, trigger=trigger),
            )
            self._audit_tampering_notified = True
        policy = self._get_audit_verification_policy()
        if policy.get("lock_on_tampering") and hasattr(self, "_lock_vault"):
            self._lock_vault(show_dialog=False)

    def export_audit_verification_report(self, recent_only: bool = False) -> bool:
        if not hasattr(self, "audit_logger"):
            return False
        start_sequence = 0
        limit = None
        if recent_only:
            start_sequence, limit = self._get_recent_audit_verification_range()
        if hasattr(self.audit_logger, "verifier") and hasattr(self.audit_logger.verifier, "export_verification_report"):
            report_text = self.audit_logger.verifier.export_verification_report(start_sequence=start_sequence, limit=limit)
        else:
            report_result = self.run_audit_verification(
                manual=False,
                recent_only=recent_only,
                trigger="report_export",
            )
            report_text = json.dumps(report_result, ensure_ascii=False, indent=2, sort_keys=True)
        target_path = self._ask_saveas_filename(
            title="Экспорт отчёта проверки аудита",
            defaultextension=".json",
            filetypes=[
                ("JSON", "*.json"),
                ("Все файлы", "*.*"),
            ],
        )
        if not target_path:
            return False
        target_directory = os.path.dirname(target_path)
        if target_directory:
            os.makedirs(target_directory, exist_ok=True)
        with open(target_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(report_text)
        event_bus.publish(
            Event(
                EventType.AUDIT_LOG_EXPORTED,
                {
                    "format": "verification_report_json",
                    "record_count": 1,
                    "path": os.path.basename(target_path),
                    "scope": "recent" if recent_only else "full",
                },
            )
        )
        self._show_info(
            "Отчёт проверки аудита",
            "Отчёт проверки целостности экспортирован.",
        )
        return True

    def run_audit_verification(
        self,
        manual: bool = False,
        recent_only: bool = False,
        trigger: Optional[str] = None,
    ) -> dict:
        if not hasattr(self, "audit_logger") or not hasattr(self.audit_logger, "verify_integrity"):
            result = {
                "verified": False,
                "total_entries": 0,
                "valid_entries": 0,
                "invalid_entries": [{"reason": "audit_logger_unavailable"}],
                "chain_breaks": [],
            }
            self._audit_integrity_status = result
            return result

        trigger_name = trigger or ("manual" if manual else "automatic")
        start_sequence = 0
        limit = None
        if recent_only:
            start_sequence, limit = self._get_recent_audit_verification_range()
        result = self.audit_logger.verify_integrity(start_sequence=start_sequence, limit=limit)
        self._audit_integrity_status = result
        self._last_audit_verification_at = datetime.now()
        if result.get("verified", False):
            self._audit_tampering_notified = False
            event_bus.publish(
                Event(
                    EventType.AUDIT_VERIFICATION_PASSED,
                    {
                        "total_entries": result.get("total_entries", 0),
                        "valid_entries": result.get("valid_entries", 0),
                        "manual": manual,
                        "recent_only": recent_only,
                        "trigger": trigger_name,
                    },
                )
            )
            if manual:
                self._show_info(
                    "Проверка аудита",
                    f"Проверка завершена успешно. Проверено записей: {result.get('valid_entries', 0)}.",
                )
            return result

        event_bus.publish(
            Event(
                EventType.AUDIT_VERIFICATION_FAILED,
                {
                    "invalid_entries": len(result.get("invalid_entries", [])),
                    "chain_breaks": len(result.get("chain_breaks", [])),
                    "total_entries": result.get("total_entries", 0),
                    "manual": manual,
                    "recent_only": recent_only,
                    "trigger": trigger_name,
                },
            )
        )
        self._handle_audit_verification_failure(result, manual=manual, trigger=trigger_name)
        return result

    def _run_periodic_audit_verification_if_due(self):
        if not hasattr(self, "auth_service") or not self.auth_service.is_authenticated():
            return
        if getattr(self, "_last_audit_verification_at", None) is None:
            return
        policy = self._get_audit_verification_policy()
        elapsed = (datetime.now() - self._last_audit_verification_at).total_seconds()
        if elapsed < int(policy.get("interval_seconds", self.AUDIT_VERIFICATION_INTERVAL_SECONDS)):
            return
        self.run_audit_verification(manual=False, recent_only=True, trigger="periodic")

    def _run_scheduled_audit_exports_if_due(self):
        if not hasattr(self, "auth_service") or not self.auth_service.is_authenticated():
            return
        policy = self._get_audit_export_schedule_policy()
        if not policy.get("enabled"):
            return
        last_run_at = str(policy.get("last_run_at", "") or "").strip()
        if last_run_at:
            try:
                previous_run = datetime.fromisoformat(last_run_at)
                if (datetime.now() - previous_run).total_seconds() < int(policy.get("interval_seconds", 24 * 60 * 60)):
                    return
            except ValueError:
                pass
        self._perform_scheduled_audit_exports(policy)

    def _perform_scheduled_audit_exports(self, policy: dict) -> bool:
        export_directory = str(policy.get("export_directory", "") or "")
        if not export_directory:
            return False
        exported_at = datetime.now()
        export_success = False
        for export_format in policy.get("formats", ["json"]):
            target_path = self._build_scheduled_audit_export_path(export_directory, export_format, exported_at)
            if self._export_audit_logs_to_path(target_path, export_format, scheduled=True):
                export_success = True

        if policy.get("include_verification_report"):
            report_path = os.path.join(
                export_directory,
                f"verification-report-{exported_at.strftime('%Y%m%d-%H%M%S')}.json",
            )
            start_sequence, limit = self._get_recent_audit_verification_range()
            if hasattr(self.audit_logger, "verifier") and hasattr(self.audit_logger.verifier, "export_verification_report"):
                report_text = self.audit_logger.verifier.export_verification_report(start_sequence=start_sequence, limit=limit)
            else:
                report_text = json.dumps(
                    self.run_audit_verification(manual=False, recent_only=True, trigger="scheduled_export_report"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            self._write_audit_export_file(report_path, report_text)
            export_success = True

        if export_success:
            updated_policy = dict(policy)
            updated_policy["last_run_at"] = exported_at.isoformat()
            self._save_audit_export_schedule_policy(updated_policy)
            self._cleanup_scheduled_audit_exports(
                export_directory,
                max_age_days=int(policy.get("max_age_days", 30)),
                max_files=int(policy.get("max_files", 20)),
            )
        return export_success

    def show_logs(self):
        self._flush_audit_logger(warn=True)
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Журнал аудита")
        dialog.geometry(self._get_screen_limited_geometry(1240, 820))
        if hasattr(dialog, "minsize"):
            dialog.minsize(960, 640)

        filter_frame = ttk.Frame(dialog, style="App.TFrame")
        filter_frame.pack(fill=tk.X, padx=8, pady=8)

        search_var = tk.StringVar()
        event_type_var = tk.StringVar(value="all")
        severity_var = tk.StringVar(value="ALL")
        user_var = tk.StringVar()
        date_from_var = tk.StringVar()
        date_to_var = tk.StringVar()
        page_var = tk.IntVar(value=1)
        page_status_var = tk.StringVar(value="Страница 1 из 1")
        refresh_status_var = tk.StringVar(value="")
        sort_column_var = tk.StringVar(value="sequence_number")
        sort_desc_var = tk.BooleanVar(value=True)

        ttk.Label(filter_frame, text="Поиск").grid(row=0, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(filter_frame, textvariable=search_var, width=18).grid(row=0, column=1, padx=4, pady=4, sticky="we")
        ttk.Label(filter_frame, text="Событие").grid(row=0, column=2, padx=4, pady=4, sticky="w")
        ttk.Combobox(
            filter_frame,
            textvariable=event_type_var,
            values=["all", "clipboard_copied", "clipboard_cleared", "clipboard_error", "entry_added", "entry_updated", "entry_deleted", "user_logged_in", "user_login_failed", "settings_changed", "search_performed", "panic_mode_activated", "panic_mode_deactivated", "audit_verification_failed"],
            width=24,
            state="readonly",
        ).grid(row=0, column=3, padx=4, pady=4, sticky="we")
        ttk.Label(filter_frame, text="Серьёзность").grid(row=0, column=4, padx=4, pady=4, sticky="w")
        ttk.Combobox(
            filter_frame,
            textvariable=severity_var,
            values=["ALL", "INFO", "WARN", "ERROR", "CRITICAL"],
            width=12,
            state="readonly",
        ).grid(row=0, column=5, padx=4, pady=4, sticky="we")

        ttk.Label(filter_frame, text="Пользователь").grid(row=1, column=0, padx=4, pady=4, sticky="w")
        ttk.Entry(filter_frame, textvariable=user_var, width=18).grid(row=1, column=1, padx=4, pady=4, sticky="we")
        ttk.Label(filter_frame, text="От").grid(row=1, column=2, padx=4, pady=4, sticky="w")
        ttk.Entry(filter_frame, textvariable=date_from_var, width=12).grid(row=1, column=3, padx=4, pady=4, sticky="w")
        ttk.Label(filter_frame, text="До").grid(row=1, column=4, padx=4, pady=4, sticky="w")
        ttk.Entry(filter_frame, textvariable=date_to_var, width=12).grid(row=1, column=5, padx=4, pady=4, sticky="w")

        content = ttk.Panedwindow(dialog, orient=tk.VERTICAL)
        content.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        upper = ttk.Frame(content, style="Surface.TFrame")
        lower = ttk.Frame(content, style="Surface.TFrame")
        content.add(upper, weight=3)
        content.add(lower, weight=2)

        ttk.Label(filter_frame, textvariable=refresh_status_var).grid(
            row=3,
            column=0,
            columnspan=9,
            padx=4,
            pady=(0, 4),
            sticky="w",
        )

        columns = ("sequence_number", "timestamp", "event_type", "severity", "source", "user_id", "entry_id")
        tree = ttk.Treeview(upper, columns=columns, show="headings", height=14, style="Vault.Treeview")
        headers = {
            "sequence_number": "#",
            "timestamp": "Время",
            "event_type": "Событие",
            "severity": "Серьёзность",
            "source": "Источник",
            "user_id": "Пользователь",
            "entry_id": "ID записи",
        }

        def toggle_sort(column_name: str):
            if sort_column_var.get() == column_name:
                sort_desc_var.set(not sort_desc_var.get())
            else:
                sort_column_var.set(column_name)
                sort_desc_var.set(False)
            load_page(page_var.get())

        for key, label in headers.items():
            tree.heading(key, text=label, command=lambda column_name=key: toggle_sort(column_name))
            if key == "sequence_number":
                tree.column(key, width=72, anchor="e")
            else:
                tree.column(key, width=120 if key != "event_type" else 180, anchor="w")
        tree.pack(fill=tk.BOTH, expand=True)

        summary_frame = ttk.LabelFrame(lower, text="Статистика и целостность")
        summary_frame.pack(fill=tk.X, expand=False, padx=4, pady=(0, 6))

        dashboard_text = self._style_text_widget(tk.Text(summary_frame, wrap=tk.WORD, height=8))
        dashboard_text.pack(fill=tk.X, expand=False, padx=6, pady=(6, 4))

        frequency_canvas = tk.Canvas(
            summary_frame,
            width=520,
            height=200,
            bg=self.UI_COLORS["surface"],
            highlightthickness=1,
            highlightbackground=self.UI_COLORS["line"],
        )
        frequency_canvas.pack(fill=tk.X, expand=False, padx=6, pady=(0, 6))

        details_text = self._style_text_widget(tk.Text(lower, wrap=tk.WORD, height=12))
        details_text.pack(fill=tk.BOTH, expand=True)

        pager = ttk.Frame(dialog, style="App.TFrame")
        pager.pack(fill=tk.X, padx=8, pady=(0, 8))

        def load_page(page: Optional[int] = None):
            self._flush_audit_logger(warn=True)
            if page is not None:
                page_var.set(max(1, int(page)))
            model = self._build_audit_log_view_model(
                search_text=search_var.get(),
                event_type=event_type_var.get(),
                severity=severity_var.get(),
                user_id=user_var.get(),
                date_from=date_from_var.get(),
                date_to=date_to_var.get(),
                page=page_var.get(),
            )
            sorted_logs = self._sort_audit_logs(
                model["logs"],
                sort_column_var.get(),
                descending=sort_desc_var.get(),
            )
            tree.delete(*tree.get_children())
            for item_id, values in self._build_audit_tree_rows(sorted_logs):
                tree.insert("", "end", iid=item_id, values=values)
            page_var.set(model["page"])
            latest_sequence = max(
                (int(getattr(log, "sequence_number", 0) or 0) for log in sorted_logs),
                default=0,
            )
            page_status_var.set(
                f"Страница {model['page']} из {model['total_pages']} | "
                f"записей: {model['total_count']} | последняя: {latest_sequence or '-'}"
            )
            refresh_status_var.set(
                f"Обновлено: {datetime.now().strftime('%H:%M:%S')} | "
                f"показана последняя запись #{latest_sequence or '-'}"
            )
            details_text.config(state=tk.NORMAL)
            details_text.delete("1.0", tk.END)
            details_text.config(state=tk.DISABLED)
            dashboard_text.config(state=tk.NORMAL)
            dashboard_text.delete("1.0", tk.END)
            dashboard_text.insert("1.0", "\n".join(self._build_audit_dashboard_lines(sorted_logs, total_count=model["total_count"])))
            dashboard_text.config(state=tk.DISABLED)
            self._render_audit_frequency_chart(frequency_canvas, sorted_logs)
            dialog._audit_logs = {
                str(getattr(log, "sequence_number", getattr(log, "id", ""))): log for log in sorted_logs
            }

        def refresh_latest():
            sort_column_var.set("sequence_number")
            sort_desc_var.set(True)
            load_page(1)

        def reset_filters_and_refresh():
            search_var.set("")
            event_type_var.set("all")
            severity_var.set("ALL")
            user_var.set("")
            date_from_var.set("")
            date_to_var.set("")
            refresh_latest()

        def on_select(_event=None):
            selected = tree.selection()
            if not selected:
                return
            log = getattr(dialog, "_audit_logs", {}).get(selected[0])
            if log is None:
                return
            details_text.config(state=tk.NORMAL)
            details_text.delete("1.0", tk.END)
            details_text.insert("1.0", "\n".join(self._build_audit_log_detail_lines(log)))
            details_text.config(state=tk.DISABLED)
            if getattr(log, "event_type", getattr(log, "action", "")).startswith("entry_"):
                self._highlight_vault_entry_from_audit_log(log)

        def export_current_view(export_format: str):
            self.export_audit_logs(
                export_format,
                search_text=search_var.get(),
                event_type=event_type_var.get(),
                severity=severity_var.get(),
                user_id=user_var.get(),
                date_from=date_from_var.get(),
                date_to=date_to_var.get(),
            )

        def show_context_menu(event):
            item_id = tree.identify_row(event.y)
            if not item_id:
                return
            tree.selection_set(item_id)
            log = getattr(dialog, "_audit_logs", {}).get(item_id)
            if log is None:
                return
            actions = self._get_audit_log_context_actions(log)
            if not actions:
                return
            menu = self._create_tk_menu(dialog, tearoff=0)
            for action in actions:
                menu.add_command(
                    label=action["label"],
                    command=lambda action_id=action["id"], selected_log=log: self._apply_audit_log_context_action(
                        selected_log,
                        action_id,
                    ),
                )
            menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<<TreeviewSelect>>", on_select)
        tree.bind("<Button-3>", show_context_menu)

        ttk.Button(filter_frame, text="Применить", command=lambda: load_page(1)).grid(row=2, column=0, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Обновить", command=refresh_latest).grid(row=2, column=1, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Сбросить фильтры", command=reset_filters_and_refresh).grid(row=2, column=2, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Проверить целостность", command=lambda: self.run_audit_verification(manual=True)).grid(row=2, column=3, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Отчёт проверки", command=lambda: self.export_audit_verification_report()).grid(row=2, column=4, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Экспорт JSON", command=lambda: export_current_view("json")).grid(row=2, column=5, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Экспорт CSV", command=lambda: export_current_view("csv")).grid(row=2, column=6, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Экспорт CEF", command=lambda: export_current_view("cef")).grid(row=2, column=7, padx=4, pady=6, sticky="w")
        ttk.Button(filter_frame, text="Экспорт PDF", command=lambda: export_current_view("pdf")).grid(row=2, column=8, padx=4, pady=6, sticky="w")
        ttk.Button(pager, text="Назад", command=lambda: load_page(page_var.get() - 1)).pack(side=tk.LEFT, padx=4)
        ttk.Label(pager, textvariable=page_status_var).pack(side=tk.LEFT, padx=8)
        ttk.Label(pager, textvariable=refresh_status_var).pack(side=tk.LEFT, padx=8)
        ttk.Button(pager, text="Вперёд", command=lambda: load_page(page_var.get() + 1)).pack(side=tk.LEFT, padx=4)

        load_page(1)

    def _build_clipboard_diagnostics_lines(self) -> list[str]:
        status = self._get_clipboard_status()
        service_settings = (
            self.clipboard_service.get_settings()
            if hasattr(self, "clipboard_service")
            else {"delivery_mode": "system", "security_level": "basic"}
        )
        memory_probe = ""
        if hasattr(self, "clipboard_service") and hasattr(self.clipboard_service, "reveal_current_text"):
            memory_probe = self.clipboard_service.reveal_current_text()
        memory_report = (
            self.clipboard_service.inspect_memory_exposure(memory_probe)
            if memory_probe and hasattr(self, "clipboard_service") and hasattr(self.clipboard_service, "inspect_memory_exposure")
            else {}
        )
        platform_report = get_platform_validation_report(
            root_available=hasattr(self, "root"),
            linux_selection_mode="clipboard",
        )

        security_level_labels = {
            "basic": "базовый",
            "advanced": "повышенный",
            "paranoid": "параноидальный",
        }
        lines = [
            "Диагностика защищённого буфера обмена",
            f"Активен: {'да' if status.active else 'нет'}",
            f"Тип данных: {self._format_clipboard_data_type(status.data_type)}",
            f"Режим доставки: {self._format_clipboard_delivery_mode(service_settings.get('delivery_mode', 'system'))}",
            f"Уровень защиты: {security_level_labels.get(str(service_settings.get('security_level', 'basic')).strip().lower(), service_settings.get('security_level', 'basic'))}",
            f"Источник: {status.source_label or 'не указан'}",
            f"Осталось времени: {status.remaining_seconds} сек" if status.active else "Осталось времени: нет активных данных",
            "",
            "Проверка системного адаптера:",
        ]

        for adapter_info in platform_report.get("adapters", []):
            state_text = "доступен" if adapter_info.get("available") else "недоступен"
            lines.append(f"- {adapter_info.get('name')}: {state_text}")

        lines.extend(
            [
                "",
                "Проверка следов в памяти:",
            ]
        )
        if memory_report:
            lines.append(f"- режим доставки: {self._format_clipboard_delivery_mode(memory_report.get('delivery_mode', 'system'))}")
            lines.append(f"- открытый текст в mask: {'да' if memory_report.get('in_mask_buffer') else 'нет'}")
            lines.append(f"- открытый текст в text_mask: {'да' if memory_report.get('in_text_mask_buffer') else 'нет'}")
            lines.append(f"- открытый текст в source_label: {'да' if memory_report.get('in_source_label') else 'нет'}")
            lines.append(f"- открытый текст в state_manager: {'да' if memory_report.get('in_state_manager') else 'нет'}")
        else:
            lines.append("- активных данных для самопроверки нет")
        return lines

    def show_clipboard_diagnostics(self):
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Диагностика буфера обмена")
        dialog.geometry(self._get_screen_limited_geometry(880, 560))
        if hasattr(dialog, "minsize"):
            dialog.minsize(680, 440)
        text = self._style_text_widget(tk.Text(dialog, wrap=tk.WORD))
        text.pack(fill=tk.BOTH, expand=True)
        text.insert("1.0", "\n".join(self._build_clipboard_diagnostics_lines()))
        text.config(state=tk.DISABLED)

    def show_settings(self):
        dialog = tk.Toplevel(self.root)
        self._prepare_dialog(dialog)
        dialog.title("Настройки")
        dialog.geometry(self._get_screen_limited_geometry(820, 760))
        if hasattr(dialog, "minsize"):
            dialog.minsize(720, 640)
        content_parent = self._create_scrollable_dialog_body(dialog)

        clipboard_settings = (
            self.clipboard_service.get_settings()
            if hasattr(self, "clipboard_service")
            else {
                "timeout_seconds": self.config.get("security.clipboard_timeout", 30),
                "notifications_enabled": self.config.get("security.clipboard_notifications", True),
                "security_level": self.config.get("security.clipboard_security_level", "basic"),
                "blocked_on_suspicious": self.config.get("security.clipboard_blocked_on_suspicious", False),
                "allowed_applications": self.config.get("security.clipboard_allowed_applications", []),
                "delivery_mode": self.config.get("security.clipboard_delivery_mode", "system"),
                "preset": "standard",
            }
        )

        clipboard_timeout = tk.IntVar(value=clipboard_settings.get("timeout_seconds", 30))
        clipboard_notifications_enabled = tk.BooleanVar(
            value=clipboard_settings.get("notifications_enabled", True)
        )
        security_level_labels = {
            "basic": "Базовый",
            "advanced": "Повышенный",
            "paranoid": "Параноидальный",
        }
        security_level_label_to_key = {label: key for key, label in security_level_labels.items()}
        delivery_mode_labels = {
            "system": "Системный буфер",
            "memory_only": "Только память",
        }
        delivery_mode_label_to_key = {label: key for key, label in delivery_mode_labels.items()}
        security_profile_labels = {
            "standard": "Стандартный",
            "enhanced": "Усиленный",
            "paranoid": "Параноидальный",
        }
        security_profile_label_to_key = {label: key for key, label in security_profile_labels.items()}

        def clipboard_security_level_key() -> str:
            return security_level_label_to_key.get(
                clipboard_security_level.get(),
                str(clipboard_security_level.get() or "basic").strip().lower(),
            )

        def clipboard_delivery_mode_key() -> str:
            return delivery_mode_label_to_key.get(
                clipboard_delivery_mode.get(),
                str(clipboard_delivery_mode.get() or "system").strip().lower(),
            )

        def security_profile_key() -> str:
            return security_profile_label_to_key.get(
                security_profile.get(),
                str(security_profile.get() or "standard").strip().lower(),
            )

        clipboard_security_level = tk.StringVar(
            value=security_level_labels.get(str(clipboard_settings.get("security_level", "basic")).strip().lower(), "Базовый")
        )
        clipboard_delivery_mode = tk.StringVar(
            value=delivery_mode_labels.get(str(clipboard_settings.get("delivery_mode", "system")).strip().lower(), "Системный буфер")
        )
        clipboard_blocked_on_suspicious = tk.BooleanVar(
            value=clipboard_settings.get("blocked_on_suspicious", False)
        )
        clipboard_allowed_applications = tk.StringVar(
            value=", ".join(clipboard_settings.get("allowed_applications", []))
        )
        detected_clipboard_preset = self._detect_clipboard_preset(
            timeout_seconds=clipboard_timeout.get(),
            notifications_enabled=clipboard_notifications_enabled.get(),
            security_level=clipboard_security_level.get(),
            blocked_on_suspicious=clipboard_blocked_on_suspicious.get(),
            delivery_mode=clipboard_delivery_mode.get(),
        )
        stored_clipboard_preset = str(clipboard_settings.get("preset", detected_clipboard_preset)).strip().lower()
        if stored_clipboard_preset not in self._get_clipboard_preset_labels():
            stored_clipboard_preset = detected_clipboard_preset
        initial_clipboard_preset = (
            stored_clipboard_preset if stored_clipboard_preset == detected_clipboard_preset else detected_clipboard_preset
        )
        clipboard_preset = tk.StringVar(value=self._get_clipboard_preset_label(initial_clipboard_preset))
        clipboard_summary = tk.StringVar()
        security_profile = tk.StringVar(
            value=security_profile_labels.get(str(self.config.get("security.security_profile", "standard")).strip().lower(), "Стандартный")
        )
        security_profile_summary = tk.StringVar(value=explain_security_profile(security_profile_key()))
        auto_lock_minutes = tk.IntVar(value=self.config.get("security.auto_lock_minutes", 5))
        min_password_length = tk.IntVar(value=self.config.get("security.min_password_length", 12))
        key_cache_timeout_minutes = tk.IntVar(value=self.config.get("security.key_cache_timeout_minutes", 60))
        lock_on_focus_loss = tk.BooleanVar(value=self.config.get("security.lock_on_focus_loss", True))
        lock_on_minimize = tk.BooleanVar(value=self.config.get("security.lock_on_minimize", True))

        ttk.Label(content_parent, text="Профиль безопасности").pack(anchor=tk.W, padx=10, pady=(12, 2))
        security_profile_box = ttk.Combobox(
            content_parent,
            textvariable=security_profile,
            state="readonly",
            values=[security_profile_labels[key] for key in SECURITY_PROFILES.keys()],
        )
        security_profile_box.pack(fill=tk.X, padx=10, pady=2)
        ttk.Label(content_parent, textvariable=security_profile_summary, wraplength=420, justify=tk.LEFT).pack(
            anchor=tk.W, padx=10, pady=(2, 8)
        )

        ttk.Label(content_parent, text="Профиль буфера обмена").pack(anchor=tk.W, padx=10, pady=(12, 2))
        clipboard_preset_box = ttk.Combobox(
            content_parent,
            textvariable=clipboard_preset,
            state="readonly",
            values=list(self._get_clipboard_preset_labels().values()),
        )
        clipboard_preset_box.pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(content_parent, text="Таймаут буфера обмена (сек)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(content_parent, from_=5, to=300, textvariable=clipboard_timeout).pack(fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(
            content_parent,
            text="Показывать уведомления буфера обмена",
            variable=clipboard_notifications_enabled,
        ).pack(anchor=tk.W, padx=10, pady=(8, 2))

        ttk.Label(content_parent, text="Уровень защиты буфера обмена").pack(anchor=tk.W, padx=10, pady=(12, 2))
        clipboard_security_level_box = ttk.Combobox(
            content_parent,
            textvariable=clipboard_security_level,
            state="readonly",
            values=list(security_level_labels.values()),
        )
        clipboard_security_level_box.pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(content_parent, text="Режим доставки буфера обмена").pack(anchor=tk.W, padx=10, pady=(12, 2))
        clipboard_delivery_mode_box = ttk.Combobox(
            content_parent,
            textvariable=clipboard_delivery_mode,
            state="readonly",
            values=list(delivery_mode_labels.values()),
        )
        clipboard_delivery_mode_box.pack(fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(
            content_parent,
            text="Блокировать будущие копирования при подозрительной активности",
            variable=clipboard_blocked_on_suspicious,
        ).pack(anchor=tk.W, padx=10, pady=(8, 2))

        ttk.Label(content_parent, text="Разрешённые приложения для буфера обмена").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Entry(content_parent, textvariable=clipboard_allowed_applications).pack(fill=tk.X, padx=10, pady=2)
        ttk.Label(
            content_parent,
            text="Укажите имена процессов через запятую, например: explorer, code, keepassxc",
            wraplength=420,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=10, pady=(2, 4))

        ttk.Label(content_parent, textvariable=clipboard_summary, wraplength=420, justify=tk.LEFT).pack(
            anchor=tk.W, padx=10, pady=(4, 8)
        )

        ttk.Label(content_parent, text="Таймаут авто-блокировки (мин)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(content_parent, from_=1, to=120, textvariable=auto_lock_minutes).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(content_parent, text="Таймаут кэша ключа (мин)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(content_parent, from_=1, to=60, textvariable=key_cache_timeout_minutes).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(content_parent, text="Минимальная длина мастер-пароля").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(content_parent, from_=8, to=64, textvariable=min_password_length).pack(fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(
            content_parent,
            text="Блокировать при потере фокуса",
            variable=lock_on_focus_loss,
        ).pack(
            anchor=tk.W, padx=10, pady=(12, 2)
        )
        ttk.Checkbutton(
            content_parent,
            text="Блокировать при сворачивании",
            variable=lock_on_minimize,
        ).pack(
            anchor=tk.W, padx=10, pady=2
        )

        ttk.Label(content_parent, text="Горячие клавиши").pack(anchor=tk.W, padx=10, pady=(18, 2))
        hotkey_status = getattr(self, "_global_hotkey_status", "not_registered")
        hotkey_status_labels = {
            "registered": "зарегистрирована",
            "not_registered": "не зарегистрирована",
            "unsupported": "не поддерживается",
            "failed": "ошибка регистрации",
        }
        descriptions = {
            "panic_mode": "экстренно заблокировать хранилище",
            "lock_vault": "заблокировать хранилище",
            "unlock_vault": "разблокировать хранилище",
            "focus_search": "перейти к поиску",
            "add_entry": "добавить запись",
            "edit_entry": "изменить выбранную запись",
            "delete_entry": "удалить выбранную запись",
            "toggle_passwords": "показать или скрыть пароли",
            "clear_clipboard": "очистить буфер обмена",
            "open_settings": "открыть настройки",
        }
        hotkey_lines = []
        for binding in get_default_hotkeys().values():
            scope = "глобально" if binding.global_hotkey else "внутри приложения"
            hotkey_lines.append(f"{binding.label} — {descriptions.get(binding.action, binding.description)} ({scope})")
        hotkey_lines.append("Ctrl+Alt+P — резервная горячая клавиша паник-режима, если Windows забирает Ctrl+Shift+Esc")
        hotkey_lines.append(f"Статус глобальной горячей клавиши паник-режима: {hotkey_status_labels.get(str(hotkey_status), hotkey_status)}")
        ttk.Label(
            content_parent,
            text="\n".join(hotkey_lines),
            wraplength=680,
            justify=tk.LEFT,
            style="Muted.TLabel",
        ).pack(anchor=tk.W, fill=tk.X, padx=10, pady=(2, 10))

        def refresh_clipboard_summary(*_args):
            detected_preset = self._detect_clipboard_preset(
                timeout_seconds=clipboard_timeout.get(),
                notifications_enabled=clipboard_notifications_enabled.get(),
                security_level=clipboard_security_level_key(),
                blocked_on_suspicious=clipboard_blocked_on_suspicious.get(),
                delivery_mode=clipboard_delivery_mode_key(),
            )
            selected_preset = self._get_clipboard_preset_key_from_label(clipboard_preset.get())
            if selected_preset != detected_preset:
                clipboard_preset.set(self._get_clipboard_preset_label(detected_preset))
            clipboard_summary.set(
                self._build_clipboard_settings_summary(
                    timeout_seconds=clipboard_timeout.get(),
                    notifications_enabled=clipboard_notifications_enabled.get(),
                    security_level=clipboard_security_level_key(),
                    blocked_on_suspicious=clipboard_blocked_on_suspicious.get(),
                    delivery_mode=clipboard_delivery_mode_key(),
                    allowed_applications=clipboard_allowed_applications.get(),
                )
            )

        def apply_selected_clipboard_preset(_event=None):
            selected_preset = self._get_clipboard_preset_key_from_label(clipboard_preset.get())
            if self._apply_clipboard_preset_to_vars(
                selected_preset,
                timeout_var=clipboard_timeout,
                notifications_var=clipboard_notifications_enabled,
                security_level_var=clipboard_security_level,
                blocked_var=clipboard_blocked_on_suspicious,
                delivery_mode_var=clipboard_delivery_mode,
            ):
                preset_settings = ClipboardService.PRESETS[selected_preset]
                clipboard_security_level.set(security_level_labels.get(str(preset_settings["security_level"]), clipboard_security_level.get()))
                clipboard_delivery_mode.set(delivery_mode_labels.get(str(preset_settings.get("delivery_mode", "system")), clipboard_delivery_mode.get()))
                clipboard_preset.set(self._get_clipboard_preset_label(selected_preset))
            refresh_clipboard_summary()

        def apply_selected_security_profile(_event=None):
            selected_profile = security_profile_key()
            profile_settings = SECURITY_PROFILES.get(selected_profile, SECURITY_PROFILES["standard"])
            security_profile_summary.set(explain_security_profile(selected_profile))
            auto_lock_minutes.set(int(profile_settings["auto_lock_minutes"]))
            key_cache_timeout_minutes.set(int(profile_settings["key_cache_timeout_minutes"]))
            lock_on_focus_loss.set(bool(profile_settings["lock_on_focus_loss"]))
            lock_on_minimize.set(bool(profile_settings["lock_on_minimize"]))
            clipboard_timeout.set(int(profile_settings["clipboard_timeout"]))
            clipboard_security_level.set(security_level_labels.get(str(profile_settings["clipboard_security_level"]), "Базовый"))
            clipboard_delivery_mode.set(delivery_mode_labels.get(str(profile_settings["clipboard_delivery_mode"]), "Системный буфер"))
            clipboard_blocked_on_suspicious.set(bool(profile_settings["clipboard_blocked_on_suspicious"]))
            refresh_clipboard_summary()

        security_profile_box.bind("<<ComboboxSelected>>", apply_selected_security_profile)
        clipboard_preset_box.bind("<<ComboboxSelected>>", apply_selected_clipboard_preset)
        for variable in (
            clipboard_timeout,
            clipboard_notifications_enabled,
            clipboard_security_level,
            clipboard_delivery_mode,
            clipboard_blocked_on_suspicious,
            clipboard_allowed_applications,
        ):
            variable.trace_add("write", refresh_clipboard_summary)
        refresh_clipboard_summary()

        def save():
            selected_security_settings = dict(self.config.get("security", {}))
            selected_security_settings.update(
                {
                    "security_profile": security_profile_key(),
                    "clipboard_timeout": clipboard_timeout.get(),
                    "clipboard_security_level": clipboard_security_level_key(),
                    "clipboard_delivery_mode": clipboard_delivery_mode_key(),
                    "clipboard_blocked_on_suspicious": clipboard_blocked_on_suspicious.get(),
                    "auto_lock_minutes": auto_lock_minutes.get(),
                    "min_password_length": min_password_length.get(),
                    "key_cache_timeout_minutes": key_cache_timeout_minutes.get(),
                    "lock_on_focus_loss": lock_on_focus_loss.get(),
                    "lock_on_minimize": lock_on_minimize.get(),
                }
            )
            validation = validate_security_settings(selected_security_settings)
            if not validation.valid:
                self._show_error("Настройки", "\n".join(validation.errors), parent=dialog)
                return
            if validation.warnings and not self._ask_yes_no(
                "Настройки",
                "Есть предупреждения по безопасности:\n\n"
                + "\n".join(f"- {warning}" for warning in validation.warnings)
                + "\n\nПродолжить?",
                parent=dialog,
            ):
                return
            self.config.set("security.security_profile", validation.settings["security_profile"])
            self.config.set("security.clipboard_timeout", clipboard_timeout.get())
            self.config.set("security.clipboard_notifications", clipboard_notifications_enabled.get())
            self.config.set("security.clipboard_security_level", clipboard_security_level_key())
            self.config.set("security.clipboard_delivery_mode", clipboard_delivery_mode_key())
            self.config.set("security.clipboard_blocked_on_suspicious", clipboard_blocked_on_suspicious.get())
            normalized_allowed_applications = [
                item.strip() for item in clipboard_allowed_applications.get().replace(";", ",").split(",") if item.strip()
            ]
            self.config.set("security.clipboard_allowed_applications", normalized_allowed_applications)
            self.config.set("security.auto_lock_minutes", auto_lock_minutes.get())
            self.config.set("security.min_password_length", min_password_length.get())
            self.config.set("security.key_cache_timeout_minutes", key_cache_timeout_minutes.get())
            self.config.set("security.lock_on_focus_loss", lock_on_focus_loss.get())
            self.config.set("security.lock_on_minimize", lock_on_minimize.get())
            selected_preset = self._detect_clipboard_preset(
                timeout_seconds=clipboard_timeout.get(),
                notifications_enabled=clipboard_notifications_enabled.get(),
                security_level=clipboard_security_level_key(),
                blocked_on_suspicious=clipboard_blocked_on_suspicious.get(),
                delivery_mode=clipboard_delivery_mode_key(),
            )
            if hasattr(self, "clipboard_service"):
                self.clipboard_service.configure(
                    timeout_seconds=clipboard_timeout.get(),
                    notifications_enabled=clipboard_notifications_enabled.get(),
                    security_level=clipboard_security_level_key(),
                    delivery_mode=clipboard_delivery_mode_key(),
                    blocked_on_suspicious=clipboard_blocked_on_suspicious.get(),
                    allowed_applications=normalized_allowed_applications,
                    preset=selected_preset,
                )
            self.password_validator.min_length = min_password_length.get()
            self.db.set_setting(
                "security.password_policy",
                {
                    "min_password_length": min_password_length.get(),
                    "require_uppercase": self.config.get("security.require_uppercase", True),
                    "require_lowercase": self.config.get("security.require_lowercase", True),
                    "require_digits": self.config.get("security.require_digits", True),
                    "require_special": self.config.get("security.require_special", True),
                },
            )
            self.state.set_inactivity_timeout(auto_lock_minutes.get() * 60)
            self.state.set_key_cache_timeout(key_cache_timeout_minutes.get() * 60)
            self.config.set("security.activity_sensitivity", validation.settings["activity_sensitivity"])
            self.config.set("security.device_profile", validation.settings["device_profile"])
            self.config.set("security.memory_locking_enabled", validation.settings["memory_locking_enabled"])
            self.config.set("security.panic_hotkey", validation.settings["panic_hotkey"])
            self.config.set("security.panic_close_application", validation.settings["panic_close_application"])
            self.config.set("security.panic_stealth_mode", validation.settings["panic_stealth_mode"])
            self.activity_monitor = self._create_activity_monitor()
            self.panic_mode = self._create_panic_mode()
            self._register_global_panic_hotkey()
            self._persist_runtime_settings()
            event_bus.publish(
                Event(
                    EventType.SETTINGS_CHANGED,
                    {
                        "scope": "security",
                        "changed_keys": [
                            "clipboard_timeout",
                            "clipboard_notifications",
                            "clipboard_security_level",
                            "clipboard_delivery_mode",
                            "clipboard_blocked_on_suspicious",
                            "clipboard_allowed_applications",
                            "auto_lock_minutes",
                            "min_password_length",
                            "key_cache_timeout_minutes",
                            "lock_on_focus_loss",
                            "lock_on_minimize",
                            "security_profile",
                        ],
                    },
                )
            )
            self._refresh_clipboard_status()
            self._show_info("Настройки", "Настройки сохранены.", parent=dialog)
            dialog.destroy()

        button_bar = self._create_dialog_button_bar(dialog)
        ttk.Button(button_bar, text="Сменить мастер-пароль", style="Ghost.TButton", command=self.change_master_password).pack(side=tk.LEFT)
        ttk.Button(button_bar, text="Сохранить", style="Accent.TButton", command=save).pack(side=tk.RIGHT)

    def change_master_password(self):
        current_password = self._ask_string("Смена пароля", "Текущий мастер-пароль:", show="*")
        if current_password is None:
            return
        new_password = self._ask_string("Смена пароля", "Новый мастер-пароль:", show="*")
        if new_password is None:
            return
        confirm = self._ask_string("Смена пароля", "Подтвердите новый мастер-пароль:", show="*")
        if confirm != new_password:
            self._show_error("Ошибка", "Пароли не совпадают.")
            return
        try:
            self.auth_service.change_master_password(
                current_password,
                new_password,
                rotate_entries_callback=self._rotate_vault_entries,
            )
            if hasattr(self, "audit_logger") and hasattr(self.audit_logger, "signer"):
                self.audit_logger.signer.clear()
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            self._show_info("Успешно", "Мастер-пароль успешно изменён.")
        except AuthenticationError as error:
            self._show_error("Ошибка", str(error))

    def _lock_vault(self, show_dialog: bool = True, *, preserve_clipboard: bool = False, reason: str = "manual"):
        self._flush_audit_logger()
        event_bus.publish(Event(EventType.VAULT_LOCKED, {"reason": reason, "preserve_clipboard": preserve_clipboard}))
        self._flush_audit_logger()
        self.auth_service.logout()
        self.key_manager.clear_key()
        if not preserve_clipboard:
            self.state.clear_clipboard()
            self._clear_system_clipboard()
            self._handle_clipboard_clear_failure()
        self._clear_sensitive_view_state()
        self._set_status("Заблокировано")
        self._update_system_tray_status()
        if show_dialog:
            self._require_login()
            if self.auth_service.is_authenticated():
                self.key_manager.store_key("active", self.auth_service.get_active_key())
                self._load_entries()
                self._update_system_tray_status()

    def _unlock_vault(self):
        if hasattr(self, "panic_mode") and getattr(self.panic_mode, "activated", False):
            self.panic_mode.reset_for_recovery()
            self._restore_main_window(force_rebuild_menu=True)
        if self.auth_service.is_authenticated():
            self._load_entries()
            self._set_status("Разблокировано")
            self._update_system_tray_status()
            return True
        self._prompt_unlock_if_needed(force=True)
        self._update_system_tray_status()
        return self.auth_service.is_authenticated()

    def _on_close(self):
        self._flush_audit_logger()
        event_bus.publish(Event(EventType.APP_SHUTDOWN, {"component": "main_window"}))
        self._flush_audit_logger()
        try:
            self.auth_service.logout()
        except Exception:
            pass
        self.key_manager.clear_key()
        self.state.clear_clipboard()
        self._clear_sensitive_view_state()
        self._clear_system_clipboard()
        self._handle_clipboard_clear_failure()
        self._clear_clipboard_recovery_pending()
        self._ui_task_pump_active = False
        self._panic_hotkey_poll_active = False
        if getattr(self, "_global_hotkey_service", None) is not None:
            self._global_hotkey_service.stop()
        self._shutdown_system_tray()
        try:
            self.audit_logger.close()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        self.root.destroy()

    def show_about(self):
        self._show_info(
            "О программе",
            "CryptoSafe Manager\nВерсия 2.0\n\n"
            "Менеджер паролей с локальным зашифрованным хранилищем, мастер-паролем и журналом аудита.",
        )

    def run(self):
        self.root.mainloop()