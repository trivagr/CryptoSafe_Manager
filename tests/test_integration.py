import os
import json
import queue
import shutil
import sys
import tempfile
import tkinter as tk
import tracemalloc
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import ClipboardStatus
from src.core.config import Config
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.legacy_encryption import LegacyXOREncryptionService
from src.core.crypto.password_validator import PasswordValidator
from src.core.audit import AuditLogger as RealAuditLogger
from src.core.events import Event, EventType
from src.core.import_export import ImportValidationError, SharePermissions
from src.core.import_export.sharing_service import SharingService
from src.core.key_manager import KeyManager
from src.core.vault import AESGCMEncryptionService, EntryManager
from src.database.db import Database
from src.database.models import VaultEntry
from src.gui.main_window import EntryView, MainWindow
from src.gui.setup_wizard import SetupWizard


class FakeVar:
    def __init__(self, value=None):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeDialog:
    def __init__(self):
        self.destroyed = False
        self.configured = {}
        self.options = {}
        self.bindings = []

    def configure(self, **kwargs):
        self.configured.update(kwargs)

    def option_add(self, key, value):
        self.options[key] = value

    def bind(self, sequence, callback, add=None):
        self.bindings.append((sequence, callback, add))

    def destroy(self):
        self.destroyed = True


class FakeMotionEvent:
    def __init__(self, x_root, y_root=100):
        self.x_root = x_root
        self.y_root = y_root


class FakeLabel:
    def __init__(self):
        self.text = ""

    def config(self, **kwargs):
        if "text" in kwargs:
            self.text = kwargs["text"]


class FakeButton:
    def __init__(self):
        self.disabled = False

    def state(self, states):
        if "disabled" in states:
            self.disabled = True
        if "!disabled" in states:
            self.disabled = False

    def winfo_rootx(self):
        return 100

    def winfo_rooty(self):
        return 100

    def winfo_height(self):
        return 24


class FakeTrayIcon:
    def __init__(self):
        self.icon = None
        self.title = ""


class FakeAuthServiceForReveal:
    def __init__(self):
        self.logged_out = False
        self.authenticated = False
        self.initialized = True
        self.password_checks = []

    def authenticate(self, password):
        self.password_checks.append(password)
        self.authenticated = password == "ValidMasterPass!9X"
        return self.authenticated

    def logout(self):
        self.logged_out = True

    def is_authenticated(self):
        return self.authenticated

    def is_initialized(self):
        return self.initialized

    def get_active_key(self):
        return b"x" * 32


class FakeEntryWidget:
    def __init__(self):
        self.focused = False
        self.selection = None

    def focus_set(self):
        self.focused = True

    def selection_range(self, start, end):
        self.selection = (start, end)


class FakeTable:
    def __init__(self):
        self.rows = []

    def set_data(self, rows):
        self.rows = list(rows)

    def clear(self):
        self.rows = []

    def get_selected(self):
        return None


class FakeClipboardService:
    def __init__(self):
        self.calls = []
        self.status = ClipboardStatus(active=False)
        self.last_clear_reason = None
        self.last_clear_failed = False
        self.settings = {
            "timeout_seconds": 30,
            "notifications_enabled": True,
            "security_level": "basic",
            "blocked_on_suspicious": False,
            "allowed_applications": [],
            "delivery_mode": "system",
            "preset": "standard",
        }
        self.configure_calls = []
        self.clear_calls = []
        self.revealed_text = "Secret!123"

    def copy_text(self, value, **kwargs):
        self.calls.append((value, kwargs))

    def get_status(self):
        return self.status

    def get_last_clear_reason(self):
        return self.last_clear_reason

    def did_last_clear_fail(self):
        return self.last_clear_failed

    def get_settings(self):
        return dict(self.settings)

    def configure(self, **kwargs):
        self.configure_calls.append(kwargs)
        self.settings.update(kwargs)

    def clear(self, reason="manual", publish_event=True):
        self.clear_calls.append({"reason": reason, "publish_event": publish_event})
        self.last_clear_reason = reason
        self.status = ClipboardStatus(
            active=False,
            suspicious_activity=self.status.suspicious_activity,
            blocked_future_copies=self.status.blocked_future_copies,
        )
        return True

    def reveal_current_text(self):
        return self.revealed_text


class FakeVaultEntryManager:
    def __init__(self):
        self.entries = [
            {
                "id": 1,
                "title": "GitHub",
                "username": "ray",
                "password": "Secret!123",
                "url": "https://github.com",
                "notes": "note",
                "category": "Dev",
                "tags": "git",
            }
        ]

    def get_all_entries(self):
        return list(self.entries)

    def get_entry(self, entry_id):
        return next(entry for entry in self.entries if entry["id"] == entry_id)

    def create_entry(self, entry):
        created = dict(entry)
        created["id"] = max((item["id"] for item in self.entries), default=0) + 1
        self.entries.append(created)
        return created

    def update_entry(self, entry_id, entry):
        for index, existing in enumerate(self.entries):
            if existing["id"] == entry_id:
                updated = dict(existing)
                updated.update(entry)
                self.entries[index] = updated
                return updated
        raise KeyError(entry_id)


class FakeAuthService:
    def __init__(self):
        self.logged_out = False
        self.authenticated = False
        self.initialized = True

    def logout(self):
        self.logged_out = True

    def is_authenticated(self):
        return self.authenticated

    def is_initialized(self):
        return self.initialized

    def get_active_key(self):
        return b"x" * 32


class FakeKeyManager:
    def __init__(self):
        self.cleared = False

    def clear_key(self):
        self.cleared = True

    def store_key(self, _key_type, _value):
        pass


class FakeAuditLogger:
    def __init__(self):
        self.closed = False
        self.verify_calls = []
        self.verification_result = {
            "verified": True,
            "total_entries": 2,
            "valid_entries": 2,
            "invalid_entries": [],
            "chain_breaks": [],
        }
        self.verifier = type(
            "Verifier",
            (),
            {"export_verification_report": staticmethod(lambda start_sequence=0, limit=None: '{"verified": true}')},
        )()

    def close(self):
        self.closed = True

    def verify_integrity(self, start_sequence=0, limit=None):
        self.verify_calls.append({"start_sequence": start_sequence, "limit": limit})
        return dict(self.verification_result)


class FakeKeyStorage:
    def is_cache_expired(self):
        return False

    def touch_cached_key(self, _timeout_seconds):
        pass


class FakeStateManager:
    def __init__(self):
        self.clipboard_cleared = False
        self.application_active = True
        self.clipboard_content = None
        self.clipboard_timer = None

    def clear_clipboard(self):
        self.clipboard_cleared = True
        self.clipboard_content = None
        self.clipboard_timer = None

    def set_application_active(self, is_active):
        self.application_active = is_active

    def get_clipboard(self):
        return self.clipboard_content

    def should_auto_lock(self):
        return False

    def should_expire_key_cache(self):
        return False


class FakeRoot:
    def __init__(self):
        self.protocols = {}
        self.destroyed = False
        self.clipboard = ""
        self.update_calls = 0
        self.after_calls = []
        self.window_state = "normal"

    def title(self, _value):
        pass

    def geometry(self, _value):
        pass

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def bind_all(self, *_args, **_kwargs):
        pass

    def bind(self, *_args, **_kwargs):
        pass

    def after(self, _delay, _callback):
        self.after_calls.append((_delay, _callback))
        return len(self.after_calls)

    def state(self, value=None):
        if value is not None:
            self.window_state = value
        return self.window_state

    def focus_displayof(self):
        return object()

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, value):
        self.clipboard = value

    def update(self):
        self.update_calls += 1

    def withdraw(self):
        self.window_state = "withdrawn"

    def deiconify(self):
        self.window_state = "normal"

    def config(self, **_kwargs):
        pass

    def destroy(self):
        self.destroyed = True

    def mainloop(self):
        pass


class FakeActivityMonitor:
    def __init__(self, should_lock=False):
        self.should_lock = should_lock
        self.recorded_sources = []
        self.tick_calls = 0

    def record_activity(self, source="user"):
        self.recorded_sources.append(source)

    def tick(self):
        self.tick_calls += 1
        return self.should_lock


class IntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_home = tempfile.TemporaryDirectory()
        self.home_path = Path(self.temp_home.name)
        self.addCleanup(self.temp_home.cleanup)

        self.config_home_patch = patch("src.core.config.Path.home", return_value=self.home_path)
        self.setup_home_patch = patch("src.gui.setup_wizard.Path.home", return_value=self.home_path)
        self.config_home_patch.start()
        self.setup_home_patch.start()
        self.addCleanup(self.config_home_patch.stop)
        self.addCleanup(self.setup_home_patch.stop)

    def make_db_path(self, filename="vault.db"):
        return str(self.home_path / ".cryptosafe" / filename)

    def make_auth_service(self, database_path):
        database = Database(database_path)
        key_storage = KeyStorage(database)
        return AuthenticationService(
            key_storage,
            KeyDerivation({}),
            PasswordValidator(),
        )


class TestSetupWizardIntegration(IntegrationTestCase):
    def test_initial_database_path_uses_selected_config_path(self):
        db_path = self.make_db_path("selected-startup-vault.db")
        wizard = SetupWizard.__new__(SetupWizard)
        wizard.config = Config()
        wizard.config.set("database.path", db_path)

        self.assertEqual(wizard._get_initial_db_path(), db_path)

    def test_finish_initial_setup_persists_configuration_and_initializes_auth(self):
        db_path = self.make_db_path()
        config = Config()
        config.set("crypto.pbkdf2_iterations", 150000)
        auth_service = self.make_auth_service(db_path)

        wizard = SetupWizard.__new__(SetupWizard)
        wizard.config = config
        wizard.auth_service = auth_service
        wizard.master_password = FakeVar("ValidMasterPass!9X")
        wizard.confirm_password = FakeVar("ValidMasterPass!9X")
        wizard.db_path = FakeVar(db_path)
        wizard.auto_lock_minutes = FakeVar(7)
        wizard.key_cache_timeout_minutes = FakeVar(17)
        wizard.wizard = FakeDialog()

        with patch("src.gui.setup_wizard.messagebox.showinfo"), patch("src.gui.setup_wizard.messagebox.showerror"):
            wizard._finish()

        self.assertTrue(auth_service.is_initialized())
        self.assertTrue(auth_service.is_authenticated())
        self.assertTrue(wizard.wizard.destroyed)
        self.assertEqual(config.get("database.path"), db_path)
        self.assertEqual(config.get("crypto.pbkdf2_iterations"), 150000)
        self.assertEqual(config.get("security.auto_lock_minutes"), 7)
        self.assertEqual(config.get("security.key_cache_timeout_minutes"), 17)

        database = Database(db_path)
        self.assertIsNotNone(database.get_key_store("auth_hash"))
        self.assertIsNotNone(database.get_key_store("enc_salt"))
        self.assertIsNotNone(database.get_key_store("params"))
        self.assertEqual(database.get_setting("security.auto_lock_timeout_minutes"), 7)
        self.assertEqual(database.get_setting("security.key_cache_timeout_minutes"), 17)
        self.assertEqual(database.get_setting("crypto.key_derivation")["pbkdf2_iterations"], 150000)
        self.assertEqual(database.get_setting("security.password_policy")["min_password_length"], 12)


class TestMainWindowIntegration(IntegrationTestCase):
    def _patch_window_chrome(self):
        return [
            patch("src.gui.main_window.tk.Tk", side_effect=FakeRoot),
            patch.object(MainWindow, "_create_menu", lambda self: None),
            patch.object(MainWindow, "_create_toolbar", lambda self: None),
            patch.object(MainWindow, "_create_main_area", lambda self: setattr(self, "table", FakeTable())),
            patch.object(
                MainWindow,
                "_create_statusbar",
                lambda self: (
                    setattr(self, "status_label", FakeLabel()),
                    setattr(self, "clipboard_label", FakeLabel()),
                ),
            ),
            patch.object(MainWindow, "_setup_events", lambda self: None),
            patch.object(MainWindow, "_setup_activity_tracking", lambda self: None),
            patch.object(MainWindow, "_schedule_security_tasks", lambda self: None),
            patch.object(
                MainWindow,
                "_select_startup_vault_path",
                lambda self: self.config.get("database.path", "cryptosafe.db"),
            ),
        ]

    def test_main_window_starts_with_existing_vault_and_loads_entries(self):
        db_path = self.make_db_path("existing.db")
        config = Config()
        config.set("database.path", db_path)
        config.set("security.auto_lock_minutes", 9)
        config.set("security.key_cache_timeout_minutes", 13)
        config.set("crypto.pbkdf2_iterations", 180000)

        database = Database(db_path)
        auth_service = self.make_auth_service(db_path)
        password = "ValidMasterPass!9X"
        auth_service.register_master_password(password)
        crypto = LegacyXOREncryptionService()
        encrypted_password = crypto.encrypt(b"secret", auth_service.get_active_key())
        auth_service.logout()
        entry_id = database.add_entry(
            VaultEntry(
                title="Example",
                username="demo",
                encrypted_password=encrypted_password,
                encrypted_data=encrypted_password,
                url="https://example.com",
                notes="seed",
                tags="",
            )
        )

        patchers = self._patch_window_chrome()
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        with patch("src.gui.main_window.simpledialog.askstring", return_value=password), patch(
            "src.gui.main_window.messagebox.showerror"
        ), patch("src.gui.main_window.messagebox.showwarning"):
            window = MainWindow()
            self.addCleanup(window._on_close)

        self.assertEqual(window.db.db_path, db_path)
        self.assertTrue(window.auth_service.is_authenticated())
        self.assertEqual(window.state.inactivity_timeout, 9 * 60)
        self.assertIn("WM_DELETE_WINDOW", window.root.protocols)
        self.assertEqual(len(window.table.rows), 1)
        self.assertEqual(window.table.rows[0]["id"], entry_id)
        self.assertEqual(window.table.rows[0]["title"], "Example")
        self.assertEqual(window.table.rows[0]["username"], "demo")
        self.assertEqual(window.table.rows[0]["url"], "example.com")
        self.assertEqual(window.db.get_setting("security.auto_lock_timeout_minutes"), 9)
        self.assertEqual(window.db.get_setting("security.key_cache_timeout_minutes"), 13)
        self.assertEqual(window.db.get_setting("crypto.key_derivation")["pbkdf2_iterations"], 180000)
        self.assertIsInstance(window.audit_logger, RealAuditLogger)

        window.audit_logger.flush()
        audit_events = [log.event_type for log in window.db.get_audit_log_chain()]
        self.assertIn("user_logged_in", audit_events)
        self.assertIn("app_started", audit_events)

    def test_main_window_triggers_setup_for_uninitialized_vault(self):
        db_path = self.make_db_path("fresh.db")
        config = Config()
        config.set("database.path", db_path)

        patchers = self._patch_window_chrome()
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        setup_calls = []

        def fake_setup(_root, passed_config, auth_service):
            setup_calls.append(passed_config.get("database.path"))
            auth_service.register_master_password("ValidMasterPass!9X")

        with patch("src.gui.main_window.SetupWizard", side_effect=fake_setup), patch(
            "src.gui.main_window.simpledialog.askstring", return_value="ValidMasterPass!9X"
        ), patch("src.gui.main_window.messagebox.showerror"), patch("src.gui.main_window.messagebox.showwarning"):
            window = MainWindow()
            self.addCleanup(window._on_close)

        self.assertEqual(setup_calls, [db_path])
        self.assertTrue(window.auth_service.is_initialized())
        self.assertTrue(window.auth_service.is_authenticated())
        self.assertEqual(window.db.db_path, db_path)
        self.assertEqual(window.key_manager.load_key("active"), window.auth_service.get_active_key())

    def test_sync_active_key_from_auth_populates_key_manager_after_setup(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.key_manager = KeyManager()

        synced = window._sync_active_key_from_auth()

        self.assertTrue(synced)
        self.assertEqual(window.key_manager.load_key("active"), window.auth_service.get_active_key())

    def test_audit_log_keeps_entry_events_when_vault_is_locked_immediately(self):
        db_path = self.make_db_path("audit-lock.db")
        config = Config()
        config.set("database.path", db_path)

        auth_service = self.make_auth_service(db_path)
        password = "ValidMasterPass!9X"
        auth_service.register_master_password(password)
        auth_service.logout()

        patchers = self._patch_window_chrome()
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        with patch("src.gui.main_window.simpledialog.askstring", return_value=password), patch(
            "src.gui.main_window.messagebox.showerror"
        ), patch("src.gui.main_window.messagebox.showwarning"):
            window = MainWindow()
            self.addCleanup(window._on_close)

        window.entry_manager.create_entry(
            {
                "title": "Audit visible entry",
                "username": "demo",
                "password": "Secret!123",
                "url": "https://example.com",
                "notes": "",
                "category": "",
                "tags": "",
            }
        )
        window._lock_vault(show_dialog=False)

        audit_events = [log.event_type for log in window.db.get_audit_log_chain()]
        self.assertIn("entry_added", audit_events)
        self.assertIn("user_logged_out", audit_events)

    def test_panic_mode_is_written_to_audit_before_keys_are_cleared(self):
        db_path = self.make_db_path("panic-audit.db")
        config = Config()
        config.set("database.path", db_path)

        auth_service = self.make_auth_service(db_path)
        password = "ValidMasterPass!9X"
        auth_service.register_master_password(password)
        auth_service.logout()

        patchers = self._patch_window_chrome()
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        with patch("src.gui.main_window.simpledialog.askstring", return_value=password), patch(
            "src.gui.main_window.messagebox.showerror"
        ), patch("src.gui.main_window.messagebox.showwarning"):
            window = MainWindow()
            self.addCleanup(window._on_close)

        window._show_panic_notification = lambda method: None
        window.activate_panic_mode("test")

        audit_events = [log.event_type for log in window.db.get_audit_log_chain()]
        self.assertIn("panic_mode_activated", audit_events)


class TestMainWindowSearchAndFilter(IntegrationTestCase):
    def _make_window(self):
        window = MainWindow.__new__(MainWindow)
        window.table = FakeTable()
        window.search_var = FakeVar("")
        window.category_filter_var = FakeVar("Все")
        window.tag_filter_var = FakeVar("")
        window.updated_from_var = FakeVar("")
        window.updated_to_var = FakeVar("")
        window.password_strength_filter_var = FakeVar("Все")
        window.search_status_var = FakeVar("")
        window.search_entry = FakeEntryWidget()
        window.search_history_button = FakeButton()
        window.password_toggle_text = FakeVar("Показать пароли")
        window.passwords_visible = False
        window.password_visibility_overrides = {}
        window.search_history = []
        window.db = Database(self.make_db_path("search.db"))
        self.addCleanup(window.db.close)
        key_manager = KeyManager()
        key_manager.store_key("active", b"x" * 32)
        window.entry_manager = EntryManager(window.db, AESGCMEncryptionService(key_manager))
        window.root = FakeRoot()
        window._all_entries = [
            {
                "id": 1,
                "title": "GitHub",
                "username": "octocat",
                "password": "Secret!123",
                "category": "Work",
                "tags": "dev,code",
                "url": "github.com",
                "notes": "code hosting",
                "updated_at": datetime(2026, 3, 31, 20, 0),
                "_password_plain": "Secret!123",
                "_search_username": "octocat",
                "_search_url": "https://github.com",
                "_search_notes": "code hosting",
            },
            {
                "id": 2,
                "title": "Local Admin",
                "username": "admin",
                "password": "Local!456",
                "category": "Home",
                "tags": "infra,local",
                "url": "localhost",
                "notes": "local server",
                "updated_at": datetime(2026, 3, 31, 20, 5),
                "_password_plain": "Local!456",
                "_search_username": "admin",
                "_search_url": "http://localhost",
                "_search_notes": "local server",
            },
        ]
        return window

    def test_apply_entry_filter_supports_general_field_and_category_filters(self):
        window = self._make_window()

        window.search_var.set("github")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1])

        window.search_var.set("title:local")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [2])

        window.search_var.set("user:octo notes:hosting")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1])

        window.search_var.set("")
        window.category_filter_var.set("Home")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [2])
        self.assertEqual(window.search_status_var.get(), "Найдено: 1 из 2")

        window.category_filter_var.set("Все")
        window.tag_filter_var.set("dev")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1])

    def test_apply_entry_filter_supports_date_range_and_password_strength_filters(self):
        window = self._make_window()

        window.updated_from_var.set("2026-03-31")
        window.updated_to_var.set("2026-03-31")
        window.password_strength_filter_var.set("Средний")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1, 2])

        window.updated_from_var.set("2026-04-01")
        window._apply_entry_filter()
        self.assertEqual(window.table.rows, [])

        window.updated_from_var.set("")
        window.updated_to_var.set("")
        window.password_strength_filter_var.set("Слабый")
        window._apply_entry_filter()
        self.assertEqual(window.table.rows, [])

    def test_toggle_password_visibility_updates_table_rows(self):
        window = self._make_window()

        window._apply_entry_filter()
        self.assertNotEqual(window.table.rows[0]["password"], "Secret!123")

        result = window._toggle_password_visibility()
        self.assertEqual(result, "break")
        self.assertEqual(window.table.rows[0]["password"], "Secret!123  🙈")
        self.assertEqual(window.password_toggle_text.get(), "Скрыть пароли")

    def test_search_history_persists_and_reapplies_queries(self):
        window = self._make_window()

        for query in [f"query-{index}" for index in range(12)]:
            window._remember_search_query(query)

        self.assertEqual(len(window.search_history), 10)
        self.assertEqual(window.search_history[0], "query-11")
        self.assertEqual(window.search_history[-1], "query-2")
        self.assertFalse(window.search_history_button.disabled)

        stored_history = window.db.get_setting("ui.search_history", [])
        self.assertEqual(stored_history, window.search_history)

        window._apply_search_history_item("query-5")
        self.assertEqual(window.search_var.get(), "query-5")
        self.assertTrue(window.search_entry.focused)
        self.assertEqual(window.search_entry.selection, (0, tk.END))


class TestMainWindowDialogHelpers(IntegrationTestCase):
    def test_generated_entry_password_updates_strength_label(self):
        window = MainWindow.__new__(MainWindow)

        class PasswordGenerator:
            def generate(self, _options):
                return "StrongGenerated!123"

            def is_strong_enough(self, password):
                return password == "StrongGenerated!123"

        class PasswordEntryField:
            def __init__(self):
                self.value = ""
                self.show_password = type("ShowPassword", (), {"set": lambda _self, value: setattr(self, "visible", value)})()

            def set(self, value):
                self.value = value

            def get(self):
                return self.value

        class StringVar:
            def __init__(self):
                self.value = "Сложность пароля: не задан"

            def set(self, value):
                self.value = value

        dialog = type("Dialog", (), {"strength_var": StringVar(), "password_was_generated": False})()
        password_entry = PasswordEntryField()
        window.password_generator = PasswordGenerator()

        window._generate_entry_password(dialog, password_entry)

        self.assertTrue(dialog.password_was_generated)
        self.assertEqual(password_entry.get(), "StrongGenerated!123")
        self.assertEqual(dialog.strength_var.value, "Сложность пароля: сильный")

    def test_add_entry_does_not_open_form_when_unlock_is_cancelled(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window._require_login = lambda: setattr(window, "_login_requested", True)
        window._build_entry_dialog = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("entry dialog should not open while vault is locked")
        )

        window.add_entry()

        self.assertTrue(window._login_requested)

    def test_collect_entry_form_reads_category_tags_and_clipboard_policy_from_dialog(self):
        window = MainWindow.__new__(MainWindow)
        window.password_generator = type("PasswordGenerator", (), {"is_strong_enough": lambda _self, _password: True})()

        class Field:
            def __init__(self, value):
                self.value = value

            def get(self):
                return self.value

        class TextField:
            def get(self, _start, _end):
                return "notes"

        class BoolVar:
            def get(self):
                return True

        dialog = type(
            "Dialog",
            (),
            {
                "category_entry": Field("Games"),
                "tags_entry": Field("steam, launcher"),
                "clipboard_policy_var": BoolVar(),
                "password_was_generated": False,
            },
        )()

        collected = window._collect_entry_form(
            dialog,
            Field("Steam"),
            Field("ray"),
            Field("StrongSecret!123"),
            Field(""),
            TextField(),
        )

        self.assertEqual(collected, ("Steam", "ray", "StrongSecret!123", "", "notes", "Games", "steam, launcher", "never"))

    def test_build_favicon_request_normalizes_host_and_builds_service_url(self):
        window = MainWindow.__new__(MainWindow)

        request_data = window._build_favicon_request("github.com/login")
        self.assertEqual(request_data["host"], "github.com")
        self.assertIn("google.com/s2/favicons", request_data["service_url"])
        self.assertIn("github.com", request_data["service_url"])

        request_with_scheme = window._build_favicon_request("https://sub.example.com/path")
        self.assertEqual(request_with_scheme["host"], "sub.example.com")

        self.assertIsNone(window._build_favicon_request(""))

    def test_set_system_clipboard_flushes_event_loop(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()

        window._set_system_clipboard("Secret!123")

        self.assertEqual(window.root.clipboard, "Secret!123")
        self.assertEqual(window.root.update_calls, 1)

    def test_clear_clipboard_from_ui_clears_active_content(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.state = FakeStateManager()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.status = ClipboardStatus(active=True, data_type="password")
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window.clipboard_notice_label = FakeLabel()

        with patch("src.gui.main_window.messagebox.showinfo") as showinfo:
            window.clear_clipboard_from_ui()

        self.assertEqual(window.clipboard_service.clear_calls[-1]["reason"], "manual")
        self.assertEqual(window.clipboard_label.text, "Буфер обмена: пуст")
        self.assertIn("очищен вручную", showinfo.call_args.args[1])

    def test_clear_clipboard_from_ui_reports_empty_state(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.state = FakeStateManager()
        window.clipboard_service = FakeClipboardService()

        with patch("src.gui.main_window.messagebox.showinfo") as showinfo:
            window.clear_clipboard_from_ui()

        self.assertIn("уже пуст", showinfo.call_args.args[1])

    def test_clear_clipboard_from_ui_warns_when_system_clear_fails(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.state = FakeStateManager()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.status = ClipboardStatus(active=True, data_type="password")
        window._clear_system_clipboard = lambda sync_service=False: False

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window.clear_clipboard_from_ui()

        self.assertIn("Очистите его вручную", showwarning.call_args.args[1])

    def test_check_security_timers_warns_once_when_monitoring_fails(self):
        window = MainWindow.__new__(MainWindow)
        window.state = FakeStateManager()
        window.config = Config()
        window.key_storage = FakeKeyStorage()
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()
        window._clipboard_monitor_warning_shown = False
        window._refresh_clipboard_status = lambda: None
        window.clipboard_service.tick = lambda: None

        class FailingMonitor:
            def poll(self):
                raise RuntimeError("monitor failed")

        window.clipboard_monitor = FailingMonitor()

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window._check_security_timers()
            window._check_security_timers()

        self.assertEqual(showwarning.call_count, 1)

    def test_copy_selected_username_uses_clipboard_service(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window._on_activity = lambda: setattr(window, "_activity_called", True)
        window._get_clipboard_application_name = lambda: "cryptosafe-manager"
        entry = EntryView(
            {
                "id": 10,
                "title": "Example",
                "username": "demo-user",
                "encrypted_password": "Secret!123",
                "url": "",
                "notes": "",
                "clipboard_policy": "allow",
            }
        )
        window._get_single_selected_entry = lambda _action: entry

        window.copy_selected_username()

        self.assertEqual(window.clipboard_service.calls[0][0], "demo-user")
        self.assertEqual(window.clipboard_service.calls[0][1]["data_type"], "username")
        self.assertEqual(window.clipboard_service.calls[0][1]["application_name"], "cryptosafe-manager")
        self.assertEqual(window.clipboard_service.calls[0][1]["entry_clipboard_policy"], "allow")
        self.assertTrue(window._activity_called)

    def test_copy_selected_all_uses_clipboard_service(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window._on_activity = lambda: setattr(window, "_activity_called", True)
        window._get_clipboard_application_name = lambda: "cryptosafe-manager"
        window._decrypt_password = lambda _value: "Secret!123"
        entry = EntryView(
            {
                "id": 11,
                "title": "Example",
                "username": "demo-user",
                "encrypted_password": "encrypted",
                "url": "https://example.com",
                "notes": "note",
                "clipboard_policy": "allow",
            }
        )
        window._get_single_selected_entry = lambda _action: entry

        window.copy_selected_all()

        copied_text = window.clipboard_service.calls[0][0]
        self.assertIn("Название: Example", copied_text)
        self.assertIn("Пароль: Secret!123", copied_text)
        self.assertEqual(window.clipboard_service.calls[0][1]["data_type"], "entry")
        self.assertEqual(window.clipboard_service.calls[0][1]["application_name"], "cryptosafe-manager")
        self.assertEqual(window.clipboard_service.calls[0][1]["entry_clipboard_policy"], "allow")
        self.assertTrue(window._activity_called)

    def test_copy_selected_username_passes_never_policy_for_protected_entry(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window._on_activity = lambda: setattr(window, "_activity_called", True)
        window._get_clipboard_application_name = lambda: "cryptosafe-manager"
        entry = EntryView(
            {
                "id": 12,
                "title": "Protected",
                "username": "demo-user",
                "encrypted_password": "Secret!123",
                "url": "",
                "notes": "",
                "clipboard_policy": "never",
            }
        )
        window._get_single_selected_entry = lambda _action: entry

        window.copy_selected_username()

        self.assertEqual(window.clipboard_service.calls[0][1]["entry_clipboard_policy"], "never")

    def test_refresh_clipboard_status_shows_preview_and_warning(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window.clipboard_preview_button = FakeButton()
        window.clipboard_service.status = ClipboardStatus(
            active=True,
            data_type="password",
            source_entry_id=11,
            source_label="Example",
            preview="Sec*****",
            remaining_seconds=4,
            warning_emitted=True,
        )

        window._refresh_clipboard_status()

        self.assertEqual(window.clipboard_label.text, "Буфер обмена: пароль (4 сек)")
        self.assertIn("Источник: Example", window.clipboard_details_label.text)
        self.assertIn("Просмотр: Sec*****", window.clipboard_details_label.text)
        self.assertIn("Скоро очистка: 4 сек", window.clipboard_details_label.text)

        self.assertFalse(window.clipboard_preview_button.disabled)

    def test_refresh_clipboard_status_disables_preview_button_when_empty(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window.clipboard_preview_button = FakeButton()

        window._refresh_clipboard_status()

        self.assertTrue(window.clipboard_preview_button.disabled)

    def test_reauthenticate_for_sensitive_action_accepts_valid_master_password(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.auth_service = FakeAuthServiceForReveal()
        window.key_manager = FakeKeyManager()

        with patch("src.gui.main_window.simpledialog.askstring", return_value="ValidMasterPass!9X"):
            result = window._reauthenticate_for_sensitive_action("Показать содержимое буфера обмена")

        self.assertTrue(result)
        self.assertEqual(window.auth_service.password_checks[-1], "ValidMasterPass!9X")

    def test_reauthenticate_for_sensitive_action_rejects_invalid_password(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.auth_service = FakeAuthServiceForReveal()
        window.key_manager = FakeKeyManager()

        with patch("src.gui.main_window.simpledialog.askstring", return_value="wrong"), patch(
            "src.gui.main_window.messagebox.showerror"
        ) as showerror:
            result = window._reauthenticate_for_sensitive_action("Показать содержимое буфера обмена")

        self.assertFalse(result)
        self.assertTrue(showerror.called)

    def test_get_full_clipboard_value_for_preview_returns_secret_after_reauth(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.auth_service = FakeAuthServiceForReveal()
        window.key_manager = FakeKeyManager()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.revealed_text = "TopSecret!789"

        with patch("src.gui.main_window.simpledialog.askstring", return_value="ValidMasterPass!9X"):
            full_value = window._get_full_clipboard_value_for_preview()

        self.assertEqual(full_value, "TopSecret!789")

    def test_show_clipboard_preview_dialog_reports_empty_clipboard(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()

        with patch("src.gui.main_window.messagebox.showinfo") as showinfo:
            window.show_clipboard_preview_dialog()

        self.assertIn("Буфер обмена пуст", showinfo.call_args.args[1])

    def test_on_clipboard_status_changed_updates_notice_and_table_marker(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.table = object()
        window.entry_manager = object()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window._clipboard_status_snapshot = ClipboardStatus(active=False)
        window._apply_entry_filter = lambda: setattr(window, "_filter_refreshed", True)
        window._show_clipboard_notification_area_message = lambda message: setattr(window, "_notification_message", message)

        status = ClipboardStatus(
            active=True,
            data_type="username",
            source_entry_id=12,
            source_label="GitHub",
            preview="d*****r",
            remaining_seconds=12,
        )

        window._on_clipboard_status_changed(status)

        self.assertEqual(window.clipboard_notice_label.text, "Скопировано: логин")
        self.assertEqual(window.clipboard_label.text, "Буфер обмена: логин (12 сек)")
        self.assertTrue(window._filter_refreshed)

    def test_format_entry_title_for_table_marks_active_clipboard_entry(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.status = ClipboardStatus(active=True, source_entry_id=42, data_type="entry")

        marked_title = window._format_entry_title_for_table({"id": 42, "title": "Example"})
        plain_title = window._format_entry_title_for_table({"id": 41, "title": "Another"})

        self.assertEqual(marked_title, "Example [В буфере]")
        self.assertEqual(plain_title, "Another")

    def test_on_clipboard_status_changed_uses_notification_area_when_window_minimized(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.root.window_state = "iconic"
        window.table = object()
        window.entry_manager = object()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window._clipboard_status_snapshot = ClipboardStatus(active=False)
        window._apply_entry_filter = lambda: None
        window._show_clipboard_notification_area_message = lambda message: setattr(window, "_notification_message", message)

        status = ClipboardStatus(active=True, data_type="password", remaining_seconds=15)

        window._on_clipboard_status_changed(status)

        self.assertEqual(window._notification_message, "Буфер обмена: скопирован пароль (системный буфер)")

    def test_show_in_system_tray_withdraws_window_when_tray_available(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window._system_tray_icon = object()
        window._system_tray_visible = False
        window._update_system_tray_status = lambda status=None: setattr(window, "_tray_status_updated", True)

        window._show_in_system_tray()

        self.assertEqual(window.root.window_state, "withdrawn")
        self.assertTrue(window._system_tray_visible)
        self.assertTrue(window._tray_status_updated)

    def test_restore_from_system_tray_restores_window_state(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.root.window_state = "withdrawn"
        window._system_tray_icon = object()
        window._system_tray_visible = True
        window._update_system_tray_status = lambda status=None: setattr(window, "_tray_status_updated", True)

        window._restore_from_system_tray()

        self.assertEqual(window.root.window_state, "normal")
        self.assertFalse(window._system_tray_visible)
        self.assertTrue(window._tray_status_updated)

    def test_system_tray_menu_labels_cover_security_actions(self):
        window = MainWindow.__new__(MainWindow)

        labels = window._get_system_tray_menu_labels()

        self.assertIn("Показать окно", labels)
        self.assertIn("Заблокировать хранилище", labels)
        self.assertIn("Разблокировать хранилище", labels)
        self.assertIn("Очистить буфер обмена", labels)
        self.assertIn("Быстрый поиск", labels)
        self.assertIn("Паник-режим", labels)
        self.assertIn("Настройки", labels)
        self.assertIn("Выход", labels)

    def test_tray_actions_are_scheduled_on_tk_thread(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window._ui_task_queue = queue.Queue()
        calls = []

        window._run_on_ui_thread(lambda: calls.append("tray"))

        self.assertEqual(calls, [])
        self.assertEqual(window._ui_task_queue.qsize(), 1)
        window._ui_task_pump_active = True
        window._process_ui_task_queue()
        self.assertEqual(calls, ["tray"])

    def test_system_tray_state_changes_for_lock_alert_and_crypto_operation(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = False
        window._tray_crypto_operation_active = False

        self.assertEqual(window._get_system_tray_state(ClipboardStatus(active=False)), "locked")

        window.auth_service.authenticated = True
        self.assertEqual(window._get_system_tray_state(ClipboardStatus(active=False)), "unlocked")

        failed_status = ClipboardStatus(active=False, suspicious_activity=True)
        self.assertEqual(window._get_system_tray_state(failed_status), "alert")

        window._tray_crypto_operation_active = True
        self.assertEqual(window._get_system_tray_state(failed_status), "crypto")

    def test_system_tray_icon_uses_green_for_unlocked_and_red_for_locked(self):
        window = MainWindow.__new__(MainWindow)

        locked_pixel = window._build_system_tray_icon_image("locked").getpixel((2, 2))
        unlocked_pixel = window._build_system_tray_icon_image("unlocked").getpixel((2, 2))

        self.assertGreater(locked_pixel[0], locked_pixel[1])
        self.assertGreater(unlocked_pixel[1], unlocked_pixel[0])

    def test_update_system_tray_status_refreshes_icon_and_animates_crypto_operation(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window._system_tray_icon = FakeTrayIcon()
        window._tray_crypto_operation_active = False
        window._tray_animation_frame = 0
        window._get_clipboard_status = lambda: ClipboardStatus(active=False)
        built_states = []
        window._build_system_tray_icon_image = lambda state, frame=0: built_states.append((state, frame)) or f"{state}-{frame}"

        window._update_system_tray_status(ClipboardStatus(active=False))
        self.assertEqual(window._system_tray_icon.icon, "unlocked-0")

        window._set_crypto_operation_active(True)
        self.assertEqual(built_states[-1][0], "crypto")
        self.assertGreater(window._tray_animation_frame, 0)
        self.assertIn("криптооперация", window._system_tray_icon.title)

    def test_unlock_vault_refreshes_system_tray_to_unlocked_state(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window._system_tray_icon = FakeTrayIcon()
        window._tray_crypto_operation_active = False
        window._tray_animation_frame = 0
        window._get_clipboard_status = lambda: ClipboardStatus(active=False)
        window._load_entries = lambda: None
        window._set_status = lambda text: setattr(window, "_status", text)
        built_states = []
        window._build_system_tray_icon_image = lambda state, frame=0: built_states.append((state, frame)) or f"{state}-{frame}"

        self.assertTrue(window._unlock_vault())

        self.assertEqual(window._system_tray_icon.icon, "unlocked-0")
        self.assertEqual(built_states[-1][0], "unlocked")

    def test_tray_quick_search_restores_window_and_applies_query(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window._system_tray_icon = object()
        window._system_tray_visible = True
        window._update_system_tray_status = lambda status=None: None
        window.search_var = FakeVar("")
        window.search_entry = FakeEntryWidget()
        window.search_history = []
        window.db = type("FakeDb", (), {"set_setting": lambda self, key, value: setattr(self, "saved", (key, value))})()
        window._update_search_history_button = lambda: None
        window._apply_entry_filter = lambda: setattr(window, "_filter_applied", True)

        window._apply_tray_quick_search("github")

        self.assertEqual(window.root.window_state, "normal")
        self.assertEqual(window.search_var.get(), "github")
        self.assertTrue(window._filter_applied)
        self.assertTrue(window.search_entry.focused)

    def test_system_tray_title_includes_vault_and_clipboard_state(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True

        title = window._build_system_tray_title(
            ClipboardStatus(active=True, data_type="password", delivery_mode="memory_only", remaining_seconds=12)
        )

        self.assertIn("хранилище разблокировано", title)
        self.assertIn("пароль", title)
        self.assertIn("внутренняя память", title)
        self.assertIn("12 сек", title)

    def test_update_clipboard_notification_area_shows_failed_clear_message_when_window_unfocused(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.root.focus_displayof = lambda: None
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.last_clear_reason = "timeout"
        window.clipboard_service.last_clear_failed = True
        window._show_clipboard_notification_area_message = lambda message: setattr(window, "_notification_message", message)

        previous_status = ClipboardStatus(active=True, data_type="password")
        current_status = ClipboardStatus(active=False)

        window._update_clipboard_notification_area(previous_status, current_status)

        self.assertIn("системный буфер обмена мог сохраниться", window._notification_message)

    def test_detect_clipboard_preset_returns_matching_profile_or_custom(self):
        window = MainWindow.__new__(MainWindow)

        secure_preset = window._detect_clipboard_preset(
            timeout_seconds=15,
            notifications_enabled=True,
            security_level="advanced",
            blocked_on_suspicious=False,
            delivery_mode="system",
        )
        custom_preset = window._detect_clipboard_preset(
            timeout_seconds=42,
            notifications_enabled=False,
            security_level="advanced",
            blocked_on_suspicious=True,
            delivery_mode="memory_only",
        )

        self.assertEqual(secure_preset, "secure")
        self.assertEqual(custom_preset, "custom")

    def test_build_clipboard_settings_summary_includes_allowed_applications(self):
        window = MainWindow.__new__(MainWindow)

        summary = window._build_clipboard_settings_summary(
            timeout_seconds=20,
            notifications_enabled=True,
            security_level="advanced",
            blocked_on_suspicious=True,
            delivery_mode="memory_only",
            allowed_applications="explorer, code, keepassxc",
        )

        self.assertIn("Разрешённые приложения: explorer, code, keepassxc", summary)

    def test_apply_clipboard_preset_to_vars_updates_all_fields(self):
        window = MainWindow.__new__(MainWindow)
        timeout_var = FakeVar(30)
        notifications_var = FakeVar(True)
        security_level_var = FakeVar("basic")
        delivery_mode_var = FakeVar("memory_only")
        blocked_var = FakeVar(False)

        applied = window._apply_clipboard_preset_to_vars(
            "public_computer",
            timeout_var=timeout_var,
            notifications_var=notifications_var,
            security_level_var=security_level_var,
            delivery_mode_var=delivery_mode_var,
            blocked_var=blocked_var,
        )

        self.assertTrue(applied)
        self.assertEqual(timeout_var.get(), 5)
        self.assertTrue(notifications_var.get())
        self.assertEqual(security_level_var.get(), "paranoid")
        self.assertEqual(delivery_mode_var.get(), "system")
        self.assertTrue(blocked_var.get())

    def test_update_clipboard_notice_respects_notification_setting(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()

        previous_status = ClipboardStatus(active=False)
        current_status = ClipboardStatus(active=True, data_type="password", remaining_seconds=30)

        window.clipboard_service.settings["notifications_enabled"] = False
        window._update_clipboard_notice(previous_status, current_status)
        self.assertEqual(window.clipboard_notice_label.text, "")

        window.clipboard_service.settings["notifications_enabled"] = True
        window._update_clipboard_notice(previous_status, current_status)
        self.assertEqual(window.clipboard_notice_label.text, "Скопировано: пароль")

    def test_update_clipboard_notice_shows_monitor_warning_reason(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_service.last_clear_reason = "monitor_warning"

        previous_status = ClipboardStatus(active=True, data_type="password")
        current_status = ClipboardStatus(active=False)

        window._update_clipboard_notice(previous_status, current_status)

        self.assertEqual(window.clipboard_notice_label.text, "Буфер обмена очищен из-за подозрительной активности")

    def test_handle_clipboard_security_alert_shows_warning_once_per_transition(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()
        previous_status = ClipboardStatus(active=True, suspicious_activity=False)
        current_status = ClipboardStatus(
            active=True,
            data_type="password",
            source_label="GitHub",
            preview="Sec*****",
            suspicious_activity=True,
            blocked_future_copies=True,
        )

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window._handle_clipboard_security_alert(previous_status, current_status)
            window._handle_clipboard_security_alert(current_status, current_status)

        self.assertEqual(showwarning.call_count, 1)
        warning_text = showwarning.call_args.args[1]
        self.assertIn("подозрительная активность", warning_text)
        self.assertIn("GitHub", warning_text)
        self.assertIn("временно заблокированы", warning_text)

    def test_refresh_clipboard_status_shows_copy_block_message(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window.clipboard_service.status = ClipboardStatus(
            active=True,
            data_type="entry",
            source_label="Example",
            preview="E******e",
            suspicious_activity=True,
            blocked_future_copies=True,
        )

        window._refresh_clipboard_status()

        self.assertIn("Обнаружена подозрительная активность", window.clipboard_details_label.text)
        self.assertIn("Дальнейшее копирование временно заблокировано", window.clipboard_details_label.text)

    def test_suggest_usernames_prefers_existing_domain_matches_and_domain_patterns(self):
        window = MainWindow.__new__(MainWindow)
        window._all_entries = [
            {"username": "deploy@example.com", "url": "https://app.example.com"},
            {"username": "admin", "url": "http://localhost"},
        ]

        suggestions = window._suggest_usernames_for_url("https://mail.example.com/login")
        self.assertEqual(suggestions[0], "deploy@example.com")
        self.assertIn("admin@example.com", suggestions)

        localhost_suggestions = window._suggest_usernames_for_url("localhost")
        self.assertEqual(localhost_suggestions[0], "admin")
        self.assertIn("root", localhost_suggestions)


    def test_format_audit_log_line_for_clipboard_copy_is_human_readable(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_copied"
            timestamp = datetime(2026, 4, 7, 12, 30, 0)
            entry_id = 7
            details = "entry_id=7, data_type=password, timeout_seconds=30, source_label=GitHub"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("Копирование в буфер обмена", line)
        self.assertIn("entry=7", line)
        self.assertIn("тип=пароль", line)
        self.assertIn("источник=GitHub", line)
        self.assertIn("таймаут=30 сек", line)

    def test_format_audit_log_line_for_clipboard_clear_expands_reason(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_cleared"
            timestamp = datetime(2026, 4, 7, 12, 30, 1)
            entry_id = 7
            details = "reason=monitor_warning, entry_id=7, data_type=password, observed_length=21"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("Очистка буфера обмена", line)
        self.assertIn("Буфер обмена очищен из-за подозрительной активности", line)
        self.assertIn("тип=пароль", line)
        self.assertIn("наблюдаемая длина=21", line)

    def test_format_audit_log_line_for_clipboard_clear_includes_monitor_reason(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_cleared"
            timestamp = datetime(2026, 4, 7, 12, 30, 2)
            entry_id = None
            details = "reason=monitor_warning, monitor_reason=external_clear, data_type=password, observed_length=0"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("external_clear", line)

    def test_format_clipboard_clear_reason_handles_manual_and_replacement(self):
        window = MainWindow.__new__(MainWindow)

        self.assertEqual(window._format_clipboard_clear_reason("manual"), "Буфер обмена очищен вручную")
        self.assertEqual(
            window._format_clipboard_clear_reason("replacement"),
            "Буфер обмена заменён новым содержимым",
        )

    def test_update_clipboard_notice_mentions_failed_system_clear(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_service.last_clear_reason = "timeout"
        window.clipboard_service.last_clear_failed = True

        previous_status = ClipboardStatus(active=True, data_type="password")
        current_status = ClipboardStatus(active=False)

        window._update_clipboard_notice(previous_status, current_status)

        self.assertIn("системный буфер обмена мог сохраниться", window.clipboard_notice_label.text)
        self.assertIn("Очистите буфер обмена вручную", window.clipboard_notice_label.text)

    def test_handle_clipboard_clear_failure_shows_warning_for_failed_service_clear(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_service.last_clear_reason = "vault_locked"
        window.clipboard_service.last_clear_failed = True

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window._handle_clipboard_clear_failure()

        self.assertIn("Очистите буфер обмена вручную", showwarning.call_args.args[1])
        self.assertIn("системный буфер обмена мог сохраниться", window.clipboard_notice_label.text)

    def test_format_audit_log_line_for_clipboard_error_is_human_readable(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_error"
            timestamp = datetime(2026, 4, 10, 10, 30, 0)
            entry_id = 7
            details = "operation=copy, error_code=adapter_write_failed, entry_id=7, data_type=password"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("Ошибка буфера обмена", line)
        self.assertIn("операция копирования", line)
        self.assertIn("сбой записи через системный адаптер", line)
        self.assertIn("тип=пароль", line)

    def test_format_audit_log_line_for_application_not_allowed_error(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_error"
            timestamp = datetime(2026, 4, 10, 10, 31, 0)
            entry_id = 7
            details = "operation=copy, error_code=application_not_allowed, application_name=telegram, entry_id=7, data_type=password"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("telegram", line)

    def test_parse_audit_details_supports_json_payload(self):
        window = MainWindow.__new__(MainWindow)

        parsed = window._parse_audit_details('{"reason":"monitor_warning","entry_id":7,"data_type":"password"}')

        self.assertEqual(parsed["reason"], "monitor_warning")
        self.assertEqual(parsed["entry_id"], "7")
        self.assertEqual(parsed["data_type"], "password")

    def test_build_audit_log_view_model_uses_filters_and_pagination(self):
        window = MainWindow.__new__(MainWindow)

        class FakeAuditDb:
            def __init__(self):
                self.query_calls = []
                self.count_calls = []

            def query_audit_logs(self, **kwargs):
                self.query_calls.append(kwargs)

                class AuditLogRecord:
                    sequence_number = 5
                    action = "settings_changed"
                    event_type = "settings_changed"
                    timestamp = datetime(2026, 5, 12, 10, 0, 0)
                    severity = "WARN"
                    user_id = "local-user"
                    source = "configuration"
                    entry_id = None
                    details = '{"scope":"security"}'
                    previous_hash = "a" * 64
                    entry_hash = "b" * 64
                    entry_data = '{"event_type":"settings_changed"}'
                    signature = "deadbeef"
                    public_key = "cafebabe"

                return [AuditLogRecord()]

            def count_audit_logs(self, **kwargs):
                self.count_calls.append(kwargs)
                return 75

        window.db = FakeAuditDb()

        model = window._build_audit_log_view_model(
            search_text="settings",
            event_type="settings_changed",
            severity="WARN",
            user_id="local-user",
            date_from="2026-05-01",
            date_to="2026-05-31",
            page=2,
        )

        self.assertEqual(model["page"], 2)
        self.assertEqual(model["total_pages"], 2)
        self.assertEqual(model["total_count"], 75)
        self.assertEqual(len(model["logs"]), 1)
        self.assertEqual(window.db.query_calls[-1]["offset"], 50)
        self.assertEqual(window.db.query_calls[-1]["search_text"], "settings")
        self.assertEqual(window.db.count_calls[-1]["severity"], "WARN")

    def test_sort_audit_logs_orders_records_by_requested_column(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            def __init__(self, sequence_number, severity, timestamp):
                self.sequence_number = sequence_number
                self.action = "settings_changed"
                self.event_type = "settings_changed"
                self.timestamp = timestamp
                self.severity = severity
                self.user_id = "local-user"
                self.source = "configuration"
                self.entry_id = None

        logs = [
            AuditLogRecord(1, "WARN", datetime(2026, 5, 12, 10, 0, 0)),
            AuditLogRecord(2, "CRITICAL", datetime(2026, 5, 12, 9, 0, 0)),
            AuditLogRecord(3, "INFO", datetime(2026, 5, 12, 11, 0, 0)),
        ]

        sorted_logs = window._sort_audit_logs(logs, "severity", descending=True)

        self.assertEqual([log.sequence_number for log in sorted_logs], [2, 1, 3])

    def test_sort_audit_logs_orders_by_sequence_number_for_latest_audit_events(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            def __init__(self, sequence_number):
                self.sequence_number = sequence_number
                self.action = "entry_added"
                self.event_type = "entry_added"
                self.timestamp = datetime(2026, 5, 16, 20, 0, 0)
                self.severity = "INFO"
                self.user_id = "local-user"
                self.source = "vault"
                self.entry_id = sequence_number

        logs = [AuditLogRecord(515), AuditLogRecord(526), AuditLogRecord(502)]

        sorted_logs = window._sort_audit_logs(logs, "sequence_number", descending=True)

        self.assertEqual([log.sequence_number for log in sorted_logs], [526, 515, 502])

    def test_format_audit_timestamp_displays_aware_utc_as_local_time(self):
        window = MainWindow.__new__(MainWindow)
        timestamp = datetime(2026, 5, 16, 21, 2, 50, tzinfo=timezone.utc)

        formatted = window._format_audit_timestamp(timestamp)

        self.assertEqual(formatted, timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S"))

    def test_build_audit_event_frequency_orders_by_count_and_formats_labels(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            def __init__(self, event_type):
                self.action = event_type
                self.event_type = event_type

        logs = [
            AuditLogRecord("settings_changed"),
            AuditLogRecord("settings_changed"),
            AuditLogRecord("user_login_failed"),
            AuditLogRecord("clipboard_error"),
            AuditLogRecord("settings_changed"),
            AuditLogRecord("user_login_failed"),
        ]

        frequency = window._build_audit_event_frequency(logs, limit=2)

        self.assertEqual(frequency[0]["event_type"], "settings_changed")
        self.assertEqual(frequency[0]["count"], 3)
        self.assertEqual(frequency[1]["event_type"], "user_login_failed")

    def test_audit_dashboard_frequency_uses_7_30_90_day_windows(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            def __init__(self, event_type, timestamp):
                self.action = event_type
                self.event_type = event_type
                self.timestamp = timestamp
                self.severity = "INFO"
                self.user_id = "local-user"

        now = datetime(2026, 5, 16, 12, 0, 0)
        logs = [
            AuditLogRecord("settings_changed", now),
            AuditLogRecord("clipboard_cleared", now.replace(day=6)),
            AuditLogRecord("user_login_failed", datetime(2026, 3, 20, 12, 0, 0)),
            AuditLogRecord("entry_created", datetime(2026, 1, 1, 12, 0, 0)),
        ]

        self.assertEqual(len(window._filter_audit_logs_by_days(logs, 7, now=now)), 1)
        self.assertEqual(len(window._filter_audit_logs_by_days(logs, 30, now=now)), 2)
        self.assertEqual(len(window._filter_audit_logs_by_days(logs, 90, now=now)), 3)

    def test_build_audit_dashboard_lines_include_integrity_and_security_metrics(self):
        window = MainWindow.__new__(MainWindow)
        window._audit_integrity_status = {
            "verified": False,
            "invalid_entries": [{"sequence_number": 8, "reason": "invalid_signature"}],
            "chain_breaks": [{"sequence_number": 9}],
        }

        class FakeAuditDb:
            def get_audit_archives(self, limit=100):
                return [{"id": 1}, {"id": 2}]

            def get_audit_security_events(self, limit=100):
                return [{"id": 1}, {"id": 2}, {"id": 3}]

        class AuditLogRecord:
            def __init__(self, sequence_number, event_type, severity, user_id):
                self.sequence_number = sequence_number
                self.action = event_type
                self.event_type = event_type
                self.severity = severity
                self.user_id = user_id

        window.db = FakeAuditDb()
        logs = [
            AuditLogRecord(1, "settings_changed", "WARN", "alice"),
            AuditLogRecord(2, "user_login_failed", "CRITICAL", "alice"),
            AuditLogRecord(3, "clipboard_error", "CRITICAL", "bob"),
        ]

        lines = window._build_audit_dashboard_lines(logs, total_count=42)
        joined = "\n".join(lines)

        self.assertIn("Записей в текущем представлении: 3 из 42", joined)
        self.assertIn("Статус целостности: требует внимания", joined)
        self.assertIn("Ошибок проверки: 1, разрывов цепочки: 1", joined)
        self.assertIn("Критических событий: 2, предупреждений: 1", joined)
        self.assertIn("Архивов журнала: 2, security events: 3", joined)

    def test_build_audit_log_detail_lines_for_failed_login_include_ip_and_time(self):
        window = MainWindow.__new__(MainWindow)
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.signer = type(
            "Signer",
            (),
            {"verify": staticmethod(lambda data, signature, public_key: True)},
        )()

        class AuditLogRecord:
            sequence_number = 11
            action = "user_login_failed"
            event_type = "user_login_failed"
            timestamp = datetime(2026, 5, 12, 22, 15, 0)
            severity = "WARN"
            user_id = "local-user"
            source = "authentication"
            entry_id = None
            details = '{"ip":"127.0.0.1","reason":"invalid_password"}'
            previous_hash = "a" * 64
            entry_hash = "b" * 64
            entry_data = '{"event_type":"user_login_failed","details":{"ip":"127.0.0.1"}}'
            signature = "deadbeef"
            public_key = "cafebabe"

        lines = window._build_audit_log_detail_lines(AuditLogRecord())
        joined = "\n".join(lines)

        self.assertIn("IP: 127.0.0.1", joined)
        self.assertIn("Время неуспешной попытки:", joined)

    def test_highlight_vault_entry_from_audit_log_selects_row_in_main_table(self):
        window = MainWindow.__new__(MainWindow)

        class FakeTree:
            def __init__(self):
                self.selected = None
                self.focused = None
                self.seen = None

            def selection_set(self, item_id):
                self.selected = item_id

            def focus(self, item_id):
                self.focused = item_id

            def see(self, item_id):
                self.seen = item_id

        class FakeMainTable:
            def __init__(self):
                self.data = [{"id": 7, "title": "GitHub"}, {"id": 9, "title": "Mail"}]
                self.tree = FakeTree()

        statuses = []
        window.table = FakeMainTable()
        window._set_status = lambda text: statuses.append(text)

        class AuditLogRecord:
            entry_id = 9

        result = window._highlight_vault_entry_from_audit_log(AuditLogRecord())

        self.assertTrue(result)
        self.assertEqual(window.table.tree.selected, "1")
        self.assertIn("#9", statuses[-1])

    def test_get_audit_log_context_actions_returns_expected_actions(self):
        window = MainWindow.__new__(MainWindow)

        class VaultAuditLog:
            event_type = "entry_updated"
            action = "entry_updated"
            entry_id = 7

        class AuthAuditLog:
            event_type = "user_login_failed"
            action = "user_login_failed"
            entry_id = None

        vault_actions = window._get_audit_log_context_actions(VaultAuditLog())
        auth_actions = window._get_audit_log_context_actions(AuthAuditLog())

        self.assertEqual(vault_actions[0]["id"], "show_vault_entry")
        self.assertEqual(auth_actions[0]["id"], "inspect_failed_login")

    @pytest.mark.slow
    def test_audit_viewer_memory_for_10000_entries_stays_under_50mb(self):
        window = MainWindow.__new__(MainWindow)

        class FakeAuditDb:
            def query_audit_logs(self, **kwargs):
                records = []
                for index in range(10000):
                    record = type(
                        "AuditLogRecord",
                        (),
                        {
                            "sequence_number": index + 1,
                            "action": "settings_changed",
                            "event_type": "settings_changed",
                            "timestamp": datetime(2026, 5, 12, 10, 0, 0),
                            "severity": "INFO",
                            "user_id": "local-user",
                            "source": "configuration",
                            "entry_id": None,
                            "details": '{"scope":"security"}',
                            "previous_hash": "a" * 64,
                            "entry_hash": "b" * 64,
                            "entry_data": '{"event_type":"settings_changed"}',
                            "signature": "deadbeef",
                            "public_key": "cafebabe",
                        },
                    )()
                    records.append(record)
                return records

            def count_audit_logs(self, **kwargs):
                return 10000

        window.db = FakeAuditDb()

        tracemalloc.start()
        model = window._build_audit_log_view_model(page=1, page_size=10000)
        rows = window._build_audit_tree_rows(model["logs"])
        _current, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(len(rows), 10000)
        self.assertLess(peak_memory, 50 * 1024 * 1024)

    def test_build_audit_log_detail_lines_include_signature_status_and_hash_chain(self):
        window = MainWindow.__new__(MainWindow)
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.signer = type(
            "Signer",
            (),
            {"verify": staticmethod(lambda data, signature, public_key: True)},
        )()

        class AuditLogRecord:
            sequence_number = 8
            action = "settings_changed"
            event_type = "settings_changed"
            timestamp = datetime(2026, 5, 12, 10, 0, 0)
            severity = "WARN"
            user_id = "local-user"
            source = "configuration"
            entry_id = None
            details = '{"scope":"security","changed_keys":"clipboard_timeout"}'
            previous_hash = "a" * 64
            entry_hash = "b" * 64
            entry_data = '{"event_type":"settings_changed","details":{"scope":"security"}}'
            signature = "deadbeef"
            public_key = "cafebabe"

        lines = window._build_audit_log_detail_lines(AuditLogRecord())
        joined = "\n".join(lines)

        self.assertIn("Статус подписи: валидна", joined)
        self.assertIn("Предыдущий хэш:", joined)
        self.assertIn("Текущий хэш:", joined)
        self.assertIn("- scope: security", joined)

    def test_run_audit_verification_manual_success_shows_message(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()

        published_events = []
        with patch("src.gui.main_window.event_bus.publish", side_effect=lambda event: published_events.append(event)), patch(
            "src.gui.main_window.messagebox.showinfo"
        ) as showinfo:
            result = window.run_audit_verification(manual=True)

        self.assertTrue(result["verified"])
        self.assertEqual(published_events[-1].type.value, "audit_verification_passed")
        self.assertTrue(showinfo.called)

    def test_run_periodic_audit_verification_uses_recent_limit_from_policy(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window._last_audit_verification_at = datetime(2026, 5, 10, 10, 0, 0)
        window.audit_logger = FakeAuditLogger()
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True

        class FakeAuditDb:
            def get_audit_verification_policy(self):
                return {"interval_seconds": 60, "recent_entry_limit": 1000, "lock_on_tampering": False}

            def get_latest_audit_log(self):
                return type("AuditLogRecord", (), {"sequence_number": 2500})()

        window.db = FakeAuditDb()

        with patch("src.gui.main_window.datetime") as fake_datetime:
            fake_datetime.now.return_value = datetime(2026, 5, 10, 10, 5, 0)
            window._run_periodic_audit_verification_if_due()

        self.assertEqual(window.audit_logger.verify_calls[-1]["start_sequence"], 1501)
        self.assertEqual(window.audit_logger.verify_calls[-1]["limit"], 1000)

    def test_run_audit_verification_failure_writes_separate_security_event(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.verification_result = {
            "verified": False,
            "total_entries": 4,
            "valid_entries": 2,
            "invalid_entries": [{"sequence_number": 7, "reason": "invalid_signature"}],
            "chain_breaks": [],
            "recovery_options": ["restore_from_backup"],
        }

        class FakeAuditDb:
            def __init__(self):
                self.security_events = []

            def add_audit_security_event(self, event_type, **kwargs):
                self.security_events.append({"event_type": event_type, **kwargs})
                return 1

        window.db = FakeAuditDb()

        with patch("src.gui.main_window.event_bus.publish"), patch("src.gui.main_window.messagebox.showwarning"):
            result = window.run_audit_verification(manual=False, trigger="startup")

        self.assertFalse(result["verified"])
        self.assertEqual(window.db.security_events[-1]["event_type"], "audit_verification_failed")
        self.assertEqual(window.db.security_events[-1]["related_sequence_number"], 7)

    def test_export_audit_verification_report_writes_json_file(self):
        temp_dir = Path(self.make_db_path("audit-verification-report")).parent
        report_path = temp_dir / "audit-verification-report.json"
        self.addCleanup(lambda: report_path.unlink(missing_ok=True) if report_path.exists() else None)

        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()

        with patch("src.gui.main_window.filedialog.asksaveasfilename", return_value=str(report_path)), patch(
            "src.gui.main_window.event_bus.publish"
        ) as publish, patch("src.gui.main_window.messagebox.showinfo"):
            result = window.export_audit_verification_report()

        self.assertTrue(result)
        self.assertTrue(report_path.exists())
        self.assertIn('"verified": true', report_path.read_text(encoding="utf-8"))
        self.assertTrue(publish.called)

    def test_build_audit_export_payload_includes_signed_json_metadata(self):
        window = MainWindow.__new__(MainWindow)
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.signer = type("Signer", (), {"public_key_hex": "cafebabe"})()

        class AuditLogRecord:
            sequence_number = 3
            timestamp = datetime(2026, 5, 12, 10, 0, 0)
            action = "settings_changed"
            event_type = "settings_changed"
            severity = "WARN"
            user_id = "local-user"
            source = "configuration"
            entry_id = None
            details = '{"scope":"security"}'
            previous_hash = "a" * 64
            entry_hash = "b" * 64
            signature = "deadbeef"
            public_key = "cafebabe"

        payload = window._build_audit_export_payload([AuditLogRecord()], "json")

        self.assertIn('"public_key": "cafebabe"', payload)
        self.assertIn('"event_type": "settings_changed"', payload)
        self.assertIn('"entries"', payload)

    def test_build_audit_export_payload_supports_cef_format(self):
        window = MainWindow.__new__(MainWindow)
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.signer = type("Signer", (), {"public_key_hex": "cafebabe"})()

        class AuditLogRecord:
            sequence_number = 3
            timestamp = datetime(2026, 5, 12, 10, 0, 0)
            action = "settings_changed"
            event_type = "settings_changed"
            severity = "WARN"
            user_id = "local-user"
            source = "configuration"
            entry_id = None
            details = '{"scope":"security"}'
            previous_hash = "a" * 64
            entry_hash = "b" * 64
            signature = "deadbeef"
            public_key = "cafebabe"

        payload = window._build_audit_export_payload([AuditLogRecord()], "cef")

        self.assertTrue(payload.startswith("CEF:0|CryptoSafe|Manager|5|"))
        self.assertIn("cs1Label=source", payload)
        self.assertIn("msg=", payload)

    def test_encrypt_and_decrypt_audit_export_payload_roundtrip(self):
        key_manager = FakeKeyManager()
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.vault_crypto = AESGCMEncryptionService(key_manager)

        encrypted_payload = window._encrypt_audit_export_payload('{"event_type":"settings_changed"}', "json")
        decrypted = window._decrypt_audit_export_payload(encrypted_payload)

        self.assertEqual(decrypted["content_format"], "json")
        self.assertEqual(decrypted["payload"].decode("utf-8"), '{"event_type":"settings_changed"}')

    def test_export_audit_logs_requires_reauth_and_logs_export_operation(self):
        temp_dir = Path(self.make_db_path("audit-export-target")).parent
        export_path = temp_dir / "audit-log.json"
        self.addCleanup(lambda: export_path.unlink(missing_ok=True) if export_path.exists() else None)

        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.signer = type("Signer", (), {"public_key_hex": "cafebabe"})()
        window._reauthenticate_for_sensitive_action = lambda action_name: True
        window.auth_service = FakeAuthService()
        window.vault_crypto = AESGCMEncryptionService(FakeKeyManager())

        class FakeAuditDb:
            def count_audit_logs(self, **kwargs):
                return 1

            def query_audit_logs(self, **kwargs):
                class AuditLogRecord:
                    sequence_number = 3
                    timestamp = datetime(2026, 5, 12, 10, 0, 0)
                    action = "settings_changed"
                    event_type = "settings_changed"
                    severity = "WARN"
                    user_id = "local-user"
                    source = "configuration"
                    entry_id = None
                    details = '{"scope":"security"}'
                    previous_hash = "a" * 64
                    entry_hash = "b" * 64
                    signature = "deadbeef"
                    public_key = "cafebabe"

                return [AuditLogRecord()]

        window.db = FakeAuditDb()
        published_events = []

        with patch("src.gui.main_window.filedialog.asksaveasfilename", return_value=str(export_path)), patch(
            "src.gui.main_window.event_bus.publish", side_effect=lambda event: published_events.append(event)
        ), patch("src.gui.main_window.messagebox.showinfo"):
            result = window.export_audit_logs("json", severity="WARN")

        self.assertTrue(result)
        self.assertTrue(export_path.exists())
        exported_bytes = export_path.read_bytes()
        exported_text = exported_bytes.decode("utf-8")
        self.assertIn('"encrypted": true', exported_text)
        self.assertNotIn('"event_type": "settings_changed"', exported_text)
        decrypted = window._decrypt_audit_export_payload(exported_bytes)
        self.assertIn('"event_type": "settings_changed"', decrypted["payload"].decode("utf-8"))
        self.assertEqual(published_events[-1].type.value, "audit_log_exported")
        self.assertEqual(published_events[-1].data["format"], "json")
        self.assertEqual(published_events[-1].data["record_count"], 1)
        self.assertTrue(published_events[-1].data["encrypted"])

    def test_get_audit_export_schedule_policy_normalizes_defaults_and_values(self):
        window = MainWindow.__new__(MainWindow)

        class FakeAuditDb:
            def get_setting(self, key, default=None):
                self.requested_key = key
                return {
                    "enabled": True,
                    "interval_seconds": 60,
                    "formats": ["json", "cef", "pdf", "invalid"],
                    "export_directory": "C:/exports",
                    "max_age_days": 0,
                    "max_files": 0,
                    "include_verification_report": False,
                    "last_run_at": "2026-05-16T10:00:00",
                }

        window.db = FakeAuditDb()

        policy = window._get_audit_export_schedule_policy()

        self.assertEqual(window.db.requested_key, "audit.export_schedule_policy")
        self.assertTrue(policy["enabled"])
        self.assertEqual(policy["interval_seconds"], 300)
        self.assertEqual(policy["formats"], ["json", "cef", "pdf"])
        self.assertEqual(policy["max_age_days"], 1)
        self.assertEqual(policy["max_files"], 1)
        self.assertFalse(policy["include_verification_report"])

    def test_perform_scheduled_audit_exports_creates_export_and_report_and_updates_policy(self):
        temp_dir = Path(self.make_db_path("scheduled-audit-exports")).parent / "scheduled-exports"
        temp_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(temp_dir, ignore_errors=True))

        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.auth_service = FakeAuthService()
        window.vault_crypto = AESGCMEncryptionService(FakeKeyManager())
        window.audit_logger = FakeAuditLogger()
        window.audit_logger.signer = type("Signer", (), {"public_key_hex": "cafebabe"})()

        class FakeAuditDb:
            def __init__(self):
                self.saved_policy = None

            def count_audit_logs(self, **kwargs):
                return 1

            def query_audit_logs(self, **kwargs):
                class AuditLogRecord:
                    sequence_number = 3
                    timestamp = datetime(2026, 5, 12, 10, 0, 0)
                    action = "settings_changed"
                    event_type = "settings_changed"
                    severity = "WARN"
                    user_id = "local-user"
                    source = "configuration"
                    entry_id = None
                    details = '{"scope":"security"}'
                    previous_hash = "a" * 64
                    entry_hash = "b" * 64
                    signature = "deadbeef"
                    public_key = "cafebabe"

                return [AuditLogRecord()]

            def set_setting(self, key, value, encrypted=False):
                self.saved_policy = {"key": key, "value": value, "encrypted": encrypted}

        window.db = FakeAuditDb()
        published_events = []
        policy = {
            "enabled": True,
            "interval_seconds": 300,
            "formats": ["json"],
            "export_directory": str(temp_dir),
            "max_age_days": 30,
            "max_files": 20,
            "include_verification_report": True,
            "last_run_at": "",
        }

        with patch("src.gui.main_window.event_bus.publish", side_effect=lambda event: published_events.append(event)):
            result = window._perform_scheduled_audit_exports(policy)

        self.assertTrue(result)
        self.assertIsNotNone(window.db.saved_policy)
        self.assertEqual(window.db.saved_policy["key"], "audit.export_schedule_policy")
        exported_files = sorted(path.name for path in temp_dir.iterdir())
        self.assertEqual(len(exported_files), 2)
        self.assertTrue(any(name.startswith("audit-log-") for name in exported_files))
        self.assertTrue(any(name.startswith("verification-report-") for name in exported_files))
        self.assertTrue(published_events)
        self.assertTrue(published_events[-1].data["scheduled"])

    def test_cleanup_scheduled_audit_exports_removes_old_and_excess_files(self):
        temp_dir = Path(self.make_db_path("scheduled-audit-cleanup")).parent / "scheduled-cleanup"
        temp_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(temp_dir, ignore_errors=True))

        window = MainWindow.__new__(MainWindow)
        stale_file = temp_dir / "audit-log-old.json"
        keep_one = temp_dir / "audit-log-newer.json"
        keep_two = temp_dir / "verification-report-newest.json"
        for file_path in (stale_file, keep_one, keep_two):
            file_path.write_text("{}", encoding="utf-8")

        now_ts = datetime.now().timestamp()
        old_ts = now_ts - (3 * 24 * 60 * 60)
        os.utime(stale_file, (old_ts, old_ts))
        os.utime(keep_one, (now_ts - 60, now_ts - 60))
        os.utime(keep_two, (now_ts, now_ts))

        window._cleanup_scheduled_audit_exports(str(temp_dir), max_age_days=1, max_files=1)

        remaining_files = sorted(path.name for path in temp_dir.iterdir())
        self.assertEqual(remaining_files, ["verification-report-newest.json"])

    def test_build_clipboard_diagnostics_lines_includes_platform_and_memory_sections(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.status = ClipboardStatus(
            active=True,
            data_type="password",
            source_label="GitHub",
            preview="Sec*****",
            remaining_seconds=12,
            delivery_mode="memory_only",
        )
        window.clipboard_service.settings["delivery_mode"] = "memory_only"
        window.clipboard_service.settings["security_level"] = "advanced"
        window.clipboard_service.inspect_memory_exposure = lambda _probe: {
            "delivery_mode": "memory_only",
            "in_mask_buffer": False,
            "in_text_mask_buffer": False,
            "in_source_label": False,
            "in_state_manager": False,
        }

        with patch("src.gui.main_window.get_platform_validation_report", return_value={
            "adapters": [
                {"name": "macos_appkit", "available": True},
                {"name": "pyperclip", "available": False},
            ]
        }):
            lines = window._build_clipboard_diagnostics_lines()

        joined = "\n".join(lines)
        self.assertIn("Диагностика защищённого буфера обмена", joined)
        self.assertIn("Режим доставки: внутренняя память", joined)
        self.assertIn("Проверка системного адаптера", joined)
        self.assertIn("macos_appkit: доступен", joined)
        self.assertIn("pyperclip: недоступен", joined)
        self.assertIn("Проверка следов в памяти", joined)
        self.assertIn("открытый текст в state_manager: нет", joined)

    def test_check_security_timers_publishes_clipboard_error_when_monitor_fails(self):
        window = MainWindow.__new__(MainWindow)
        window.state = FakeStateManager()
        window.config = Config()
        window.key_storage = FakeKeyStorage()
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()
        window._clipboard_monitor_warning_shown = False
        window._refresh_clipboard_status = lambda: None
        window.clipboard_service.tick = lambda: None

        class FailingMonitor:
            def poll(self):
                raise RuntimeError("monitor failed")

        window.clipboard_monitor = FailingMonitor()
        published_events = []

        with patch("src.gui.main_window.event_bus.publish", side_effect=lambda event: published_events.append(event)), patch(
            "src.gui.main_window.messagebox.showwarning"
        ):
            window._check_security_timers()

        self.assertEqual(published_events[-1].type.value, "clipboard_error")
        self.assertEqual(published_events[-1].data["operation"], "monitor_poll")
        self.assertEqual(published_events[-1].data["error_code"], "monitor_unavailable")

class TestMainWindowSecurityState(IntegrationTestCase):
    def test_lock_vault_clears_decrypted_entries_and_password_visibility_state(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.key_manager = FakeKeyManager()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.table = FakeTable()
        window.table.set_data([{"id": 1, "title": "Visible"}])
        window.password_toggle_text = FakeVar("Скрыть пароли")
        window.search_status_var = FakeVar("Найдено: 1")
        window.passwords_visible = True
        window.password_visibility_overrides = {1: True}
        window._all_entries = [{"id": 1, "password": "Secret!123"}]
        window._set_status = lambda value: setattr(window, "_status_value", value)

        with patch("src.gui.main_window.event_bus.publish"), patch.object(MainWindow, "_require_login") as require_login:
            window._lock_vault(show_dialog=False)

        self.assertTrue(window.auth_service.logged_out)
        self.assertTrue(window.key_manager.cleared)
        self.assertTrue(window.state.clipboard_cleared)
        self.assertEqual(window._all_entries, [])
        self.assertFalse(window.passwords_visible)
        self.assertEqual(window.password_visibility_overrides, {})
        self.assertEqual(window.password_toggle_text.get(), "Показать пароли")
        self.assertEqual(window.search_status_var.get(), "Найдено: 0")
        self.assertEqual(window.table.rows, [])
        self.assertEqual(window._status_value, "Заблокировано")
        self.assertFalse(require_login.called)

    def test_lock_if_window_minimized_locks_authenticated_session(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.root.window_state = "iconic"
        window._lock_vault = lambda show_dialog=True, **_kwargs: setattr(window, "_locked_with", show_dialog)

        window._lock_if_window_minimized()

        self.assertFalse(window.state.application_active)
        self.assertEqual(window._locked_with, False)

    def test_activity_monitor_tick_locks_authenticated_session(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.state = FakeStateManager()
        window.key_storage = FakeKeyStorage()
        def fake_lock(show_dialog=True, **_kwargs):
            setattr(window, "_locked_with", show_dialog)
        window._lock_vault = fake_lock
        window.activity_monitor = type(
            "Monitor",
            (),
            {"tick_calls": 0, "tick": lambda monitor: setattr(monitor, "tick_calls", monitor.tick_calls + 1) or fake_lock(False) or True},
        )()
        window._refresh_clipboard_status = lambda: None
        window.clipboard_service = None
        window.clipboard_monitor = None

        window._check_security_timers()

        self.assertEqual(window.activity_monitor.tick_calls, 1)
        self.assertEqual(window._locked_with, False)

    def test_on_activity_records_source_in_activity_monitor(self):
        window = MainWindow.__new__(MainWindow)
        window.state = FakeStateManager()
        window.state.is_unlocked = lambda: True
        window.state.key_cache_timeout = 3600
        window.state.update_activity = lambda: setattr(window, "_state_activity_updated", True)
        window.key_storage = FakeKeyStorage()
        window.activity_monitor = FakeActivityMonitor()
        event = type("FakeEvent", (), {"type": "KeyPress"})()

        window._on_activity(event)

        self.assertTrue(window._state_activity_updated)
        self.assertEqual(window.activity_monitor.recorded_sources, ["keyboard"])

    def test_accessibility_summary_documents_keyboard_and_feedback_support(self):
        window = MainWindow.__new__(MainWindow)

        summary = window._get_accessibility_summary()

        self.assertTrue(summary["keyboard_only"])
        self.assertTrue(summary["screen_reader_labels"])
        self.assertTrue(summary["long_operation_progress"])
        self.assertEqual(summary["shortcuts"]["Ctrl+F"], "focus_search")
        self.assertEqual(summary["shortcuts"]["Ctrl+Shift+Esc"], "panic_mode")
        self.assertEqual(summary["shortcuts"]["Ctrl+Alt+P"], "panic_mode_fallback")
        self.assertEqual(summary["shortcuts"]["Ctrl+L"], "lock_vault")
        self.assertEqual(summary["shortcuts"]["Ctrl+N"], "add_entry")

    def test_keyboard_shortcuts_bind_panic_and_common_actions(self):
        class BindingRoot(FakeRoot):
            def __init__(self):
                super().__init__()
                self.bindings = []

            def bind_all(self, sequence, callback, add=None):
                self.bindings.append((sequence, callback, add))

        window = MainWindow.__new__(MainWindow)
        window.root = BindingRoot()
        window.config = Config()
        window._register_global_panic_hotkey = lambda: setattr(window, "_global_registration_attempted", True)

        window._setup_activity_tracking()

        sequences = [binding[0] for binding in window.root.bindings]
        self.assertIn("<Control-Shift-Escape>", sequences)
        self.assertIn("<Control-Shift-P>", sequences)
        self.assertIn("<Control-Alt-p>", sequences)
        self.assertIn("<Control-l>", sequences)
        self.assertIn("<Control-u>", sequences)
        self.assertIn("<Control-n>", sequences)
        self.assertTrue(window._global_registration_attempted)

    def test_keypress_fallback_handles_password_toggle_and_panic_hotkey(self):
        window = MainWindow.__new__(MainWindow)
        calls = []
        window._toggle_password_visibility = lambda event=None: calls.append("toggle") or "break"
        window._handle_shortcut = lambda action, event=None: calls.append(action) or "break"

        ctrl_shift_p = type("Event", (), {"keysym": "P", "state": 0x0004 | 0x0001})()
        ctrl_alt_p = type("Event", (), {"keysym": "p", "state": 0x0004 | 0x0008})()

        self.assertEqual(window._handle_hotkey_keypress(ctrl_shift_p), "break")
        self.assertEqual(window._handle_hotkey_keypress(ctrl_alt_p), "break")
        self.assertEqual(calls, ["toggle", "panic_mode"])

    def test_prepare_dialog_applies_accessibility_metadata(self):
        window = MainWindow.__new__(MainWindow)
        dialog = FakeDialog()

        prepared = window._prepare_dialog(dialog)

        self.assertIs(prepared, dialog)
        self.assertTrue(dialog.configured["takefocus"])
        self.assertEqual(dialog.options["*TakeFocus"], 1)
        self.assertTrue(dialog._cryptosafe_keyboard_navigation)
        self.assertEqual(dialog._cryptosafe_accessibility_role, "dialog")

    def test_activate_panic_mode_locks_clears_hides_and_logs_event(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.root = FakeRoot()
        window._clear_system_clipboard = lambda sync_service=True: setattr(window, "_clipboard_cleared", sync_service) or True
        window._lock_vault = lambda show_dialog=True, **_kwargs: setattr(window, "_locked_with", show_dialog)
        window._clear_sensitive_view_state = lambda: setattr(window, "_view_cleared", True)
        window._flush_audit_logger = lambda: setattr(window, "_audit_flushed", True)
        window._show_panic_notification = lambda method: setattr(window, "_panic_notification_method", method)
        window.panic_mode = window._create_panic_mode()
        events = []

        with patch("src.gui.main_window.event_bus.publish", lambda event: events.append(event)):
            result = window.activate_panic_mode("hotkey")

        self.assertTrue(result.activated)
        self.assertTrue(window._clipboard_cleared)
        self.assertEqual(window._locked_with, False)
        self.assertTrue(window._view_cleared)
        self.assertEqual(window.root.window_state, "withdrawn")
        self.assertEqual(window._panic_notification_method, "hotkey")
        self.assertEqual(events[-1].type, EventType.PANIC_MODE_ACTIVATED)
        self.assertNotIn("Secret!123", str(events[-1].data))

    def test_panic_mode_closes_child_windows_before_hiding_root(self):
        class ChildWindow:
            def __init__(self):
                self.destroyed = False
                self.grab_released = False

            def grab_release(self):
                self.grab_released = True

            def winfo_toplevel(self):
                return self

            def destroy(self):
                self.destroyed = True

        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        child = ChildWindow()
        window.root.winfo_children = lambda: [child]

        window._hide_windows_for_panic()

        self.assertTrue(child.grab_released)
        self.assertTrue(child.destroyed)
        self.assertEqual(window.root.window_state, "withdrawn")

    def test_recover_from_panic_mode_restores_window_and_unlock_flow(self):
        window = MainWindow.__new__(MainWindow)
        window.config = Config()
        window.root = FakeRoot()
        window.root.window_state = "withdrawn"
        window.panic_mode = window._create_panic_mode()
        window._unlock_vault = lambda: setattr(window, "_unlock_called", True) or True

        recovered = window.recover_from_panic_mode()

        self.assertTrue(recovered)
        self.assertTrue(window._unlock_called)
        self.assertEqual(window.root.window_state, "normal")
        self.assertFalse(window.panic_mode.activated)

    def test_panic_mouse_shake_gesture_activates_panic_mode(self):
        window = MainWindow.__new__(MainWindow)
        window.config = Config()
        window._panic_gesture_samples = []
        window.panic_mode = type("FakePanic", (), {"activated": False})()
        activated_methods = []
        def fake_activate(method="manual"):
            window.panic_mode.activated = True
            activated_methods.append(method)
        window.activate_panic_mode = fake_activate

        for x_position in (100, 250, 90, 260, 80, 270, 75):
            window._record_panic_gesture(FakeMotionEvent(x_position))

        self.assertEqual(activated_methods, ["mouse_gesture"])
        self.assertEqual(window._panic_gesture_samples, [])

    def test_panic_stealth_actions_support_fake_error_decoy_and_redirect(self):
        window = MainWindow.__new__(MainWindow)
        window.config = Config()
        window.config.set("security.panic_fake_error", True)
        window.config.set("security.panic_decoy_command", "calc")
        window.config.set("security.panic_redirect_url", "https://example.com")

        with patch("src.gui.main_window.messagebox.showerror") as showerror, patch(
            "src.gui.main_window.subprocess.Popen"
        ) as popen, patch("src.gui.main_window.webbrowser.open") as open_url:
            window._execute_panic_stealth_actions()

        self.assertTrue(showerror.called)
        popen.assert_called_once_with("calc", shell=True)
        open_url.assert_called_once_with("https://example.com")

    def test_prompt_unlock_if_needed_reloads_entries_after_restore(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = False
        window.key_manager = FakeKeyManager()
        window._initial_login_completed = True
        window._login_prompt_active = False
        window._require_login = lambda initial=False: setattr(window.auth_service, "authenticated", True)
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)

        window._prompt_unlock_if_needed()

        self.assertTrue(window.auth_service.authenticated)
        self.assertTrue(window._entries_reloaded)

    def test_unlock_vault_button_flow_prompts_login_and_reloads_entries(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = False
        window.config = Config()
        window.key_manager = FakeKeyManager()
        window._initial_login_completed = True
        window._login_prompt_active = False
        window._require_login = lambda initial=False: setattr(window.auth_service, "authenticated", True)
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)

        unlocked = window._unlock_vault()

        self.assertTrue(unlocked)
        self.assertTrue(window.auth_service.authenticated)
        self.assertTrue(window._entries_reloaded)

    def test_unlock_vault_button_forces_prompt_even_before_initial_login_flag(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = False
        window.key_manager = FakeKeyManager()
        window._initial_login_completed = False
        window._login_prompt_active = False
        window._require_login = lambda initial=False: setattr(window.auth_service, "authenticated", True)
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)

        unlocked = window._unlock_vault()

        self.assertTrue(unlocked)
        self.assertTrue(window._entries_reloaded)

    def test_unlock_vault_recovers_from_panic_state(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = False
        window.config = Config()
        window.key_manager = FakeKeyManager()
        window.root = FakeRoot()
        window._initial_login_completed = True
        window._login_prompt_active = False
        window.panic_mode = window._create_panic_mode()
        window.panic_mode.activated = True
        window._require_login = lambda initial=False: setattr(window.auth_service, "authenticated", True)
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)

        unlocked = window._unlock_vault()

        self.assertTrue(unlocked)
        self.assertFalse(window.panic_mode.activated)
        self.assertEqual(window.root.window_state, "normal")
        self.assertTrue(window._entries_reloaded)

    def test_focus_loss_lock_preserves_active_clipboard_handoff(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.state = FakeStateManager()
        window.state.application_active = False
        window.state.clipboard_content = "Secret!123"
        window.root = FakeRoot()
        window.root.focus_displayof = lambda: None
        window._lock_vault = lambda show_dialog=True, **kwargs: setattr(
            window,
            "_locked_with",
            {"show_dialog": show_dialog, **kwargs},
        )

        window._lock_if_application_inactive()

        self.assertEqual(
            window._locked_with,
            {"show_dialog": False, "preserve_clipboard": True, "reason": "focus_loss"},
        )

    def test_focus_loss_lock_preserves_temporary_clipboard_until_timeout(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.key_manager = FakeKeyManager()
        window.state = FakeStateManager()
        window.state.clipboard_content = "Secret!123"
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()
        window.clipboard_service = FakeClipboardService()
        window._clear_sensitive_view_state = lambda: setattr(window, "_view_cleared", True)
        window._clear_system_clipboard = lambda sync_service=True: setattr(window, "_system_clipboard_cleared", True)
        window._handle_clipboard_clear_failure = lambda: setattr(window, "_clear_failure_checked", True)
        window._set_status = lambda text: setattr(window, "_status", text)
        events = []

        with patch("src.gui.main_window.event_bus.publish", lambda event: events.append(event)):
            window._lock_vault(show_dialog=False, preserve_clipboard=True, reason="focus_loss")

        self.assertTrue(window.auth_service.logged_out)
        self.assertTrue(window.key_manager.cleared)
        self.assertEqual(window.state.clipboard_content, "Secret!123")
        self.assertFalse(window.state.clipboard_cleared)
        self.assertFalse(hasattr(window, "_system_clipboard_cleared"))
        self.assertFalse(window.clipboard_service.clear_calls)
        self.assertTrue(window._view_cleared)
        self.assertEqual(window._status, "Заблокировано")
        self.assertEqual(events[-1].data, {"reason": "focus_loss", "preserve_clipboard": True})

    def test_vault_locked_event_preserves_clipboard_when_requested(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()

        window._on_vault_locked_event(Event(EventType.VAULT_LOCKED, {"preserve_clipboard": True}))

        self.assertFalse(window.clipboard_service.clear_calls)

    def test_focus_loss_lock_is_suspended_while_internal_dialog_is_active(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.state = FakeStateManager()
        window.state.application_active = False
        window.root = FakeRoot()
        window.root.focus_displayof = lambda: None
        window._internal_modal_depth = 1
        window._lock_vault = lambda show_dialog=True, **_kwargs: setattr(window, "_locked_with", show_dialog)

        window._lock_if_application_inactive()

        self.assertTrue(window.state.application_active)
        self.assertFalse(hasattr(window, "_locked_with"))

    def test_internal_warning_does_not_schedule_focus_loss_lock(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.state = FakeStateManager()
        window._internal_modal_depth = 1

        window._on_focus_out()

        self.assertTrue(window.state.application_active)
        self.assertEqual(window.root.after_calls, [])

    def test_combobox_popdown_focus_loss_does_not_crash_or_lock(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.state = FakeStateManager()
        window.root.grab_current = lambda: (_ for _ in ()).throw(KeyError("popdown"))

        window._on_focus_out()

        self.assertTrue(window.state.application_active)
        self.assertEqual(window.root.after_calls, [])

    def test_clipboard_expiration_locks_unfocused_window_when_focus_lock_is_enabled(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.key_storage = FakeKeyStorage()
        window.state = FakeStateManager()
        window.state.application_active = False
        window.state.clipboard_timer = object()
        window.state.clipboard_content = None
        window.root = FakeRoot()
        window.clipboard_label = FakeLabel()
        window._lock_vault = lambda show_dialog=True, **_kwargs: setattr(window, "_locked_with", show_dialog)
        window._clear_system_clipboard = lambda: setattr(window, "_clipboard_cleared", True)

        with patch("src.gui.main_window.event_bus.publish"):
            window._check_security_timers()

        self.assertTrue(window._clipboard_cleared)
        self.assertEqual(window._locked_with, False)

    def test_on_close_clears_sensitive_state_and_destroys_window(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.key_manager = FakeKeyManager()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()
        window.db = Database(self.make_db_path("close-test.db"))
        self.addCleanup(window.db.close)
        window.db.set_setting(MainWindow.CLIPBOARD_RECOVERY_PENDING_KEY, True)
        window.clipboard_service = FakeClipboardService()
        window._clear_sensitive_view_state = lambda: setattr(window, "_view_cleared", True)
        window._clear_system_clipboard = lambda sync_service=True: True
        window._handle_clipboard_clear_failure = lambda: setattr(window, "_clear_failure_checked", True)

        window._on_close()

        self.assertTrue(window.auth_service.logged_out)
        self.assertTrue(window.key_manager.cleared)
        self.assertTrue(window.state.clipboard_cleared)
        self.assertTrue(window._view_cleared)
        self.assertTrue(window._clear_failure_checked)
        self.assertTrue(window.audit_logger.closed)
        self.assertTrue(window.root.destroyed)
        self.assertFalse(window.db.get_setting(MainWindow.CLIPBOARD_RECOVERY_PENDING_KEY, True))

    # Устаревшая локальная проверка не входит в автоматический набор.
    def legacy_on_close_warns_when_clipboard_clear_failed(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.key_manager = FakeKeyManager()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()
        window.db = Database(self.make_db_path("close-failed-clear.db"))
        self.addCleanup(window.db.close)
        window.clipboard_service = FakeClipboardService()
        window._clear_sensitive_view_state = lambda: None

        def fake_clear_system_clipboard(sync_service=True):
            window.clipboard_service.last_clear_reason = "manual"
            window.clipboard_service.last_clear_failed = True
            return False

        window._clear_system_clipboard = fake_clear_system_clipboard

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window._on_close()

        self.assertTrue(showwarning.called)
        """
        self.assertIn("Очистите буфер обмена вручную", showwarning.call_args.args[1])
        """
        self.assertIn("Очистите буфер обмена вручную", showwarning.call_args.args[1])

    def test_run_startup_clipboard_recovery_clears_pending_clipboard(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.db = Database(self.make_db_path("startup-recovery.db"))
        self.addCleanup(window.db.close)
        window.db.set_setting(MainWindow.CLIPBOARD_RECOVERY_PENDING_KEY, True)
        window.clipboard_service = FakeClipboardService()
        window._handle_clipboard_clear_failure = lambda: setattr(window, "_startup_failure_handled", True)
        window._clear_system_clipboard = lambda sync_service=False: True

        window._setup_clipboard_recovery_tracking()
        window._run_startup_clipboard_recovery()

        self.assertTrue(window._startup_clipboard_recovery_performed)
        self.assertFalse(window._startup_clipboard_recovery_failed)
        self.assertEqual(
            window.clipboard_service.clear_calls[-1],
            {"reason": "startup_recovery", "publish_event": False},
        )
        self.assertFalse(getattr(window, "_startup_failure_handled", False))
        self.assertTrue(window.db.get_setting(MainWindow.CLIPBOARD_RECOVERY_PENDING_KEY, False))

    def test_run_startup_clipboard_recovery_warns_when_system_clear_fails(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.db = Database(self.make_db_path("startup-recovery-failed.db"))
        self.addCleanup(window.db.close)
        window.db.set_setting(MainWindow.CLIPBOARD_RECOVERY_PENDING_KEY, True)
        window.clipboard_service = FakeClipboardService()
        window._clear_system_clipboard = lambda sync_service=False: False
        window._handle_clipboard_clear_failure = lambda: setattr(window, "_startup_failure_handled", True)

        window._setup_clipboard_recovery_tracking()
        window._run_startup_clipboard_recovery()

        self.assertTrue(window._startup_clipboard_recovery_performed)
        self.assertTrue(window._startup_clipboard_recovery_failed)
        self.assertTrue(window._startup_failure_handled)
        self.assertEqual(window.clipboard_service.last_clear_reason, "startup_recovery")
        self.assertTrue(window.clipboard_service.last_clear_failed)

    def test_run_startup_clipboard_recovery_clears_stale_root_clipboard_value(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.root.clipboard = "stale-secret"
        window.db = Database(self.make_db_path("startup-recovery-stale-root.db"))
        self.addCleanup(window.db.close)
        window.db.set_setting(MainWindow.CLIPBOARD_RECOVERY_PENDING_KEY, True)
        window.clipboard_service = FakeClipboardService()
        window._clear_windows_clipboard = lambda: False
        window._handle_clipboard_clear_failure = lambda: setattr(window, "_startup_failure_handled", True)

        window._setup_clipboard_recovery_tracking()
        window._run_startup_clipboard_recovery()

        self.assertEqual(window.root.clipboard, "")
        self.assertGreater(window.root.update_calls, 0)
        self.assertEqual(
            window.clipboard_service.clear_calls[-1],
            {"reason": "startup_recovery", "publish_event": False},
        )
        self.assertFalse(getattr(window, "_startup_failure_handled", False))

    def test_on_close_warns_when_clipboard_clear_failed_with_readable_message(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.key_manager = FakeKeyManager()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.audit_logger = FakeAuditLogger()
        window.db = Database(self.make_db_path("close-failed-clear-readable.db"))
        self.addCleanup(window.db.close)
        window.clipboard_service = FakeClipboardService()
        window._clear_sensitive_view_state = lambda: None

        def fake_clear_system_clipboard(sync_service=True):
            window.clipboard_service.last_clear_reason = "manual"
            window.clipboard_service.last_clear_failed = True
            return False

        window._clear_system_clipboard = fake_clear_system_clipboard

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window._on_close()

        self.assertTrue(showwarning.called)
        self.assertIn(
            "\u041e\u0447\u0438\u0441\u0442\u0438\u0442\u0435 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430 \u0432\u0440\u0443\u0447\u043d\u0443\u044e",
            showwarning.call_args.args[1],
        )

    def test_vault_export_import_gui_helpers_roundtrip_encrypted_json(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-import-export-gui")).parent
        export_path = temp_dir / "vault-export.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None
        window._show_warning = lambda *args, **kwargs: None
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)

        exported = window.export_vault_encrypted_json_to_path(str(export_path), "ExportPassword!123")
        window.entry_manager.entries = []
        result = window.import_vault_file(
            str(export_path),
            import_format="encrypted_json",
            password="ExportPassword!123",
            mode="merge",
        )

        self.assertTrue(exported)
        self.assertEqual(result["created"], 1)
        self.assertEqual(window.entry_manager.entries[0]["title"], "GitHub")
        self.assertTrue(getattr(window, "_entries_reloaded", False))

    def test_vault_export_preview_lists_scope_fields_and_titles(self):
        window = MainWindow.__new__(MainWindow)
        window.db = Database(self.make_db_path("vault-export-preview.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: [EntryView(window.entry_manager.entries[0])]

        preview = window.build_vault_export_preview(selected_only=True, excluded_fields=["notes"])

        self.assertEqual(preview["mode"], "selected")
        self.assertEqual(preview["entry_count"], 1)
        self.assertIn("GitHub", preview["titles"])
        self.assertIn("notes", preview["excluded_fields"])
        self.assertNotIn("notes", preview["included_fields"])

    def test_vault_export_helper_applies_selected_fields_and_strength(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-export-fields")).parent
        export_path = temp_dir / "vault-export.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None

        result = window.export_vault_encrypted_json_to_path(
            str(export_path),
            "ExportPassword!123",
            include_fields=["title", "username", "password"],
            encryption_strength=128,
            compression=False,
        )
        preview = window.preview_vault_import_file(
            str(export_path),
            import_format="encrypted_json",
            password="ExportPassword!123",
        )
        exported_payload = json.loads(export_path.read_text(encoding="utf-8"))

        self.assertTrue(result)
        self.assertEqual(exported_payload["encryption"]["algorithm"], "AES-128-GCM")
        self.assertEqual(preview["validated"], 1)
        self.assertEqual(preview["titles"], ["GitHub"])

    def test_vault_export_helper_uses_explicit_dialog_entry_selection(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-export-explicit-selection")).parent
        export_path = temp_dir / "vault-export-selected.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window.entry_manager.entries.append(
            {
                "id": 2,
                "title": "Steam",
                "username": "ray-steam",
                "password": "SteamSecret!123",
                "url": "https://steam.example",
                "notes": "games",
                "category": "Games",
                "tags": "steam",
            }
        )
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None

        result = window.export_vault_encrypted_json_to_path(
            str(export_path),
            "ExportPassword!123",
            selected_only=True,
            selected_entry_ids=[2],
        )
        preview = window.preview_vault_import_file(
            str(export_path),
            import_format="encrypted_json",
            password="ExportPassword!123",
        )

        self.assertTrue(result)
        self.assertEqual(preview["validated"], 1)
        self.assertEqual(preview["titles"], ["Steam"])

    def test_vault_import_preview_dry_run_does_not_create_entries(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-import-preview")).parent
        export_path = temp_dir / "vault-export.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None

        window.export_vault_encrypted_json_to_path(str(export_path), "ExportPassword!123")
        window.entry_manager.entries = []
        preview = window.preview_vault_import_file(
            str(export_path),
            import_format="encrypted_json",
            password="ExportPassword!123",
        )

        self.assertEqual(preview["mode"], "dry-run")
        self.assertEqual(preview["validated"], 1)
        self.assertEqual(preview["titles"], ["GitHub"])
        self.assertEqual(window.entry_manager.entries, [])

    def test_vault_import_auto_detects_native_and_password_manager_formats(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-import-detect")).parent
        native_path = temp_dir / "vault-export.json"
        bitwarden_path = temp_dir / "bitwarden.json"
        bitwarden_encrypted_path = temp_dir / "bitwarden-protected.json"
        lastpass_path = temp_dir / "lastpass.csv"
        share_path = temp_dir / "entry-share.cs-share.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None

        window.export_vault_encrypted_json_to_path(str(native_path), "ExportPassword!123")
        bitwarden_path.write_text('{"items":[{"type":1,"name":"Example","login":{"username":"u","password":"p"}}]}', encoding="utf-8")
        bitwarden_encrypted_path.write_text('{"encrypted":true,"passwordProtected":true,"data":"2.a|b|c"}', encoding="utf-8")
        lastpass_path.write_text("url,username,password,extra,name,grouping\nhttps://e.test,u,p,,Example,Work\n", encoding="utf-8")
        share_path.write_text(
            SharingService(window.entry_manager).create_password_share_package(
                entry_id=1,
                recipient="ray@example.test",
                password="SharePassword!123",
                permissions=SharePermissions(read=True, edit=False, expires_in_days=2),
            ),
            encoding="utf-8",
        )

        self.assertEqual(window.detect_vault_import_format(str(native_path), native_path.read_bytes()), "encrypted_json")
        self.assertEqual(window.detect_vault_import_format(str(bitwarden_path), bitwarden_path.read_bytes()), "bitwarden_json")
        self.assertEqual(window.detect_vault_import_format(str(bitwarden_encrypted_path), bitwarden_encrypted_path.read_bytes()), "bitwarden_encrypted_json")
        self.assertEqual(window.detect_vault_import_format(str(lastpass_path), lastpass_path.read_bytes()), "lastpass_csv")
        self.assertEqual(window.detect_vault_import_format(str(share_path), share_path.read_bytes()), "share_package")

    def test_share_package_import_preview_and_merge_use_sharing_service(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("share-package-import-gui")).parent
        share_path = temp_dir / "entry-share.cs-share.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._show_info = lambda *args, **kwargs: None
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)
        share_path.write_text(
            SharingService(window.entry_manager).create_password_share_package(
                entry_id=1,
                recipient="ray@example.test",
                password="SharePassword!123",
                permissions=SharePermissions(read=True, edit=False, expires_in_days=2),
            ),
            encoding="utf-8",
        )
        window.entry_manager.entries = []

        preview = window.preview_vault_import_file(
            str(share_path),
            import_format="auto",
            password="SharePassword!123",
        )
        dry_run = window.import_vault_file(
            str(share_path),
            import_format="auto",
            password="SharePassword!123",
            mode="dry-run",
        )
        result = window.import_vault_file(
            str(share_path),
            import_format="auto",
            password="SharePassword!123",
            mode="merge",
        )

        self.assertEqual(preview["format"], "share_package")
        self.assertEqual(preview["validated"], 1)
        self.assertEqual(preview["titles"], ["GitHub"])
        self.assertEqual(dry_run["created"], 0)
        self.assertEqual(result["created"], 1)
        self.assertEqual(window.entry_manager.entries[0]["title"], "GitHub")
        self.assertTrue(window._entries_reloaded)

    def test_vault_encrypted_export_toggles_tray_crypto_operation_status(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-export-crypto-status")).parent
        export_path = temp_dir / "vault-export.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None
        status_changes = []
        original_set_status = MainWindow._set_crypto_operation_active.__get__(window, MainWindow)
        def record_status(active):
            status_changes.append(active)
            original_set_status(active)
        window._set_crypto_operation_active = record_status

        window.export_vault_encrypted_json_to_path(str(export_path), "ExportPassword!123")

        self.assertEqual(status_changes, [True, False])
        self.assertFalse(window._tray_crypto_operation_active)

    def test_vault_import_auto_detect_failure_requires_manual_format(self):
        window = MainWindow.__new__(MainWindow)

        with self.assertRaises(ImportValidationError) as context:
            window.detect_vault_import_format("unknown.data", b"not a known export")

        self.assertIn("Выберите формат вручную", str(context.exception))

    def test_vault_bitwarden_encrypted_export_gui_helper_never_writes_plaintext(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-bitwarden-encrypted-export-gui")).parent
        export_path = temp_dir / "bitwarden-export.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        window.entry_manager = FakeVaultEntryManager()
        window._get_selected_entries = lambda: []
        window._show_info = lambda *args, **kwargs: None
        window._show_warning = lambda *args, **kwargs: None

        result = window.export_vault_bitwarden_encrypted_json_to_path(str(export_path), "BitwardenExport!123")
        exported = export_path.read_text(encoding="utf-8")
        formats = window._get_export_format_descriptions()

        self.assertTrue(result)
        self.assertIn('"passwordProtected": true', exported)
        self.assertNotIn("GitHub", exported)
        self.assertNotIn("Secret!123", exported)
        self.assertIn("bitwarden_encrypted_json", formats)
        self.assertNotIn("csv", formats)
        self.assertNotIn("lastpass_csv", formats)
        self.assertNotIn("bitwarden_json", formats)

    def test_share_selected_entry_gui_helper_writes_package_and_db_record(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-share-gui")).parent
        share_path = temp_dir / "entry-share.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        entry_id = window.db.add_entry(
            VaultEntry(
                title="GitHub",
                username="ray",
                encrypted_password=b"secret",
                encrypted_data=b"secret",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )
        window.entry_manager = FakeVaultEntryManager()
        window.entry_manager.entries[0]["id"] = entry_id
        window._get_single_selected_entry = lambda _action: EntryView(window.entry_manager.entries[0])
        window._show_info = lambda *args, **kwargs: None

        result = window.share_selected_entry_to_path(
            str(share_path),
            recipient="student@example.test",
            password="SharePassword!123",
        )

        self.assertTrue(result)
        self.assertTrue(share_path.exists())
        self.assertEqual(window.db.get_shared_entries(limit=1)[0]["recipient_info"], "student@example.test")

    def test_share_selected_entry_helper_applies_permissions_and_expiration(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("vault-share-permissions")).parent
        share_path = temp_dir / "entry-share.json"
        window.db = Database(str(temp_dir / "vault.db"))
        self.addCleanup(window.db.close)
        entry_id = window.db.add_entry(
            VaultEntry(
                title="GitHub",
                username="ray",
                encrypted_password=b"secret",
                encrypted_data=b"secret",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )
        window.entry_manager = FakeVaultEntryManager()
        window.entry_manager.entries[0]["id"] = entry_id
        window._get_single_selected_entry = lambda _action: EntryView(window.entry_manager.entries[0])
        window._show_info = lambda *args, **kwargs: None

        result = window.share_selected_entry_to_path(
            str(share_path),
            recipient="editor@example.test",
            password="SharePassword!123",
            expires_in_days=14,
            read=True,
            edit=True,
        )
        package = json.loads(share_path.read_text(encoding="utf-8"))
        permissions = package["metadata"]["permissions"]

        self.assertTrue(result)
        self.assertTrue(permissions["read"])
        self.assertTrue(permissions["edit"])
        self.assertEqual(permissions["expires_in_days"], 14)

    def test_share_history_status_marks_expired_packages(self):
        window = MainWindow.__new__(MainWindow)
        window.db = Database(self.make_db_path("share-history-status.db"))
        self.addCleanup(window.db.close)
        entry_id = window.db.add_entry(
            VaultEntry(
                title="GitHub",
                username="ray",
                encrypted_password=b"secret",
                encrypted_data=b"secret",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )
        window.db.add_shared_entry(
            share_id="share-expired",
            original_entry_id=entry_id,
            recipient_info="student@example.test",
            permissions={"read": True},
            shared_at=datetime.now(timezone.utc),
            expires_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
            encryption_method="password",
            status="active",
            package_checksum="checksum",
        )

        history = window.get_share_history_status(limit=5)

        self.assertEqual(history[0]["share_id"], "share-expired")
        self.assertEqual(history[0]["computed_status"], "expired")

    def test_show_share_dialog_checks_selected_entry_before_prompting_details(self):
        window = MainWindow.__new__(MainWindow)
        window._reauthenticate_for_sensitive_action = lambda _action: True
        window._get_single_selected_entry = lambda _action: None
        window._ask_string = lambda *args, **kwargs: setattr(window, "_asked_string", True)
        window._ask_saveas_filename = lambda *args, **kwargs: setattr(window, "_asked_file", True)

        result = window.show_share_dialog()

        self.assertFalse(result)
        self.assertFalse(hasattr(window, "_asked_string"))
        self.assertFalse(hasattr(window, "_asked_file"))

    def test_share_package_gui_helper_generates_qr_preview_png(self):
        window = MainWindow.__new__(MainWindow)
        window.db = Database(self.make_db_path("share-package-qr.db"))
        self.addCleanup(window.db.close)
        package_payload = json.dumps(
            {
                "cryptosafe_share": True,
                "metadata": {"recipient": "alice"},
                "data": {"ciphertext": "encrypted-only"},
            },
            sort_keys=True,
        )

        pngs = window.generate_share_package_qr_pngs(package_payload=package_payload, label="alice")

        self.assertTrue(pngs)
        self.assertTrue(pngs[0].startswith(b"\x89PNG"))

    def test_key_exchange_gui_helpers_generate_and_import_contact(self):
        window = MainWindow.__new__(MainWindow)
        window.db = Database(self.make_db_path("key-exchange-gui.db"))
        self.addCleanup(window.db.close)
        window._show_info = lambda *args, **kwargs: None

        payload = window.generate_key_exchange_payload_text(identifier="alice@example.test", public_key="public-key")
        contact_id = window.import_key_exchange_payload_text(payload, contact_name="Alice")
        contacts = window.db.get_contacts(limit=5)

        self.assertGreater(contact_id, 0)
        self.assertEqual(contacts[0]["identifier"], "alice@example.test")
        self.assertEqual(contacts[0]["name"], "Alice")

    def test_key_exchange_gui_helper_scans_payload_from_camera_adapter(self):
        window = MainWindow.__new__(MainWindow)
        window.db = Database(self.make_db_path("key-exchange-camera.db"))
        self.addCleanup(window.db.close)
        payload = window.generate_key_exchange_payload_text(identifier="camera@example.test", public_key="public-key")
        window.qr_camera_scanner = lambda: payload

        scanned_payload = window.scan_key_exchange_payload_from_camera()

        self.assertEqual(scanned_payload, payload)

    def test_key_exchange_gui_helper_writes_private_payload_and_qr_files(self):
        window = MainWindow.__new__(MainWindow)
        temp_dir = Path(self.make_db_path("key-exchange-files")).parent
        window.db = Database(str(temp_dir / "key-exchange.db"))
        self.addCleanup(window.db.close)

        bundle = window.generate_key_exchange_file_bundle(identifier="alice@example.test", output_dir=str(temp_dir))

        self.assertTrue(Path(bundle["private_key_path"]).exists())
        self.assertTrue(Path(bundle["payload_path"]).exists())
        self.assertTrue(Path(bundle["qr_paths"][0]).exists())
        self.assertTrue(bundle["qr_pngs"][0].startswith(b"\x89PNG"))
        self.assertIn("BEGIN PRIVATE KEY", Path(bundle["private_key_path"]).read_text(encoding="utf-8"))
        self.assertIn("cryptosafe_key_exchange", Path(bundle["payload_path"]).read_text(encoding="utf-8"))
        self.assertIn("<svg", Path(bundle["qr_paths"][0]).read_text(encoding="utf-8"))

    def test_new_database_does_not_overwrite_existing_vault_file(self):
        window = MainWindow.__new__(MainWindow)
        existing_path = Path(self.make_db_path("existing-vault-file.db"))
        existing_path.parent.mkdir(parents=True, exist_ok=True)
        existing_path.write_text("existing vault data", encoding="utf-8")
        warnings = []
        window._ask_saveas_filename = lambda *args, **kwargs: str(existing_path)
        window._show_warning = lambda title, message, **kwargs: warnings.append((title, message))

        result = window.new_database()

        self.assertIsNone(result)
        self.assertEqual(existing_path.read_text(encoding="utf-8"), "existing vault data")
        self.assertTrue(warnings)


if __name__ == "__main__":
    unittest.main()