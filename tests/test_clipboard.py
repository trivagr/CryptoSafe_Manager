import ctypes
import os
import sys
import tempfile
import threading
import time
import tracemalloc
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import ClipboardAccessError, ClipboardMonitor, ClipboardService, SecureClipboardItem
from src.core.config import Config
from src.core.events import EventBus, EventType
from src.core.state_manager import StateManager
from src.database.db import Database
from unittest.mock import patch


class FakeClipboardAdapter:
    def __init__(self):
        self.value = None
        self.copy_calls = 0
        self.clear_calls = 0
        self.access_token = 0

    def copy_to_clipboard(self, data: str) -> bool:
        self.value = data
        self.copy_calls += 1
        return True

    def clear_clipboard(self) -> bool:
        self.value = ""
        self.clear_calls += 1
        return True

    def get_clipboard_content(self):
        return self.value

    def get_clipboard_access_token(self):
        return self.access_token


class FailingCopyClipboardAdapter(FakeClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        self.copy_calls += 1
        return False


class FailingClearClipboardAdapter(FakeClipboardAdapter):
    def clear_clipboard(self) -> bool:
        self.clear_calls += 1
        return False


def _contains_secret_in_process_memory(pid: int, secret_bytes: bytes) -> bool:
    if os.name == "nt":
        return _contains_secret_in_windows_process_memory(pid, secret_bytes)
    if sys.platform.startswith("linux"):
        return _contains_secret_in_linux_process_memory(pid, secret_bytes)
    raise unittest.SkipTest("Р РµР°Р»СЊРЅР°СЏ РїСЂРѕРІРµСЂРєР° РґР°РјРїР° РїР°РјСЏС‚Рё РїРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РЅР° Windows Рё Linux")


def _contains_secret_in_windows_process_memory(pid: int, secret_bytes: bytes) -> bool:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    kernel32 = ctypes.windll.kernel32
    process_handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not process_handle:
        raise RuntimeError("РќРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РєСЂС‹С‚СЊ РїСЂРѕС†РµСЃСЃ РґР»СЏ С‡С‚РµРЅРёСЏ РїР°РјСЏС‚Рё")

    try:
        address = 0
        max_address = 0x7FFFFFFFFFFF
        mbi_size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
        while address < max_address:
            mbi = MEMORY_BASIC_INFORMATION()
            result = kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
            if not result:
                break

            base_address = int(mbi.BaseAddress or 0)
            region_size = int(mbi.RegionSize or 0)
            next_address = base_address + max(region_size, 0x1000)
            if mbi.State == 0x1000 and not (mbi.Protect & 0x100) and not (mbi.Protect & 0x01):
                offset = 0
                while offset < region_size:
                    chunk_size = min(1024 * 1024, region_size - offset)
                    buffer = ctypes.create_string_buffer(chunk_size)
                    bytes_read = ctypes.c_size_t(0)
                    success = kernel32.ReadProcessMemory(
                        process_handle,
                        ctypes.c_void_p(base_address + offset),
                        buffer,
                        chunk_size,
                        ctypes.byref(bytes_read),
                    )
                    if success and bytes_read.value:
                        if secret_bytes in buffer.raw[: bytes_read.value]:
                            return True
                    offset += chunk_size
            address = next_address
    finally:
        kernel32.CloseHandle(process_handle)
    return False


def _contains_secret_in_linux_process_memory(pid: int, secret_bytes: bytes) -> bool:
    maps_path = Path(f"/proc/{pid}/maps")
    mem_path = Path(f"/proc/{pid}/mem")
    if not maps_path.exists() or not mem_path.exists():
        raise unittest.SkipTest("РўРµРєСѓС‰Р°СЏ Linux-СЃСЂРµРґР° РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚ С‡С‚РµРЅРёРµ /proc/<pid>/mem")

    with maps_path.open("r", encoding="utf-8") as maps_file, mem_path.open("rb", buffering=0) as mem_file:
        for line in maps_file:
            parts = line.split()
            if len(parts) < 2:
                continue
            address_range, permissions = parts[0], parts[1]
            if "r" not in permissions:
                continue
            start_hex, end_hex = address_range.split("-", 1)
            start_address = int(start_hex, 16)
            end_address = int(end_hex, 16)
            region_size = max(0, end_address - start_address)
            offset = 0
            while offset < region_size:
                chunk_size = min(1024 * 1024, region_size - offset)
                try:
                    mem_file.seek(start_address + offset)
                    chunk = mem_file.read(chunk_size)
                except OSError:
                    break
                if secret_bytes in chunk:
                    return True
                offset += chunk_size
    return False


def _derive_memory_dump_secret(seed_bytes: bytes) -> bytes:
    alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    state = 0xA5A5A5A5
    for value in seed_bytes:
        state = ((state << 5) ^ (state >> 2) ^ value) & 0xFFFFFFFF

    derived = bytearray(b"TEST3-")
    for _index in range(32):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        derived.append(alphabet[state % len(alphabet)])
    return bytes(derived)


class ClipboardServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_home = tempfile.TemporaryDirectory()
        self.home_path = Path(self.temp_home.name)
        self.original_home = Path.home
        Path.home = lambda: self.home_path
        self.addCleanup(self.temp_home.cleanup)
        self.addCleanup(self._restore_home)
        self.config = Config()
        self.database = Database(str(self.home_path / "clipboard.db"))
        self.addCleanup(self.database.close)
        self.state = StateManager()
        self.state.unlock()
        self.adapter = FakeClipboardAdapter()
        self.bus = EventBus()
        self.service = ClipboardService(
            self.adapter,
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )

    def _restore_home(self):
        Path.home = self.original_home

    def test_copy_text_updates_status_and_state(self):
        self.service.copy_text("Secret!123", data_type="password", source_entry_id=7, source_label="GitHub")

        status = self.service.get_status()
        self.assertTrue(status.active)
        self.assertEqual(status.data_type, "password")
        self.assertEqual(status.source_entry_id, 7)
        self.assertEqual(self.adapter.value, "Secret!123")
        self.assertEqual(self.state.get_clipboard(), self.state.CLIPBOARD_REDACTED_MARKER)
        self.assertIn("Sec", status.preview)
        self.assertEqual(self.service.reveal_current_text(), "Secret!123")

    def test_timeout_warning_and_clear(self):
        self.service.configure(timeout_seconds=5)
        self.service.copy_text("Secret!123")
        self.service._current_item.expires_at = datetime.now() + timedelta(seconds=4)

        result = self.service.tick()
        self.assertEqual(result, "warning")
        self.assertTrue(self.service.get_status().warning_emitted)

        self.service._current_item.expires_at = datetime.now() - timedelta(seconds=1)
        result = self.service.tick()
        self.assertEqual(result, "timeout")
        self.assertFalse(self.service.get_status().active)
        self.assertEqual(self.adapter.clear_calls, 1)

    def test_auto_clear_short_expiry_completes_within_100ms_tolerance(self):
        self.service.copy_text("Secret!123")
        expected_delay = 0.08
        self.service._current_item.expires_at = datetime.now() + timedelta(seconds=expected_delay)

        started_at = time.perf_counter()
        result = None
        while time.perf_counter() - started_at < 1:
            result = self.service.tick()
            if result == "timeout":
                break
            time.sleep(0.01)
        elapsed = time.perf_counter() - started_at

        self.assertEqual(result, "timeout")
        self.assertLess(abs(elapsed - expected_delay), 0.1)

    def test_copy_is_blocked_when_state_is_locked(self):
        self.state.lock()

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123")

    def test_monitor_flags_external_change(self):
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = "Changed by another app"

        monitor.poll()
        status = self.service.get_status()
        self.assertFalse(status.suspicious_activity)

        monitor.poll()

        status = self.service.get_status()
        self.assertTrue(status.suspicious_activity)
        self.assertLessEqual(status.remaining_seconds, 1)

    def test_monitor_reacts_immediately_in_paranoid_mode(self):
        self.service.configure(security_level="paranoid")
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = "Changed by another app"

        monitor.poll()

        status = self.service.get_status()
        self.assertTrue(status.suspicious_activity)
        self.assertLessEqual(status.remaining_seconds, 1)

    def test_monitor_detects_external_read_when_access_token_changes(self):
        received_events = []
        self.bus.subscribe(EventType.CLIPBOARD_CLEARED, received_events.append)
        self.service.configure(security_level="paranoid")
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)

        monitor.poll()
        self.assertFalse(self.service.get_status().suspicious_activity)

        self.adapter.access_token += 1
        monitor.poll()

        status = self.service.get_status()
        self.assertTrue(status.suspicious_activity)
        self.assertEqual(received_events[-1].data["reason"], "monitor_warning")
        self.assertEqual(received_events[-1].data["monitor_reason"], "external_read")

    def test_monitor_marks_external_clear_with_separate_reason(self):
        received_events = []
        self.bus.subscribe(EventType.CLIPBOARD_CLEARED, received_events.append)
        self.service.configure(security_level="paranoid")
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = ""

        monitor.poll()

        self.assertEqual(received_events[-1].data["reason"], "monitor_warning")
        self.assertEqual(received_events[-1].data["monitor_reason"], "external_clear")
        self.assertEqual(received_events[-1].data["entry_id"], None)
        self.assertEqual(received_events[-1].data["data_type"], "password")
        self.assertEqual(received_events[-1].data["observed_length"], 0)

    def test_settings_are_persisted_in_database(self):
        self.service.configure(
            timeout_seconds=15,
            notifications_enabled=False,
            security_level="paranoid",
            blocked_on_suspicious=True,
            preset="public_computer",
        )

        stored = self.database.get_setting("security.clipboard", {})
        self.assertEqual(stored["timeout_seconds"], 15)
        self.assertEqual(stored["security_level"], "paranoid")
        self.assertTrue(stored["blocked_on_suspicious"])

    def test_custom_preset_name_is_persisted_for_manual_profile(self):
        self.service.configure(
            timeout_seconds=42,
            notifications_enabled=False,
            security_level="advanced",
            blocked_on_suspicious=True,
            preset="custom",
        )

        stored = self.database.get_setting("security.clipboard", {})
        self.assertEqual(stored["preset"], "custom")
        self.assertEqual(stored["timeout_seconds"], 42)

    def test_allowed_applications_are_normalized_and_persisted(self):
        self.service.configure(
            allowed_applications=[" Code.exe ", "explorer", "code", "KEEPASSXC.EXE"],
        )

        stored = self.database.get_setting("security.clipboard", {})
        self.assertEqual(stored["allowed_applications"], ["code", "explorer", "keepassxc"])
        self.assertTrue(self.service.is_application_allowed("code.exe"))
        self.assertTrue(self.service.is_application_allowed("Keepassxc"))
        self.assertFalse(self.service.is_application_allowed("telegram"))

    def test_copy_is_blocked_for_application_outside_whitelist(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service.configure(allowed_applications=["cryptosafe-manager"])

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123", application_name="telegram")

        self.assertFalse(self.service.get_status().active)
        self.assertEqual(clipboard_errors[-1].data["error_code"], "application_not_allowed")
        self.assertEqual(clipboard_errors[-1].data["application_name"], "telegram")

    def test_copy_is_blocked_when_entry_policy_forbids_clipboard_usage(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123", source_entry_id=7, entry_clipboard_policy="never")

        self.assertFalse(self.service.get_status().active)
        self.assertEqual(clipboard_errors[-1].data["error_code"], "entry_copy_disabled")

    def test_memory_only_delivery_mode_keeps_secret_out_of_system_clipboard(self):
        copied_events = []
        self.bus.subscribe(EventType.CLIPBOARD_COPIED, copied_events.append)
        self.service.configure(delivery_mode="memory_only")

        self.service.copy_text("Secret!123", data_type="password", source_entry_id=7)

        status = self.service.get_status()
        self.assertTrue(status.active)
        self.assertEqual(status.delivery_mode, "memory_only")
        self.assertEqual(self.adapter.copy_calls, 0)
        self.assertEqual(self.adapter.clear_calls, 0)
        self.assertEqual(self.service.reveal_current_text(), "Secret!123")
        self.assertEqual(self.state.get_clipboard(), self.state.CLIPBOARD_REDACTED_MARKER)
        self.assertEqual(copied_events[-1].data["delivery_mode"], "memory_only")

    def test_memory_exposure_probe_does_not_find_plaintext_in_memory_only_mode(self):
        self.service.configure(delivery_mode="memory_only")
        self.service.copy_text("Secret!123", source_label="Example")

        exposure = self.service.inspect_memory_exposure("Secret!123")

        self.assertFalse(exposure["in_mask_buffer"])
        self.assertFalse(exposure["in_text_mask_buffer"])
        self.assertFalse(exposure["in_source_label"])
        self.assertFalse(exposure["in_state_manager"])
        self.assertEqual(exposure["delivery_mode"], "memory_only")

    def test_memory_security_self_test_does_not_find_plaintext_in_memory_only_snapshot(self):
        self.service.configure(delivery_mode="memory_only")
        self.service.copy_text("Secret!123", source_label="Example")

        report = self.service.run_memory_security_self_test("Secret!123")

        self.assertFalse(report["in_mask_buffer"])
        self.assertFalse(report["in_text_mask_buffer"])
        self.assertFalse(report["in_state_manager"])
        self.assertFalse(report["in_memory_dump_snapshot"])
        self.assertGreater(report["snapshot_size_bytes"], 0)

    def test_memory_dump_snapshot_does_not_contain_plaintext_after_memory_only_copy(self):
        self.service.configure(delivery_mode="memory_only")
        self.service.copy_text("Secret!123", source_label="Example")

        snapshot = self.service.build_memory_dump_snapshot()

        self.assertNotIn(b"Secret!123", snapshot)

    def test_memory_exposure_probe_detects_plaintext_copy_in_state_manager_for_system_mode(self):
        self.service.copy_text("Secret!123")

        exposure = self.service.inspect_memory_exposure("Secret!123")

        self.assertFalse(exposure["in_mask_buffer"])
        self.assertFalse(exposure["in_text_mask_buffer"])
        self.assertFalse(exposure["in_state_manager"])
        self.assertEqual(exposure["delivery_mode"], "system")

    def test_memory_security_self_test_detects_plaintext_in_system_snapshot(self):
        self.service.copy_text("Secret!123")

        report = self.service.run_memory_security_self_test("Secret!123")

        self.assertFalse(report["in_state_manager"])
        self.assertFalse(report["in_memory_dump_snapshot"])

    def test_memory_dump_snapshot_does_not_contain_plaintext_after_system_copy(self):
        self.service.copy_text("Secret!123", source_label="Example")

        snapshot = self.service.build_memory_dump_snapshot()

        self.assertNotIn(b"Secret!123", snapshot)

    def test_memory_dump_snapshot_stays_clean_after_clear(self):
        self.service.copy_text("Secret!123", source_label="Example")
        self.service.clear(reason="manual")

        snapshot = self.service.build_memory_dump_snapshot()

        self.assertNotIn(b"Secret!123", snapshot)

    def test_copy_rejects_null_bytes_in_value(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret\x00Value")

        self.assertEqual(clipboard_errors[-1].data["error_code"], "invalid_content")

    def test_copy_rejects_oversized_value_for_paranoid_level(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service.configure(security_level="paranoid")

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("x" * 4097, data_type="entry")

        self.assertEqual(clipboard_errors[-1].data["error_code"], "value_too_large")
        self.assertEqual(clipboard_errors[-1].data["max_length"], 4096)
        self.assertEqual(clipboard_errors[-1].data["actual_length"], 4097)

    def test_copy_sanitizes_source_label_before_storing_status(self):
        self.service.copy_text("Secret!123", source_label="Example\nInjected\tLabel")

        status = self.service.get_status()
        self.assertEqual(status.source_label, "ExampleInjected\tLabel")

    def test_replacement_copy_clears_previous_clipboard_content(self):
        self.service.copy_text("first-secret", source_entry_id=1)
        self.service.copy_text("second-secret", source_entry_id=2)

        status = self.service.get_status()
        self.assertTrue(status.active)
        self.assertEqual(status.source_entry_id, 2)
        self.assertEqual(self.adapter.value, "second-secret")
        self.assertEqual(self.adapter.clear_calls, 1)

    def test_copy_text_raises_error_when_adapter_write_fails(self):
        self.service = ClipboardService(
            FailingCopyClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123")

        self.assertFalse(self.service.get_status().active)

    def test_suspicious_activity_can_block_future_copies(self):
        self.service.configure(blocked_on_suspicious=True)
        self.service.copy_text("Secret!123")
        self.service.register_suspicious_activity(reason="external_change", observed_value="changed")

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("AnotherSecret!456")

    def test_clear_event_marks_failed_system_clear(self):
        received_events = []
        self.bus.subscribe(EventType.CLIPBOARD_CLEARED, received_events.append)
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service = ClipboardService(
            FailingClearClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )
        self.service.copy_text("Secret!123")

        result = self.service.clear(reason="manual")

        self.assertTrue(result)
        self.assertTrue(self.service.did_last_clear_fail())
        self.assertEqual(received_events[-1].data["reason"], "manual")
        self.assertTrue(received_events[-1].data["clear_failed"])
        self.assertEqual(clipboard_errors[-1].data["operation"], "clear")
        self.assertEqual(clipboard_errors[-1].data["error_code"], "adapter_clear_failed")
        self.assertEqual(clipboard_errors[-1].data["clear_reason"], "manual")

    def test_copy_failure_publishes_clipboard_error_without_secret_value(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service = ClipboardService(
            FailingCopyClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123", data_type="password", source_entry_id=5)

        self.assertEqual(clipboard_errors[-1].data["operation"], "copy")
        self.assertEqual(clipboard_errors[-1].data["error_code"], "adapter_write_failed")
        self.assertEqual(clipboard_errors[-1].data["entry_id"], 5)
        self.assertEqual(clipboard_errors[-1].data["data_type"], "password")
        self.assertNotIn("Secret!123", str(clipboard_errors[-1].data))

    def test_failed_replacement_does_not_leave_previous_secret_active(self):
        self.service.copy_text("first-secret", data_type="password", source_entry_id=1)
        self.service.adapter = FailingCopyClipboardAdapter()

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("second-secret", data_type="password", source_entry_id=2)

        self.assertFalse(self.service.get_status().active)
        self.assertIsNone(self.state.get_clipboard())

    def test_rapid_concurrent_copy_operations_keep_consistent_final_state(self):
        start_event = threading.Event()
        errors = []
        values = [f"secret-{index}" for index in range(5)]
        threads = []

        def worker(value: str, entry_id: int):
            try:
                start_event.wait(timeout=5)
                self.service.copy_text(value, data_type="password", source_entry_id=entry_id)
            except Exception as error:
                errors.append(error)

        for index, value in enumerate(values, start=1):
            thread = threading.Thread(target=worker, args=(value, index))
            threads.append(thread)
            thread.start()

        start_event.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(errors, [])
        final_value = self.service.reveal_current_text()
        self.assertIn(final_value, values)
        self.assertEqual(self.state.get_clipboard(), self.state.CLIPBOARD_REDACTED_MARKER)

    def test_concurrent_copy_clear_and_tick_operations_keep_state_consistent(self):
        start_event = threading.Event()
        errors = []

        def copy_worker():
            try:
                start_event.wait(timeout=5)
                for index in range(10):
                    self.service.copy_text(f"secret-{index}", data_type="password", source_entry_id=index)
            except Exception as error:
                errors.append(error)

        def clear_worker():
            try:
                start_event.wait(timeout=5)
                for _index in range(10):
                    self.service.clear(reason="manual", publish_event=False)
            except Exception as error:
                errors.append(error)

        def tick_worker():
            try:
                start_event.wait(timeout=5)
                for _index in range(10):
                    self.service.tick()
            except Exception as error:
                errors.append(error)

        threads = [
            threading.Thread(target=copy_worker),
            threading.Thread(target=clear_worker),
            threading.Thread(target=tick_worker),
        ]
        for thread in threads:
            thread.start()

        start_event.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(errors, [])
        status = self.service.get_status()
        revealed = self.service.reveal_current_text()
        if status.active:
            self.assertEqual(self.state.get_clipboard(), self.state.CLIPBOARD_REDACTED_MARKER)
            self.assertEqual(self.adapter.value, revealed)
        else:
            self.assertIn(self.state.get_clipboard(), {None, ""})

    def test_successful_copy_resets_failed_clear_flag_after_previous_failure(self):
        self.service = ClipboardService(
            FailingClearClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )
        self.service.copy_text("Secret!123")
        self.service.clear(reason="manual")
        self.assertTrue(self.service.did_last_clear_fail())

        self.service.adapter = FakeClipboardAdapter()
        self.service.copy_text("Recovered!456")

        self.assertFalse(self.service.did_last_clear_fail())
        self.assertIsNone(self.service.get_last_clear_reason())

    def test_copy_operation_completes_under_100ms_with_fake_adapter(self):
        started_at = time.perf_counter()
        self.service.copy_text("Secret!123", data_type="password", source_entry_id=7, source_label="GitHub")
        elapsed = time.perf_counter() - started_at

        self.assertLess(elapsed, 0.1)

    def test_idle_clipboard_monitor_poll_loop_stays_lightweight(self):
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = None

        started_at = time.perf_counter()
        for _index in range(1000):
            monitor.poll()
        elapsed = time.perf_counter() - started_at

        self.assertLess(elapsed, 0.5)

    @pytest.mark.slow
    def test_idle_clipboard_monitor_cpu_ratio_stays_below_one_percent(self):
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = None

        cpu_started_at = time.process_time()
        wall_started_at = time.perf_counter()
        for _index in range(100):
            monitor.poll()
            time.sleep(0.06)
        cpu_elapsed = time.process_time() - cpu_started_at
        wall_elapsed = time.perf_counter() - wall_started_at
        cpu_ratio = 0 if wall_elapsed <= 0 else cpu_elapsed / wall_elapsed

        max_cpu_ratio = 0.05 if sys.gettrace() else 0.01
        self.assertLess(cpu_ratio, max_cpu_ratio)

    def test_clipboard_monitor_ignores_system_clipboard_when_delivery_mode_is_memory_only(self):
        self.service.configure(delivery_mode="memory_only")
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = "Changed by another app"

        monitor.poll()

        status = self.service.get_status()
        self.assertFalse(status.suspicious_activity)
        self.assertEqual(status.delivery_mode, "memory_only")

    def test_clipboard_service_memory_overhead_stays_below_10mb_for_large_payload(self):
        large_value = "A" * 4096

        tracemalloc.start()
        try:
            self.service.copy_text(large_value, data_type="entry", source_label="Large payload")
            _revealed = self.service.reveal_current_text()
            current_bytes, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertLess(peak_bytes, 10 * 1024 * 1024)

    def test_secure_clipboard_item_uses_virtual_lock_on_windows_when_available(self):
        calls = {"lock": 0, "unlock": 0}
        fake_kernel32 = types.SimpleNamespace(
            VirtualLock=lambda _buffer, _size: calls.update(lock=calls["lock"] + 1) or True,
            VirtualUnlock=lambda _buffer, _size: calls.update(unlock=calls["unlock"] + 1) or True,
        )

        with patch("src.core.clipboard.clipboard_service.os.name", "nt"), patch.object(
            sys.modules["src.core.clipboard.clipboard_service"].ctypes,
            "windll",
            types.SimpleNamespace(kernel32=fake_kernel32),
            create=True,
        ):
            item = SecureClipboardItem.create("Secret!123", data_type="password")
            self.assertTrue(item.memory_locked)
            item.secure_wipe()

        self.assertEqual(calls["lock"], 2)
        self.assertEqual(calls["unlock"], 2)

    def test_secure_clipboard_item_uses_mlock_on_unix_when_available(self):
        calls = {"mlock": 0, "munlock": 0}
        fake_libc = types.SimpleNamespace(
            mlock=lambda _buffer, _size: calls.update(mlock=calls["mlock"] + 1) or 0,
            munlock=lambda _buffer, _size: calls.update(munlock=calls["munlock"] + 1) or 0,
        )

        with patch("src.core.clipboard.clipboard_service.os.name", "posix"), patch.object(
            sys.modules["src.core.clipboard.clipboard_service"].ctypes,
            "CDLL",
            return_value=fake_libc,
        ):
            item = SecureClipboardItem.create("Secret!123", data_type="password")
            self.assertTrue(item.memory_locked)
            item.secure_wipe()

        self.assertEqual(calls["mlock"], 2)
        self.assertEqual(calls["munlock"], 2)


if __name__ == "__main__":
    unittest.main()