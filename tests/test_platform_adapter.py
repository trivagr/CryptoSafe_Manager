import os
import sys
import types
import unittest
from builtins import __import__ as builtin_import
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import platform_adapter


class FakeRoot:
    def __init__(self):
        self.clipboard_value = ""
        self.update_calls = 0

    def clipboard_clear(self):
        self.clipboard_value = ""

    def clipboard_append(self, value):
        self.clipboard_value = value

    def clipboard_get(self):
        return self.clipboard_value

    def update(self):
        self.update_calls += 1


class FakeProcessResult:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


class FakePasteboard:
    def __init__(self):
        self.value = ""
        self.declared_types = []

    def clearContents(self):
        self.value = ""

    def declareTypes_owner_(self, types_list, _owner):
        self.declared_types = list(types_list)

    def setString_forType_(self, value, _string_type):
        self.value = value
        return True

    def stringForType_(self, _string_type):
        return self.value


class TestCompositeClipboardAdapter(unittest.TestCase):
    def test_copy_and_clear_return_true_when_any_adapter_succeeds(self):
        class AdapterA:
            def copy_to_clipboard(self, _data):
                return False

            def clear_clipboard(self):
                return False

            def get_clipboard_content(self):
                return None

        class AdapterB:
            def copy_to_clipboard(self, _data):
                return True

            def clear_clipboard(self):
                return True

            def get_clipboard_content(self):
                return "value"

        adapter = platform_adapter.CompositeClipboardAdapter([AdapterA(), AdapterB()])

        self.assertTrue(adapter.copy_to_clipboard("secret"))
        self.assertTrue(adapter.clear_clipboard())
        self.assertEqual(adapter.get_clipboard_content(), "value")


class TestCreatePlatformAdapter(unittest.TestCase):
    def test_create_platform_adapter_uses_windows_and_tk_fallbacks(self):
        root = FakeRoot()
        windows_adapter = object()
        tk_adapter = object()

        with patch.object(platform_adapter.os, "name", "nt"), patch.object(
            platform_adapter, "WindowsClipboardAdapter", return_value=windows_adapter
        ), patch.object(platform_adapter, "TkClipboardAdapter", return_value=tk_adapter), patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            adapter = platform_adapter.create_platform_adapter(root)

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [windows_adapter, tk_adapter])

    def test_create_platform_adapter_uses_appkit_then_command_adapter_on_macos(self):
        appkit_adapter = object()
        command_adapter = object()

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "darwin"
        ), patch.object(
            platform_adapter, "AppKitClipboardAdapter", return_value=appkit_adapter
        ), patch.object(
            platform_adapter, "MacOSClipboardAdapter", return_value=command_adapter
        ), patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            adapter = platform_adapter.create_platform_adapter()

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [appkit_adapter, command_adapter])

    def test_create_platform_adapter_passes_macos_pasteboard_mode(self):
        appkit_adapter = object()
        command_adapter = object()

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "darwin"
        ), patch.object(
            platform_adapter, "AppKitClipboardAdapter", return_value=appkit_adapter
        ) as appkit_factory, patch.object(
            platform_adapter, "MacOSClipboardAdapter", return_value=command_adapter
        ), patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            adapter = platform_adapter.create_platform_adapter(macos_pasteboard_mode="drag")

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [appkit_adapter, command_adapter])
        appkit_factory.assert_called_once_with(pasteboard_mode="drag")

    def test_create_platform_adapter_uses_pyperclip_when_platform_specific_adapter_missing(self):
        pyperclip_adapter = object()

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "unknown"
        ), patch.object(platform_adapter, "PyperclipClipboardAdapter", return_value=pyperclip_adapter):
            adapter = platform_adapter.create_platform_adapter()

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [pyperclip_adapter])

    def test_create_platform_adapter_raises_when_no_adapter_available(self):
        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "unknown"
        ), patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            with self.assertRaises(platform_adapter.ClipboardAdapterError):
                platform_adapter.create_platform_adapter()

    def test_create_platform_adapter_passes_linux_selection_mode(self):
        linux_adapter = object()

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "linux"
        ), patch.object(
            platform_adapter, "LinuxClipboardAdapter", return_value=linux_adapter
        ) as linux_factory, patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            adapter = platform_adapter.create_platform_adapter(linux_selection_mode="primary")

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [linux_adapter])
        linux_factory.assert_called_once_with(selection_mode="primary")


class TestPlatformValidationReport(unittest.TestCase):
    def test_validation_report_detects_windows_backends(self):
        fake_user32 = object()

        with patch.object(platform_adapter.os, "name", "nt"), patch.object(
            platform_adapter.sys, "platform", "win32"
        ), patch.dict(
            sys.modules, {"win32clipboard": object()}
        ), patch.object(
            platform_adapter.ctypes, "windll", types.SimpleNamespace(user32=fake_user32), create=True
        ):
            report = platform_adapter.get_platform_validation_report(root_available=True)

        self.assertTrue(report["ready"])
        self.assertEqual(report["platform"], "win32")
        self.assertTrue(any(item["name"] == "windows_win32clipboard" and item["available"] for item in report["adapters"]))
        self.assertTrue(any(item["name"] == "windows_user32" and item["available"] for item in report["adapters"]))
        self.assertTrue(any(item["name"] == "tk_root" and item["available"] for item in report["adapters"]))

    def test_validation_report_detects_macos_backends(self):
        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "darwin"
        ), patch.dict(
            sys.modules, {"AppKit": object()}
        ), patch.object(
            platform_adapter.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name in {"pbcopy", "pbpaste", "osascript"} else None
        ):
            report = platform_adapter.get_platform_validation_report()

        self.assertTrue(report["ready"])
        self.assertEqual(report["macos_pasteboard_mode"], "general")
        self.assertTrue(any(item["name"] == "macos_appkit" and item["available"] for item in report["adapters"]))
        self.assertTrue(any(item["name"] == "macos_pasteboard_general" and item["available"] for item in report["adapters"]))
        self.assertTrue(any(item["name"] == "macos_pbcopy" and item["available"] for item in report["adapters"]))
        self.assertTrue(any(item["name"] == "macos_osascript" and item["available"] for item in report["adapters"]))

    def test_validation_report_respects_drag_pasteboard_mode_on_macos(self):
        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "darwin"
        ), patch.dict(
            sys.modules, {"AppKit": object()}
        ), patch.object(
            platform_adapter.shutil, "which", return_value=None
        ):
            report = platform_adapter.get_platform_validation_report(macos_pasteboard_mode="drag")

        self.assertEqual(report["macos_pasteboard_mode"], "drag")
        self.assertTrue(any(item["name"] == "macos_pasteboard_drag" and item["available"] for item in report["adapters"]))

    def test_validation_report_detects_linux_backends_for_primary_mode(self):
        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "linux"
        ), patch.object(
            platform_adapter.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name in {"xclip", "xsel"} else None
        ):
            report = platform_adapter.get_platform_validation_report(linux_selection_mode="primary")

        self.assertTrue(report["ready"])
        self.assertEqual(report["linux_selection_mode"], "primary")
        self.assertTrue(any(item["name"] == "linux_xclip" and item["available"] for item in report["adapters"]))
        self.assertTrue(any(item["name"] == "linux_xsel" and item["available"] for item in report["adapters"]))

    def test_validation_report_marks_not_ready_when_no_backends_exist(self):
        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {"pyperclip", "AppKit", "win32clipboard"}:
                raise ImportError(name)
            return builtin_import(name, globals, locals, fromlist, level)

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "linux"
        ), patch.object(
            platform_adapter.shutil, "which", return_value=None
        ), patch(
            "builtins.__import__", side_effect=fake_import
        ):
            report = platform_adapter.get_platform_validation_report(root_available=False)

        self.assertFalse(report["ready"])
        self.assertTrue(any(item["name"] == "tk_root" and not item["available"] for item in report["adapters"]))


class TestPlatformAdapters(unittest.TestCase):
    def test_appkit_clipboard_adapter_roundtrip(self):
        general_pasteboard = FakePasteboard()
        drag_pasteboard = FakePasteboard()
        fake_appkit = types.SimpleNamespace(
            NSPasteboard=types.SimpleNamespace(
                generalPasteboard=lambda: general_pasteboard,
                pasteboardWithName_=lambda name: general_pasteboard if name == "general" else drag_pasteboard,
            ),
            NSPasteboardNameGeneral="general",
            NSPasteboardNameDrag="drag",
            NSPasteboardTypeString="public.utf8-plain-text",
        )

        with patch.dict(sys.modules, {"AppKit": fake_appkit}):
            adapter = platform_adapter.AppKitClipboardAdapter()

        self.assertTrue(adapter.copy_to_clipboard("Secret!123"))
        self.assertEqual(adapter.get_clipboard_content(), "Secret!123")
        self.assertTrue(adapter.clear_clipboard())
        self.assertEqual(adapter.get_clipboard_content(), "")
        self.assertEqual(general_pasteboard.declared_types, ["public.utf8-plain-text"])
        self.assertEqual(adapter.pasteboard_mode, "general")

    def test_appkit_clipboard_adapter_supports_drag_pasteboard_mode(self):
        general_pasteboard = FakePasteboard()
        drag_pasteboard = FakePasteboard()
        fake_appkit = types.SimpleNamespace(
            NSPasteboard=types.SimpleNamespace(
                generalPasteboard=lambda: general_pasteboard,
                pasteboardWithName_=lambda name: general_pasteboard if name == "general" else drag_pasteboard,
            ),
            NSPasteboardNameGeneral="general",
            NSPasteboardNameDrag="drag",
            NSPasteboardTypeString="public.utf8-plain-text",
        )

        with patch.dict(sys.modules, {"AppKit": fake_appkit}):
            adapter = platform_adapter.AppKitClipboardAdapter(pasteboard_mode="drag")

        self.assertEqual(adapter.pasteboard_mode, "drag")
        self.assertTrue(adapter.copy_to_clipboard("Secret!123"))
        self.assertEqual(drag_pasteboard.declared_types, ["public.utf8-plain-text"])
        self.assertEqual(drag_pasteboard.value, "Secret!123")

    def test_windows_clipboard_adapter_retries_busy_clipboard_and_succeeds(self):
        state = {"open_calls": 0, "closed_calls": 0, "stored_text": None}

        fake_win32clipboard = types.SimpleNamespace(
            CF_UNICODETEXT=13,
            OpenClipboard=lambda: self._fake_open_clipboard(state),
            EmptyClipboard=lambda: None,
            SetClipboardText=lambda value, _fmt: state.update(stored_text=value),
            CloseClipboard=lambda: state.update(closed_calls=state["closed_calls"] + 1),
            IsClipboardFormatAvailable=lambda _fmt: True,
            GetClipboardData=lambda _fmt: state["stored_text"],
        )

        adapter = platform_adapter.WindowsClipboardAdapter()

        with patch.dict(sys.modules, {"win32clipboard": fake_win32clipboard}):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(state["open_calls"], 2)
        self.assertEqual(state["closed_calls"], 1)
        self.assertEqual(state["stored_text"], "Secret!123")

    def test_windows_clipboard_adapter_uses_user32_fallback_for_clear(self):
        user32_calls = {"open": 0, "empty": 0, "close": 0}
        fake_user32 = types.SimpleNamespace(
            OpenClipboard=lambda _handle: self._fake_user32_open(user32_calls),
            EmptyClipboard=lambda: user32_calls.update(empty=user32_calls["empty"] + 1),
            CloseClipboard=lambda: user32_calls.update(close=user32_calls["close"] + 1),
        )
        adapter = platform_adapter.WindowsClipboardAdapter()

        with patch.object(adapter, "_with_win32clipboard", return_value=False), patch.object(
            platform_adapter.ctypes, "windll", types.SimpleNamespace(user32=fake_user32), create=True
        ):
            result = adapter.clear_clipboard()

        self.assertTrue(result)
        self.assertEqual(user32_calls["open"], 1)
        self.assertEqual(user32_calls["empty"], 1)
        self.assertEqual(user32_calls["close"], 1)

    def test_macos_clipboard_adapter_falls_back_to_osascript_on_missing_pbcopy(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            if command[0] == "pbcopy":
                raise FileNotFoundError("pbcopy not found")
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.MacOSClipboardAdapter()

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard('Secret "123"')

        self.assertTrue(result)
        self.assertEqual(calls[0], ["pbcopy"])
        self.assertEqual(calls[1][0], "osascript")

    def test_macos_clipboard_adapter_reads_with_osascript_fallback(self):
        calls = []

        def fake_run(command, text=None, capture_output=None, check=None):
            calls.append(command)
            if command[0] == "pbpaste":
                raise FileNotFoundError("pbpaste not found")
            return FakeProcessResult(returncode=0, stdout="clipboard text")

        adapter = platform_adapter.MacOSClipboardAdapter()

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            value = adapter.get_clipboard_content()

        self.assertEqual(value, "clipboard text")
        self.assertEqual(calls[0], ["pbpaste"])
        self.assertEqual(calls[1], ["osascript", "-e", "the clipboard as text"])

    def test_tk_clipboard_adapter_roundtrip(self):
        root = FakeRoot()
        adapter = platform_adapter.TkClipboardAdapter(root)

        self.assertTrue(adapter.copy_to_clipboard("Secret!123"))
        self.assertEqual(adapter.get_clipboard_content(), "Secret!123")
        self.assertTrue(adapter.clear_clipboard())
        self.assertEqual(adapter.get_clipboard_content(), "")
        self.assertEqual(root.update_calls, 2)

    def test_linux_clipboard_adapter_falls_back_to_next_command_on_missing_binary(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            if command[0] == "wl-copy":
                raise FileNotFoundError("wl-copy not found")
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.LinuxClipboardAdapter()

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(calls[0], ["wl-copy"])
        self.assertEqual(calls[1], ["xclip", "-selection", "clipboard"])

    def test_linux_clipboard_adapter_reads_from_first_successful_backend(self):
        calls = []

        def fake_run(command, text=None, capture_output=None, check=None):
            calls.append(command)
            if command[0] == "wl-paste":
                raise FileNotFoundError("wl-paste not found")
            return FakeProcessResult(returncode=0, stdout="clipboard text")

        adapter = platform_adapter.LinuxClipboardAdapter()

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            value = adapter.get_clipboard_content()

        self.assertEqual(value, "clipboard text")
        self.assertEqual(calls[0], ["wl-paste", "-n"])
        self.assertEqual(calls[1], ["xclip", "-selection", "clipboard", "-o"])

    def test_linux_clipboard_adapter_uses_primary_selection_commands(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.LinuxClipboardAdapter(selection_mode="primary")

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(calls[0], ["xclip", "-selection", "primary"])

    def test_linux_clipboard_adapter_reads_primary_selection_when_requested(self):
        calls = []

        def fake_run(command, text=None, capture_output=None, check=None):
            calls.append(command)
            return FakeProcessResult(returncode=0, stdout="primary text")

        adapter = platform_adapter.LinuxClipboardAdapter(selection_mode="primary")

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            value = adapter.get_clipboard_content()

        self.assertEqual(value, "primary text")
        self.assertEqual(calls[0], ["xclip", "-selection", "primary", "-o"])

    def test_linux_clipboard_adapter_writes_both_clipboard_and_primary_when_requested(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.LinuxClipboardAdapter(selection_mode="both")

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(calls[0], ["wl-copy"])
        self.assertIn(["xclip", "-selection", "clipboard"], calls)
        self.assertIn(["xclip", "-selection", "primary"], calls)

    @staticmethod
    def _fake_open_clipboard(state):
        state["open_calls"] += 1
        if state["open_calls"] == 1:
            raise RuntimeError("clipboard busy")

    @staticmethod
    def _fake_user32_open(state):
        state["open"] += 1
        return True


if __name__ == "__main__":
    unittest.main()