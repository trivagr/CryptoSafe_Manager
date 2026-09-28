from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from typing import Optional


class ClipboardAdapterError(RuntimeError):
    pass


def get_platform_validation_report(
    *,
    root_available: bool = False,
    linux_selection_mode: str = "clipboard",
    macos_pasteboard_mode: str = "general",
) -> dict:
    normalized_linux_mode = str(linux_selection_mode or "clipboard").strip().lower()
    if normalized_linux_mode not in {"clipboard", "primary", "both"}:
        normalized_linux_mode = "clipboard"
    normalized_macos_mode = str(macos_pasteboard_mode or "general").strip().lower()
    if normalized_macos_mode not in {"general", "drag"}:
        normalized_macos_mode = "general"

    report = {
        "platform": sys.platform,
        "os_name": os.name,
        "root_available": bool(root_available),
        "linux_selection_mode": normalized_linux_mode,
        "macos_pasteboard_mode": normalized_macos_mode,
        "adapters": [],
        "ready": False,
    }

    if os.name == "nt":
        try:
            import win32clipboard  # type: ignore  # noqa: F401

            report["adapters"].append({"name": "windows_win32clipboard", "available": True})
        except Exception:
            report["adapters"].append({"name": "windows_win32clipboard", "available": False})

        try:
            user32 = ctypes.windll.user32
            report["adapters"].append({"name": "windows_user32", "available": bool(user32)})
        except Exception:
            report["adapters"].append({"name": "windows_user32", "available": False})
    elif sys.platform == "darwin":
        try:
            import AppKit  # type: ignore  # noqa: F401

            report["adapters"].append({"name": "macos_appkit", "available": True})
            report["adapters"].append({"name": f"macos_pasteboard_{normalized_macos_mode}", "available": True})
        except Exception:
            report["adapters"].append({"name": "macos_appkit", "available": False})
            report["adapters"].append({"name": f"macos_pasteboard_{normalized_macos_mode}", "available": False})

        report["adapters"].append({"name": "macos_pbcopy", "available": shutil.which("pbcopy") is not None})
        report["adapters"].append({"name": "macos_pbpaste", "available": shutil.which("pbpaste") is not None})
        report["adapters"].append({"name": "macos_osascript", "available": shutil.which("osascript") is not None})
    elif sys.platform.startswith("linux"):
        linux_commands = {
            "clipboard": ["wl-copy", "wl-paste", "xclip", "xsel"],
            "primary": ["xclip", "xsel"],
            "both": ["wl-copy", "wl-paste", "xclip", "xsel"],
        }
        for command_name in linux_commands[normalized_linux_mode]:
            report["adapters"].append(
                {
                    "name": f"linux_{command_name}",
                    "available": shutil.which(command_name) is not None,
                }
            )

    report["adapters"].append({"name": "tk_root", "available": bool(root_available)})

    try:
        import pyperclip  # type: ignore  # noqa: F401

        report["adapters"].append({"name": "pyperclip", "available": True})
    except Exception:
        report["adapters"].append({"name": "pyperclip", "available": False})

    report["ready"] = any(adapter["available"] for adapter in report["adapters"])
    return report


class ClipboardAdapter(ABC):
    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def clear_clipboard(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_clipboard_content(self) -> Optional[str]:
        raise NotImplementedError


class CompositeClipboardAdapter(ClipboardAdapter):
    def __init__(self, adapters: list[ClipboardAdapter]):
        self.adapters = adapters

    def copy_to_clipboard(self, data: str) -> bool:
        result = False
        for adapter in self.adapters:
            result = adapter.copy_to_clipboard(data) or result
        return result

    def clear_clipboard(self) -> bool:
        result = False
        for adapter in self.adapters:
            result = adapter.clear_clipboard() or result
        return result

    def get_clipboard_content(self) -> Optional[str]:
        for adapter in self.adapters:
            value = adapter.get_clipboard_content()
            if value is not None:
                return value
        return None


class WindowsClipboardAdapter(ClipboardAdapter):
    def _with_win32clipboard(self, action) -> bool:
        try:
            import win32clipboard  # type: ignore
        except Exception:
            return False

        for _attempt in range(3):
            opened = False
            try:
                win32clipboard.OpenClipboard()
                opened = True
                action(win32clipboard)
                return True
            except Exception:
                time.sleep(0.02)
            finally:
                if opened:
                    try:
                        win32clipboard.CloseClipboard()
                    except Exception:
                        pass
        return False

    def copy_to_clipboard(self, data: str) -> bool:
        return self._with_win32clipboard(
            lambda win32clipboard: (
                win32clipboard.EmptyClipboard(),
                win32clipboard.SetClipboardText(data, win32clipboard.CF_UNICODETEXT),
            )
        )

    def clear_clipboard(self) -> bool:
        if self._with_win32clipboard(lambda win32clipboard: win32clipboard.EmptyClipboard()):
            return True
        try:
            user32 = ctypes.windll.user32
            if not user32.OpenClipboard(None):
                return False
            try:
                user32.EmptyClipboard()
                return True
            finally:
                try:
                    user32.CloseClipboard()
                except Exception:
                    pass
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            import win32clipboard  # type: ignore
        except Exception:
            return None

        for _attempt in range(3):
            opened = False
            try:
                win32clipboard.OpenClipboard()
                opened = True
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                return None
            except Exception:
                time.sleep(0.02)
            finally:
                if opened:
                    try:
                        win32clipboard.CloseClipboard()
                    except Exception:
                        pass
        return None


class MacOSClipboardAdapter(ClipboardAdapter):
    def _run_commands(self, commands: list[list[str]], *, input_data: Optional[str] = None) -> bool:
        for command in commands:
            try:
                process = subprocess.run(
                    command,
                    input=input_data,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if process.returncode == 0:
                    return True
            except FileNotFoundError:
                continue
            except Exception:
                return False
        return False

    def copy_to_clipboard(self, data: str) -> bool:
        escaped_data = data.replace("\\", "\\\\").replace('"', '\\"')
        return self._run_commands(
            [
                ["pbcopy"],
                ["osascript", "-e", f'set the clipboard to "{escaped_data}"'],
            ],
            input_data=data,
        )

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        for command in [["pbpaste"], ["osascript", "-e", "the clipboard as text"]]:
            try:
                process = subprocess.run(command, text=True, capture_output=True, check=False)
                if process.returncode == 0:
                    return process.stdout
            except FileNotFoundError:
                continue
            except Exception:
                return None
        return None


class AppKitClipboardAdapter(ClipboardAdapter):
    def __init__(self, pasteboard_mode: str = "general"):
        try:
            from AppKit import (  # type: ignore
                NSPasteboard,
                NSPasteboardNameDrag,
                NSPasteboardNameGeneral,
                NSPasteboardTypeString,
            )
        except Exception as error:
            raise ClipboardAdapterError("AppKit clipboard недоступен") from error
        normalized_mode = str(pasteboard_mode or "general").strip().lower()
        if normalized_mode not in {"general", "drag"}:
            normalized_mode = "general"
        self.pasteboard_mode = normalized_mode
        if normalized_mode == "drag":
            self._pasteboard = NSPasteboard.pasteboardWithName_(NSPasteboardNameDrag)
        else:
            self._pasteboard = NSPasteboard.pasteboardWithName_(NSPasteboardNameGeneral)
        self._string_type = NSPasteboardTypeString

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self._pasteboard.clearContents()
            self._pasteboard.declareTypes_owner_([self._string_type], None)
            return bool(self._pasteboard.setString_forType_(data, self._string_type))
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self._pasteboard.clearContents()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self._pasteboard.stringForType_(self._string_type)
        except Exception:
            return None


class LinuxClipboardAdapter(ClipboardAdapter):
    def __init__(self, selection_mode: str = "clipboard"):
        normalized_mode = str(selection_mode or "clipboard").strip().lower()
        if normalized_mode not in {"clipboard", "primary", "both"}:
            normalized_mode = "clipboard"
        self.selection_mode = normalized_mode

    def _copy_commands(self) -> list[list[str]]:
        if self.selection_mode == "primary":
            return [["xclip", "-selection", "primary"], ["xsel", "--primary", "--input"]]
        if self.selection_mode == "both":
            return [
                ["wl-copy"],
                ["xclip", "-selection", "clipboard"],
                ["xclip", "-selection", "primary"],
                ["xsel", "--clipboard", "--input"],
                ["xsel", "--primary", "--input"],
            ]
        return [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]

    def _read_commands(self) -> list[list[str]]:
        if self.selection_mode == "primary":
            return [["xclip", "-selection", "primary", "-o"], ["xsel", "--primary", "--output"]]
        if self.selection_mode == "both":
            return [
                ["wl-paste", "-n"],
                ["xclip", "-selection", "clipboard", "-o"],
                ["xclip", "-selection", "primary", "-o"],
                ["xsel", "--clipboard", "--output"],
                ["xsel", "--primary", "--output"],
            ]
        return [["wl-paste", "-n"], ["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]]

    def copy_to_clipboard(self, data: str) -> bool:
        result = False
        for command in self._copy_commands():
            try:
                process = subprocess.run(command, input=data, text=True, capture_output=True, check=False)
                if process.returncode == 0:
                    result = True
                    if self.selection_mode != "both":
                        return True
            except FileNotFoundError:
                continue
            except Exception:
                return False
        return result

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        for command in self._read_commands():
            try:
                process = subprocess.run(command, text=True, capture_output=True, check=False)
                if process.returncode == 0:
                    return process.stdout
            except FileNotFoundError:
                continue
            except Exception:
                return None
        return None


class PyperclipClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        try:
            import pyperclip  # type: ignore
        except Exception as error:
            raise ClipboardAdapterError("Pyperclip недоступен") from error
        self.pyperclip = pyperclip

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self.pyperclip.paste()
        except Exception:
            return None


class TkClipboardAdapter(ClipboardAdapter):
    def __init__(self, root):
        self.root = root

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(data)
            self.root.update()
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self.root.clipboard_clear()
            self.root.update()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self.root.clipboard_get()
        except Exception:
            return None


def create_platform_adapter(
    root=None,
    *,
    linux_selection_mode: str = "clipboard",
    macos_pasteboard_mode: str = "general",
) -> ClipboardAdapter:
    adapters: list[ClipboardAdapter] = []

    if os.name == "nt":
        adapters.append(WindowsClipboardAdapter())
    elif sys.platform == "darwin":
        try:
            adapters.append(AppKitClipboardAdapter(pasteboard_mode=macos_pasteboard_mode))
        except ClipboardAdapterError:
            pass
        adapters.append(MacOSClipboardAdapter())
    elif sys.platform.startswith("linux"):
        adapters.append(LinuxClipboardAdapter(selection_mode=linux_selection_mode))

    if root is not None:
        adapters.append(TkClipboardAdapter(root))

    try:
        adapters.append(PyperclipClipboardAdapter())
    except ClipboardAdapterError:
        pass

    if not adapters:
        raise ClipboardAdapterError("Не удалось подобрать адаптер буфера обмена")
    return CompositeClipboardAdapter(adapters)