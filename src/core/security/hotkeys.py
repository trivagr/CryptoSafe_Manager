import ctypes
import ctypes.wintypes
import os
import threading
from dataclasses import dataclass
from typing import Callable


MODIFIERS = {
    "ctrl": 0x0002,
    "control": 0x0002,
    "shift": 0x0004,
    "alt": 0x0001,
    "win": 0x0008,
    "windows": 0x0008,
}

VK_CODES = {
    "esc": 0x1B,
    "escape": 0x1B,
    "delete": 0x2E,
    "del": 0x2E,
    "comma": 0xBC,
}


@dataclass(frozen=True)
class HotkeyBinding:
    action: str
    label: str
    tk_sequence: str
    description: str
    global_hotkey: bool = False


DEFAULT_HOTKEYS: tuple[HotkeyBinding, ...] = (
    HotkeyBinding("panic_mode", "Ctrl+Shift+Esc", "<Control-Shift-Escape>", "Экстренно заблокировать хранилище", True),
    HotkeyBinding("lock_vault", "Ctrl+L", "<Control-l>", "Заблокировать хранилище"),
    HotkeyBinding("unlock_vault", "Ctrl+U", "<Control-u>", "Разблокировать хранилище"),
    HotkeyBinding("focus_search", "Ctrl+F", "<Control-f>", "Перейти к поиску"),
    HotkeyBinding("add_entry", "Ctrl+N", "<Control-n>", "Добавить запись"),
    HotkeyBinding("edit_entry", "Ctrl+E", "<Control-e>", "Изменить выбранную запись"),
    HotkeyBinding("delete_entry", "Delete", "<Delete>", "Удалить выбранную запись"),
    HotkeyBinding("toggle_passwords", "Ctrl+Shift+P", "<Control-Shift-P>", "Показать или скрыть пароли"),
    HotkeyBinding("clear_clipboard", "Ctrl+Shift+C", "<Control-Shift-C>", "Очистить буфер обмена"),
    HotkeyBinding("open_settings", "Ctrl+,", "<Control-comma>", "Открыть настройки"),
)


def get_default_hotkeys() -> dict[str, HotkeyBinding]:
    return {binding.action: binding for binding in DEFAULT_HOTKEYS}


def parse_windows_hotkey(label: str) -> tuple[int, int]:
    parts = [part.strip().lower() for part in str(label or "").replace("+", " ").split() if part.strip()]
    if not parts:
        raise ValueError("Hotkey is empty")

    modifiers = 0
    key = ""
    for part in parts:
        if part in MODIFIERS:
            modifiers |= MODIFIERS[part]
        else:
            key = part
    if not key:
        raise ValueError("Hotkey key is missing")

    if len(key) == 1 and key.isalnum():
        virtual_key = ord(key.upper())
    else:
        try:
            virtual_key = VK_CODES[key]
        except KeyError as error:
            raise ValueError(f"Unsupported Windows hotkey key: {key}") from error
    return modifiers, virtual_key


class WindowsGlobalHotkeyService:
    def __init__(self, tk_root, callback: Callable[[str], None], *, user32=None, kernel32=None):
        self.tk_root = tk_root
        self.callback = callback
        windll = getattr(ctypes, "windll", None)
        self.user32 = user32 if user32 is not None else windll.user32 if os.name == "nt" and windll is not None else None
        self.kernel32 = kernel32 if kernel32 is not None else windll.kernel32 if os.name == "nt" and windll is not None else None
        self._registered: dict[int, tuple[str, int | None]] = {}
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._next_id = 0x4353

    @property
    def supported(self) -> bool:
        return os.name == "nt" and self.user32 is not None

    def register(self, label: str, action: str) -> bool:
        if not self.supported:
            return False
        modifiers, virtual_key = parse_windows_hotkey(label)
        hotkey_id = self._next_id
        self._next_id += 1
        ready = threading.Event()
        result = {"registered": False, "thread_id": None}
        thread = threading.Thread(
            target=self._run_hotkey_loop,
            args=(hotkey_id, modifiers, virtual_key, action, ready, result),
            name=f"cryptosafe-hotkey-{hotkey_id}",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)
        ready.wait(timeout=1.0)
        if not result["registered"]:
            return False
        self._registered[hotkey_id] = (action, result["thread_id"])
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if not self.supported:
            return
        for hotkey_id, (_action, thread_id) in list(self._registered.items()):
            if thread_id is not None:
                try:
                    self.user32.PostThreadMessageW(thread_id, 0x0012, 0, 0)
                except Exception:
                    pass
            try:
                self.user32.UnregisterHotKey(None, hotkey_id)
            except Exception:
                pass
        self._registered.clear()

    def _run_hotkey_loop(self, hotkey_id: int, modifiers: int, virtual_key: int, action: str, ready, result) -> None:
        if self.kernel32 is not None:
            try:
                result["thread_id"] = int(self.kernel32.GetCurrentThreadId())
            except Exception:
                result["thread_id"] = None
        result["registered"] = bool(self.user32.RegisterHotKey(None, hotkey_id, modifiers, virtual_key))
        ready.set()
        if not result["registered"]:
            return

        msg = ctypes.wintypes.MSG()
        while not self._stop_event.is_set():
            message_result = self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if message_result <= 0:
                break
            if msg.message == 0x0312 and int(msg.wParam) == hotkey_id:
                self._dispatch(action)
        try:
            self.user32.UnregisterHotKey(None, hotkey_id)
        except Exception:
            pass

    def _dispatch(self, action: str) -> None:
        try:
            self.tk_root.after(0, lambda: self.callback(action))
        except Exception:
            self.callback(action)