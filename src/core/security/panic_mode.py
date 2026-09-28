import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from .side_channel_protection import sanitize_security_metadata


@dataclass
class PanicModeConfig:
    hotkey: str = "Ctrl+Shift+Esc"
    close_application: bool = False
    hide_windows: bool = True
    clear_clipboard: bool = True
    stealth_mode: bool = False


@dataclass
class PanicModeResult:
    activated: bool
    method: str
    handlers_run: list[str] = field(default_factory=list)
    handler_errors: dict[str, str] = field(default_factory=dict)


class PanicMode:
    def __init__(self, config: PanicModeConfig | None = None, event_bus: Any | None = None):
        self.config = config or PanicModeConfig()
        self.event_bus = event_bus
        self.activated = False
        self._handlers: list[tuple[str, Callable[[], None]]] = []
        self._lock = threading.RLock()

    def register_handler(self, name: str, handler: Callable[[], None]) -> None:
        clean_name = str(name or "handler").strip() or "handler"
        self._handlers.append((clean_name, handler))

    def activate(self, method: str = "hotkey", details: dict | None = None) -> PanicModeResult:
        with self._lock:
            if self.activated:
                return PanicModeResult(activated=False, method=method)
            self.activated = True

        result = PanicModeResult(activated=True, method=method)
        # Publish before handlers: panic handlers wipe keys and lock the vault,
        # so audit must receive the activation while signing key is still alive.
        self._publish_activation(method, details or {}, result)
        for name, handler in list(self._handlers):
            try:
                handler()
                result.handlers_run.append(name)
            except Exception as exc:
                result.handler_errors[name] = str(exc)

        return result

    def reset_for_recovery(self) -> None:
        with self._lock:
            self.activated = False
        if self.event_bus is not None:
            from ..events import Event, EventType

            self.event_bus.publish(Event(EventType.PANIC_MODE_DEACTIVATED, {"status": "recovered"}))

    def _publish_activation(self, method: str, details: dict, result: PanicModeResult) -> None:
        if self.event_bus is None:
            return
        from ..events import Event, EventType

        payload = {
            "method": method,
            "hotkey": self.config.hotkey,
            "handlers_run": list(result.handlers_run),
            "handler_errors": dict(result.handler_errors),
            "details": sanitize_security_metadata(details),
        }
        self.event_bus.publish(Event(EventType.PANIC_MODE_ACTIVATED, payload))