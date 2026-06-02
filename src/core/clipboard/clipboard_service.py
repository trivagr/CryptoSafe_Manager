import threading
import time
from datetime import datetime

from src.core.events import (
    ClipboardCopied,
    ClipboardCleared
)

from src.core.config import ConfigManager


class ClipboardType:

    TEXT = "text"
    TOTP = "totp"
    ENCRYPTED = "encrypted"


class ClipboardService:

    def __init__(self, adapter, event_bus):

        self.adapter = adapter
        self.event_bus = event_bus

        self.config = ConfigManager()

        self._observers = []

        self._timer = None

        self._current_type = None
        self._current_entry = None

        self._expires_at = None

    def subscribe(self, callback):

        if callback not in self._observers:
            self._observers.append(callback)

    def unsubscribe(self, callback):

        if callback in self._observers:
            self._observers.remove(callback)

    def _notify(self, event):

        for observer in self._observers:
            observer(event)

    def _cancel_timer(self):

        if self._timer:

            self._timer.cancel()

            self._timer = None

    def _start_timer(self):

        timeout = self.config.clipboard["auto_clear_seconds"]

        if timeout == 0:
            return

        if timeout < 5 or timeout > 300:
            raise ValueError(
                "Clipboard timeout must be between 5 and 300 seconds"
            )

        self._expires_at = time.time() + timeout

        self._timer = threading.Timer(
            timeout,
            self.clear
        )

        self._timer.daemon = True

        self._timer.start()

    def copy(self, data, data_type=ClipboardType.TEXT, entry_id=0):

        self.clear()

        self.adapter.set_text(
            str(data)
        )

        self._current_type = data_type

        self._current_entry = entry_id

        event = ClipboardCopied(
            timestamp=datetime.now(),
            entry_id=entry_id
        )

        self.event_bus.publish(event)

        self._notify(event)

        self._start_timer()

    def clear(self):

        self._cancel_timer()

        self.adapter.clear()

        self._current_type = None

        self._current_entry = None

        self._expires_at = None

        event = ClipboardCleared(
            timestamp=datetime.now()
        )

        self.event_bus.publish(event)

        self._notify(event)

    def get_text(self):

        return self.adapter.get_text()

    def get_remaining_seconds(self):

        if self._expires_at is None:
            return 0

        remaining = int(
            self._expires_at - time.time()
        )

        return max(
            0,
            remaining
        )

    @property
    def current_type(self):

        return self._current_type

    @property
    def current_entry(self):

        return self._current_entry