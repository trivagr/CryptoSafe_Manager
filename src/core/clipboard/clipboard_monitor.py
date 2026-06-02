import threading
import time


class ClipboardMonitor:

    def __init__(
        self,
        clipboard_service,
        check_interval=1
    ):

        self.clipboard_service = clipboard_service

        self.check_interval = check_interval

        self.suspicious_activity = False

        self.block_future_copies = False

        self._running = False

        self._thread = None

        self._last_known_value = ""

        self._internal_change = False

        self._callbacks = []

    def subscribe(self, callback):

        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def unsubscribe(self, callback):

        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def _notify(self):

        for callback in self._callbacks:

            try:
                callback()
            except Exception:
                pass

    def start(self):

        if self._running:
            return

        self._running = True

        try:
            self._last_known_value = (
                self.clipboard_service.get_text()
            )
        except Exception:
            self._last_known_value = ""

        self._thread = threading.Thread(
            target=self._worker,
            daemon=True
        )

        self._thread.start()

    def stop(self):

        self._running = False

    def reset_alerts(self):

        self.suspicious_activity = False

        self.block_future_copies = False

    def block_copying(self):

        self.block_future_copies = True

    def allow_copying(self):

        self.block_future_copies = False

    def mark_internal_copy(self):

        self._internal_change = True

        try:
            self._last_known_value = (
                self.clipboard_service.get_text()
            )
        except Exception:
            self._last_known_value = ""

    def _handle_suspicious_activity(self):

        self.suspicious_activity = True

        self.clipboard_service.clear()

        self._notify()

    def _worker(self):

        while self._running:

            try:

                current = (self.clipboard_service.get_text())

                if self._internal_change:

                    self._internal_change = False

                    self._last_known_value = current

                elif current != self._last_known_value:

                    self._handle_suspicious_activity()

                    self._last_known_value = ""

                time.sleep(self.check_interval)

            except Exception:

                time.sleep( self.check_interval)