import threading
import time


class RotationWorker:
    def __init__(self, db_helper, crypto):
        self.db = db_helper
        self.crypto = crypto

        self._pause_event = threading.Event()
        self._pause_event.set()

        self._cancel = False
        self.progress = 0
        self.total = 0
        self._status = "idle"

        self.on_progress = None  # callback

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def cancel(self):
        self._cancel = True
        self._status = "cancelled"

    def run(self, old_key, new_key):
        self._status = "running"
        entries = self.db.get_all_entries()

        self.total = len(entries)
        self.progress = 0

        for entry in entries:

            self._pause_event.wait(timeout=0.1)

            if self._cancel:
                self._status = "cancelled"
                return

            decrypted = self.crypto.decrypt(
                entry["encrypted_password"],
                old_key
            )

            encrypted = self.crypto.encrypt(
                decrypted,
                new_key
            )

            self.db.update_entry_password(entry["id"], encrypted)

            self.progress += 1

            if self.on_progress:
                self.on_progress(self.progress, self.total)

            time.sleep(0.01)
        self._status = "done"