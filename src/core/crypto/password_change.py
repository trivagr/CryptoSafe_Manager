import threading
import time
from src.core.crypto.password_validator import validate_password
from src.core.crypto.rotation_worker import RotationWorker


class PasswordChange:
    def __init__(self, key_manager, key_deriver, db_helper):
        self.key_manager = key_manager
        self.key_deriver = key_deriver
        self.db_helper = db_helper

        self._status = "idle"
        self._state_lock = threading.Lock()

        self.worker = None
        self.thread = None

    def change_password_async(
        self,
        old_password,
        new_password,
        confirm_password,
        on_progress=None,
        on_done=None,
        on_error=None
    ):
        with self._state_lock:
            if self.thread and self.thread.is_alive():
                raise ValueError("Rotation already in progress")
            self._status = "running"

        record = self.db_helper.get_active_key()

        salt = record["salt"]
        stored_hash = record["hash"]

        if not self.key_manager.unlock(old_password, stored_hash, salt):
            raise ValueError("Auth failed")

        if not validate_password(new_password):
            raise ValueError("Weak password")

        if new_password != confirm_password:
            raise ValueError("Passwords do not match")

        old_key = self.key_manager.get_key()

        new_salt = self.key_deriver.salt_generate()
        new_key = self.key_deriver.derive(new_password, new_salt)

        self.worker = RotationWorker(self.db_helper, self.db_helper.crypto)
        self.worker.on_progress = on_progress

        def job():
            try:
                self.key_manager.lock()

                self.db_helper.begin()

                self.worker.run(old_key, new_key)

                new_hash = self.key_deriver.hash_password(new_password)
                self._update_key_store(new_hash, new_salt)

                self.db_helper.commit()

                with self._state_lock:
                    self._status = "done"

                if on_done:
                    on_done(new_hash, new_salt)

            except Exception as e:
                self.db_helper.rollback()

                self.key_manager.unlock(old_password, stored_hash, salt)

                with self._state_lock:
                    self._status = "failed"

                if on_error:
                    on_error(e)

            finally:
                self.clean_up()

        self.thread = threading.Thread(target=job, daemon=True)
        self.thread.start()

    def clean_up(self):
        with self._state_lock:
            self.worker = None
            self.thread = None
            self._status = "idle"

    def _update_key_store(self, new_hash, new_salt):
        params = {
            "type": "argon2_pbkdf2",
            "active": True
        }

        self.db_helper.execute("""
            UPDATE key_store
            SET salt = ?, hash = ?, params = ?, created_at = ?, version = version + 1
            WHERE key_type = 'master_key'
        """, (
            new_salt,
            new_hash,
            str(params),
            time.time()
        ))