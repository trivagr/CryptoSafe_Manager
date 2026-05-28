import threading

from src.core.crypto.password_validator import validate_password
from src.core.crypto.placeholder import secure_zero_bytes


class PasswordChange:

    def __init__(
            self,
            key_manager,
            key_deriver,
            db_helper
    ):

        self.key_manager = key_manager
        self.key_deriver = key_deriver
        self.db_helper = db_helper

        self._state_lock = (threading.Lock())

        self.thread = None

    def change_password_async(self, old_password: bytes, new_password: bytes, confirm_password: bytes, on_progress=None, on_done=None, on_error=None):

        if self.thread and self.thread.is_alive():

            raise ValueError(
                "Password change already running"
            )

        credentials = (self.db_helper.get_master_credentials())

        if credentials is None:

            raise ValueError(
                "Credentials not found"
            )

        stored_hash = (credentials["password_hash"])

        valid = (self.key_manager.hashing.password_verify(old_password, stored_hash))

        if not valid:
            raise ValueError("Wrong password")

        new_password_str = new_password.decode()
        confirm_password_str = confirm_password.decode()

        try:
            if not validate_password(new_password_str):
                raise ValueError("Weak password")

            if (new_password_str != confirm_password_str):
                raise ValueError("Passwords do not match")

        finally:
            del new_password_str
            del confirm_password_str

        old_key = (self.key_manager.get_key())
        new_salt = (self.key_deriver.salt_generate())
        new_key = bytearray(self.key_deriver.derive(new_password, new_salt))

        def job():

            try:

                rows = self.db_helper.execute("""
                    SELECT id, encrypted_data
                    FROM vault_entries
                """)

                total = len(rows)

                for index, row in enumerate(rows):

                    entry_id = row[0]
                    encrypted = row[1]

                    self.key_manager.storage.store_key(old_key)

                    data = self.db_helper.crypto.decrypt(encrypted)

                    self.key_manager.storage.store_key(new_key)

                    new_encrypted = self.db_helper.crypto.encrypt(data)

                    self.db_helper.execute("""
                        UPDATE vault_entries
                        SET encrypted_data=?
                        WHERE id=?
                    """, (
                        new_encrypted,
                        entry_id
                    ), fetch=False)

                    if on_progress:
                        percent = int((index + 1) / total * 100)

                        on_progress(percent)

                new_hash = self.key_deriver.hash_password(
                    new_password
                )

                self.db_helper.set_master_password(
                    new_hash,
                    new_salt
                )

                self.key_manager.lock()

                self.key_manager.storage.store_key(
                    new_key
                )

                self.key_manager._unlocked = True

                if on_done:
                    on_done()

            except Exception as e:

                import traceback

                traceback.print_exc()

                if on_error:
                    on_error(str(e))

            finally:
                secure_zero_bytes(new_key)