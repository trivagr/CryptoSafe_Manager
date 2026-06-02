from pathlib import Path


class ConfigManager:

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, env: str = "development"):

        if hasattr(self, "_initialized"):
            return

        self._initialized = True

        self.env = env
        self.database_dir = Path.home() / "databases"

        self.database = {
            "vault_entries": "vault_entries.db",
            "audit_log": "audit_log.db",
            "settings": "settings.db",
            "key_store": "key_store.db",
        }

        self.crypto = {
            "AES256": {}
        }

        self.ui = {
            "language": "ru",
            "theme": "WHITE",
            "font_size": 14,
        }

        self.argon2 = {
            "time_cost": 3,
            "memory_cost": 65536,
            "parallelism": 4,
            "hash_len": 32,
            "salt_len": 16,
            "type": "argon2id"
        }

        self.pbkdf2 = {
            "iterations": 100000
        }

        self.password_generator = {
            "length": 16,
            "min_length": 8,
            "max_length": 64
        }

        self.clipboard = {
            "auto_clear_seconds" : 30
        }

    def ensure_dirs_exist(self):
        self.database_dir.mkdir(parents=True, exist_ok=True)

    def get_db_path(self, db_name: str) -> Path:
        return self.database_dir / self.database[db_name]

    def set_ui_settings(self, setting: str, value):
        if setting not in self.ui:
            raise ValueError("Unknown UI setting")

        self.ui[setting] = value
        return self.ui

    def get_ui_settings(self, setting: str):
        return self.ui[setting]

    def get_crypto_settings(self):
        return self.crypto

    def get_argon2_settings(self):
        return self.argon2

    def get_pbkdf2_settings(self):
        return self.pbkdf2

    def get_password_generator(self):
        return self.password_generator

    def get_clipboard(self):
        return self.clipboard