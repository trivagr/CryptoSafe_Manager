from pathlib import Path

class ConfigManager :
    def __init__(self,env: str="development"):
        self.env = env
        self.database_dir = Path.home() / "databases"
        self.database = {
            "vault_entries" : "vault_entries.db",
            "audit_log" : "audit_log.db",
            "settings" : "settings.db",
            "key_store" : "key_store.db",
        }

        self.crypto = {
            "algorithm" : "AES256",
        }

        self.ui = {
            "language" : "ru",
            "theme" : "WHITE",
            "font_size" : 14,
        }

    def ensure_dirs_existe(self):
            self.database_dir.mkdir(parents=True, exist_ok=True)

    def get_db_path(self, db_name: str) -> Path:
            return Path(self.database_dir / self.database[db_name])

    def set_ui_settings(self, setting: str, update):
        if setting == "font_size" and isinstance(update, int):
            self.ui.update({setting: update})
        elif setting != "font_size" and isinstance(update, str):
            self.ui.update({setting: update})
        else:
            print("Неправильный формат данных")
        return self.ui

    def get_ui_settings(self, setting: str):
            return self.ui[setting]

    def get_crypto_settings(self, algorithm: str):
            return self.crypto[algorithm]