import copy
import json
from pathlib import Path
from typing import Any


class Config:  #этот класс будет хранить все настройки программы и сохранять их в файл
    #значения по дефолту (если нет файла конфигурации)
    DEFAULTS = {
        "database": {
            "path": str(Path.home() / ".cryptosafe" / "vault.db"),  #путь к файлу БД в домашней папке пользователя
        },
        #настройки безопасности
        "security": {
            "security_profile": "standard",
            "clipboard_timeout": 30,
            "auto_lock_minutes": 5,
            "activity_sensitivity": "medium",
            "device_profile": "desktop",
            "key_cache_timeout_minutes": 60,
            "lock_on_focus_loss": True,
            "lock_on_minimize": True,
            "memory_locking_enabled": True,
            "panic_hotkey": "Ctrl+Shift+Esc",
            "panic_close_application": False,
            "panic_stealth_mode": False,
            "panic_gesture_enabled": True,
            "panic_fake_error": True,
            "panic_decoy_command": "",
            "panic_redirect_url": "",
            "min_password_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_special": True,
        },
        #настройки криптографии
        "crypto": {
            "algorithm": "AES-256-GCM",
            "argon2_time": 3,
            "argon2_memory": 65536,
            "argon2_parallelism": 4,
            "argon2_hash_len": 32,
            "pbkdf2_iterations": 100000,
            "pbkdf2_salt_len": 16,
            "pbkdf2_key_len": 32,
        },
        #настройки внешнего вида
        "appearance": {
            "theme": "default", 
            "language": "ru",
        },
    }

    def __init__(self):  #при инициализации создаем копию дефолтных настроек, определяем путь к файлу конфигурации, создаем папку для конфигурации, если ее нет, и загружаем настройки из файла
        self.config = copy.deepcopy(self.DEFAULTS)
        self.config_file = Path.home() / ".cryptosafe" / "config.json"
        self._ensure_config_dir()
        self._load()

    def _ensure_config_dir(self):  #создаем папку для конфигурации, если ее нет
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

    def _deep_update(self, target: dict, source: dict):  #рекурсивно обновляем словарь target значениями из source, сохраняя структуру вложенности
        for key, value in source.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):  #если оба значения - словари, то рекурсивно обновляем их
                self._deep_update(target[key], value)
            else:
                target[key] = value

    def _load(self):  #загружаем конфигурацию из файла, если он существует, и обновляем дефолтные значения
        if not self.config_file.exists():
            return
        try:
            with open(self.config_file, "r", encoding="utf-8") as file:
                user_config = json.load(file)
            if isinstance(user_config, dict):
                self._deep_update(self.config, user_config)
        except Exception as error:
            print(f"Config load error: {error}")

    def save(self):  #сохраняем текущую конфигурацию в файл, перезаписывая его
        try:
            with open(self.config_file, "w", encoding="utf-8") as file:
                json.dump(self.config, file, indent=2, ensure_ascii=False)
        except Exception as error:
            print(f"Config save error: {error}")

    def get(self, key: str, default: Any = None) -> Any:  #получаем значение из конфигурации по ключу, который может быть вложенным 
        value: Any = self.config
        for part in key.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value

    def set(self, key: str, value: Any):  #устанавливаем значение в конфигурации по ключу, который может быть вложенным, и сохраняем изменения в файл
        parts = key.split(".")
        target = self.config
        for part in parts[:-1]:
            if part not in target or not isinstance(target[part], dict):
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value
        self.save()

    def get_security_settings(self) -> dict:
        from .security import validate_security_settings

        validation = validate_security_settings(dict(self.config.get("security", {})))
        return validation.settings

    def apply_security_profile(self, profile_name: str) -> dict:
        from .security import apply_security_profile

        updated = apply_security_profile(dict(self.config.get("security", {})), profile_name)
        self.config["security"].update(updated)
        self.save()
        return updated

    def validate_security_settings(self) -> Any:
        from .security import validate_security_settings

        return validate_security_settings(dict(self.config.get("security", {})))