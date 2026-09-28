import base64
import os
import re
from typing import Dict, Optional

from argon2 import PasswordHasher, Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..security.side_channel_protection import constant_time_compare


class KeyDerivation:  #класс для управления процессом создания и проверки хэшей паролей
    ARGON2_HASH_RE = re.compile(
        r"^\$argon2id\$v=(?P<version>\d+)\$m=(?P<memory>\d+),t=(?P<time>\d+),p=(?P<parallelism>\d+)"
        r"\$(?P<salt>[^$]+)\$(?P<hash>[^$]+)$"
    )

    def __init__(self, config: Dict):
        self.argon2_time = self._validated_int(config.get("argon2_time", 3), minimum=3, maximum=10, default=3)
        self.argon2_memory = self._validated_int(
            config.get("argon2_memory", 65536), minimum=65536, maximum=262144, default=65536
        )
        self.argon2_parallelism = self._validated_int(
            config.get("argon2_parallelism", 4), minimum=1, maximum=8, default=4
        )
        self.argon2_hash_len = self._validated_int(config.get("argon2_hash_len", 32), minimum=16, maximum=64, default=32)
        self.pbkdf2_iterations = self._validated_int(
            config.get("pbkdf2_iterations", 100000), minimum=100000, maximum=1000000, default=100000
        )
        self.pbkdf2_salt_len = self._validated_int(config.get("pbkdf2_salt_len", 16), minimum=16, maximum=64, default=16)
        self.pbkdf2_key_len = self._validated_int(config.get("pbkdf2_key_len", 32), minimum=32, maximum=64, default=32)

        self.argon2_hasher = PasswordHasher(
            time_cost=self.argon2_time,
            memory_cost=self.argon2_memory,
            parallelism=self.argon2_parallelism,
            hash_len=self.argon2_hash_len,
            salt_len=16,
            type=Type.ID,
        )

    def export_params(self) -> dict:
        return {
            "version": 1,
            "auth_algorithm": "argon2id",
            "argon2_version": 19,
            "argon2_time": self.argon2_time,
            "argon2_memory": self.argon2_memory,
            "argon2_parallelism": self.argon2_parallelism,
            "argon2_hash_len": self.argon2_hash_len,
            "encryption_kdf": "pbkdf2-hmac-sha256",
            "pbkdf2_iterations": self.pbkdf2_iterations,
            "pbkdf2_salt_len": self.pbkdf2_salt_len,
            "pbkdf2_key_len": self.pbkdf2_key_len,
        }

    @classmethod
    def from_params(cls, params: Optional[Dict]) -> "KeyDerivation":
        return cls(params or {})

    def create_auth_hash(self, password: str) -> dict:  #метод для создания хэша пароля, который возвращает словарь с хэшем и параметрами алгоритма
        hash_str = self.argon2_hasher.hash(password)
        return {
            "hash": hash_str,
            "algorithm": "argon2id",
            "time_cost": self.argon2_time,
            "memory_cost": self.argon2_memory,
            "parallelism": self.argon2_parallelism,
            "hash_len": self.argon2_hash_len,
            "version": 19,
        }

    def verify_auth_hash(self, password: str, stored_hash: str) -> bool:  #метод для проверки пароля по хэшу
        match = self.ARGON2_HASH_RE.match(stored_hash)
        if not match:
            self._dummy_verify()
            return False

        try:
            expected_hash = self._argon2_b64decode(match.group("hash"))  #декодируем хэш из строки
            salt = self._argon2_b64decode(match.group("salt"))  #декодируем соль из строки
            derived_hash = hash_secret_raw(
                secret=password.encode("utf-8"),
                salt=salt,
                time_cost=int(match.group("time")),
                memory_cost=int(match.group("memory")),
                parallelism=int(match.group("parallelism")),
                hash_len=len(expected_hash),
                type=Type.ID,
                version=int(match.group("version")),
            )
            return constant_time_compare(derived_hash, expected_hash)
        except Exception:
            self._dummy_verify()
            return False

    def hash_needs_rehash(self, stored_hash: str) -> bool:  #метод для проверки, нужно ли обновить хэш пароля
        try:
            return self.argon2_hasher.check_needs_rehash(stored_hash)
        except Exception:
            return True

    def derive_encryption_key(self, password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:  #метод для получения ключа шифрования из пароля
        if salt is None:
            salt = os.urandom(self.pbkdf2_salt_len)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.pbkdf2_key_len,
            salt=salt,
            iterations=self.pbkdf2_iterations,
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt

    def derive_key_with_known_salt(self, password: str, salt: bytes) -> bytes:  #метод для получения ключа шифрования из пароля и известного соли
        key, _ = self.derive_encryption_key(password, salt)
        return key

    def _dummy_verify(self):  #метод для выполнения фиктивной проверки пароля
        constant_time_compare(b"dummy_constant_time_string", b"dummy_constant_time_string")

    def _validated_int(self, value, minimum: int, maximum: int, default: int) -> int:  #метод для проверки и ограничения целочисленных параметров конфигурации
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        if parsed < minimum:
            return minimum
        if parsed > maximum:
            return maximum
        return parsed

    def _argon2_b64decode(self, value: str) -> bytes:  #метод для декодирования строки хэша и соли
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding)