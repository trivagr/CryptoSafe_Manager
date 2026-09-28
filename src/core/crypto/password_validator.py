import ctypes
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from ...database.db import Database
from ...database.models import KeyStore


@dataclass
class KeyMetadata:  #класс для хранения метаданных ключа
    auth_hash: str
    encryption_salt: bytes
    params: dict
    version: int = 1


class KeyStorage:  #класс для управления хранением ключей и метаданных в базе данных
    AUTH_HASH_KEY_TYPE = "auth_hash"
    ENC_SALT_KEY_TYPE = "enc_salt"
    PARAMS_KEY_TYPE = "params"
    LEGACY_MASTER_KEY_TYPE = "master"

    def __init__(self, database: Database):
        self.database = database
        self._cached_key: Optional[bytearray] = None
        self._cached_key_length = 0
        self._cache_expires_at: Optional[datetime] = None
        self._memory_protected = False
        self._crypt32 = self._load_crypt32()

    def has_master_key(self) -> bool:  #метод для проверки наличия сохраненного ключа в базе данных
        return (
            self.database.get_key_store(self.AUTH_HASH_KEY_TYPE) is not None
            or self.database.get_key_store(self.LEGACY_MASTER_KEY_TYPE) is not None
        )

    def store_metadata(self, auth_hash: str, encryption_salt: bytes, params: dict):  #метод для сохранения метаданных ключа в базе данных
        now = datetime.now()
        version = int(params.get("version", 1))
        params_json = json.dumps(params, ensure_ascii=False)

        records = [
            KeyStore(
                key_type=self.AUTH_HASH_KEY_TYPE,
                key_data=auth_hash.encode("utf-8"),
                version=version,
                created_at=now,
                hash=auth_hash,
                last_rotated_at=now,
            ),
            KeyStore(
                key_type=self.ENC_SALT_KEY_TYPE,
                key_data=encryption_salt,
                version=version,
                created_at=now,
                salt=encryption_salt,
                last_rotated_at=now,
            ),
            KeyStore(
                key_type=self.PARAMS_KEY_TYPE,
                key_data=params_json.encode("utf-8"),
                version=version,
                created_at=now,
                params=params_json,
                last_rotated_at=now,
            ),
        ]

        for record in records:
            self.database.save_key_store(record)

    def load_metadata(self) -> Optional[KeyMetadata]:  #метод для загрузки метаданных ключа из базы данных
        auth_hash = self.database.get_key_store(self.AUTH_HASH_KEY_TYPE)
        enc_salt = self.database.get_key_store(self.ENC_SALT_KEY_TYPE)
        params = self.database.get_key_store(self.PARAMS_KEY_TYPE)
        if auth_hash and enc_salt and params:
            params_data = self._decode_params(params)
            return KeyMetadata(
                auth_hash=self._decode_text(auth_hash.key_data, auth_hash.hash),
                encryption_salt=enc_salt.key_data or enc_salt.salt,
                params=params_data,
                version=auth_hash.version or params_data.get("version", 1),
            )

        legacy = self.database.get_key_store(self.LEGACY_MASTER_KEY_TYPE)
        if legacy is None:
            return None
        params_data = self._decode_legacy_params(legacy)
        return KeyMetadata(
            auth_hash=legacy.hash or self._decode_text(legacy.key_data, ""),
            encryption_salt=legacy.salt,
            params=params_data,
            version=int(params_data.get("version", legacy.version or 1)),
        )

    def cache_active_key(self, key: bytes, ttl_seconds: int = 3600):
        self.clear_cached_key()
        self._cached_key = bytearray(key)
        self._cached_key_length = len(key)
        self._cache_expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
        self._memory_protected = self._protect_memory(self._cached_key)

    def touch_cached_key(self, ttl_seconds: int = 3600):
        if self._cached_key is None:
            return
        self._cache_expires_at = datetime.now() + timedelta(seconds=ttl_seconds)

    def is_cache_expired(self) -> bool:
        return self._cache_expires_at is not None and datetime.now() >= self._cache_expires_at

    def get_cached_key(self) -> Optional[bytes]:
        if self._cached_key is None or self.is_cache_expired():
            return None
        key_bytes = self._read_cached_key()
        return key_bytes[: self._cached_key_length]

    def clear_cached_key(self):
        if self._cached_key is None:
            return
        if self._memory_protected:
            self._unprotect_in_place(self._cached_key)
        for index in range(len(self._cached_key)):
            self._cached_key[index] = 0
        self._cached_key = None
        self._cached_key_length = 0
        self._cache_expires_at = None
        self._memory_protected = False

    def _decode_params(self, record: KeyStore) -> dict:
        raw = record.key_data or record.params.encode("utf-8")
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _decode_legacy_params(self, record: KeyStore) -> dict:
        if not record.params:
            return {}
        try:
            return json.loads(record.params)
        except json.JSONDecodeError:
            return {}

    def _decode_text(self, raw: bytes, fallback: str) -> str:
        if raw:
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return fallback
        return fallback

    def _read_cached_key(self) -> bytes:
        if self._cached_key is None:
            return b""
        temp = bytearray(self._cached_key)
        try:
            if self._memory_protected:
                self._unprotect_in_place(temp)
            return bytes(temp)
        finally:
            for index in range(len(temp)):
                temp[index] = 0

    def _load_crypt32(self):
        if ctypes.sizeof(ctypes.c_void_p) == 0:
            return None
        try:
            crypt32 = ctypes.windll.crypt32
            crypt32.CryptProtectMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
            crypt32.CryptProtectMemory.restype = ctypes.c_bool
            crypt32.CryptUnprotectMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
            crypt32.CryptUnprotectMemory.restype = ctypes.c_bool
            return crypt32
        except AttributeError:
            return None

    def _protect_memory(self, buffer: bytearray) -> bool:
        if self._crypt32 is None:
            return False
        block_size = 16
        remainder = len(buffer) % block_size
        if remainder:
            buffer.extend(b"\x00" * (block_size - remainder))
        raw = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        return bool(self._crypt32.CryptProtectMemory(raw, len(buffer), 0))

    def _unprotect_in_place(self, buffer: bytearray):
        if self._crypt32 is None:
            return
        raw = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        self._crypt32.CryptUnprotectMemory(raw, len(buffer), 0)