from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class VaultEntry:  # Класс для представления записи в хранилище паролей.
    id: Optional[int] = None
    title: str = ""
    username: str = ""
    encrypted_password: bytes = b""
    encrypted_data: bytes = b""
    url: str = ""
    notes: str = ""
    category: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: str = ""


@dataclass
class DeletedEntry:
    id: Optional[int] = None
    original_entry_id: Optional[int] = None
    encrypted_data: bytes = b""
    deleted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    title: str = ""


@dataclass
class AuditLog:  # Класс для представления записи в журнале аудита.
    id: Optional[int] = None
    sequence_number: Optional[int] = None
    action: str = ""
    event_type: str = ""
    timestamp: Optional[datetime] = None
    severity: str = "INFO"
    user_id: str = "local-user"
    source: str = "unknown"
    entry_id: Optional[int] = None
    details: str = ""
    previous_hash: str = ""
    entry_hash: str = ""
    entry_data: str = ""
    signature: str = ""
    public_key: str = ""


@dataclass
class Setting:  # Класс для представления настройки приложения.
    id: Optional[int] = None
    setting_key: str = ""
    setting_value: str = ""
    encrypted: bool = False


@dataclass
class KeyStore:  # Класс для представления информации о ключе шифрования.
    id: Optional[int] = None
    key_type: str = ""
    key_data: bytes = b""
    version: int = 1
    created_at: Optional[datetime] = None
    salt: bytes = b""
    hash: str = ""
    params: str = ""
    last_rotated_at: Optional[datetime] = None