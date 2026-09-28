import hashlib
import hmac
import os
import time
from typing import Any

from .memory_guard import MemoryGuard


def normalize_secret(value: str | bytes | bytearray | memoryview | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, memoryview):
        return value.tobytes()
    return bytes(value)


def constant_time_compare(left: str | bytes | bytearray | memoryview | None, right: str | bytes | bytearray | memoryview | None) -> bool:
    left_bytes = normalize_secret(left)
    right_bytes = normalize_secret(right)
    max_len = max(len(left_bytes), len(right_bytes), 1)
    padded_left = left_bytes.ljust(max_len, b"\0")
    padded_right = right_bytes.ljust(max_len, b"\0")
    length_match = hmac.compare_digest(len(left_bytes).to_bytes(8, "big"), len(right_bytes).to_bytes(8, "big"))
    return bool(hmac.compare_digest(padded_left, padded_right) and length_match)


def secure_string_compare(left: str | None, right: str | None) -> bool:
    return constant_time_compare(left or "", right or "")


def constant_time_lookup(candidate: str, allowed_values: list[str] | tuple[str, ...] | set[str]) -> bool:
    found = False
    for value in sorted(str(item) for item in allowed_values):
        found = bool(constant_time_compare(candidate, value) or found)
    return found


def blind_digest(payload: bytes, *, salt: bytes | None = None) -> bytes:
    selected_salt = bytes(salt) if salt is not None else os.urandom(16)
    return hashlib.sha256(selected_salt + bytes(payload)).digest()


def optional_random_delay(enabled: bool, *, max_delay_ms: int = 5) -> float:
    if not enabled or max_delay_ms <= 0:
        return 0.0
    delay = int.from_bytes(os.urandom(2), "big") % (max_delay_ms + 1)
    seconds = delay / 1000
    time.sleep(seconds)
    return seconds


def sanitize_security_metadata(data: dict[str, Any]) -> dict[str, Any]:
    sensitive_markers = {"password", "secret", "token", "key", "private", "payload"}
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in sensitive_markers):
            sanitized[key] = "[redacted]"
        else:
            sanitized[key] = value
    return sanitized


class ProtectedKeyOperation:
    def __init__(self, key: bytes | bytearray | memoryview):
        self._guard = MemoryGuard()
        self._key_buffer = bytearray(normalize_secret(key))

    @property
    def key(self) -> bytes:
        return bytes(self._key_buffer)

    @property
    def mutable_key(self) -> bytearray:
        return self._key_buffer

    def wipe(self) -> None:
        self._guard.wipe_bytearray(self._key_buffer)

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.wipe()