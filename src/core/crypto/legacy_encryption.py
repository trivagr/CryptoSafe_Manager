from typing import Optional

from .abstract import EncryptionService


class LegacyXOREncryptionService(EncryptionService):
    """Compatibility cipher for entries created before AES-GCM vault encryption."""

    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        resolved_key = self._resolve_key(key)
        prepared_key = self._prepare_key(resolved_key, len(data))
        return bytes(data[index] ^ prepared_key[index] for index in range(len(data)))

    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        return self.encrypt(ciphertext, key)

    def _prepare_key(self, key: bytes, length: int) -> bytes:
        if length == 0:
            return b""
        if not key:
            raise ValueError("Legacy encryption key must not be empty")
        if len(key) >= length:
            return key[:length]
        repetitions = (length + len(key) - 1) // len(key)
        return (key * repetitions)[:length]