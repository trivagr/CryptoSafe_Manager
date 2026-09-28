from abc import ABC, abstractmethod
from typing import Optional


class EncryptionService(ABC):
    def __init__(self, key_manager=None):
        self.key_manager = key_manager

    def _resolve_key(self, key: Optional[bytes]) -> bytes:
        if key is not None:
            return key
        if self.key_manager is None:
            raise ValueError("Encryption key was not provided")
        resolved = self.key_manager.load_key("active")
        if resolved is None:
            raise ValueError("No active encryption key is available")
        return resolved

    @abstractmethod
    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        pass