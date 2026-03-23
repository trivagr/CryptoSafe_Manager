from abc import ABC, abstractmethod
from src.core import key_manager


class EncryptionService(ABC):
    def __init__(self, key_manager: key_manager.KeyManager):
        self._key_manager = key_manager

    @abstractmethod
    def encrypt(self, data : bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cyphertext : bytes) -> bytes:
        pass