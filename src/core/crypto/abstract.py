from abc import ABC, abstractmethod


class EncryptionService(ABC):
    def __init__(self, key_manager):
        self._key_manager = key_manager

    @abstractmethod
    def encrypt(self, data : dict) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext : bytes) -> bytes:
        pass