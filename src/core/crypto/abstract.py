from abc import ABC, abstractmethod

class EncryptionService(ABC):

    @abstractmethod
    def encrypt(self, data : bytes, key : bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cyphertext : bytes, key : bytes) -> bytes:
        pass