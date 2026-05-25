import os
from src.core.crypto.abstract import EncryptionService
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AES256EncryptionService(EncryptionService):

    NONCE_SIZE = 12

    def encrypt(self, data: bytes) -> bytes:

        key = self._key_manager.get_key()

        nonce = os.urandom(self.NONCE_SIZE)

        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(
            nonce=nonce,
            data=data,
            associated_data=None
        )

        return nonce + ciphertext

    def decrypt(self, encrypted: bytes) -> bytes:

        key = self._key_manager.get_key()

        nonce = encrypted[:self.NONCE_SIZE]
        ciphertext = encrypted[self.NONCE_SIZE:]

        aesgcm = AESGCM(key)

        return aesgcm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None
        )