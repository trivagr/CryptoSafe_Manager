import ctypes
from src.core.crypto.abstract import EncryptionService

def secure_zero_bytes(data: bytes):
    length = len(data)
    ptr = (ctypes.c_char * length).from_buffer(data)
    for i in range(length):
        ptr[i] = 0

class AES256Placeholder(EncryptionService):

    def encrypt(self, data: bytes) -> bytes:
        return self._key_manager.limited_use_key(lambda key: self.xor(data, key))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._key_manager.limited_use_key(lambda key: self.xor(ciphertext, key))

    def xor(self, data: bytes, key: bytes ) -> bytes:

        data_bytes = bytearray(data)
        key_bytes = bytearray(key)
        result_data = bytearray()

        key_pos = 0
        for b in data_bytes:
            result_data.append(b ^ key_bytes[key_pos])
            key_pos = (key_pos + 1) % len(key_bytes)

        secure_zero_bytes(data_bytes)
        secure_zero_bytes(key_bytes)

        return bytes(result_data)