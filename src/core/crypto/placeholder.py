import ctypes
from src.core.crypto.abstract import EncryptionService

def secure_zero_bytes(data: bytes):
    length = len(data)
    ptr = (ctypes.c_char * length).from_buffer(data)
    for i in range(length):
        ptr[i] = 0

class AES256Placeholder(EncryptionService):

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        data_bytes = bytearray(data)
        key_bytes = bytearray(key)
        encrypted_data = bytearray()

        key_pos = 0
        for b in data_bytes:
            encrypted_data.append(b ^ key_bytes[key_pos])
            key_pos = (key_pos + 1) % len(key_bytes)

        secure_zero_bytes(data_bytes)
        secure_zero_bytes(key_bytes)

        return bytes(encrypted_data)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        cipher_bytes = bytearray(ciphertext)
        key_bytes = bytearray(key)
        decrypted_data = bytearray()

        key_pos = 0
        for b in cipher_bytes:
            decrypted_data.append(b ^ key_bytes[key_pos])
            key_pos = (key_pos + 1) % len(key_bytes)

        secure_zero_bytes(cipher_bytes)
        secure_zero_bytes(key_bytes)

        return bytes(decrypted_data)