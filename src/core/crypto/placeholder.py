from src.core.crypto.abstract import EncryptionService

class AES256Placeholder(EncryptionService):

    def encrypt(self, data : bytes, key : bytes) -> bytes:
        encrypt_data = bytearray()
        key_byte_position = 0
        for i in range(len(data)):
            encrypt_data.append(data[i] ^ key[key_byte_position])
            key_byte_position = (key_byte_position + 1) % len(key)
        return bytes(encrypt_data)

    def decrypt(self, cyphertext : bytes, key : bytes) -> bytes:
        decrypt_data = bytearray()
        key_byte_position = 0
        for i in range(len(cyphertext)):
            decrypt_data.append(cyphertext[i] ^ key[key_byte_position])
            key_byte_position = (key_byte_position + 1) % len(key)
        return bytes(decrypt_data)