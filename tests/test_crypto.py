import unittest

from src.core.crypto.placeholder import AES256EncryptionService
from src.core.key_manager import KeyManager


class TestAES256Encryption(unittest.TestCase):

    def setUp(self):

        self.key_manager = KeyManager()

        self.key_manager.storage.store_key(b"1" * 32)

        self.key_manager._unlocked = True

        self.crypto = AES256EncryptionService(self.key_manager)

        self.data = {
            "title": "gmail",
            "username": "admin",
            "password": "123456",
            "url": "https://gmail.com",
            "notes": "secret",
            "category": "mail"
        }

    def test_encrypt_decrypt(self):

        encrypted = self.crypto.encrypt(self.data)

        decrypted = self.crypto.decrypt(encrypted)

        self.assertEqual(
            decrypted["title"],
            self.data["title"]
        )

        self.assertEqual(
            decrypted["username"],
            self.data["username"]
        )

        self.assertEqual(
            decrypted["password"],
            self.data["password"]
        )

    def test_encrypt_changes_data(self):

        encrypted = self.crypto.encrypt(self.data)

        self.assertNotEqual(
            encrypted,
            str(self.data).encode()
        )


if __name__ == "__main__":
    unittest.main()