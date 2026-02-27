import unittest
from src.core.crypto.placeholder import AES256Placeholder

class TestAES256Placeholder(unittest.TestCase):

    def setUp(self):
        self.crypto = AES256Placeholder()
        self.key = b"testkey12345678"
        self.data = b"Hello, CryptoSafe!"

    def test_encrypt_decrypt(self):
        encrypted = self.crypto.encrypt(self.data, self.key)
        decrypted = self.crypto.decrypt(encrypted, self.key)

        self.assertEqual(decrypted, self.data)

    def test_encrypt_changes_data(self):
        encrypted = self.crypto.encrypt(self.data, self.key)
        self.assertNotEqual(encrypted, self.data)

if __name__ == "__main__":
    unittest.main()