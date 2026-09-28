import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.crypto.abstract import EncryptionService
from src.core.crypto.legacy_encryption import LegacyXOREncryptionService
from src.core.key_manager import KeyManager


class TestCrypto(unittest.TestCase):  # класс для тестирования криптографических функций

    def setUp(self):  # метод для настройки тестовой среды
        self.crypto = LegacyXOREncryptionService()
        self.key_manager = KeyManager()
        self.test_key = b"test_key_16_bytes"
        self.test_data = b"Hello, World!"

    def test_encryption_service_abstract(
            self):  # тест для проверки, что абстрактный класс EncryptionService не может быть инстанцирован напрямую
        with self.assertRaises(TypeError):
            EncryptionService()

    def test_encrypt_decrypt(self):  # тест для проверки шифрования и расшифровки
        encrypted = self.crypto.encrypt(self.test_data, self.test_key)
        decrypted = self.crypto.decrypt(encrypted, self.test_key)
        self.assertEqual(self.test_data, decrypted)

    def test_different_keys(self):  # тест для проверки, что разные ключи дают разный результат
        key1 = b"key123"
        key2 = b"key456"

        encrypted1 = self.crypto.encrypt(self.test_data, key1)
        encrypted2 = self.crypto.encrypt(self.test_data, key2)

        self.assertNotEqual(encrypted1, encrypted2)

    def test_key_manager_derive(self):  # тест для проверки, что key_manager может создать ключ из пароля
        password = "test_password"
        key, salt = self.key_manager.derive_key(password)

        self.assertIsInstance(key, bytes)
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(key), 32)  # 32 байта для AES-256

    def test_key_manager_store_load(self):  # тест для проверки, что key_manager может сохранить и загрузить ключ
        test_key = b"test_key_123"
        self.key_manager.store_key("test", test_key)
        loaded = self.key_manager.load_key("test")
        self.assertEqual(test_key, loaded)


if __name__ == '__main__':
    unittest.main()