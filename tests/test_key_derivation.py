import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.crypto.key_derivation import KeyDerivation


class TestKeyDerivation(unittest.TestCase):
    """Тесты для формирования ключей"""

    def setUp(self):
        """Подготовка перед каждым тестом"""
        self.config = {
            'argon2_time': 3,
            'argon2_memory': 65536,
            'argon2_parallelism': 4,
            'pbkdf2_iterations': 100000
        }
        self.kd = KeyDerivation(self.config)
        self.test_password = "TestPassword123!@#"

    def test_create_auth_hash(self):
        """Тест создания хэша Argon2 (HASH-1, HASH-2)"""
        hash_data = self.kd.create_auth_hash(self.test_password)

        self.assertIn('hash', hash_data)
        self.assertIn('algorithm', hash_data)
        self.assertIn('time_cost', hash_data)
        self.assertIn('memory_cost', hash_data)

        self.assertTrue(hash_data['hash'].startswith('$argon2id$'))

        self.assertEqual(hash_data['time_cost'], 3)
        self.assertEqual(hash_data['memory_cost'], 65536)
        self.assertEqual(hash_data['parallelism'], 4)

    def test_verify_auth_hash_correct(self):
        """Тест проверки правильного пароля"""
        hash_data = self.kd.create_auth_hash(self.test_password)

        result = self.kd.verify_auth_hash(self.test_password, hash_data['hash'])
        self.assertTrue(result)

    def test_verify_auth_hash_incorrect(self):
        """Тест проверки неправильного пароля"""
        hash_data = self.kd.create_auth_hash(self.test_password)

        result = self.kd.verify_auth_hash("WrongPassword", hash_data['hash'])
        self.assertFalse(result)

    def test_derive_encryption_key_consistency(self):
        """Тест консистентности ключа"""
        key1, salt = self.kd.derive_encryption_key(self.test_password)

        for i in range(5):
            key2, _ = self.kd.derive_encryption_key(self.test_password, salt)
            self.assertEqual(key1, key2, f"Итерация {i}: ключи не совпадают")

    def test_derive_key_different_salts(self):
        """Тест: разные соли дают разные ключи"""
        key1, salt1 = self.kd.derive_encryption_key(self.test_password)
        key2, salt2 = self.kd.derive_encryption_key(self.test_password)

        self.assertNotEqual(salt1, salt2)

        self.assertNotEqual(key1, key2)

    def test_derive_key_length(self):
        """Тест: длина ключа 32 байта"""
        key, _ = self.kd.derive_encryption_key(self.test_password)
        self.assertEqual(len(key), 32)

    def test_derive_key_with_known_salt(self):
        """Тест: derive_key_with_known_salt возвращает тот же ключ"""
        key1, salt = self.kd.derive_encryption_key(self.test_password)
        key2 = self.kd.derive_key_with_known_salt(self.test_password, salt)

        self.assertEqual(key1, key2)

    def test_different_passwords_different_keys(self):
        """Тест: разные пароли дают разные ключи (с одинаковой солью)"""
        password1 = "Password123!"
        password2 = "Password456!"

        _, salt = self.kd.derive_encryption_key(password1)

        key1 = self.kd.derive_key_with_known_salt(password1, salt)
        key2 = self.kd.derive_key_with_known_salt(password2, salt)

        self.assertNotEqual(key1, key2)

    def test_derive_key_empty_password(self):
        """Тест: пустой пароль должен работать (но лучше не использовать)"""
        key, salt = self.kd.derive_encryption_key("")
        self.assertEqual(len(key), 32)
        self.assertEqual(len(salt), 16)


if __name__ == '__main__':
    unittest.main()