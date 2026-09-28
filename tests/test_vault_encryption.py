import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.key_manager import KeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService, VaultEncryptionError


class TestVaultEncryption(unittest.TestCase):
    def setUp(self):
        self.key_manager = KeyManager()
        self.service = AESGCMEncryptionService(self.key_manager)
        self.key = os.urandom(32)
        self.plaintext = b'{"title":"Example","password":"secret"}'

    def test_encrypt_decrypt_roundtrip_with_explicit_key(self):
        mutable_key = bytearray(self.key)

        encrypted = self.service.encrypt(self.plaintext, mutable_key)
        decrypted = self.service.decrypt(encrypted, mutable_key)

        self.assertEqual(decrypted, self.plaintext)
        self.assertNotEqual(encrypted, self.plaintext)
        self.assertEqual(len(encrypted[:12]), 12)
        self.assertEqual(mutable_key, bytearray(self.key))

    def test_encrypt_decrypt_uses_active_key_from_key_manager(self):
        self.key_manager.store_key("active", self.key)

        encrypted = self.service.encrypt(self.plaintext)
        decrypted = self.service.decrypt(encrypted)

        self.assertEqual(decrypted, self.plaintext)

    def test_tampered_ciphertext_fails_authentication(self):
        encrypted = bytearray(self.service.encrypt(self.plaintext, self.key))
        encrypted[-1] ^= 0x01

        with self.assertRaises(VaultEncryptionError):
            self.service.decrypt(bytes(encrypted), self.key)

    def test_missing_active_key_raises_error(self):
        with self.assertRaises(ValueError):
            self.service.encrypt(self.plaintext)

    def test_invalid_key_length_raises_error(self):
        with self.assertRaises(ValueError):
            self.service.encrypt(self.plaintext, b"short-key")

    def test_payload_shorter_than_nonce_is_invalid(self):
        with self.assertRaises(VaultEncryptionError):
            self.service.decrypt(b"too-short", self.key)


if __name__ == "__main__":
    unittest.main()