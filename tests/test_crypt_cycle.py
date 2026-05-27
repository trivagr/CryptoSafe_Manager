from src.core.key_manager import KeyManager
from src.core.crypto.placeholder import AES256EncryptionService


def test_encrypt_decrypt_cycle():
    key_manager = KeyManager()

    key_manager.storage.store_key(b"1"*32)

    key_manager._unlocked = True

    crypto = AES256EncryptionService(key_manager)

    data = {
        "title": "gmail",
        "username": "admin",
        "password": "123456",
        "url": "https://gmail.com",
        "notes": "secret",
        "category": "mail"
    }

    encrypted = crypto.encrypt(data)

    blob_text = encrypted.decode(errors="ignore")

    assert "gmail" not in blob_text
    assert "admin" not in blob_text
    assert "123456" not in blob_text

    decrypted = crypto.decrypt(encrypted)

    assert decrypted["title"]=="gmail"

    assert decrypted["username"]=="admin"

    assert decrypted["password"]=="123456"