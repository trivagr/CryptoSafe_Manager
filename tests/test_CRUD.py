from datetime import datetime

from src.database.db import DatabaseHelper
from src.core.key_manager import KeyManager
from src.core.crypto.placeholder import AES256EncryptionService


def test_crud_integration(tmp_path):

    key_manager=KeyManager()

    key_manager.storage.store_key(b"1"*32)

    key_manager._unlocked=True

    crypto=(AES256EncryptionService(key_manager))

    db=DatabaseHelper(tmp_path/"test.db", crypto)

    for i in range(100):

        db.add_entry(
            title=f"site{i}",
            username="user",
            password="pass",
            url="url",
            notes="notes",
            category="test",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags=""
        )

    rows=db.get_all()

    assert len(rows)==100

    for i in range(1,20):

        db.delete_entry(i)

    rows=db.get_all()

    assert len(rows)==81