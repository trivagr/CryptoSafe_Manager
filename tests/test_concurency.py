import threading
from datetime import datetime

from src.database.db import DatabaseHelper
from src.core.key_manager import KeyManager
from src.core.crypto.placeholder import AES256EncryptionService


def test_concurrency(tmp_path):

    manager=KeyManager()

    manager.storage.store_key(b"1"*32)

    manager._unlocked=True

    crypto=(AES256EncryptionService(manager))

    db=DatabaseHelper(tmp_path/"concurrent.db",crypto)

    def worker(index):

        db.add_entry(
            title=f"{index}",
            username="u",
            password="p",
            url="x",
            notes="n",
            category="c",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags=""
        )

    threads=[]

    for i in range(50):
        t=threading.Thread(
            target=worker,
            args=(i,)
        )

        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    rows=db.get_all()

    assert len(rows)==50