import os
import json
from typing import List, Dict
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EntryManager:

    def __init__(self, db_connection, key_manager, event_system):
        self.db = db_connection
        self.key_manager = key_manager
        self.event_system = event_system

    def create_entry(self, data: dict) -> int:

        key = self.key_manager.get_key()
        aesgcm = AESGCM(key)

        nonce = os.urandom(12)

        payload = {
            **data,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "version": 1
        }

        plaintext = json.dumps(payload).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        encrypted_blob = nonce + ciphertext

        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO vault_entries (encrypted_data, created_at, updated_at)
                VALUES (?, ?, ?)
            """, (
                encrypted_blob,
                payload["created_at"],
                payload["created_at"]
            ))

            entry_id = cursor.lastrowid

        self.event_system.publish("EntryCreated", {"entry_id": entry_id})

        return entry_id

    def get_entry(self, entry_id: int) -> dict:

        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT encrypted_data, created_at, updated_at
                FROM vault_entries
                WHERE id = ?
            """, (entry_id,))

            row = cursor.fetchone()

        if not row:
            raise ValueError("Entry not found")

        encrypted_blob = row[0]
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]

        key = self.key_manager.get_key()
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext.decode("utf-8"))

        return {
            "id": entry_id,
            **data,
            "created_at": row[1],
            "updated_at": row[2],
        }

    def get_all_entries(self) -> List[Dict]:

        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, encrypted_data, created_at, updated_at
                FROM vault_entries
            """)

            rows = cursor.fetchall()

        result = []
        key = self.key_manager.get_key()
        aesgcm = AESGCM(key)

        for row in rows:
            entry_id = row[0]
            encrypted_blob = row[1]

            nonce = encrypted_blob[:12]
            ciphertext = encrypted_blob[12:]

            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            data = json.loads(plaintext.decode("utf-8"))

            result.append({
                "id": entry_id,
                **data,
                "created_at": row[2],
                "updated_at": row[3],
            })

        return result

    def update_entry(self, entry_id: int, data: dict) -> dict:

        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id FROM vault_entries WHERE id = ?
            """, (entry_id,))

            if not cursor.fetchone():
                raise ValueError("Entry not found")

            key = self.key_manager.get_key()
            aesgcm = AESGCM(key)

            nonce = os.urandom(12)

            payload = {
                **data,
                "version": 1,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

            plaintext = json.dumps(payload).encode("utf-8")
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            encrypted_blob = nonce + ciphertext

            cursor.execute("""
                UPDATE vault_entries
                SET encrypted_data = ?, updated_at = ?
                WHERE id = ?
            """, (
                encrypted_blob,
                payload["updated_at"],
                entry_id
            ))

        self.event_system.publish(
            "EntryUpdated",
            {"entry_id": entry_id}
        )

        return {"id": entry_id, **payload}

    def delete_entry(self, entry_id: int, soft_delete: bool = True):

        with self.db._connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT encrypted_data FROM vault_entries WHERE id = ?
            """, (entry_id,))

            row = cursor.fetchone()

            if not row:
                raise ValueError("Entry not found")

            if soft_delete:

                cursor.execute("""
                    INSERT INTO deleted_entries (
                        entry_id,
                        encrypted_data,
                        deleted_at
                    ) VALUES (?, ?, ?)
                """, (
                    entry_id,
                    row[0],
                    datetime.now(timezone.utc).isoformat()
                ))

            cursor.execute("""  
                DELETE FROM vault_entries WHERE id = ?
            """, (entry_id,))

        self.event_system.publish(
            "EntryDeleted",
            {"entry_id": entry_id}
        )