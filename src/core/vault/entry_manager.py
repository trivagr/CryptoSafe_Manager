from datetime import (
    datetime,
    timezone
)

from src.core.events import (
    EntryAdded,
    EntryUpdated,
    EntryDeleted
)


class EntryManager:

    def __init__(
            self,
            db_connection,
            key_manager,
            event_system
    ):

        self.db = db_connection
        self.key_manager = key_manager
        self.event_system = event_system

    def create_entry(self, data):

        created = datetime.now(timezone.utc).isoformat()

        entry_id = self.db.add_entry(
            title=data.get("title",""),
            username=data.get("username",""),
            password=data.get("password",""),
            url=data.get("url",""),
            notes=data.get("notes",""),
            category=data.get("category",""),
            created_at=created,
            updated_at=created,
            tags=""
        )

        self.event_system.publish(
            EntryAdded(
                timestamp=datetime.now(),
                entry_id=entry_id
            )
        )

        return entry_id

    def get_all_entries(self):

        with self.db._connection() as conn:

            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, encrypted_data, created_at, updated_at FROM vault_entries
            """)

            rows = cursor.fetchall()

        result = []

        for row in rows:
            decrypted = self.db.crypto.decrypt(row[1])

            result.append({
                "id":row[0],
                "title":
                    decrypted.get("title",""),
                "username":
                    decrypted.get("username",""),
                "password":
                    decrypted.get("password",""),
                "url":
                    decrypted.get("url",""),
                "notes":
                    decrypted.get("notes",""),
                "category":
                    decrypted.get("category",""),
                "created_at": row[2],
                "updated_at": row[3]})

        return result

    def update_entry(self, entry_id, data):
        old = None

        for item in self.get_all_entries():

            if item["id"] == entry_id:
                old = item
                break

        if old is None:

            raise ValueError(
                "Entry not found"
            )

        updated = {
            "title":
                data.get("title", old["title"]),
            "username":
                data.get("username", old["username"]),
            "password":
                data.get( "password", old["password"]),
            "url":
                data.get("url", old["url"]),
            "notes":
                data.get("notes", old["notes"]),
            "category":
                data.get("category", old["category"])
        }

        encrypted = (self.db.crypto.encrypt(updated))

        with self.db._connection() as conn:

            cursor = conn.cursor()

            cursor.execute("""
                UPDATE vault_entries
                SET encrypted_data=?, title=?, username=?, url=?, notes=?, category=?, updated_at=?
                WHERE id=?
            """, (
                encrypted,
                updated["title"],
                updated["username"],
                updated["url"],
                updated["notes"],
                updated["category"],
                datetime.now(timezone.utc).isoformat(),
                entry_id
            ))

        self.event_system.publish(

            EntryUpdated(
                timestamp=
                datetime.now(),
                entry_id=
                entry_id
            )
        )

    def delete_entry(
            self,
            entry_id,
            soft_delete=True
    ):

        with self.db._connection() as conn:

            cursor = conn.cursor()

            if soft_delete:

                cursor.execute("""
                    INSERT INTO
                    deleted_entries(original_entry_id, encrypted_data, deleted_at, expires_at)
                    SELECT id, encrypted_data, ?, ?
                    FROM vault_entries WHERE id=?
                """, (
                    datetime.now(timezone.utc).isoformat(),
                    None,
                    entry_id
                ))

            cursor.execute("""
                DELETE FROM vault_entries
                WHERE id=?
            """, (
                entry_id,
            ))

        self.event_system.publish(

            EntryDeleted(
                timestamp=
               datetime.now(),
                entry_id=
                entry_id
            )
        )