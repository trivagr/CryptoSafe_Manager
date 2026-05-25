class VaultService:
    def __init__(self, db, crypto):
        self.db = db
        self.crypto = crypto

    def get_all_entries(self):
        rows = self.db.execute("""
            SELECT id, encrypted_data, created_at, updated_at
            FROM vault_entries
        """, fetch=True)

        result = []
        for r in rows:
            data = self.crypto.decrypt(r["encrypted_data"])
            result.append({
                "id": r["id"],
                **data,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })

        return result

    def search(self, query: str):
        return self.db.execute("""
            SELECT rowid FROM vault_entries_fts
            WHERE vault_entries_fts MATCH ?
        """, (query,))