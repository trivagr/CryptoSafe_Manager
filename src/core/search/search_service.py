from rapidfuzz import fuzz
from collections import deque
from src.database.db import DatabaseHelper


class SearchService:

    def __init__(self, db: DatabaseHelper):
        self.db = db
        self.history = deque(maxlen=10)

    def search(self, query: str):
        query = query.strip()

        if not query:
            return []

        self.history.append(query)

        fts_results = self.db.execute("""
            SELECT rowid, title, username, url, notes
            FROM vault_entries_fts
            WHERE vault_entries_fts MATCH ?
            LIMIT 50
        """, (query,))

        if fts_results:
            return self._format(fts_results)

        all_rows = self.db.execute("""
            SELECT id, encrypted_data
            FROM vault_entries
        """)

        results = []

        for row_id, enc in all_rows:
            data = self.db.crypto.decrypt(enc)

            blob = " ".join([
                data.get("title", ""),
                data.get("username", ""),
                data.get("url", ""),
                data.get("notes", "")
            ])

            score = fuzz.token_sort_ratio(query, blob)

            if score > 60:
                results.append((row_id, data, score))

        results.sort(key=lambda x: x[2], reverse=True)

        return [r[1] for r in results]

    def _format(self, rows):
        return [
            {
                "id": r[0],
                "title": r[1],
                "username": r[2],
                "url": r[3],
                "notes": r[4],
            }
            for r in rows
        ]