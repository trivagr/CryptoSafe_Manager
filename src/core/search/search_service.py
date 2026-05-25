import re
from typing import List, Dict

from rapidfuzz import fuzz


class SearchService:

    def __init__(self, entry_manager):
        self.entry_manager = entry_manager

        self._history = []
        self._max_history = 10

    def search(self, query: str) -> List[Dict]:

        query = query.strip().lower()
        if not query:
            return []

        self._add_to_history(query)

        parsed = self._parse_query(query)

        entries = self.entry_manager.get_all_entries()

        results = []

        for entry in entries:
            if self._match(entry, parsed, query):
                results.append(entry)

        results.sort(
            key=lambda x: self._score(x, query),
            reverse=True
        )

        return results

    def get_history(self) -> List[str]:
        return list(self._history)

    def _parse_query(self, query: str) -> dict:

        filters = {}

        pattern = r'(\w+):"([^"]+)"'
        matches = re.findall(pattern, query)

        for key, value in matches:
            filters[key] = value.lower()

        cleaned = re.sub(pattern, "", query).strip()

        return {
            "filters": filters,
            "text": cleaned
        }

    def _match(self, entry: dict, parsed: dict, raw_query: str) -> bool:

        filters = parsed["filters"]
        text = parsed["text"]

        if "title" in filters:
            if filters["title"] not in entry.get("title", "").lower():
                return False

        if "username" in filters:
            if filters["username"] not in entry.get("username", "").lower():
                return False

        if "url" in filters:
            if filters["url"] not in (entry.get("url") or "").lower():
                return False

        if "tag" in filters:
            if filters["tag"] not in (entry.get("tags") or "").lower():
                return False

        if text:
            blob = " ".join([
                entry.get("title", ""),
                entry.get("username", ""),
                entry.get("url", "") or "",
                entry.get("notes", "") or ""
            ]).lower()

            if text not in blob and fuzz.partial_ratio(text, blob) < 70:
                return False

        return True

    def _score(self, entry: dict, query: str) -> int:

        blob = " ".join([
            entry.get("title", ""),
            entry.get("username", ""),
            entry.get("url", "") or "",
            entry.get("notes", "") or ""
        ]).lower()

        return int(fuzz.token_sort_ratio(query, blob))

    def _add_to_history(self, query: str):

        if query in self._history:
            self._history.remove(query)

        self._history.insert(0, query)

        if len(self._history) > self._max_history:
            self._history.pop()